use core_ruleset::{
    ParseError, RulesetCompiled, RulesetFormat, RulesetInterfaceAddress, RulesetIpPrefixSemantics,
    RulesetMatchContext, RulesetMatcher, parse_ruleset, parse_ruleset_compiled,
};

const FIXTURES: [(&[u8], u8); 5] = [
    (include_bytes!("data/singbox_v1.srs"), 1),
    (include_bytes!("data/singbox_v2.srs"), 2),
    (include_bytes!("data/singbox_v3.srs"), 3),
    (include_bytes!("data/singbox_v4.srs"), 4),
    (include_bytes!("data/singbox_v5.srs"), 5),
];

fn context<'a>(host: &'a str) -> RulesetMatchContext<'a> {
    RulesetMatchContext {
        dst_host: host,
        dst_ip: Some("192.0.2.42".parse().unwrap()),
        dst_port: Some(443),
        src_ip: Some("10.1.2.3".parse().unwrap()),
        src_port: Some(1500),
        network: Some("tcp"),
        process_name: Some("Curl"),
        ..Default::default()
    }
}

fn matcher(name: &str, bytes: &[u8]) -> RulesetMatcher {
    RulesetMatcher::compile_any(
        name,
        parse_ruleset_compiled(RulesetFormat::Srs, bytes).unwrap(),
    )
}

#[test]
fn official_writer_v1_through_v5_preserve_semantics() {
    for (fixture, expected_version) in FIXTURES {
        assert_eq!(&fixture[..3], b"SRS");
        assert_eq!(fixture[3], expected_version);

        let compiled = parse_ruleset_compiled(RulesetFormat::Srs, fixture).unwrap();
        let RulesetCompiled::Semantic(program) = &compiled else {
            panic!("SRS must compile to semantic IR");
        };
        assert_eq!(program.version(), expected_version);
        assert_eq!(program.rule_count(), 1);

        let matcher = RulesetMatcher::compile_any("srs", compiled);
        assert!(matcher.matches_context(&context("exact.example")));
        assert!(matcher.matches_context(&context("www.suffix.example")));
        assert!(matcher.matches_context(&context("root.example")));
        assert!(matcher.matches_context(&context("www.root.example")));

        // leading-dot suffix excludes the root itself.
        assert!(!matcher.matches_context(&context("suffix.example")));
        // Nested logical AND + invert excludes this otherwise matching domain.
        assert!(!matcher.matches_context(&context("blocked.example")));

        let base = context("exact.example");
        assert!(!matcher.matches_context(&RulesetMatchContext {
            src_ip: None,
            ..base
        }));
        assert!(!matcher.matches_context(&RulesetMatchContext {
            src_port: Some(999),
            ..base
        }));
        assert!(!matcher.matches_context(&RulesetMatchContext {
            dst_ip: Some("198.51.100.1".parse().unwrap()),
            ..base
        }));
        assert!(!matcher.matches_context(&RulesetMatchContext {
            dst_port: Some(80),
            ..base
        }));
        assert!(!matcher.matches_context(&RulesetMatchContext {
            network: Some("udp"),
            ..base
        }));
        assert!(!matcher.matches_context(&RulesetMatchContext {
            process_name: Some("curl"),
            ..base
        }));

        let (semantics, ipv4, ipv6) = matcher.destination_ip_prefixes().unwrap();
        assert_eq!(semantics, RulesetIpPrefixSemantics::Extracted);
        assert!(ipv4.contains(&"192.0.2.0/24".parse::<ipnet::Ipv4Net>().unwrap()));
        assert!(
            !ipv4.iter().any(|prefix| {
                prefix.contains(&"10.1.2.3".parse::<std::net::Ipv4Addr>().unwrap())
            }),
            "source_ip_cidr must not leak into destination prefixes"
        );
        assert!(ipv6.is_empty());
    }
}

#[test]
fn old_classical_api_rejects_srs_without_lossy_flattening() {
    let error = parse_ruleset(RulesetFormat::Srs, FIXTURES[0].0).unwrap_err();
    assert!(matches!(error, ParseError::InvalidRule(_)));
    assert!(error.to_string().contains("parse_ruleset_compiled"));
}

#[test]
fn official_v1_context_fields_preserve_and_semantics() {
    let matcher = matcher(
        "srs-fields-v1",
        include_bytes!("data/singbox_fields_v1.srs"),
    );
    let packages = vec!["com.android.chrome".to_owned()];
    let context = RulesetMatchContext {
        query_type: Some(1),
        process_path: Some("/usr/bin/curl"),
        package_names: &packages,
        wifi_ssid: Some("Lab-5G"),
        wifi_bssid: Some("aa:bb:cc:dd:ee:ff"),
        ..Default::default()
    };
    assert!(matcher.matches_context(&context));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        query_type: Some(0),
        ..context
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        wifi_ssid: Some("lab-5g"),
        ..context
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        process_path: Some("/USR/BIN/CURL"),
        ..context
    }));
}

#[test]
fn official_v2_adguard_matcher_preserves_anchors_wildcards_and_suffixes() {
    let matcher = matcher(
        "srs-adguard-v2",
        include_bytes!("data/singbox_adguard_v2.srs"),
    );
    for host in [
        "example.org",
        "www.example.org",
        "EXAMPLE.ORG",
        "exact.example",
        "prefix.ads123.example.suffix",
    ] {
        assert!(matcher.matches_context(&RulesetMatchContext {
            dst_host: host,
            ..Default::default()
        }));
    }
    for host in ["badexample.org", "www.exact.example", "unrelated.example"] {
        assert!(!matcher.matches_context(&RulesetMatchContext {
            dst_host: host,
            ..Default::default()
        }));
    }
}

#[test]
fn official_v3_network_metadata_is_required_and_combined_with_and() {
    let matcher = matcher(
        "srs-network-v3",
        include_bytes!("data/singbox_network_v3.srs"),
    );
    let context = RulesetMatchContext {
        network_type: Some(0),
        network_is_expensive: Some(true),
        network_is_constrained: Some(true),
        ..Default::default()
    };
    assert!(matcher.matches_context(&context));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network_type: None,
        ..context
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network_is_expensive: Some(false),
        ..context
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network_is_constrained: None,
        ..context
    }));
}

#[test]
fn official_v4_interface_fields_keep_map_and_prefix_and_semantics() {
    let matcher = matcher(
        "srs-interfaces-v4",
        include_bytes!("data/singbox_interfaces_v4.srs"),
    );
    let interfaces = vec![
        RulesetInterfaceAddress {
            interface_type: 0,
            address: "192.168.50.0/24".parse().unwrap(),
            is_own: false,
        },
        RulesetInterfaceAddress {
            interface_type: 2,
            address: "10.20.1.0/24".parse().unwrap(),
            is_own: false,
        },
    ];
    let default_addresses = vec![
        "192.168.1.0/24".parse().unwrap(),
        "2001:db8:1::/64".parse().unwrap(),
    ];
    let context = RulesetMatchContext {
        network_interface_addresses: &interfaces,
        default_interface_addresses: &default_addresses,
        ..Default::default()
    };
    assert!(matcher.matches_context(&context));

    // map keys are AND: Wi-Fi alone is insufficient without Ethernet.
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network_interface_addresses: &interfaces[..1],
        ..context
    }));
    // own/tun interfaces are ignored.
    let own_interfaces = vec![
        RulesetInterfaceAddress {
            is_own: true,
            ..interfaces[0].clone()
        },
        interfaces[1].clone(),
    ];
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network_interface_addresses: &own_interfaces,
        ..context
    }));
    // default-interface rule prefixes are AND, not OR.
    assert!(!matcher.matches_context(&RulesetMatchContext {
        default_interface_addresses: &default_addresses[..1],
        ..context
    }));
}

#[test]
fn official_v5_package_regex_is_case_sensitive() {
    let matcher = matcher(
        "srs-package-v5",
        include_bytes!("data/singbox_package_v5.srs"),
    );
    let matching = vec!["com.google.android.gms".to_owned()];
    assert!(matcher.matches_context(&RulesetMatchContext {
        package_names: &matching,
        ..Default::default()
    }));
    let wrong_case = vec!["COM.GOOGLE.android".to_owned()];
    assert!(!matcher.matches_context(&RulesetMatchContext {
        package_names: &wrong_case,
        ..Default::default()
    }));
}

#[test]
fn official_writer_raw_values_are_not_trimmed_lowercased_or_dot_stripped() {
    let matcher = matcher(
        "srs-raw",
        include_bytes!("data/singbox_raw_semantics_v1.srs"),
    );
    // Hostnames are lowercased by the upstream matcher, but stored rules are untouched.
    for host in ["case.example", "key.example", "api.example"] {
        assert!(!matcher.matches_context(&RulesetMatchContext {
            dst_host: host,
            ..Default::default()
        }));
    }
    assert!(matcher.matches_context(&RulesetMatchContext {
        dst_host: "trailing.example.",
        ..Default::default()
    }));
    assert!(matcher.matches_context(&RulesetMatchContext {
        dst_host: "例子.测试",
        ..Default::default()
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        dst_host: "trailing.example",
        ..Default::default()
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        network: Some("tcp"),
        ..Default::default()
    }));
    assert!(matcher.matches_context(&RulesetMatchContext {
        process_name: Some(" Name "),
        ..Default::default()
    }));
    assert!(!matcher.matches_context(&RulesetMatchContext {
        process_name: Some("Name"),
        ..Default::default()
    }));
}
