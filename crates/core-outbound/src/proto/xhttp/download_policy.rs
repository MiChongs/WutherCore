//! Xray `downloadSettings` 的运行时能力边界。
//!
//! 配置层完整、强类型地保存 pinned Xray StreamConfig；真正拨号前，本模块
//! 对当前 Rust 传输尚不能兑现的非默认能力 fail closed，避免“已接受但被忽略”。

use std::io;

use core_config::model::{
    XhttpAddressPortStrategy, XhttpDomainStrategy, XhttpDownloadSocketSettings,
    XhttpDownloadTlsSettings, XhttpFinalMask, XhttpPortList, XhttpQuicParams, XhttpTcpFastOpen,
    XhttpUdpHop,
};

use super::config::DownloadSettings;

pub(super) fn validate_download_runtime(settings: &DownloadSettings) -> io::Result<()> {
    let security = settings.security.trim();
    if !security.is_empty()
        && !security.eq_ignore_ascii_case("none")
        && !security.eq_ignore_ascii_case("tls")
        && !security.eq_ignore_ascii_case("reality")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported xhttp downloadSettings security: {security}"),
        ));
    }
    if security.eq_ignore_ascii_case("reality") {
        return Err(unsupported(
            "realitySettings",
            "Reality TLS handshake is unavailable",
        ));
    }

    // 与 Xray StreamConfig 一致，security 是唯一选择器。未选 TLS 时，
    // 残留的 tlsSettings/realitySettings 不产生任何运行时效果。
    if security.eq_ignore_ascii_case("tls") {
        if let Some(tls) = settings.tls.as_ref() {
            tls.validate_client().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xhttp downloadSettings {error}"),
                )
            })?;
        }
    }

    if let Some(socket) = settings.socket.as_ref() {
        if let Some(field) = unsupported_socket_field(socket) {
            return Err(unsupported(
                field,
                "per-download platform socket policy is unavailable",
            ));
        }
    }

    if let Some(final_mask) = settings.final_mask.as_ref() {
        if let Some(field) = unsupported_final_mask_field(final_mask) {
            return Err(unsupported(
                field,
                "the configured finalmask transform is unavailable",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_primary_tls_runtime(settings: &XhttpDownloadTlsSettings) -> io::Result<()> {
    settings
        .validate_client()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn unsupported(field: &str, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("xhttp downloadSettings {field}: {reason}; refusing to ignore it"),
    )
}

fn has_text(value: Option<&String>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn unsupported_socket_field(settings: &XhttpDownloadSocketSettings) -> Option<&'static str> {
    if settings.mark.is_some_and(|value| value != 0) {
        return Some("sockopt.mark");
    }
    match settings.tcp_fast_open.as_ref() {
        // Xray distinguishes an explicit false (`TFO = -1`) from absence
        // (`TFO = 0`), so both boolean spellings are non-default policies.
        Some(XhttpTcpFastOpen::Enabled(_)) => return Some("sockopt.tcpFastOpen"),
        Some(XhttpTcpFastOpen::QueueLength(value)) if *value != 0 => {
            return Some("sockopt.tcpFastOpen");
        }
        _ => {}
    }
    // tproxy、acceptProxyProtocol、v6only 与 trustedXForwardedFor 都是
    // listener/inbound 上下文字段；downloadSettings 的拨号路径会忽略它们。
    if settings
        .domain_strategy
        .is_some_and(|value| value != XhttpDomainStrategy::AsIs)
    {
        return Some("sockopt.domainStrategy");
    }
    if has_text(settings.dialer_proxy.as_ref()) {
        return Some("sockopt.dialerProxy");
    }
    if settings
        .tcp_keep_alive_interval
        .is_some_and(|value| value != 0)
    {
        return Some("sockopt.tcpKeepAliveInterval");
    }
    if settings.tcp_keep_alive_idle.is_some_and(|value| value != 0) {
        return Some("sockopt.tcpKeepAliveIdle");
    }
    if has_text(settings.tcp_congestion.as_ref()) {
        return Some("sockopt.tcpCongestion");
    }
    if settings.tcp_window_clamp.is_some_and(|value| value != 0) {
        return Some("sockopt.tcpWindowClamp");
    }
    if settings.tcp_max_seg.is_some_and(|value| value != 0) {
        return Some("sockopt.tcpMaxSeg");
    }
    // Xray 只读取外层 XHTTP streamSettings 的 penetrate，用它覆盖嵌套
    // downloadSettings.sockopt；嵌套字段本身不会参与下载拨号。
    if settings.tcp_user_timeout.is_some_and(|value| value != 0) {
        return Some("sockopt.tcpUserTimeout");
    }
    if has_text(settings.interface.as_ref()) {
        return Some("sockopt.interface");
    }
    if settings.tcp_mptcp.unwrap_or(false) {
        return Some("sockopt.tcpMptcp");
    }
    if !settings.custom_sockopt.is_empty() {
        return Some("sockopt.customSockopt");
    }
    if settings
        .address_port_strategy
        .is_some_and(|value| value != XhttpAddressPortStrategy::None)
    {
        return Some("sockopt.addressPortStrategy");
    }
    if settings.happy_eyeballs.as_ref().is_some_and(|value| {
        value.prioritize_ipv6.unwrap_or(false)
            || value.try_delay_ms.unwrap_or(0) != 0
            || value.interleave.is_some_and(|interleave| interleave != 1)
            || value
                .max_concurrent_try
                .is_some_and(|max_concurrent| max_concurrent != 4)
    }) {
        return Some("sockopt.happyEyeballs");
    }
    None
}

fn unsupported_final_mask_field(settings: &XhttpFinalMask) -> Option<&'static str> {
    if !settings.tcp.is_empty() {
        return Some("finalmask.tcp");
    }
    if !settings.udp.is_empty() {
        return Some("finalmask.udp");
    }
    if settings
        .quic_params
        .as_ref()
        .is_some_and(quic_params_non_default)
    {
        return Some("finalmask.quicParams");
    }
    None
}

fn quic_params_non_default(settings: &XhttpQuicParams) -> bool {
    has_text(settings.congestion.as_ref())
        || settings.debug.unwrap_or(false)
        || has_text(settings.bbr_profile.as_ref())
        || has_text(settings.brutal_up.as_ref())
        || has_text(settings.brutal_down.as_ref())
        || settings.udp_hop.as_ref().is_some_and(udp_hop_non_default)
        || settings
            .init_stream_receive_window
            .is_some_and(|value| value != 0)
        || settings
            .max_stream_receive_window
            .is_some_and(|value| value != 0)
        || settings
            .init_connection_receive_window
            .is_some_and(|value| value != 0)
        || settings
            .max_connection_receive_window
            .is_some_and(|value| value != 0)
        || settings.max_idle_timeout.is_some_and(|value| value != 0)
        || settings.keep_alive_period.is_some_and(|value| value != 0)
        || settings.disable_path_mtu_discovery.unwrap_or(false)
        || settings
            .max_incoming_streams
            .is_some_and(|value| value != 0)
}

fn udp_hop_non_default(settings: &XhttpUdpHop) -> bool {
    let ports = match settings.ports.as_ref() {
        Some(XhttpPortList::One(port)) => *port != 0,
        Some(XhttpPortList::List(ports)) => !ports.is_empty(),
        None => false,
    };
    ports
        || settings
            .interval
            .is_some_and(|range| range.left != 0 || range.right != 0)
}

#[cfg(test)]
mod tests {
    use core_config::model::{
        XhttpDownloadTlsCertificate, XhttpFragmentMask, XhttpQuicParams, XhttpTcpMask,
        XhttpTproxyMode,
    };

    use super::*;

    fn settings_with_tls(tls: XhttpDownloadTlsSettings) -> DownloadSettings {
        DownloadSettings {
            security: "tls".into(),
            tls: Some(tls),
            ..Default::default()
        }
    }

    #[test]
    fn supported_tls_download_fields_are_executable() {
        let settings = settings_with_tls(XhttpDownloadTlsSettings {
            server_name: Some("download.example".into()),
            allow_insecure: Some(false),
            alpn: Some(vec!["h2".into()]),
            enable_session_resumption: Some(true),
            fingerprint: Some("chrome".into()),
            pinned_peer_cert_sha256: Some("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".into()),
            verify_peer_cert_by_name: Some("download.example, 127.0.0.1".into()),
            ..Default::default()
        });
        validate_download_runtime(&settings).unwrap();
    }

    #[test]
    fn advanced_tls_fields_are_validated_before_dial() {
        validate_download_runtime(&settings_with_tls(XhttpDownloadTlsSettings {
            min_version: Some("1.2".into()),
            max_version: Some("1.3".into()),
            curve_preferences: Some(vec!["X25519MLKEM768".into(), "X25519".into()]),
            ..Default::default()
        }))
        .unwrap();

        let invalid_cases = [
            XhttpDownloadTlsSettings {
                certificates: vec![XhttpDownloadTlsCertificate::default()],
                ..Default::default()
            },
            XhttpDownloadTlsSettings {
                disable_system_root: Some(true),
                ..Default::default()
            },
            XhttpDownloadTlsSettings {
                ech_config_list: Some("AA==".into()),
                ..Default::default()
            },
        ];
        for tls in invalid_cases {
            let error = validate_download_runtime(&settings_with_tls(tls)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn removed_allow_insecure_is_invalid_but_false_and_absent_are_supported() {
        for allow_insecure in [None, Some(false)] {
            validate_download_runtime(&settings_with_tls(XhttpDownloadTlsSettings {
                allow_insecure,
                ..Default::default()
            }))
            .unwrap();
        }

        let error = validate_download_runtime(&settings_with_tls(XhttpDownloadTlsSettings {
            allow_insecure: Some(true),
            ..Default::default()
        }))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("allowInsecure=true"));
    }

    #[test]
    fn outbound_context_only_fields_match_xray_noop_semantics() {
        validate_download_runtime(&settings_with_tls(XhttpDownloadTlsSettings {
            reject_unknown_sni: Some(true),
            ech_server_keys: Some("server-only".into()),
            ..Default::default()
        }))
        .unwrap();

        let settings = DownloadSettings {
            socket: Some(XhttpDownloadSocketSettings {
                tproxy: Some(XhttpTproxyMode::Redirect),
                accept_proxy_protocol: Some(true),
                penetrate: Some(true),
                v6only: Some(true),
                trusted_x_forwarded_for: vec!["X-Forwarded-For".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_download_runtime(&settings).unwrap();
    }

    #[test]
    fn tls_objects_are_ignored_when_security_does_not_select_tls() {
        let settings = DownloadSettings {
            security: "none".into(),
            tls: Some(XhttpDownloadTlsSettings {
                fingerprint: Some("chrome".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_download_runtime(&settings).unwrap();
    }

    #[test]
    fn reality_socket_and_finalmask_fail_closed() {
        let reality = DownloadSettings {
            security: "reality".into(),
            ..Default::default()
        };
        assert_eq!(
            validate_download_runtime(&reality).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let explicit_tfo_false = DownloadSettings {
            socket: Some(XhttpDownloadSocketSettings {
                tcp_fast_open: Some(XhttpTcpFastOpen::Enabled(false)),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_download_runtime(&explicit_tfo_false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );

        let tcp_mask = DownloadSettings {
            final_mask: Some(XhttpFinalMask {
                tcp: vec![XhttpTcpMask::Fragment {
                    settings: XhttpFragmentMask::default(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_download_runtime(&tcp_mask).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );

        let quic = DownloadSettings {
            final_mask: Some(XhttpFinalMask {
                quic_params: Some(XhttpQuicParams {
                    max_idle_timeout: Some(1),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_download_runtime(&quic).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn explicit_zero_value_policy_objects_remain_noops() {
        let settings = DownloadSettings {
            socket: Some(XhttpDownloadSocketSettings {
                mark: Some(0),
                tcp_fast_open: Some(XhttpTcpFastOpen::QueueLength(0)),
                happy_eyeballs: Some(Default::default()),
                ..Default::default()
            }),
            final_mask: Some(XhttpFinalMask {
                quic_params: Some(XhttpQuicParams::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        validate_download_runtime(&settings).unwrap();
    }
}
