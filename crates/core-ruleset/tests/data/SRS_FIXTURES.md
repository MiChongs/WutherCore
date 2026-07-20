# sing-box SRS fixtures

`singbox_v1.srs` through `singbox_v5.srs` were generated from
`srs_fixture.json` with the official `common/srs.Write` implementation at
sing-box commit `fa36eb769a200e9558c414a36eb16da9a2446ea9`, using sing
`4f1ed45a99a547f387eed5f941841ec60c9e5c2e`.

The fixture generator unmarshalled `srs_fixture.json` as
`option.PlainRuleSetCompat` and called:

```go
srs.Write(output, ruleSet.Options, version)
```

for each version from 1 through 5. Direct use of the official writer is
intentional: the `sing-box rule-set compile` command automatically downgrades
v3–v5 files when their version-specific fields are absent, while these fixtures
must exercise the common supported fields under every binary version.

Current upstream version gates in `common/srs/binary.go` are:

- v1: base fields, including process-path regex.
- v2: AdGuard domain matcher.
- v3: network type, expensive, and constrained flags.
- v4: network-interface and default-interface addresses.
- v5: package-name regex.

Additional fixtures exercise every version-gated field through the official
CLI at the same upstream commit:

- `singbox_fields_v1.srs` was compiled from `srs_fields_v1.json` and covers
  query type, process path/regex, package name, Wi-Fi SSID and BSSID.
- `singbox_adguard_v2.srs` was produced by
  `rule-set convert --type adguard srs_adguard_v2.txt`; AdGuard's compact
  matcher is intentionally not a source-rule JSON field.
- `singbox_network_v3.srs`, `singbox_interfaces_v4.srs`, and
  `singbox_package_v5.srs` were compiled from their same-named JSON sources.
  Each source contains a field introduced by that version, so the official
  compiler cannot downgrade the binary.
- `singbox_raw_semantics_v1.srs` was compiled from
  `srs_raw_semantics.json` and guards upstream case, whitespace, and trailing
  dot behavior.

Commands:

```text
sing-box rule-set compile srs_fields_v1.json -o singbox_fields_v1.srs
sing-box rule-set convert --type adguard srs_adguard_v2.txt -o singbox_adguard_v2.srs
sing-box rule-set compile srs_network_v3.json -o singbox_network_v3.srs
sing-box rule-set compile srs_interfaces_v4.json -o singbox_interfaces_v4.srs
sing-box rule-set compile srs_package_v5.json -o singbox_package_v5.srs
sing-box rule-set compile srs_raw_semantics.json -o singbox_raw_semantics_v1.srs
```
