# Third-party notices

The low-level TLS 1.3 record and REALITY state-machine implementation in
`src/donor/` is adapted from Shoes, commit
`386b11532424b8665ee3e46340c6236fb3c47595`:

- Project: https://github.com/cfal/shoes
- Copyright: 2021-2023 Alex Lau
- License: MIT (see `LICENSE-SHOES`)

The integration layer, bounded framing, authentication policy, hybrid
X25519MLKEM768 support, ML-DSA-65 certificate extension, PROXY protocol,
fallback rate limiting and cancellation handling are WutherCore changes.
Protocol behavior is tested against Xray-core commit
`6e3322d219140a025285ded1114fe17a5edb74d8` and xtls/reality commit
`9234c772ba8f`.

The client-side single-ClientHello finalization, current Xray/uTLS profile
catalogue and TLS completion are provided by xray-rust commit
`bb3e00da1abfc5fff70487b0dd2ba16054797584` through the vendored,
locally documented `third_party/xray-transport` crate and the pinned
`xray-utls` crate:

- Project: https://github.com/aimalygin/xray-rust
- Declared license: MPL-2.0
- Vendored license and patch record: `../../third_party/xray-transport/`

Those crates use shaped-rustls commit
`94f088e210fd2a56e413cce1c6d79c10852d500a` so the authenticated REALITY
session ID is finalized on the same live ClientHello used by the TLS transcript
and network write, including a real X25519MLKEM768 key exchange.
