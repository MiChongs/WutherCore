#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsClientHelloProfile {
    pub cipher_suites: &'static [u16],
    pub supported_versions: &'static [u16],
    pub supported_groups: &'static [u16],
    pub key_shares: &'static [UtlsKeyShare],
    pub signature_algorithms: &'static [u16],
    pub delegated_credentials_algorithms: &'static [u16],
    pub alpn_protocols: &'static [&'static [u8]],
    pub certificate_compression_algorithms: &'static [u16],
    pub record_size_limit: Option<u16>,
    pub application_settings: &'static [UtlsApplicationSettings],
    pub extensions: &'static [UtlsExtension],
    pub padding_length: Option<usize>,
    pub encrypted_client_hello_length: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsKeyShare {
    pub group: u16,
    pub key_exchange_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsApplicationSettings {
    pub extension_type: u16,
    pub protocols: &'static [&'static [u8]],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct UtlsExtension {
    pub extension_type: u16,
    pub payload_len: usize,
}

const GREASE: u16 = 0x0a0a;
const GREASE_SECOND: u16 = 0x1a1a;

const PROFILE_0_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_0_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_0_GROUPS: &[u16] = &[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018];
const PROFILE_0_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x11ec,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_0_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_0_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_0_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_0_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_0_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_0_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x44cd,
    protocols: PROFILE_0_APP_0_PROTOCOLS,
}];
const PROFILE_0_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 186,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x44cd,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_0: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_0_CIPHERS,
    supported_versions: PROFILE_0_VERSIONS,
    supported_groups: PROFILE_0_GROUPS,
    key_shares: PROFILE_0_KEY_SHARES,
    signature_algorithms: PROFILE_0_SIGALGS,
    delegated_credentials_algorithms: PROFILE_0_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_0_ALPN,
    certificate_compression_algorithms: PROFILE_0_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_0_APPS,
    extensions: PROFILE_0_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: Some(186),
};

const PROFILE_1_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_1_VERSIONS: &[u16] = &[0x0304, 0x0303];
const PROFILE_1_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_1_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x11ec,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_1_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_1_DELEGATED_CREDENTIALS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const PROFILE_1_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_1_CERT_COMP: &[u16] = &[0x0001, 0x0002, 0x0003];
const PROFILE_1_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_1_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0022,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1327,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 281,
    },
];
const PROFILE_1: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_1_CIPHERS,
    supported_versions: PROFILE_1_VERSIONS,
    supported_groups: PROFILE_1_GROUPS,
    key_shares: PROFILE_1_KEY_SHARES,
    signature_algorithms: PROFILE_1_SIGALGS,
    delegated_credentials_algorithms: PROFILE_1_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_1_ALPN,
    certificate_compression_algorithms: PROFILE_1_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_1_APPS,
    extensions: PROFILE_1_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: Some(281),
};

const PROFILE_2_CIPHERS: &[u16] = &[
    0x0a0a, 0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
    0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const PROFILE_2_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_2_GROUPS: &[u16] = &[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_2_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x11ec,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_2_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_2_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_2_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_2_CERT_COMP: &[u16] = &[0x0001];
const PROFILE_2_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_2_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 22,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_2: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_2_CIPHERS,
    supported_versions: PROFILE_2_VERSIONS,
    supported_groups: PROFILE_2_GROUPS,
    key_shares: PROFILE_2_KEY_SHARES,
    signature_algorithms: PROFILE_2_SIGALGS,
    delegated_credentials_algorithms: PROFILE_2_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_2_ALPN,
    certificate_compression_algorithms: PROFILE_2_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_2_APPS,
    extensions: PROFILE_2_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_3_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc024, 0xc023,
    0xc00a, 0xc009, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
    0xc008, 0xc012, 0x000a,
];
const PROFILE_3_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_3_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_3_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_3_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_3_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_3_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_3_CERT_COMP: &[u16] = &[];
const PROFILE_3_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_3_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 190,
    },
];
const PROFILE_3: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_3_CIPHERS,
    supported_versions: PROFILE_3_VERSIONS,
    supported_groups: PROFILE_3_GROUPS,
    key_shares: PROFILE_3_KEY_SHARES,
    signature_algorithms: PROFILE_3_SIGALGS,
    delegated_credentials_algorithms: PROFILE_3_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_3_ALPN,
    certificate_compression_algorithms: PROFILE_3_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_3_APPS,
    extensions: PROFILE_3_EXTENSIONS,
    padding_length: Some(190),
    encrypted_client_hello_length: None,
};

const PROFILE_4_CIPHERS: &[u16] = &[
    0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_4_VERSIONS: &[u16] = &[];
const PROFILE_4_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018];
const PROFILE_4_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_4_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_4_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_4_ALPN: &[&[u8]] = &[];
const PROFILE_4_CERT_COMP: &[u16] = &[];
const PROFILE_4_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_4_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 8,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
];
const PROFILE_4: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_4_CIPHERS,
    supported_versions: PROFILE_4_VERSIONS,
    supported_groups: PROFILE_4_GROUPS,
    key_shares: PROFILE_4_KEY_SHARES,
    signature_algorithms: PROFILE_4_SIGALGS,
    delegated_credentials_algorithms: PROFILE_4_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_4_ALPN,
    certificate_compression_algorithms: PROFILE_4_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_4_APPS,
    extensions: PROFILE_4_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_5_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_5_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_5_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_5_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_5_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_5_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_5_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_5_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_5_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_5_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 209,
    },
];
const PROFILE_5: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_5_CIPHERS,
    supported_versions: PROFILE_5_VERSIONS,
    supported_groups: PROFILE_5_GROUPS,
    key_shares: PROFILE_5_KEY_SHARES,
    signature_algorithms: PROFILE_5_SIGALGS,
    delegated_credentials_algorithms: PROFILE_5_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_5_ALPN,
    certificate_compression_algorithms: PROFILE_5_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_5_APPS,
    extensions: PROFILE_5_EXTENSIONS,
    padding_length: Some(209),
    encrypted_client_hello_length: None,
};

const PROFILE_6_CIPHERS: &[u16] = &[
    0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
    0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a,
];
const PROFILE_6_VERSIONS: &[u16] = &[];
const PROFILE_6_GROUPS: &[u16] = &[0x0017, 0x0018, 0x0019];
const PROFILE_6_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_6_SIGALGS: &[u16] = &[
    0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202,
];
const PROFILE_6_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_6_ALPN: &[&[u8]] = &[b"spdy/2", b"spdy/3", b"spdy/3.1", b"http/1.1"];
const PROFILE_6_CERT_COMP: &[u16] = &[];
const PROFILE_6_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_6_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 8,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x3374,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 34,
    },
    UtlsExtension {
        extension_type: 0x754f,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
];
const PROFILE_6: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_6_CIPHERS,
    supported_versions: PROFILE_6_VERSIONS,
    supported_groups: PROFILE_6_GROUPS,
    key_shares: PROFILE_6_KEY_SHARES,
    signature_algorithms: PROFILE_6_SIGALGS,
    delegated_credentials_algorithms: PROFILE_6_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_6_ALPN,
    certificate_compression_algorithms: PROFILE_6_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_6_APPS,
    extensions: PROFILE_6_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_7_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_7_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_7_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_7_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_7_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_7_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_7_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_7_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_7_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_7_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_7_APP_0_PROTOCOLS,
}];
const PROFILE_7_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 200,
    },
];
const PROFILE_7: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_7_CIPHERS,
    supported_versions: PROFILE_7_VERSIONS,
    supported_groups: PROFILE_7_GROUPS,
    key_shares: PROFILE_7_KEY_SHARES,
    signature_algorithms: PROFILE_7_SIGALGS,
    delegated_credentials_algorithms: PROFILE_7_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_7_ALPN,
    certificate_compression_algorithms: PROFILE_7_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_7_APPS,
    extensions: PROFILE_7_EXTENSIONS,
    padding_length: Some(200),
    encrypted_client_hello_length: None,
};

const PROFILE_8_CIPHERS: &[u16] = &[
    0x1302, 0x1301, 0x1303, 0xcca9, 0x009d, 0x003c, 0x009c, 0xc02f, 0xc02c, 0xcca8, 0xc027, 0xc023,
    0xc030, 0xc02b, 0xc014, 0x002f, 0xc00a, 0xc013, 0xc009, 0xc012, 0x000a,
];
const PROFILE_8_VERSIONS: &[u16] = &[0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_8_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_8_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x11ec,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_8_SIGALGS: &[u16] = &[
    0x0503, 0x0804, 0x0201, 0x0501, 0x0401, 0x0601, 0x0806, 0x0403, 0x0805,
];
const PROFILE_8_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_8_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_8_CERT_COMP: &[u16] = &[];
const PROFILE_8_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_8_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1327,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 9,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
];
const PROFILE_8: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_8_CIPHERS,
    supported_versions: PROFILE_8_VERSIONS,
    supported_groups: PROFILE_8_GROUPS,
    key_shares: PROFILE_8_KEY_SHARES,
    signature_algorithms: PROFILE_8_SIGALGS,
    delegated_credentials_algorithms: PROFILE_8_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_8_ALPN,
    certificate_compression_algorithms: PROFILE_8_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_8_APPS,
    extensions: PROFILE_8_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_9_CIPHERS: &[u16] = &[
    0xc023, 0x003c, 0xc02f, 0x009d, 0xc02c, 0xcca8, 0xc02b, 0x009c, 0xc030, 0xc027, 0xc013, 0x000a,
    0x0005, 0x0035, 0x002f, 0xc00a, 0xc011, 0xc014, 0xc009, 0xc007, 0xc012,
];
const PROFILE_9_VERSIONS: &[u16] = &[];
const PROFILE_9_GROUPS: &[u16] = &[0x0017, 0x0018, 0x0019];
const PROFILE_9_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_9_SIGALGS: &[u16] = &[0x0501, 0x0503, 0x0201, 0x0601, 0x0401, 0x0603, 0x0403];
const PROFILE_9_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_9_ALPN: &[&[u8]] = &[];
const PROFILE_9_CERT_COMP: &[u16] = &[];
const PROFILE_9_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_9_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 8,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
];
const PROFILE_9: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_9_CIPHERS,
    supported_versions: PROFILE_9_VERSIONS,
    supported_groups: PROFILE_9_GROUPS,
    key_shares: PROFILE_9_KEY_SHARES,
    signature_algorithms: PROFILE_9_SIGALGS,
    delegated_credentials_algorithms: PROFILE_9_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_9_ALPN,
    certificate_compression_algorithms: PROFILE_9_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_9_APPS,
    extensions: PROFILE_9_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_10_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_10_VERSIONS: &[u16] = &[0x0304, 0x0303];
const PROFILE_10_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_10_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_10_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_10_DELEGATED_CREDENTIALS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const PROFILE_10_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_10_CERT_COMP: &[u16] = &[];
const PROFILE_10_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_10_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0022,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 281,
    },
];
const PROFILE_10: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_10_CIPHERS,
    supported_versions: PROFILE_10_VERSIONS,
    supported_groups: PROFILE_10_GROUPS,
    key_shares: PROFILE_10_KEY_SHARES,
    signature_algorithms: PROFILE_10_SIGALGS,
    delegated_credentials_algorithms: PROFILE_10_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_10_ALPN,
    certificate_compression_algorithms: PROFILE_10_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_10_APPS,
    extensions: PROFILE_10_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: Some(281),
};

const PROFILE_11_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_11_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_11_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_11_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_11_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_11_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_11_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_11_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_11_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_11_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_11_APP_0_PROTOCOLS,
}];
const PROFILE_11_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 186,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 14,
    },
];
const PROFILE_11: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_11_CIPHERS,
    supported_versions: PROFILE_11_VERSIONS,
    supported_groups: PROFILE_11_GROUPS,
    key_shares: PROFILE_11_KEY_SHARES,
    signature_algorithms: PROFILE_11_SIGALGS,
    delegated_credentials_algorithms: PROFILE_11_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_11_ALPN,
    certificate_compression_algorithms: PROFILE_11_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_11_APPS,
    extensions: PROFILE_11_EXTENSIONS,
    padding_length: Some(14),
    encrypted_client_hello_length: Some(186),
};

const PROFILE_12_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_12_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_12_GROUPS: &[u16] = &[0x0a0a, 0x11ec, 0x001d, 0x0017, 0x0018];
const PROFILE_12_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x11ec,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_12_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_12_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_12_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_12_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_12_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_12_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_12_APP_0_PROTOCOLS,
}];
const PROFILE_12_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 186,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_12: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_12_CIPHERS,
    supported_versions: PROFILE_12_VERSIONS,
    supported_groups: PROFILE_12_GROUPS,
    key_shares: PROFILE_12_KEY_SHARES,
    signature_algorithms: PROFILE_12_SIGALGS,
    delegated_credentials_algorithms: PROFILE_12_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_12_ALPN,
    certificate_compression_algorithms: PROFILE_12_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_12_APPS,
    extensions: PROFILE_12_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: Some(186),
};

const PROFILE_13_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f,
    0xc028, 0xc027, 0xc014, 0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008,
    0xc012, 0x000a,
];
const PROFILE_13_VERSIONS: &[u16] = &[0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_13_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_13_KEY_SHARES: &[UtlsKeyShare] = &[UtlsKeyShare {
    group: 0x001d,
    key_exchange_len: 32,
}];
const PROFILE_13_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_13_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_13_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_13_CERT_COMP: &[u16] = &[];
const PROFILE_13_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_13_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 38,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 9,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 210,
    },
];
const PROFILE_13: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_13_CIPHERS,
    supported_versions: PROFILE_13_VERSIONS,
    supported_groups: PROFILE_13_GROUPS,
    key_shares: PROFILE_13_KEY_SHARES,
    signature_algorithms: PROFILE_13_SIGALGS,
    delegated_credentials_algorithms: PROFILE_13_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_13_ALPN,
    certificate_compression_algorithms: PROFILE_13_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_13_APPS,
    extensions: PROFILE_13_EXTENSIONS,
    padding_length: Some(210),
    encrypted_client_hello_length: None,
};

const PROFILE_14_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_14_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_14_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_14_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_14_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_14_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_14_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_14_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_14_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_14_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_14_APP_0_PROTOCOLS,
}];
const PROFILE_14_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 204,
    },
];
const PROFILE_14: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_14_CIPHERS,
    supported_versions: PROFILE_14_VERSIONS,
    supported_groups: PROFILE_14_GROUPS,
    key_shares: PROFILE_14_KEY_SHARES,
    signature_algorithms: PROFILE_14_SIGALGS,
    delegated_credentials_algorithms: PROFILE_14_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_14_ALPN,
    certificate_compression_algorithms: PROFILE_14_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_14_APPS,
    extensions: PROFILE_14_EXTENSIONS,
    padding_length: Some(204),
    encrypted_client_hello_length: None,
};

const PROFILE_15_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
];
const PROFILE_15_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_15_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_15_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_15_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_15_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_15_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_15_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_15_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_15_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x7550,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 201,
    },
];
const PROFILE_15: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_15_CIPHERS,
    supported_versions: PROFILE_15_VERSIONS,
    supported_groups: PROFILE_15_GROUPS,
    key_shares: PROFILE_15_KEY_SHARES,
    signature_algorithms: PROFILE_15_SIGALGS,
    delegated_credentials_algorithms: PROFILE_15_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_15_ALPN,
    certificate_compression_algorithms: PROFILE_15_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_15_APPS,
    extensions: PROFILE_15_EXTENSIONS,
    padding_length: Some(201),
    encrypted_client_hello_length: None,
};

const PROFILE_16_CIPHERS: &[u16] = &[
    0xc023, 0x003c, 0xc02f, 0x009d, 0xc02c, 0xcca8, 0xc02b, 0x009c, 0xc030, 0xc027, 0xc013, 0x000a,
    0x0005, 0x0035, 0x002f, 0xc00a, 0xc011, 0xc014, 0xc009, 0xc007, 0xc012,
];
const PROFILE_16_VERSIONS: &[u16] = &[];
const PROFILE_16_GROUPS: &[u16] = &[0x0017, 0x0018, 0x0019];
const PROFILE_16_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_16_SIGALGS: &[u16] = &[0x0501, 0x0503, 0x0201, 0x0601, 0x0401, 0x0603, 0x0403];
const PROFILE_16_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_16_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_16_CERT_COMP: &[u16] = &[];
const PROFILE_16_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_16_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 8,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
];
const PROFILE_16: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_16_CIPHERS,
    supported_versions: PROFILE_16_VERSIONS,
    supported_groups: PROFILE_16_GROUPS,
    key_shares: PROFILE_16_KEY_SHARES,
    signature_algorithms: PROFILE_16_SIGALGS,
    delegated_credentials_algorithms: PROFILE_16_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_16_ALPN,
    certificate_compression_algorithms: PROFILE_16_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_16_APPS,
    extensions: PROFILE_16_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_17_CIPHERS: &[u16] = &[
    0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039,
    0x002f, 0x0035, 0x000a,
];
const PROFILE_17_VERSIONS: &[u16] = &[];
const PROFILE_17_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_17_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_17_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_17_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_17_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_17_CERT_COMP: &[u16] = &[];
const PROFILE_17_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_17_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
];
const PROFILE_17: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_17_CIPHERS,
    supported_versions: PROFILE_17_VERSIONS,
    supported_groups: PROFILE_17_GROUPS,
    key_shares: PROFILE_17_KEY_SHARES,
    signature_algorithms: PROFILE_17_SIGALGS,
    delegated_credentials_algorithms: PROFILE_17_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_17_ALPN,
    certificate_compression_algorithms: PROFILE_17_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_17_APPS,
    extensions: PROFILE_17_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_18_CIPHERS: &[u16] = &[
    0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039,
    0x002f, 0x0035, 0x000a,
];
const PROFILE_18_VERSIONS: &[u16] = &[];
const PROFILE_18_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_18_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_18_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_18_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_18_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_18_CERT_COMP: &[u16] = &[];
const PROFILE_18_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_18_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
];
const PROFILE_18: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_18_CIPHERS,
    supported_versions: PROFILE_18_VERSIONS,
    supported_groups: PROFILE_18_GROUPS,
    key_shares: PROFILE_18_KEY_SHARES,
    signature_algorithms: PROFILE_18_SIGALGS,
    delegated_credentials_algorithms: PROFILE_18_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_18_ALPN,
    certificate_compression_algorithms: PROFILE_18_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_18_APPS,
    extensions: PROFILE_18_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_19_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a,
];
const PROFILE_19_VERSIONS: &[u16] = &[0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_19_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_19_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_19_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_19_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_19_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_19_CERT_COMP: &[u16] = &[];
const PROFILE_19_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_19_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 9,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 147,
    },
];
const PROFILE_19: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_19_CIPHERS,
    supported_versions: PROFILE_19_VERSIONS,
    supported_groups: PROFILE_19_GROUPS,
    key_shares: PROFILE_19_KEY_SHARES,
    signature_algorithms: PROFILE_19_SIGALGS,
    delegated_credentials_algorithms: PROFILE_19_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_19_ALPN,
    certificate_compression_algorithms: PROFILE_19_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_19_APPS,
    extensions: PROFILE_19_EXTENSIONS,
    padding_length: Some(147),
    encrypted_client_hello_length: None,
};

const PROFILE_20_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x0033, 0x0039, 0x002f, 0x0035, 0x000a,
];
const PROFILE_20_VERSIONS: &[u16] = &[0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_20_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_20_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_20_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_20_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_20_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_20_CERT_COMP: &[u16] = &[];
const PROFILE_20_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_20_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 9,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 147,
    },
];
const PROFILE_20: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_20_CIPHERS,
    supported_versions: PROFILE_20_VERSIONS,
    supported_groups: PROFILE_20_GROUPS,
    key_shares: PROFILE_20_KEY_SHARES,
    signature_algorithms: PROFILE_20_SIGALGS,
    delegated_credentials_algorithms: PROFILE_20_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_20_ALPN,
    certificate_compression_algorithms: PROFILE_20_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_20_APPS,
    extensions: PROFILE_20_EXTENSIONS,
    padding_length: Some(147),
    encrypted_client_hello_length: None,
};

const PROFILE_21_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
];
const PROFILE_21_VERSIONS: &[u16] = &[0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_21_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_21_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_21_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_21_DELEGATED_CREDENTIALS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const PROFILE_21_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_21_CERT_COMP: &[u16] = &[];
const PROFILE_21_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_21_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0022,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 9,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 133,
    },
];
const PROFILE_21: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_21_CIPHERS,
    supported_versions: PROFILE_21_VERSIONS,
    supported_groups: PROFILE_21_GROUPS,
    key_shares: PROFILE_21_KEY_SHARES,
    signature_algorithms: PROFILE_21_SIGALGS,
    delegated_credentials_algorithms: PROFILE_21_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_21_ALPN,
    certificate_compression_algorithms: PROFILE_21_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_21_APPS,
    extensions: PROFILE_21_EXTENSIONS,
    padding_length: Some(133),
    encrypted_client_hello_length: None,
};

const PROFILE_22_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_22_VERSIONS: &[u16] = &[0x0304, 0x0303];
const PROFILE_22_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_22_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_22_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_22_DELEGATED_CREDENTIALS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const PROFILE_22_ALPN: &[&[u8]] = &[b"h2"];
const PROFILE_22_CERT_COMP: &[u16] = &[];
const PROFILE_22_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_22_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0022,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 148,
    },
];
const PROFILE_22: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_22_CIPHERS,
    supported_versions: PROFILE_22_VERSIONS,
    supported_groups: PROFILE_22_GROUPS,
    key_shares: PROFILE_22_KEY_SHARES,
    signature_algorithms: PROFILE_22_SIGALGS,
    delegated_credentials_algorithms: PROFILE_22_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_22_ALPN,
    certificate_compression_algorithms: PROFILE_22_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_22_APPS,
    extensions: PROFILE_22_EXTENSIONS,
    padding_length: Some(148),
    encrypted_client_hello_length: None,
};

const PROFILE_23_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_23_VERSIONS: &[u16] = &[0x0304, 0x0303];
const PROFILE_23_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101];
const PROFILE_23_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
    UtlsKeyShare {
        group: 0x0017,
        key_exchange_len: 65,
    },
];
const PROFILE_23_SIGALGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
const PROFILE_23_DELEGATED_CREDENTIALS: &[u16] = &[0x0403, 0x0503, 0x0603, 0x0203];
const PROFILE_23_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_23_CERT_COMP: &[u16] = &[];
const PROFILE_23_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_23_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0022,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 107,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001c,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 139,
    },
];
const PROFILE_23: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_23_CIPHERS,
    supported_versions: PROFILE_23_VERSIONS,
    supported_groups: PROFILE_23_GROUPS,
    key_shares: PROFILE_23_KEY_SHARES,
    signature_algorithms: PROFILE_23_SIGALGS,
    delegated_credentials_algorithms: PROFILE_23_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_23_ALPN,
    certificate_compression_algorithms: PROFILE_23_CERT_COMP,
    record_size_limit: Some(0x4001),
    application_settings: PROFILE_23_APPS,
    extensions: PROFILE_23_EXTENSIONS,
    padding_length: Some(139),
    encrypted_client_hello_length: None,
};

const PROFILE_24_CIPHERS: &[u16] = &[
    0x0a0a, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
    0x0035, 0x000a,
];
const PROFILE_24_VERSIONS: &[u16] = &[];
const PROFILE_24_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_24_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_24_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_24_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_24_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_24_CERT_COMP: &[u16] = &[];
const PROFILE_24_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_24_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x7550,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_24: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_24_CIPHERS,
    supported_versions: PROFILE_24_VERSIONS,
    supported_groups: PROFILE_24_GROUPS,
    key_shares: PROFILE_24_KEY_SHARES,
    signature_algorithms: PROFILE_24_SIGALGS,
    delegated_credentials_algorithms: PROFILE_24_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_24_ALPN,
    certificate_compression_algorithms: PROFILE_24_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_24_APPS,
    extensions: PROFILE_24_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_25_CIPHERS: &[u16] = &[
    0x0a0a, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
    0x0035, 0x000a,
];
const PROFILE_25_VERSIONS: &[u16] = &[];
const PROFILE_25_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_25_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_25_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_25_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_25_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_25_CERT_COMP: &[u16] = &[];
const PROFILE_25_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_25_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x7550,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_25: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_25_CIPHERS,
    supported_versions: PROFILE_25_VERSIONS,
    supported_groups: PROFILE_25_GROUPS,
    key_shares: PROFILE_25_KEY_SHARES,
    signature_algorithms: PROFILE_25_SIGALGS,
    delegated_credentials_algorithms: PROFILE_25_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_25_ALPN,
    certificate_compression_algorithms: PROFILE_25_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_25_APPS,
    extensions: PROFILE_25_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_26_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
];
const PROFILE_26_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_26_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_26_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_26_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_26_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_26_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_26_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_26_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_26_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x7550,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 201,
    },
];
const PROFILE_26: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_26_CIPHERS,
    supported_versions: PROFILE_26_VERSIONS,
    supported_groups: PROFILE_26_GROUPS,
    key_shares: PROFILE_26_KEY_SHARES,
    signature_algorithms: PROFILE_26_SIGALGS,
    delegated_credentials_algorithms: PROFILE_26_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_26_ALPN,
    certificate_compression_algorithms: PROFILE_26_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_26_APPS,
    extensions: PROFILE_26_EXTENSIONS,
    padding_length: Some(201),
    encrypted_client_hello_length: None,
};

const PROFILE_27_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
];
const PROFILE_27_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_27_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_27_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_27_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_27_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_27_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_27_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_27_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_27_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 205,
    },
];
const PROFILE_27: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_27_CIPHERS,
    supported_versions: PROFILE_27_VERSIONS,
    supported_groups: PROFILE_27_GROUPS,
    key_shares: PROFILE_27_KEY_SHARES,
    signature_algorithms: PROFILE_27_SIGALGS,
    delegated_credentials_algorithms: PROFILE_27_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_27_ALPN,
    certificate_compression_algorithms: PROFILE_27_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_27_APPS,
    extensions: PROFILE_27_EXTENSIONS,
    padding_length: Some(205),
    encrypted_client_hello_length: None,
};

const PROFILE_28_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_28_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_28_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_28_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_28_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_28_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_28_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_28_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_28_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_28_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 209,
    },
];
const PROFILE_28: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_28_CIPHERS,
    supported_versions: PROFILE_28_VERSIONS,
    supported_groups: PROFILE_28_GROUPS,
    key_shares: PROFILE_28_KEY_SHARES,
    signature_algorithms: PROFILE_28_SIGALGS,
    delegated_credentials_algorithms: PROFILE_28_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_28_ALPN,
    certificate_compression_algorithms: PROFILE_28_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_28_APPS,
    extensions: PROFILE_28_EXTENSIONS,
    padding_length: Some(209),
    encrypted_client_hello_length: None,
};

const PROFILE_29_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_29_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_29_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_29_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_29_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_29_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_29_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_29_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_29_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_29_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 209,
    },
];
const PROFILE_29: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_29_CIPHERS,
    supported_versions: PROFILE_29_VERSIONS,
    supported_groups: PROFILE_29_GROUPS,
    key_shares: PROFILE_29_KEY_SHARES,
    signature_algorithms: PROFILE_29_SIGALGS,
    delegated_credentials_algorithms: PROFILE_29_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_29_ALPN,
    certificate_compression_algorithms: PROFILE_29_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_29_APPS,
    extensions: PROFILE_29_EXTENSIONS,
    padding_length: Some(209),
    encrypted_client_hello_length: None,
};

const PROFILE_30_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_30_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_30_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_30_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_30_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_30_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_30_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_30_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_30_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_30_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_30_APP_0_PROTOCOLS,
}];
const PROFILE_30_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 200,
    },
];
const PROFILE_30: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_30_CIPHERS,
    supported_versions: PROFILE_30_VERSIONS,
    supported_groups: PROFILE_30_GROUPS,
    key_shares: PROFILE_30_KEY_SHARES,
    signature_algorithms: PROFILE_30_SIGALGS,
    delegated_credentials_algorithms: PROFILE_30_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_30_ALPN,
    certificate_compression_algorithms: PROFILE_30_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_30_APPS,
    extensions: PROFILE_30_EXTENSIONS,
    padding_length: Some(200),
    encrypted_client_hello_length: None,
};

const PROFILE_31_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_31_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_31_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_31_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_31_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_31_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_31_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_31_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_31_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_31_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_31_APP_0_PROTOCOLS,
}];
const PROFILE_31_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 204,
    },
];
const PROFILE_31: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_31_CIPHERS,
    supported_versions: PROFILE_31_VERSIONS,
    supported_groups: PROFILE_31_GROUPS,
    key_shares: PROFILE_31_KEY_SHARES,
    signature_algorithms: PROFILE_31_SIGALGS,
    delegated_credentials_algorithms: PROFILE_31_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_31_ALPN,
    certificate_compression_algorithms: PROFILE_31_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_31_APPS,
    extensions: PROFILE_31_EXTENSIONS,
    padding_length: Some(204),
    encrypted_client_hello_length: None,
};

const PROFILE_32_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_32_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_32_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_32_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_32_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_32_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_32_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_32_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_32_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_32_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_32_APP_0_PROTOCOLS,
}];
const PROFILE_32_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 204,
    },
];
const PROFILE_32: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_32_CIPHERS,
    supported_versions: PROFILE_32_VERSIONS,
    supported_groups: PROFILE_32_GROUPS,
    key_shares: PROFILE_32_KEY_SHARES,
    signature_algorithms: PROFILE_32_SIGALGS,
    delegated_credentials_algorithms: PROFILE_32_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_32_ALPN,
    certificate_compression_algorithms: PROFILE_32_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_32_APPS,
    extensions: PROFILE_32_EXTENSIONS,
    padding_length: Some(204),
    encrypted_client_hello_length: None,
};

const PROFILE_33_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_33_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_33_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_33_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_33_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_33_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_33_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_33_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_33_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_33_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_33_APP_0_PROTOCOLS,
}];
const PROFILE_33_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 204,
    },
];
const PROFILE_33: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_33_CIPHERS,
    supported_versions: PROFILE_33_VERSIONS,
    supported_groups: PROFILE_33_GROUPS,
    key_shares: PROFILE_33_KEY_SHARES,
    signature_algorithms: PROFILE_33_SIGALGS,
    delegated_credentials_algorithms: PROFILE_33_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_33_ALPN,
    certificate_compression_algorithms: PROFILE_33_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_33_APPS,
    extensions: PROFILE_33_EXTENSIONS,
    padding_length: Some(204),
    encrypted_client_hello_length: None,
};

const PROFILE_34_CIPHERS: &[u16] = &[
    0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014,
    0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
];
const PROFILE_34_VERSIONS: &[u16] = &[];
const PROFILE_34_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_34_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_34_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_34_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_34_ALPN: &[&[u8]] = &[
    b"h2",
    b"h2-16",
    b"h2-15",
    b"h2-14",
    b"spdy/3.1",
    b"spdy/3",
    b"http/1.1",
];
const PROFILE_34_CERT_COMP: &[u16] = &[];
const PROFILE_34_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_34_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 20,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x3374,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 48,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
];
const PROFILE_34: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_34_CIPHERS,
    supported_versions: PROFILE_34_VERSIONS,
    supported_groups: PROFILE_34_GROUPS,
    key_shares: PROFILE_34_KEY_SHARES,
    signature_algorithms: PROFILE_34_SIGALGS,
    delegated_credentials_algorithms: PROFILE_34_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_34_ALPN,
    certificate_compression_algorithms: PROFILE_34_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_34_APPS,
    extensions: PROFILE_34_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_35_CIPHERS: &[u16] = &[
    0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xcca9, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014,
    0xc013, 0xcca8, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const PROFILE_35_VERSIONS: &[u16] = &[];
const PROFILE_35_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_35_KEY_SHARES: &[UtlsKeyShare] = &[];
const PROFILE_35_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_35_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_35_ALPN: &[&[u8]] = &[
    b"h2",
    b"h2-16",
    b"h2-15",
    b"h2-14",
    b"spdy/3.1",
    b"spdy/3",
    b"http/1.1",
];
const PROFILE_35_CERT_COMP: &[u16] = &[];
const PROFILE_35_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_35_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x3374,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 48,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
];
const PROFILE_35: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_35_CIPHERS,
    supported_versions: PROFILE_35_VERSIONS,
    supported_groups: PROFILE_35_GROUPS,
    key_shares: PROFILE_35_KEY_SHARES,
    signature_algorithms: PROFILE_35_SIGALGS,
    delegated_credentials_algorithms: PROFILE_35_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_35_ALPN,
    certificate_compression_algorithms: PROFILE_35_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_35_APPS,
    extensions: PROFILE_35_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_36_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a, 0xc009,
    0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a,
];
const PROFILE_36_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303, 0x0302, 0x0301];
const PROFILE_36_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018, 0x0019];
const PROFILE_36_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_36_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const PROFILE_36_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_36_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_36_CERT_COMP: &[u16] = &[0x0001];
const PROFILE_36_APPS: &[UtlsApplicationSettings] = &[];
const PROFILE_36_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 24,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 11,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 195,
    },
];
const PROFILE_36: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_36_CIPHERS,
    supported_versions: PROFILE_36_VERSIONS,
    supported_groups: PROFILE_36_GROUPS,
    key_shares: PROFILE_36_KEY_SHARES,
    signature_algorithms: PROFILE_36_SIGALGS,
    delegated_credentials_algorithms: PROFILE_36_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_36_ALPN,
    certificate_compression_algorithms: PROFILE_36_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_36_APPS,
    extensions: PROFILE_36_EXTENSIONS,
    padding_length: Some(195),
    encrypted_client_hello_length: None,
};

const PROFILE_37_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_37_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_37_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_37_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_37_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_37_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_37_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_37_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_37_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_37_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_37_APP_0_PROTOCOLS,
}];
const PROFILE_37_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_37: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_37_CIPHERS,
    supported_versions: PROFILE_37_VERSIONS,
    supported_groups: PROFILE_37_GROUPS,
    key_shares: PROFILE_37_KEY_SHARES,
    signature_algorithms: PROFILE_37_SIGALGS,
    delegated_credentials_algorithms: PROFILE_37_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_37_ALPN,
    certificate_compression_algorithms: PROFILE_37_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_37_APPS,
    extensions: PROFILE_37_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_38_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_38_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_38_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_38_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_38_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_38_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_38_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_38_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_38_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_38_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_38_APP_0_PROTOCOLS,
}];
const PROFILE_38_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_38: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_38_CIPHERS,
    supported_versions: PROFILE_38_VERSIONS,
    supported_groups: PROFILE_38_GROUPS,
    key_shares: PROFILE_38_KEY_SHARES,
    signature_algorithms: PROFILE_38_SIGALGS,
    delegated_credentials_algorithms: PROFILE_38_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_38_ALPN,
    certificate_compression_algorithms: PROFILE_38_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_38_APPS,
    extensions: PROFILE_38_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_39_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_39_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_39_GROUPS: &[u16] = &[0x0a0a, 0x001d, 0x0017, 0x0018];
const PROFILE_39_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_39_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_39_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_39_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_39_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_39_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_39_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_39_APP_0_PROTOCOLS,
}];
const PROFILE_39_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 43,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 10,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x0015,
        payload_len: 204,
    },
];
const PROFILE_39: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_39_CIPHERS,
    supported_versions: PROFILE_39_VERSIONS,
    supported_groups: PROFILE_39_GROUPS,
    key_shares: PROFILE_39_KEY_SHARES,
    signature_algorithms: PROFILE_39_SIGALGS,
    delegated_credentials_algorithms: PROFILE_39_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_39_ALPN,
    certificate_compression_algorithms: PROFILE_39_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_39_APPS,
    extensions: PROFILE_39_EXTENSIONS,
    padding_length: Some(204),
    encrypted_client_hello_length: None,
};

const PROFILE_40_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_40_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_40_GROUPS: &[u16] = &[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018];
const PROFILE_40_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x6399,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_40_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_40_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_40_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_40_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_40_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_40_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_40_APP_0_PROTOCOLS,
}];
const PROFILE_40_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_40: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_40_CIPHERS,
    supported_versions: PROFILE_40_VERSIONS,
    supported_groups: PROFILE_40_GROUPS,
    key_shares: PROFILE_40_KEY_SHARES,
    signature_algorithms: PROFILE_40_SIGALGS,
    delegated_credentials_algorithms: PROFILE_40_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_40_ALPN,
    certificate_compression_algorithms: PROFILE_40_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_40_APPS,
    extensions: PROFILE_40_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_41_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_41_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_41_GROUPS: &[u16] = &[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018];
const PROFILE_41_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x6399,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_41_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_41_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_41_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_41_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_41_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_41_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_41_APP_0_PROTOCOLS,
}];
const PROFILE_41_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_41: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_41_CIPHERS,
    supported_versions: PROFILE_41_VERSIONS,
    supported_groups: PROFILE_41_GROUPS,
    key_shares: PROFILE_41_KEY_SHARES,
    signature_algorithms: PROFILE_41_SIGALGS,
    delegated_credentials_algorithms: PROFILE_41_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_41_ALPN,
    certificate_compression_algorithms: PROFILE_41_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_41_APPS,
    extensions: PROFILE_41_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: None,
};

const PROFILE_42_CIPHERS: &[u16] = &[
    0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
const PROFILE_42_VERSIONS: &[u16] = &[0x0a0a, 0x0304, 0x0303];
const PROFILE_42_GROUPS: &[u16] = &[0x0a0a, 0x6399, 0x001d, 0x0017, 0x0018];
const PROFILE_42_KEY_SHARES: &[UtlsKeyShare] = &[
    UtlsKeyShare {
        group: 0x0a0a,
        key_exchange_len: 1,
    },
    UtlsKeyShare {
        group: 0x6399,
        key_exchange_len: 1216,
    },
    UtlsKeyShare {
        group: 0x001d,
        key_exchange_len: 32,
    },
];
const PROFILE_42_SIGALGS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
const PROFILE_42_DELEGATED_CREDENTIALS: &[u16] = &[];
const PROFILE_42_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
const PROFILE_42_CERT_COMP: &[u16] = &[0x0002];
const PROFILE_42_APP_0_PROTOCOLS: &[&[u8]] = &[b"h2"];
const PROFILE_42_APPS: &[UtlsApplicationSettings] = &[UtlsApplicationSettings {
    extension_type: 0x4469,
    protocols: PROFILE_42_APP_0_PROTOCOLS,
}];
const PROFILE_42_EXTENSIONS: &[UtlsExtension] = &[
    UtlsExtension {
        extension_type: GREASE,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xfe0d,
        payload_len: 186,
    },
    UtlsExtension {
        extension_type: 0x002d,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x4469,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x000d,
        payload_len: 18,
    },
    UtlsExtension {
        extension_type: 0x002b,
        payload_len: 7,
    },
    UtlsExtension {
        extension_type: 0x0023,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x0033,
        payload_len: 1263,
    },
    UtlsExtension {
        extension_type: 0x0000,
        payload_len: 16,
    },
    UtlsExtension {
        extension_type: 0x0005,
        payload_len: 5,
    },
    UtlsExtension {
        extension_type: 0x0010,
        payload_len: 14,
    },
    UtlsExtension {
        extension_type: 0x0017,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0xff01,
        payload_len: 1,
    },
    UtlsExtension {
        extension_type: 0x000b,
        payload_len: 2,
    },
    UtlsExtension {
        extension_type: 0x001b,
        payload_len: 3,
    },
    UtlsExtension {
        extension_type: 0x0012,
        payload_len: 0,
    },
    UtlsExtension {
        extension_type: 0x000a,
        payload_len: 12,
    },
    UtlsExtension {
        extension_type: GREASE_SECOND,
        payload_len: 1,
    },
];
const PROFILE_42: UtlsClientHelloProfile = UtlsClientHelloProfile {
    cipher_suites: PROFILE_42_CIPHERS,
    supported_versions: PROFILE_42_VERSIONS,
    supported_groups: PROFILE_42_GROUPS,
    key_shares: PROFILE_42_KEY_SHARES,
    signature_algorithms: PROFILE_42_SIGALGS,
    delegated_credentials_algorithms: PROFILE_42_DELEGATED_CREDENTIALS,
    alpn_protocols: PROFILE_42_ALPN,
    certificate_compression_algorithms: PROFILE_42_CERT_COMP,
    record_size_limit: None,
    application_settings: PROFILE_42_APPS,
    extensions: PROFILE_42_EXTENSIONS,
    padding_length: None,
    encrypted_client_hello_length: Some(186),
};

pub(super) fn profile_for_fingerprint(
    fingerprint: &str,
) -> Option<&'static UtlsClientHelloProfile> {
    match fingerprint {
        "chrome" => Some(&PROFILE_0),
        "hellochrome_133" => Some(&PROFILE_0),
        "hellochrome_auto" => Some(&PROFILE_0),
        "firefox" => Some(&PROFILE_1),
        "hellofirefox_148" => Some(&PROFILE_1),
        "hellofirefox_auto" => Some(&PROFILE_1),
        "safari" => Some(&PROFILE_2),
        "hellosafari_26_3" => Some(&PROFILE_2),
        "hellosafari_auto" => Some(&PROFILE_2),
        "ios" => Some(&PROFILE_3),
        "helloios_14" => Some(&PROFILE_3),
        "helloios_auto" => Some(&PROFILE_3),
        "android" => Some(&PROFILE_4),
        "helloandroid_11_okhttp" => Some(&PROFILE_4),
        "edge" => Some(&PROFILE_5),
        "helloedge_85" => Some(&PROFILE_5),
        "helloedge_auto" => Some(&PROFILE_5),
        "360" => Some(&PROFILE_6),
        "hello360_auto" => Some(&PROFILE_6),
        "hello360_7_5" => Some(&PROFILE_6),
        "qq" => Some(&PROFILE_7),
        "helloqq_11_1" => Some(&PROFILE_7),
        "helloqq_auto" => Some(&PROFILE_7),
        "random" => Some(&PROFILE_8),
        "randomized" => Some(&PROFILE_8),
        "hellorandomized" => Some(&PROFILE_8),
        "randomizednoalpn" => Some(&PROFILE_9),
        "hellorandomizednoalpn" => Some(&PROFILE_9),
        "hellofirefox_120" => Some(&PROFILE_10),
        "hellochrome_120" => Some(&PROFILE_11),
        "hellochrome_131" => Some(&PROFILE_12),
        "helloios_13" => Some(&PROFILE_13),
        "helloedge_106" => Some(&PROFILE_14),
        "hello360_11_0" => Some(&PROFILE_15),
        "hellorandomizedalpn" => Some(&PROFILE_16),
        "hellofirefox_55" => Some(&PROFILE_17),
        "hellofirefox_56" => Some(&PROFILE_18),
        "hellofirefox_63" => Some(&PROFILE_19),
        "hellofirefox_65" => Some(&PROFILE_20),
        "hellofirefox_99" => Some(&PROFILE_21),
        "hellofirefox_102" => Some(&PROFILE_22),
        "hellofirefox_105" => Some(&PROFILE_23),
        "hellochrome_58" => Some(&PROFILE_24),
        "hellochrome_62" => Some(&PROFILE_25),
        "hellochrome_70" => Some(&PROFILE_26),
        "hellochrome_72" => Some(&PROFILE_27),
        "hellochrome_83" => Some(&PROFILE_28),
        "hellochrome_87" => Some(&PROFILE_29),
        "hellochrome_96" => Some(&PROFILE_30),
        "hellochrome_100" => Some(&PROFILE_31),
        "hellochrome_102" => Some(&PROFILE_32),
        "hellochrome_106_shuffle" => Some(&PROFILE_33),
        "helloios_11_1" => Some(&PROFILE_34),
        "helloios_12_1" => Some(&PROFILE_35),
        "hellosafari_16_0" => Some(&PROFILE_36),
        "hellochrome_100_psk" => Some(&PROFILE_37),
        "hellochrome_112_psk_shuf" => Some(&PROFILE_38),
        "hellochrome_114_padding_psk_shuf" => Some(&PROFILE_39),
        "hellochrome_115_pq" => Some(&PROFILE_40),
        "hellochrome_115_pq_psk" => Some(&PROFILE_41),
        "hellochrome_120_pq" => Some(&PROFILE_42),
        _ => None,
    }
}
