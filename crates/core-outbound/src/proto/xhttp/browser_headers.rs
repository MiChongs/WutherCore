//! Xray-compatible browser identity generation for XHTTP request headers.
//!
//! Xray anchors these values once per process. Its pseudo-random stream is
//! seeded with FNV-1 over selected CPU topology values and uses Go's legacy
//! `math/rand` source. Only the first four values are consumed (curl, Firefox,
//! Safari, then Chromium), so this module derives exactly that prefix instead
//! of carrying the full 607-word generator state.
//!
//! The small legacy RNG compatibility routine and cooked constants are
//! derived from Go's BSD-3-Clause `src/math/rand/rng.go`.

use std::sync::OnceLock;

use chrono::{Datelike, Local, TimeZone, Utc};

const GO_RNG_LEN: i32 = 607;
const GO_RNG_TAP: i32 = 273;
const GO_INT32_MAX: i64 = (1_i64 << 31) - 1;
const GO_RNG_MASK: u64 = (1_u64 << 63) - 1;
const GO_FLOAT_DENOMINATOR: f64 = (1_u64 << 63) as f64;
const PREFIX_WORDS: usize = 20;

// rngCooked[314..=333].
const FEED_COOKED: [i64; PREFIX_WORDS] = [
    -3825019837890901156,
    4602025990114250980,
    1044646352569048800,
    9106614159853161675,
    -8394115921626182539,
    -4304087667751778808,
    2681532557646850893,
    3681559472488511871,
    -3915372517896561773,
    -2889241648411946534,
    -6564663803938238204,
    -8060058171802589521,
    581945337509520675,
    3648778920718647903,
    -4799698790548231394,
    -7602572252857820065,
    220828013409515943,
    -1072987336855386047,
    4287360518296753003,
    -4633371852008891965,
];

// rngCooked[587..=606].
const TAP_COOKED: [i64; PREFIX_WORDS] = [
    -245039190118465649,
    -6320577374581628592,
    7208698530190629697,
    7276901792339343736,
    -7490986807540332668,
    4133292154170828382,
    2918308698224194548,
    -7703910638917631350,
    -3929437324238184044,
    -4300543082831323144,
    -6344160503358350167,
    5896236396443472108,
    -758328221503023383,
    -1894351639983151068,
    -307900319840287220,
    -6278469401177312761,
    -2171292963361310674,
    8382142935188824023,
    9103922860780351547,
    4152330101494654406,
];

const SAFARI_MINOR: [i32; 25] = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BrowserIdentity {
    pub(super) curl_ua: String,
    pub(super) firefox_ua: String,
    pub(super) safari_ua: String,
    pub(super) chrome_ua: String,
    pub(super) chrome_ua_ch: String,
    pub(super) edge_ua: String,
    pub(super) edge_ua_ch: String,
}

pub(super) fn browser_identity() -> &'static BrowserIdentity {
    static IDENTITY: OnceLock<BrowserIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let now = Local::now();
        browser_identity_for(cpu_seed(), now.timestamp(), now.year())
    })
}

fn browser_identity_for(seed: i64, now_unix: i64, local_year: i32) -> BrowserIdentity {
    let random = go_float64_prefix(seed);
    let current_day = now_unix / 86_400;

    // Package-level initialization order in Xray's common/utils/browser.go.
    let curl_time_diff =
        current_day - utc_day(2023, 3, 20) - 60 - (random[0].powi(2) * 165.0).floor() as i64;
    let curl_version = format!("8.{}.0", curl_time_diff / 57);

    let firefox_time_diff =
        current_day - utc_day(2024, 7, 29) - 25 - (random[1].powi(2) * 50.0).floor() as i64;
    let firefox_version = firefox_time_diff / 30 + 128;

    let safari_delay_days = (random[2].powi(3) * 75.0).floor() as i64;
    let mut safari_year = local_year;
    let mut safari_split = utc_timestamp(safari_year, 9, 23) + safari_delay_days * 86_400;
    if now_unix < safari_split {
        safari_year -= 1;
        safari_split = utc_timestamp(safari_year, 9, 23) + safari_delay_days * 86_400;
    }
    let safari_minor_index = ((now_unix - safari_split) / 1_296_000) as usize;
    let safari_minor = SAFARI_MINOR
        .get(safari_minor_index)
        .copied()
        .expect("Xray Safari cadence produced an out-of-range minor version");
    let safari_version = format!("{}.{}", safari_year - 1999, safari_minor);

    let chrome_time_diff =
        current_day - utc_day(2026, 1, 13) - 35 - (random[3].powi(2) * 105.0).floor() as i64;
    let chrome_version = 144 + chrome_time_diff / 35;

    let chrome_ua = format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/{chrome_version}.0.0.0 Safari/537.36"
    );
    BrowserIdentity {
        curl_ua: format!("curl/{curl_version}"),
        firefox_ua: format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox_version}.0) \
             Gecko/20100101 Firefox/{firefox_version}.0"
        ),
        safari_ua: format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/{safari_version} Safari/605.1.15"
        ),
        edge_ua: format!("{chrome_ua}Edg/{chrome_version}.0.0.0"),
        chrome_ua_ch: greased_ch_ua(chrome_version, "chrome"),
        edge_ua_ch: greased_ch_ua(chrome_version, "edge"),
        chrome_ua,
    }
}

fn utc_day(year: i32, month: u32, day: u32) -> i64 {
    utc_timestamp(year, month, day) / 86_400
}

fn utc_timestamp(year: i32, month: u32, day: u32) -> i64 {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid Xray browser release date")
        .timestamp()
}

fn go_seedrand(x: i32) -> i32 {
    const A: i64 = 48_271;
    const Q: i64 = 44_488;
    const R: i64 = 3_399;
    let x = i64::from(x);
    let hi = x / Q;
    let lo = x % Q;
    let mut next = A * lo - R * hi;
    if next < 0 {
        next += GO_INT32_MAX;
    }
    next as i32
}

/// Return enough of Go's `Rand.Float64` prefix for Xray's four package-level
/// browser version initializers. Extra words preserve Go's retry-on-1.0 rule.
fn go_float64_prefix(seed: i64) -> [f64; 4] {
    let mut seed = seed % GO_INT32_MAX;
    if seed < 0 {
        seed += GO_INT32_MAX;
    }
    if seed == 0 {
        seed = 89_482_311;
    }

    let mut x = seed as i32;
    let mut feed = [0_i64; PREFIX_WORDS];
    let mut tap = [0_i64; PREFIX_WORDS];
    for index in -20..GO_RNG_LEN {
        x = go_seedrand(x);
        if index < 0 {
            continue;
        }
        let mut value = i64::from(x).wrapping_shl(40);
        x = go_seedrand(x);
        value ^= i64::from(x).wrapping_shl(20);
        x = go_seedrand(x);
        value ^= i64::from(x);

        if (314..=333).contains(&index) {
            let slot = (index - 314) as usize;
            feed[slot] = value ^ FEED_COOKED[slot];
        } else if (587..=606).contains(&index) {
            let slot = (index - 587) as usize;
            tap[slot] = value ^ TAP_COOKED[slot];
        }
    }

    let mut result = [0.0; 4];
    let mut produced = 0;
    for slot in (0..PREFIX_WORDS).rev() {
        let integer = (feed[slot].wrapping_add(tap[slot]) as u64 & GO_RNG_MASK) as f64;
        let value = integer / GO_FLOAT_DENOMINATOR;
        if value == 1.0 {
            continue;
        }
        result[produced] = value;
        produced += 1;
        if produced == result.len() {
            return result;
        }
    }
    unreachable!("twenty Go RNG words all rounded to 1.0")
}

fn greased_ch_ua(major_version: i64, fork: &str) -> String {
    let grease = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    let grease_version = ["8", "99", "24"];
    let seed = major_version as usize;
    let invalid_brand = format!(
        "\"Not{}A{}Brand\";v=\"{}\"",
        grease[seed % grease.len()],
        grease[(seed + 1) % grease.len()],
        grease_version[seed % grease_version.len()]
    );
    let mut brands = vec![invalid_brand, format!("\"Chromium\";v=\"{major_version}\"")];
    match fork {
        "chrome" => brands.push(format!("\"Google Chrome\";v=\"{major_version}\"")),
        "edge" => brands.push(format!("\"Microsoft Edge\";v=\"{major_version}\"")),
        _ => {}
    }

    let order = greased_order(brands.len(), seed);
    let mut shuffled = vec![String::new(); brands.len()];
    for (source, destination) in order.into_iter().enumerate() {
        shuffled[destination] = brands[source].clone();
    }
    shuffled.join(", ")
}

fn greased_order(length: usize, seed: usize) -> Vec<usize> {
    const SHUFFLE_3: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    const SHUFFLE_4: [[usize; 4]; 24] = [
        [0, 1, 2, 3],
        [0, 1, 3, 2],
        [0, 2, 1, 3],
        [0, 2, 3, 1],
        [0, 3, 1, 2],
        [0, 3, 2, 1],
        [1, 0, 2, 3],
        [1, 0, 3, 2],
        [1, 2, 0, 3],
        [1, 2, 3, 0],
        [1, 3, 0, 2],
        [1, 3, 2, 0],
        [2, 0, 1, 3],
        [2, 0, 3, 1],
        [2, 1, 0, 3],
        [2, 1, 3, 0],
        [2, 3, 0, 1],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [3, 0, 2, 1],
        [3, 1, 0, 2],
        [3, 1, 2, 0],
        [3, 2, 0, 1],
        [3, 2, 1, 0],
    ];
    match length {
        1 => vec![0],
        2 => vec![seed % 2, (seed + 1) % 2],
        3 => SHUFFLE_3[seed % SHUFFLE_3.len()].to_vec(),
        _ => SHUFFLE_4[seed % SHUFFLE_4.len()].to_vec(),
    }
}

fn cpu_seed() -> i64 {
    cpu_seed_from_parts(cpu_seed_parts())
}

fn cpu_seed_from_parts(parts: CpuSeedParts) -> i64 {
    let text = format!(
        "{}{}{}{}{}{}",
        parts.family,
        parts.model,
        parts.physical_cores,
        parts.logical_cores,
        parts.cache_line,
        parts.threads_per_core
    );
    // hash/fnv.New64 is FNV-1 (multiply, then XOR), not FNV-1a.
    let mut hash = 14_695_981_039_346_656_037_u64;
    for byte in text.bytes() {
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= u64::from(byte);
    }
    hash as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuSeedParts {
    family: i32,
    model: i32,
    physical_cores: i32,
    logical_cores: i32,
    cache_line: i32,
    threads_per_core: i32,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_seed_parts() -> CpuSeedParts {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count};

    let leaf0 = __cpuid(0);
    let max_basic = leaf0.eax;
    let mut vendor_bytes = Vec::with_capacity(12);
    vendor_bytes.extend_from_slice(&leaf0.ebx.to_le_bytes());
    vendor_bytes.extend_from_slice(&leaf0.edx.to_le_bytes());
    vendor_bytes.extend_from_slice(&leaf0.ecx.to_le_bytes());
    let vendor = match vendor_bytes.as_slice() {
        b"GenuineIntel" => CpuVendor::Intel,
        b"AuthenticAMD" | b"AMDisbetter!" => CpuVendor::Amd,
        b"HygonGenuine" => CpuVendor::Hygon,
        _ => CpuVendor::Other,
    };
    let leaf1 = (max_basic >= 1).then(|| __cpuid(1));
    let (family, model) = leaf1.map_or((0, 0), |leaf| {
        let base_family = ((leaf.eax >> 8) & 0xf) as i32;
        let mut family = base_family;
        let mut extended_model = base_family == 0x6;
        if base_family == 0xf {
            family += ((leaf.eax >> 20) & 0xff) as i32;
            extended_model = true;
        }
        let mut model = ((leaf.eax >> 4) & 0xf) as i32;
        if extended_model {
            model += ((leaf.eax >> 12) & 0xf0) as i32;
        }
        (family, model)
    });
    let max_extended = __cpuid(0x8000_0000).eax;
    let cache_line = leaf1.map_or(0, |leaf| {
        let primary = ((leaf.ebx & 0xff00) >> 5) as i32;
        if primary == 0 && max_extended >= 0x8000_0006 {
            (__cpuid(0x8000_0006).ecx & 0xff) as i32
        } else {
            primary
        }
    });

    let threads_per_core = match vendor {
        CpuVendor::Intel | CpuVendor::Amd if max_basic >= 4 => {
            if max_basic < 0xb {
                if vendor != CpuVendor::Intel {
                    1
                } else if leaf1.is_some_and(|leaf| leaf.edx & (1 << 28) != 0) {
                    let logical = leaf1.map_or(0, |leaf| ((leaf.ebx >> 16) & 0xff) as i32);
                    let physical = ((__cpuid(4).eax >> 26) + 1) as i32;
                    if logical > 1 && physical > 0 {
                        logical / physical
                    } else {
                        1
                    }
                } else {
                    1
                }
            } else {
                let topology = __cpuid_count(0xb, 0).ebx & 0xffff;
                if topology != 0 {
                    topology as i32
                } else if vendor == CpuVendor::Amd
                    && family >= 23
                    && leaf1.is_some_and(|leaf| leaf.edx & (1 << 28) != 0)
                {
                    if max_extended >= 0x8000_001e {
                        (((__cpuid(0x8000_001e).ebx >> 8) & 0xff) + 1) as i32
                    } else {
                        2
                    }
                } else {
                    1
                }
            }
        }
        _ => 1,
    };

    let logical_cores = match vendor {
        CpuVendor::Intel if max_basic >= 0xb => (__cpuid_count(0xb, 1).ebx & 0xffff) as i32,
        CpuVendor::Intel | CpuVendor::Amd | CpuVendor::Hygon => {
            leaf1.map_or(0, |leaf| ((leaf.ebx >> 16) & 0xff) as i32)
        }
        CpuVendor::Other => 0,
    };
    let physical_cores = if logical_cores > 0 && threads_per_core > 0 {
        logical_cores / threads_per_core
    } else if vendor == CpuVendor::Amd && max_extended >= 0x8000_0008 {
        let count = __cpuid(0x8000_0008).ecx & 0xff;
        (count + 1) as i32
    } else {
        0
    };

    CpuSeedParts {
        family,
        model,
        physical_cores,
        logical_cores,
        cache_line,
        threads_per_core,
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuVendor {
    Intel,
    Amd,
    Hygon,
    Other,
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_seed_parts() -> CpuSeedParts {
    let logical = std::thread::available_parallelism()
        .map(|value| value.get() as i32)
        .unwrap_or(1);
    CpuSeedParts {
        family: 0,
        model: 0,
        physical_cores: logical,
        logical_cores: logical,
        cache_line: 64,
        threads_per_core: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_rng_prefix_matches_go_math_rand_golden_values() {
        assert_eq!(
            go_float64_prefix(1).map(f64::to_bits),
            [
                0x3fe359608841ff3f,
                0x3fee18a683d7cfc6,
                0x3fe5441371d9a55d,
                0x3fdc03825dbda6be,
            ]
        );
        assert_eq!(
            go_float64_prefix(-7_477_466_199_320_545_235).map(f64::to_bits),
            [
                0x3fecc7fb013f8c45,
                0x3fd9702f87520799,
                0x3fe434d699616be1,
                0x3fe722352a05b031,
            ]
        );
    }

    #[test]
    fn browser_versions_and_grease_match_xray_go_oracle() {
        let identity = browser_identity_for(1, 1_774_051_200, 2026);
        assert_eq!(identity.curl_ua, "curl/8.17.0");
        assert!(identity.firefox_ua.contains("Firefox/145.0"));
        assert!(identity.safari_ua.contains("Version/26.3"));
        assert!(identity.chrome_ua.contains("Chrome/144.0.0.0"));
        assert_eq!(
            identity.chrome_ua_ch,
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144""#
        );
        assert_eq!(
            identity.edge_ua_ch,
            r#""Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144""#
        );
    }

    #[test]
    fn cpu_topology_fnv_seed_matches_xray_go_oracle() {
        assert_eq!(
            cpu_seed_from_parts(CpuSeedParts {
                family: 6,
                model: 183,
                physical_cores: 12,
                logical_cores: 24,
                cache_line: 64,
                threads_per_core: 2,
            }),
            -4_444_068_514_562_985_806
        );
        assert_eq!(
            go_float64_prefix(-4_444_068_514_562_985_806).map(f64::to_bits),
            [
                0x3fd487b50e0f21bd,
                0x3fdc03f01b8eaa49,
                0x3fdcbe0e75b97523,
                0x3fe0ac5408168242,
            ]
        );
    }
}
