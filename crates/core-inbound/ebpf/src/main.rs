#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::BPF_F_NO_PREALLOC,
    helpers::{bpf_map_lookup_elem, bpf_setsockopt, bpf_sk_assign, bpf_sk_release},
    macros::{cgroup_sock_addr, classifier, map},
    maps::{Array, HashMap, LpmTrie, PerCpuArray, SockMap},
    programs::{SockAddrContext, TcContext},
};
#[cfg(not(feature = "android-compat"))]
use aya_ebpf::{macros::sk_lookup, programs::SkLookupContext};

#[cfg(not(feature = "android-compat"))]
const SK_PASS: u32 = 1;
const TC_ACT_OK: i32 = 0;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;
const MAX_UID_RANGES: u32 = 256;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ETH_HEADER_LEN: usize = 14;

const FLAG_INCLUDE_UID: u32 = 1 << 0;
const FLAG_IPV4: u32 = 1 << 1;
const FLAG_IPV6: u32 = 1 << 2;
const FLAG_HIJACK_DNS: u32 = 1 << 3;
const FLAG_SHARED_NETWORK: u32 = 1 << 4;
const FLAG_SHARED_SOURCE_ANY_V4: u32 = 1 << 5;
const FLAG_SHARED_SOURCE_ANY_V6: u32 = 1 << 6;
const FLAG_SHARED_HAS_INCLUDE_V4: u32 = 1 << 7;
const FLAG_SHARED_HAS_INCLUDE_V6: u32 = 1 << 8;
const FLAG_SHARED_HAS_EXCLUDE_V4: u32 = 1 << 9;
const FLAG_SHARED_HAS_EXCLUDE_V6: u32 = 1 << 10;
const FLAG_SHARED_BLOCK_ALL_V4: u32 = 1 << 11;
const FLAG_SHARED_BLOCK_ALL_V6: u32 = 1 << 12;
const FLAG_SHARED_PACKET_STATS: u32 = 1 << 13;

const STAT_SELECTED: u32 = 0;
const STAT_BYPASS_SELF: u32 = 1;
const STAT_BYPASS_UID: u32 = 2;
const STAT_BYPASS_DESTINATION: u32 = 3;
const STAT_MARK_FAILED: u32 = 4;
const STAT_LOOKUP_ASSIGNED: u32 = 5;
const STAT_LOOKUP_FAILED: u32 = 6;
#[cfg(not(feature = "android-compat"))]
const STAT_BYPASS_INGRESS: u32 = 7;
const STAT_SHARED_SELECTED: u32 = 8;
const STAT_SHARED_BYPASS_SOURCE: u32 = 9;
const STAT_SHARED_BYPASS_DESTINATION: u32 = 10;
const STAT_SHARED_UNSUPPORTED: u32 = 11;
#[cfg(not(feature = "android-compat"))]
const STAT_SHARED_LOOKUP_ASSIGNED: u32 = 12;
#[cfg(not(feature = "android-compat"))]
const STAT_SHARED_LOOKUP_FAILED: u32 = 13;
const STAT_COUNT: u32 = 14;

#[repr(C)]
#[derive(Clone, Copy)]
struct EbpfConfig {
    mark: u32,
    self_tgid: u32,
    flags: u32,
    bypass_bank: u32,
    include_range_count: u32,
    exclude_range_count: u32,
    loopback_ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UidRange {
    start: u32,
    end: u32,
}

#[map]
static CONFIG: Array<EbpfConfig> = Array::with_max_entries(1, 0);

#[map]
static INCLUDE_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static EXCLUDE_UIDS: HashMap<u32, u8> = HashMap::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static INCLUDE_UID_RANGES: Array<UidRange> = Array::with_max_entries(MAX_UID_RANGES, 0);

#[map]
static EXCLUDE_UID_RANGES: Array<UidRange> = Array::with_max_entries(MAX_UID_RANGES, 0);

#[map]
static SHARED_INTERFACES: HashMap<u32, u8> =
    HashMap::with_max_entries(256, BPF_F_NO_PREALLOC as u32);

#[map]
static SHARED_SOURCE_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static SHARED_SOURCE_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static SHARED_EXCLUDE_SOURCE_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static SHARED_EXCLUDE_SOURCE_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V4_ALT: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static BYPASS_V6_ALT: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(65_536, BPF_F_NO_PREALLOC as u32);

#[map]
static TCP_SOCKETS: SockMap = SockMap::with_max_entries(2, 0);

#[map]
static UDP_SOCKETS: SockMap = SockMap::with_max_entries(2, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_COUNT, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET6)
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    select_socket(ctx, AF_INET6)
}

#[classifier]
pub fn capture_shared_ingress(ctx: TcContext) -> i32 {
    select_shared_packet(&ctx);
    TC_ACT_OK
}

/// Android vendor kernels can allow loading `BPF_PROG_TYPE_SK_LOOKUP` while
/// rejecting the netns `BPF_LINK_CREATE` operation used to attach it.  The
/// kernel has supported assigning a socket from TC ingress since Linux 5.7,
/// so the userspace controller can attach this program to loopback as a
/// functionally equivalent, link-API-independent data path.
#[classifier]
pub fn assign_proxy_socket_tc(ctx: TcContext) -> i32 {
    assign_marked_socket(&ctx);
    TC_ACT_OK
}

fn select_socket(ctx: SockAddrContext, family: u32) -> i32 {
    let Some(config) = CONFIG.get(0) else {
        return 1;
    };
    if (family == AF_INET && config.flags & FLAG_IPV4 == 0)
        || (family == AF_INET6 && config.flags & FLAG_IPV6 == 0)
    {
        return 1;
    }
    if ctx.tgid() == config.self_tgid {
        increment(STAT_BYPASS_SELF);
        return 1;
    }
    let uid = ctx.uid();
    if !uid_allowed(uid, config) {
        increment(STAT_BYPASS_UID);
        return 1;
    }
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && destination_port(&ctx) == 53;
    if !hijack_dns && destination_bypassed(&ctx, family, config.bypass_bank) {
        increment(STAT_BYPASS_DESTINATION);
        return 1;
    }

    let mut mark = config.mark;
    let result = unsafe {
        bpf_setsockopt(
            ctx.as_ptr(),
            SOL_SOCKET,
            SO_MARK,
            core::ptr::from_mut(&mut mark).cast(),
            core::mem::size_of::<u32>() as i32,
        )
    };
    if result != 0 {
        increment(STAT_MARK_FAILED);
        return 1;
    }
    increment(STAT_SELECTED);
    1
}

fn select_shared_packet(ctx: &TcContext) {
    let Some(config) = CONFIG.get(0) else {
        return;
    };
    if config.flags & FLAG_SHARED_NETWORK == 0 {
        return;
    }
    let Some((protocol, offset)) = ethernet_protocol(ctx) else {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    };
    match protocol {
        ETH_P_IP if config.flags & FLAG_IPV4 != 0 => select_shared_v4(ctx, offset, config),
        ETH_P_IPV6 if config.flags & FLAG_IPV6 != 0 => select_shared_v6(ctx, offset, config),
        _ => increment_shared(config.flags, STAT_SHARED_UNSUPPORTED),
    }
}

fn ethernet_protocol(ctx: &TcContext) -> Option<(u16, usize)> {
    let mut protocol = u16::from_be(ctx.load::<u16>(12).ok()?);
    let mut offset = ETH_HEADER_LEN;
    let mut depth = 0;
    while (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) && depth < 2 {
        protocol = u16::from_be(ctx.load::<u16>(offset + 2).ok()?);
        offset += 4;
        depth += 1;
    }
    Some((protocol, offset))
}

fn select_shared_v4(ctx: &TcContext, offset: usize, config: &EbpfConfig) {
    let version_ihl = match ctx.load::<u8>(offset) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    if version_ihl >> 4 != 4 {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    }
    let header_len = usize::from(version_ihl & 0x0f) * 4;
    if header_len < 20 {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    }
    let transport = match ctx.load::<u8>(offset + 9) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    if transport != IPPROTO_TCP as u8 && transport != IPPROTO_UDP as u8 {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    }
    let source = match ctx.load::<[u8; 4]>(offset + 12) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    if !shared_source_v4_allowed(source, config.flags) {
        increment_shared(config.flags, STAT_SHARED_BYPASS_SOURCE);
        return;
    }
    let destination = match ctx.load::<[u8; 4]>(offset + 16) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    let fragment = ctx
        .load::<u16>(offset + 6)
        .map(u16::from_be)
        .unwrap_or(u16::MAX);
    let first_fragment = fragment & 0x1fff == 0;
    let destination_port = if first_fragment {
        ctx.load::<u16>(offset + header_len + 2)
            .map(u16::from_be)
            .unwrap_or(0)
    } else {
        0
    };
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && destination_port == 53;
    if !hijack_dns && lookup_v4_bypassed(u32::from_ne_bytes(destination), config.bypass_bank) {
        increment_shared(config.flags, STAT_SHARED_BYPASS_DESTINATION);
        return;
    }
    ctx.set_mark(config.mark);
    increment_shared(config.flags, STAT_SHARED_SELECTED);
}

fn select_shared_v6(ctx: &TcContext, offset: usize, config: &EbpfConfig) {
    let version = match ctx.load::<u8>(offset) {
        Ok(value) => value >> 4,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    if version != 6 {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    }
    let source = match ctx.load::<[u8; 16]>(offset + 8) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    if !shared_source_v6_allowed(source, config.flags) {
        increment_shared(config.flags, STAT_SHARED_BYPASS_SOURCE);
        return;
    }
    let destination = match ctx.load::<[u8; 16]>(offset + 24) {
        Ok(value) => value,
        Err(_) => {
            increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
            return;
        }
    };
    let Some((transport, transport_offset, first_fragment)) =
        ipv6_transport(ctx, offset + 40, offset)
    else {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    };
    if transport != IPPROTO_TCP as u8 && transport != IPPROTO_UDP as u8 {
        increment_shared(config.flags, STAT_SHARED_UNSUPPORTED);
        return;
    }
    let destination_port = if first_fragment {
        ctx.load::<u16>(transport_offset + 2)
            .map(u16::from_be)
            .unwrap_or(0)
    } else {
        0
    };
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && destination_port == 53;
    if !hijack_dns && lookup_v6_bypassed(bytes_to_ipv6_words(destination), config.bypass_bank) {
        increment_shared(config.flags, STAT_SHARED_BYPASS_DESTINATION);
        return;
    }
    ctx.set_mark(config.mark);
    increment_shared(config.flags, STAT_SHARED_SELECTED);
}

fn assign_marked_socket(ctx: &TcContext) {
    let Some(config) = CONFIG.get(0) else {
        return;
    };
    let mark = unsafe { (*ctx.skb.skb).mark };
    if mark != config.mark {
        return;
    }

    let protocol = u16::from_be(ctx.skb.protocol() as u16);
    let assignment = match protocol {
        ETH_P_IP if config.flags & FLAG_IPV4 != 0 => {
            let transport = match ctx.load::<u8>(9) {
                Ok(value) => value,
                Err(_) => return,
            };
            assign_tc_transport(ctx, AF_INET, transport)
        }
        ETH_P_IPV6 if config.flags & FLAG_IPV6 != 0 => {
            let Some((transport, _, _)) = ipv6_transport(ctx, 40, 0) else {
                return;
            };
            assign_tc_transport(ctx, AF_INET6, transport)
        }
        _ => return,
    };
    match assignment {
        Ok(()) => increment(STAT_LOOKUP_ASSIGNED),
        Err(_) => increment(STAT_LOOKUP_FAILED),
    }
}

fn assign_tc_transport(ctx: &TcContext, family: u32, protocol: u8) -> Result<(), i32> {
    let index = if family == AF_INET { 0 } else { 1 };
    match u32::from(protocol) {
        IPPROTO_TCP => assign_tc_socket(ctx, &TCP_SOCKETS, index),
        IPPROTO_UDP => assign_tc_socket(ctx, &UDP_SOCKETS, index),
        _ => Err(-1),
    }
}

fn assign_tc_socket(ctx: &TcContext, sockets: &SockMap, mut index: u32) -> Result<(), i32> {
    // SockMap is repr(transparent) over its map definition. Taking the address
    // of the static map produces the same map relocation used by Aya's map
    // methods while allowing the TC form of bpf_sk_assign to be used.
    let map = core::ptr::from_ref(sockets).cast_mut().cast();
    let key = core::ptr::from_mut(&mut index).cast();
    let socket = unsafe { bpf_map_lookup_elem(map, key) };
    if socket.is_null() {
        return Err(-2);
    }
    let result = unsafe { bpf_sk_assign(ctx.as_ptr(), socket, 0) };
    let _ = unsafe { bpf_sk_release(socket) };
    if result == 0 {
        Ok(())
    } else {
        Err(result as i32)
    }
}

fn ipv6_transport(
    ctx: &TcContext,
    mut offset: usize,
    ipv6_offset: usize,
) -> Option<(u8, usize, bool)> {
    let mut next = ctx.load::<u8>(ipv6_offset + 6).ok()?;
    let mut first_fragment = true;
    let mut depth = 0;
    while depth < 6 {
        match next {
            0 | 43 | 60 => {
                next = ctx.load::<u8>(offset).ok()?;
                let length = usize::from(ctx.load::<u8>(offset + 1).ok()?);
                offset += (length + 1) * 8;
            }
            44 => {
                next = ctx.load::<u8>(offset).ok()?;
                let fragment = u16::from_be(ctx.load::<u16>(offset + 2).ok()?);
                first_fragment = fragment & 0xfff8 == 0;
                offset += 8;
            }
            51 => {
                next = ctx.load::<u8>(offset).ok()?;
                let length = usize::from(ctx.load::<u8>(offset + 1).ok()?);
                offset += (length + 2) * 4;
            }
            _ => return Some((next, offset, first_fragment)),
        }
        depth += 1;
    }
    None
}

fn shared_source_v4_allowed(address: [u8; 4], flags: u32) -> bool {
    if flags & FLAG_SHARED_BLOCK_ALL_V4 != 0 {
        return false;
    }
    if flags & FLAG_SHARED_HAS_EXCLUDE_V4 != 0 {
        let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
        if SHARED_EXCLUDE_SOURCE_V4.get(&key).is_some() {
            return false;
        }
    }
    if flags & FLAG_SHARED_SOURCE_ANY_V4 != 0 {
        return true;
    }
    if flags & FLAG_SHARED_HAS_INCLUDE_V4 == 0 {
        return false;
    }
    let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
    SHARED_SOURCE_V4.get(&key).is_some()
}

fn shared_source_v6_allowed(address: [u8; 16], flags: u32) -> bool {
    if flags & FLAG_SHARED_BLOCK_ALL_V6 != 0 {
        return false;
    }
    if flags & FLAG_SHARED_HAS_EXCLUDE_V6 != 0 {
        let key = aya_ebpf::maps::lpm_trie::Key::new(128, address);
        if SHARED_EXCLUDE_SOURCE_V6.get(&key).is_some() {
            return false;
        }
    }
    if flags & FLAG_SHARED_SOURCE_ANY_V6 != 0 {
        return true;
    }
    if flags & FLAG_SHARED_HAS_INCLUDE_V6 == 0 {
        return false;
    }
    let key = aya_ebpf::maps::lpm_trie::Key::new(128, address);
    SHARED_SOURCE_V6.get(&key).is_some()
}

fn uid_allowed(uid: u32, config: &EbpfConfig) -> bool {
    if exact_uid(&EXCLUDE_UIDS, uid)
        || range_contains(&EXCLUDE_UID_RANGES, config.exclude_range_count, uid)
    {
        return false;
    }
    if config.flags & FLAG_INCLUDE_UID == 0 {
        return true;
    }
    exact_uid(&INCLUDE_UIDS, uid)
        || range_contains(&INCLUDE_UID_RANGES, config.include_range_count, uid)
}

fn exact_uid(map: &HashMap<u32, u8>, uid: u32) -> bool {
    unsafe { map.get(&uid).is_some() }
}

fn range_contains(map: &Array<UidRange>, count: u32, uid: u32) -> bool {
    let mut index = 0;
    while index < count && index < MAX_UID_RANGES {
        if let Some(range) = map.get(index)
            && uid >= range.start
            && uid <= range.end
        {
            return true;
        }
        index += 1;
    }
    false
}

fn destination_bypassed(ctx: &SockAddrContext, family: u32, bank: u32) -> bool {
    if family == AF_INET {
        let address = unsafe { (*ctx.sock_addr).user_ip4.to_ne_bytes() };
        let key = aya_ebpf::maps::lpm_trie::Key::new(32, address);
        if bank == 0 {
            BYPASS_V4.get(&key).is_some()
        } else {
            BYPASS_V4_ALT.get(&key).is_some()
        }
    } else {
        let words = unsafe { (*ctx.sock_addr).user_ip6 };
        let key = aya_ebpf::maps::lpm_trie::Key::new(128, ipv6_bytes(words));
        if bank == 0 {
            BYPASS_V6.get(&key).is_some()
        } else {
            BYPASS_V6_ALT.get(&key).is_some()
        }
    }
}

#[cfg(not(feature = "android-compat"))]
#[sk_lookup]
pub fn assign_proxy_socket(ctx: SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let Some(config) = CONFIG.get(0) else {
        return SK_PASS;
    };
    // A map key must live in verifier-approved memory. In particular, Android
    // kernels reject passing a pointer into `bpf_sk_lookup` directly to
    // bpf_map_lookup_elem. The volatile scalar load prevents LLVM from folding
    // this local back into `ctx + offsetof(ingress_ifindex)`, so taking its
    // address below materializes the key on the eBPF stack.
    let ingress_ifindex =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(lookup.ingress_ifindex)) };
    let shared = ingress_ifindex != config.loopback_ifindex;
    if shared && unsafe { SHARED_INTERFACES.get(&ingress_ifindex).is_none() } {
        increment(STAT_BYPASS_INGRESS);
        return SK_PASS;
    }
    let bank = config.bypass_bank;
    let hijack_dns = config.flags & FLAG_HIJACK_DNS != 0 && lookup.local_port == 53;
    let result = match (lookup.family, lookup.protocol) {
        (AF_INET, IPPROTO_TCP) if hijack_dns || !lookup_v4_bypassed(lookup.local_ip4, bank) => {
            TCP_SOCKETS.redirect_sk_lookup(&ctx, 0, 0)
        }
        (AF_INET6, IPPROTO_TCP) if hijack_dns || !lookup_v6_bypassed(lookup.local_ip6, bank) => {
            TCP_SOCKETS.redirect_sk_lookup(&ctx, 1, 0)
        }
        (AF_INET, IPPROTO_UDP) if hijack_dns || !lookup_v4_bypassed(lookup.local_ip4, bank) => {
            UDP_SOCKETS.redirect_sk_lookup(&ctx, 0, 0)
        }
        (AF_INET6, IPPROTO_UDP) if hijack_dns || !lookup_v6_bypassed(lookup.local_ip6, bank) => {
            UDP_SOCKETS.redirect_sk_lookup(&ctx, 1, 0)
        }
        _ => return SK_PASS,
    };
    match result {
        Ok(()) if shared => increment(STAT_SHARED_LOOKUP_ASSIGNED),
        Ok(()) => increment(STAT_LOOKUP_ASSIGNED),
        Err(_) if shared => increment(STAT_SHARED_LOOKUP_FAILED),
        Err(_) => increment(STAT_LOOKUP_FAILED),
    }
    SK_PASS
}

fn destination_port(ctx: &SockAddrContext) -> u16 {
    let port = unsafe { (*ctx.sock_addr).user_port } as u16;
    u16::from_be(port)
}

fn lookup_v4_bypassed(address: u32, bank: u32) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(32, address.to_ne_bytes());
    if bank == 0 {
        BYPASS_V4.get(&key).is_some()
    } else {
        BYPASS_V4_ALT.get(&key).is_some()
    }
}

fn lookup_v6_bypassed(words: [u32; 4], bank: u32) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(128, ipv6_bytes(words));
    if bank == 0 {
        BYPASS_V6.get(&key).is_some()
    } else {
        BYPASS_V6_ALT.get(&key).is_some()
    }
}

fn ipv6_bytes(words: [u32; 4]) -> [u8; 16] {
    let mut address = [0u8; 16];
    let mut index = 0;
    while index < 4 {
        let bytes = words[index].to_ne_bytes();
        let offset = index * 4;
        address[offset] = bytes[0];
        address[offset + 1] = bytes[1];
        address[offset + 2] = bytes[2];
        address[offset + 3] = bytes[3];
        index += 1;
    }
    address
}

fn bytes_to_ipv6_words(address: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_ne_bytes([address[4], address[5], address[6], address[7]]),
        u32::from_ne_bytes([address[8], address[9], address[10], address[11]]),
        u32::from_ne_bytes([address[12], address[13], address[14], address[15]]),
    ]
}

fn increment(index: u32) {
    if let Some(value) = STATS.get_ptr_mut(index) {
        unsafe {
            *value = (*value).wrapping_add(1);
        }
    }
}

fn increment_shared(flags: u32, index: u32) {
    if flags & FLAG_SHARED_PACKET_STATS != 0 {
        increment(index);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
