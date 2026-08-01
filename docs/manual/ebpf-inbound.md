---
title: Aya eBPF 入站
description: Linux 与 Android root 的本机流量、热点共享、规则集旁路和 DNS 劫持
---

# Aya eBPF 入站

Aya eBPF 入站属于 `core-inbound`。配置直接写在 `inbounds`，不会转换成
`capture`，也不会调用 `core-capture` 的 TUN、TPROXY 或 REDIRECT 后端。

## 数据路径

本机进程创建 TCP 连接或发送 UDP 数据时，挂在 cgroup v2 的 connect4、
connect6、sendmsg4 和 sendmsg6 程序读取 UID、TGID、目标地址和目标端口。
符合条件的 socket 获得专用 mark。

启用 `shared_network` 后，TC ingress 程序会挂到匹配的热点、USB 共享、蓝牙
PAN、网桥或路由下游接口。它解析 Ethernet、双层 VLAN、IPv4、IPv6 扩展头和
分片信息，按源地址与目标旁路集合筛选 TCP/UDP。选中的转发包直接写入同一个
mark，不依赖发起进程 UID。

对应的 IPv4 或 IPv6 策略路由把带 mark 的包送到本机 local route。Linux 优先把
sk_lookup 挂到当前 network namespace，再把 TCP 或 UDP 包分配给
`core-inbound` 持有的透明 socket。旧 Linux 内核缺少完整 sk_lookup 上下文时会
自动改用 loopback TC ingress。

Android 直接使用 loopback TC ingress 和 `bpf_sk_assign`。这是因为不少 Android
厂商内核提供了 `BPF_PROG_TYPE_SK_LOOKUP`，却没有 Linux 5.17 增加的
`ingress_ifindex` 上下文字段。Android 专用 eBPF 对象不会编译这个不兼容程序，
因此不会先触发 verifier 的 `invalid bpf_context access off=64`。TC 程序只处理
带专用 mark 的包，不会接管未标记的真实本机服务流量。两条路径都不安装
iptables, nftables, TPROXY 或 DNAT。

核心进程自身的 TGID 始终旁路，避免出站再次进入 eBPF 入站。回环、链路本地、
RFC1918、CGNAT、ULA、组播、广播、redirect 地址和宿主接口地址也会进入内核
LPM 旁路集合。配置的规则集前缀与这些安全前缀合并。

TCP 保留原始目标地址并进入统一 `ListenerHandler`。UDP 按来源和目标建立会话，
响应使用 `IP_TRANSPARENT` socket 以原始目标作为源地址发回应用。连接表、规则
匹配、策略组、上传和下载统计继续使用核心运行时的统一实现。

## 完整配置

```yaml
inbounds:
  - type: ebpf
    tag: ebpf-in
    enabled: true

    redirect_address:
      - 127.128.0.0/9
      - 2001:db8:2030::/64

    bypass_rule_set:
      - geoip-cn

    include_uid: []
    include_uid_range:
      - "10000:19999"
    exclude_uid:
      - 0
    exclude_uid_range: []

    cgroup_path: /sys/fs/cgroup
    route_table: 721
    rule_priority: 8999
    mark: 721
    map_capacity: 65536

    capabilities:
      auto_raise: true
      allow_sys_admin_fallback: true

    shared_network:
      enabled: true
      include_interface:
        - ap*
        - swlan*
        - wlan*
        - rndis*
        - usb*
        - bt-pan*
        - bnep*
        - br*
        - eth*
        - en*
      exclude_interface:
        - lo
        - tun*
        - tap*
        - wg*
        - rpktun*
        - docker*
        - veth*
        - rmnet*
        - ccmni*
        - wwan*
      include_source_address:
        - 0.0.0.0/0
        - ::/0
      exclude_source_address: []
      interface_refresh_interval: 3s
      packet_stats: false
      tc_priority: 1

    dns_mode: hijack
```

字段语义：

| 字段 | 行为 |
| --- | --- |
| `tag` | 路由、连接表、日志和 API 使用的入站名称 |
| `enabled` | 保留配置但不启动该入口 |
| `redirect_address` | 为每个启用地址族提供内部透明 socket 锚点，至少一个 CIDR |
| `bypass_rule_set` | 在 cgroup 层直接旁路的目标 IP 规则集 |
| `include_uid` | 只接管列出的单个 UID |
| `include_uid_range` | 只接管 `start:end` 闭区间中的 UID |
| `exclude_uid` | 不接管列出的单个 UID，优先级高于包含条件 |
| `exclude_uid_range` | 不接管 `start:end` 闭区间中的 UID |
| `cgroup_path` | Aya cgroup sock_addr 程序的挂载点 |
| `route_table` | 带 mark 流量使用的独立策略路由表 |
| `rule_priority` | fwmark rule 优先级，必须排在 main rule 之前 |
| `mark` | eBPF 写入 socket 的非零 mark |
| `map_capacity` | 每个 UID hash map 和每个 IP LPM map 的容量 |
| `capabilities` | eBPF 权限探测、线程级提升和旧内核兼容策略 |
| `shared_network` | 热点、网络共享和路由转发流量接管 |
| `dns_mode` | `hijack` 接管 TCP/UDP 53，`off` 按普通流量处理 |

包含 UID 列表和区间都为空时，默认接管所有 UID。精确 UID 和区间可以同时使用，
两者是并集。任何排除条件命中后都不会接管。

## 热点与共享网络

`shared_network.enabled: true` 开启转发设备接管。该功能不会创建热点、DHCP、
NAT 或修改系统 IP forwarding。Android 系统、NetworkManager、hostapd 或用户
自己的路由服务仍负责建立共享网络，核心只处理进入下游接口的 TCP 和 UDP。

| 字段 | 行为 |
| --- | --- |
| `enabled` | 开启 TC ingress 共享网络接管 |
| `include_interface` | 允许挂载的 Linux 接口名 glob，支持接口数组或单值 |
| `exclude_interface` | 排除接口名 glob，优先级高于包含模式 |
| `include_source_address` | 允许接管的下游源 CIDR；空列表表示任意源地址 |
| `exclude_source_address` | 不接管的源 CIDR，优先级高于包含地址 |
| `interface_refresh_interval` | 接口重扫周期，范围 `1s..=5m` |
| `packet_stats` | 记录共享网络逐包诊断计数，默认关闭以降低热点高流量时的 CPU 开销 |
| `tc_priority` | 旧内核 clsact 挂载的 TC 优先级，数值越小越先执行 |

接口会按刷新周期重新扫描。Android 开启或关闭 Wi-Fi 热点、USB 网络共享、蓝牙
网络共享时，不需要重启核心。Linux 新增或删除 bridge、AP 和有线下游接口也会
自动挂载或卸载。

源地址条件会在加载时按 IPv4 和 IPv6 分别编译。空列表及 `0.0.0.0/0`、
`::/0` 使用无 LPM 查询的放行快速路径，空排除列表不会触发排除 Map 查询。
`packet_stats` 默认关闭，因此 TC 不会为每个转发包更新统计 Map。连接级重定向、
失败计数和本机进程统计仍会保留。只有排查源地址过滤或不支持协议时才建议临时
开启逐包统计。

Linux 6.6 及更新内核优先使用 TCX，并把程序放在已有 TCX 链的前面。旧内核自动
使用 clsact direct-action，`tc_priority` 默认 1，使接管发生在常见硬件 offload
和 Android tethering offload 程序之前。已经存在的 clsact 不会被删除或替换。

默认接口模式覆盖常见的 `ap`、`swlan`、`wlan`、`rndis`、`usb`、`bt-pan`、
`bnep`、bridge 和以太网名称，并排除 TUN、WireGuard、容器 veth 与移动数据
上游接口。目标是宿主地址、私网、链路本地、组播或广播时仍按内核旁路集合直接
通过；53 端口在 `dns_mode: hijack` 下例外，会进入核心 DNS 服务。

热点客户端的真实源地址作为连接表 `source`，原始远端地址作为 `destination`，
不会把节点服务器地址写入连接表。TCP、UDP 和 QUIC 都进入统一路由、策略组、
Clash API 与流量统计。ICMP、ARP、NDP 和其它非 TCP/UDP 协议保持系统原路径。

## 规则集同步

`bypass_rule_set` 通过共享的 `RulesetIndex` 获取一个版本一致的快照。以下状态会
让启动直接失败：

| 状态 | 处理 |
| --- | --- |
| 名称不存在 | 报错，不启动 |
| 首次下载失败 | 报错，不启动 |
| 仍在加载 | 报错，不启动 |
| 仅包含域名 | 报错，不启动 |
| IP 范围展开超过限制 | 报错，不启动 |
| 合并前缀超过 `map_capacity` | 报错，不启动 |

运行中刷新采用双 LPM map。新快照完整写入非活动 map，随后通过一次 CONFIG map
更新切换活动 bank。写入失败时继续使用旧快照。该过程不会先清空正在使用的规则。

## DNS 劫持

`dns_mode: hijack` 对 UID 和进程过滤范围内的 TCP 53 与 UDP 53 生效。DNS 接管
优先于目标地址旁路，因此公开 DNS 地址即使位于 `bypass_rule_set` 中也仍会进入
核心 DNS 服务。核心 DNS 服务继续执行 nameserver policy、Fake IP、缓存和地址到
域名映射。

`dns_mode: off` 不做这项特殊处理。DNS 流量是否进入普通代理路径取决于目标地址
旁路和路由规则。

## 构建

```bash
rustup toolchain install nightly --component rust-src --profile minimal
cargo install bpf-linker --version 0.10.4 --locked

cargo build --release -p wuther-core \
  --no-default-features \
  --features "with_ebpf,with_api"
```

`with_ebpf` 只支持 Linux 和 Android 目标。构建脚本使用稳定工具链编译用户态核心，
并通过 Aya 在构建期间调用 nightly、rust-src 和 bpf-linker 生成嵌入式 eBPF ELF。
GitHub Build Matrix 在选择该标签时会安装并缓存同一套工具。

## 系统要求

目标系统需要：

- Linux 或 Android 特权环境
- cgroup v2 挂载点
- 支持 cgroup sock_addr 的内核
- 支持 sk_lookup，或者支持 TC ingress `bpf_sk_assign`
- 热点共享需要 SCHED_CLS、TCX 或 clsact 支持
- `CAP_NET_ADMIN`
- 现代内核使用 `CAP_BPF`，旧内核或厂商兼容路径使用 `CAP_SYS_ADMIN`
- 旧式 memlock 记账内核需要足够的 `RLIMIT_MEMLOCK`，提高硬限制时还需要 `CAP_SYS_RESOURCE`

sk_lookup 需要 Linux 5.9 或更新内核。TC socket assignment 从 Linux 5.7 开始
可用。启动时先尝试 sk_lookup，程序类型不支持或 link attach 失败时自动切换到
loopback TC。TCX 不可用时继续切换到 clsact netlink。cgroup BPF link 不可用时
继续使用 legacy `BPF_PROG_ATTACH`。只有这些路径全部失败时入口才停止，错误会
包含失败阶段, syscall errno, 内核版本, CapEff, CapBnd, seccomp 状态和 SELinux
上下文。

### Capability 处理

eBPF 权限由 `caps` 依赖读取和操作，不再根据 uid 猜测。现代 Linux 的网络 BPF
程序需要 `CAP_NET_ADMIN` 加 `CAP_BPF`。`CAP_PERFMON` 面向 tracing 和 perf 类型，
本入口的 cgroup sock_addr、SCHED_CLS 与 sk_lookup 不需要该权限，因此默认不会
扩大到 `CAP_PERFMON`。旧于 CAP_BPF 的内核以及部分 Android 厂商回移实现可以由
`CAP_SYS_ADMIN` 提供 BPF authority。

`capabilities.auto_raise: true` 会在每个执行特权操作的 Tokio 线程上，把 permitted
集合中已有的 `CAP_NET_ADMIN`、`CAP_BPF` 或兼容的 `CAP_SYS_ADMIN` 提升到 effective
集合。该行为不会扩大 permitted 或 bounding 集合。如果能力不在 permitted 集合，
或者已经被 capability bounding set、seccomp 或 Android SELinux 拒绝，核心会在
加载 Aya 对象之前失败并给出三组 capability 状态。

`capabilities.allow_sys_admin_fallback: false` 可以在现代内核上强制只接受最小权限
`CAP_BPF`。保留默认值可以兼容未实现 CAP_BPF 的旧内核和 Android vendor backport。

推荐的 Linux 文件能力：

```bash
sudo setcap cap_net_admin,cap_bpf+ep ./wuther-core
getcap ./wuther-core
```

旧内核可以使用：

```bash
sudo setcap cap_net_admin,cap_sys_admin+ep ./wuther-core
```

systemd 服务可以使用：

```ini
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF
LimitMEMLOCK=infinity
```

Android 上的 `su` 必须把对应能力保留给核心进程。只有 `uid=0` 与
`CAP_NET_ADMIN` 仍不足以执行 `BPF_MAP_CREATE` 和 `BPF_PROG_LOAD`。可以通过以下
信息核对实际执行上下文：

```bash
cat /proc/sys/kernel/cap_last_cap
grep -E '^(Uid|CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status
cat /proc/self/attr/current
```

默认 `cgroup_path` 不是 cgroup v2 时，核心会从 `/proc/self/mountinfo` 自动发现实际
cgroup v2 挂载点。显式指定的自定义路径必须自身属于 cgroup v2，避免把程序错误
挂载到 cgroup v1 hierarchy。

## 启动与清理

启动顺序是加载 map 和程序, 绑定透明 socket, 挂载 sk_lookup 或 loopback TC,
安装策略路由, 挂载共享接口 TC, 最后挂载 cgroup 程序。TC 或 cgroup 挂载失败时
会回滚已有 link, filter, 策略路由和 socket。

关闭时核心先移除共享接口 TC 和 cgroup 程序，阻止新流量进入，再删除策略路由、
移除 sk_lookup 或 loopback TC filter，停止 TCP 和 UDP relay。进程异常退出后
BPF link 随文件描述符关闭，下一次启动还会删除该 tag 配置对应的旧策略路由状态。

## 诊断

先确认二进制包含组件：

```bash
wuther-core components
```

输出必须包含 `with_ebpf`。常见错误对应关系：

| 错误 | 检查 |
| --- | --- |
| 打开 cgroup 失败 | `cgroup_path` 是否存在，是否为 cgroup v2 |
| 加载或 verifier 失败 | 内核 BPF 配置、程序类型和权限 |
| capability preflight 失败 | 检查 CAP_NET_ADMIN 与 CAP_BPF，旧内核检查 CAP_SYS_ADMIN |
| `bpf_link_create` 失败 | 查看后续日志是否已切换为 `tc_ingress`；切换成功不影响接管 |
| 所有 lookup 挂载方式失败 | 根据错误中的 errno、CapEff、seccomp 和 SELinux 上下文定位内核限制 |
| 创建透明 socket 失败 | root 或网络管理能力，redirect 地址格式 |
| 安装 fwmark rule 失败 | `route_table`、`rule_priority`、外部策略路由冲突 |
| 热点客户端未进入连接表 | 接口是否匹配、TC 能力、源 CIDR、状态中的共享接口列表 |
| Android 热点开关后无流量 | 缩短 `interface_refresh_interval`，检查实际下游接口名 |
| 规则集不可用 | 规则集 URL、缓存、格式、类型和首次刷新日志 |
| map 容量不足 | 增大 `map_capacity`，或缩小旁路规则集 |

完整可运行文件见仓库中的
[`examples/advanced/linux-ebpf.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/linux-ebpf.yaml)。
