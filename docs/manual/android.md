---
title: Android 完整部署
description: Android root TUN、TPROXY、REDIRECT 与 VpnService 的源码级部署手册
---

# Android 完整部署

WutherCore 在 Android 上提供四条实际可用的接管路径：

1. root TUN，由 native 进程直接打开 `/dev/net/tun`。
2. root TPROXY，由 native 进程建立 TCP 和 UDP 透明监听并安装策略路由。
3. root REDIRECT，由 native 进程建立 TCP 透明监听并原子安装 nftables NAT 规则。
4. 非 root VpnService，由宿主应用建立 TUN，再把文件描述符交给 native。

`method: auto` 在 Android 上选择 TUN。TUN 打开时先尝试 root `/dev/net/tun`，失败后
才消费宿主注入的 VpnService 文件描述符。因此同一份 `virtual_nic` 配置可以同时
服务 root daemon 和普通 Android 应用，但两条路径的启动方式、路由所有权和应用
过滤边界不同。

仓库提供三份 root 配置：

| 数据面 | 配置文件 |
| --- | --- |
| root TUN | [`android-root-tun.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tun.yaml) |
| root TPROXY | [`android-root-tproxy.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tproxy.yaml) |
| root REDIRECT | [`android-root-redirect.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-redirect.yaml) |

非 root 宿主配置见
[`android.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/android.yaml)。

## 模式选择

| 模式 | `capture.method` | TCP | UDP | 设备或规则 | 最低权限 |
| --- | --- | --- | --- | --- | --- |
| root TUN | `virtual_nic` 或 `auto` | 支持 | 支持 | `/dev/net/tun`，接口地址，策略路由 | UID 0 或足够的有效 capability |
| root TPROXY | `tproxy` | 支持 | 支持 | 透明 socket，iptables，策略路由 | 有效 `CAP_NET_ADMIN` |
| root REDIRECT | `redirect` | 支持 | 不支持 | 透明 TCP socket，nftables NAT | 有效 `CAP_NET_ADMIN` |
| VpnService | `virtual_nic` 或 `auto` | 支持 | 支持 | 宿主提供的预配置 TUN fd | Android VPN 授权 |

优先按下面的条件选择：

| 需求 | 推荐 |
| --- | --- |
| 普通应用分发，不要求 root | VpnService |
| root 设备，需要完整 TCP 和 UDP，要求按应用过滤 | root TUN |
| root 设备，不希望创建 TUN，内核具备 TPROXY | root TPROXY |
| 旧内核或只需要 TCP 接管 | root REDIRECT |
| 同时兼容 root 和非 root 宿主 | `method: auto`，由启动方式决定 TUN 来源 |

不要把 `tun.auto_redirect` 当作 Android root 开关。Android 支持显式
`method: redirect`，但不支持 Linux 专用的 `tun.auto_redirect` 混合数据面。

## 源码中的实际调用链

Android 平台入口位于
[`platform/android.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/android.rs)。
生产 Android 构建会把 TUN、TPROXY 和 REDIRECT 都交给 Linux 系数据面实现：

```text
CapturePlan
  -> platform::android::build_engine
  -> platform::linux::build_engine
  -> LinuxTun | LinuxTproxy | LinuxRedirect
```

三条路径分别继续执行：

```text
root TUN
  -> android_tun_io::open
  -> LinuxTunIo::open("/dev/net/tun")
  -> 配置接口和策略路由
  -> 启动 TUN dispatcher

root TPROXY
  -> require_net_admin
  -> 绑定 7894 TCP 和 UDP 透明监听
  -> 安装 iptables 和 ip6tables 规则
  -> 安装 fwmark 策略路由

root REDIRECT
  -> require_net_admin
  -> 先绑定临时 TCP 监听
  -> 检查 nftables 批处理
  -> 原子发布 NAT 规则

VpnService
  -> android_tun_io::open
  -> root TUN 打开失败
  -> 消费 JNI 注入的 fd 和实际 MTU
  -> 跳过 native 接口与路由配置
```

关键实现文件：

| 行为 | 源码 |
| --- | --- |
| Android 数据面选择 | [`platform/android.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/android.rs) |
| root TUN 优先和 VpnService fallback | [`platform/android_tun_io.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/android_tun_io.rs) |
| TUN、TPROXY 和 REDIRECT 生命周期 | [`platform/linux.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/linux.rs) |
| TPROXY 固定 mark、端口和规则 | [`tproxy_rules.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/tproxy_rules.rs) |
| REDIRECT 原子 nftables 规则 | [`platform/linux_auto_redirect.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/linux_auto_redirect.rs) |
| JNI 和 `VpnService.protect` | [`platform/android_jni.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-capture/src/platform/android_jni.rs) |
| 权限检测 | [`core-inbound/privilege.rs`](https://github.com/MiChongs/WutherCore/blob/main/crates/core-inbound/src/privilege.rs) |

### 四层 capability 探测与生产数据面的关系

源码中还保留了 `AndroidCapability::select_tier`，它可以描述四层旧式 root 能力：

| tier | 探测条件 | 能力描述 |
| --- | --- | --- |
| `nftables-full` | nft、双栈 TPROXY、IPv6 NAT、owner match | 完整双栈透明代理 |
| `iptables-v4v6-tproxy` | iptables、ip6tables、双栈 TPROXY | 双栈 TCP 和 UDP |
| `iptables-v4v6-redirect` | iptables、ip6tables、IPv6 NAT | 双栈 TCP，UDP 受限 |
| `iptables-v4-only` | 只有 IPv4 iptables | IPv4 TCP |

这段代码当前只用于能力描述、测试和非 Android 调试 stub。生产 Android 的
`build_engine` 不会调用这个 tier 自动降级器，而是直接按配置选择 Linux 系
TUN、TPROXY 或 REDIRECT。

因此当前生产行为是：

1. `method: tproxy` 缺少 TPROXY 能力时启动失败，不会自动退到 REDIRECT。
2. `method: redirect` 走当前 nftables 原子后端，不会自动退到旧 iptables v4。
3. `method: virtual_nic` 只在 root TUN 和 VpnService fd 之间 fallback。

部署脚本应在启动前探测设备能力，再选择对应配置文件。不能只看到
`select_tier` 的四个枚举，就假定生产 engine 已经自动执行四级降级。

## root 权限的真实含义

启动时执行的 `su -c id` 只是探测 root 管理器是否允许 root 子命令。它不会改变当前
native 进程的 UID，也不会给当前进程补上 `CAP_NET_ADMIN`。

这意味着下面的启动方式不成立：

```text
普通应用进程启动 native
  -> native 内部探测到 su
  -> 误以为当前进程已经成为 root
```

root 数据面要求下面两种方式之一：

1. 直接由 root shell、Magisk service 或 KernelSU service 启动整个
   `wuther-core` 进程。
2. 让服务进程真正持有所需的有效 capability。只有可以执行 `su -c` 但当前进程
   仍是普通应用 UID，不足以创建 root TUN 或透明 socket。

通过 adb 首次验证：

```bash
adb push wuther-core /data/local/tmp/wuther-core
adb push config.yaml /data/local/tmp/wuther-core.yaml
adb shell su -c 'chmod 0755 /data/local/tmp/wuther-core'
adb shell su -c '/data/local/tmp/wuther-core components'
adb shell su -c '/data/local/tmp/wuther-core check /data/local/tmp/wuther-core.yaml'
adb shell su -c '/data/local/tmp/wuther-core explain /data/local/tmp/wuther-core.yaml'
adb shell su -c '/data/local/tmp/wuther-core run --config /data/local/tmp/wuther-core.yaml'
```

确认实际身份：

```bash
adb shell su -c 'id'
adb shell su -c 'grep CapEff /proc/self/status'
adb shell su -c 'test -c /dev/net/tun'
```

使用 Magisk 或 KernelSU 模块时，可由 `service.sh` 启动：

```sh
#!/system/bin/sh

MODDIR=${0%/*}
RUNDIR="$MODDIR/run"
LOGDIR="$MODDIR/log"

mkdir -p "$RUNDIR" "$LOGDIR"
chmod 0700 "$RUNDIR" "$LOGDIR"

"$MODDIR/bin/wuther-core" check "$MODDIR/config.yaml" || exit 1

"$MODDIR/bin/wuther-core" run \
  --config "$MODDIR/config.yaml" \
  >>"$LOGDIR/wuther-core.log" 2>&1 &

echo $! >"$RUNDIR/wuther-core.pid"
```

配置、日志和状态目录不要放在普通应用可以修改的位置。root daemon 读取的订阅、
规则集和证书也应限制文件权限。

## root TUN

### 完整配置

```yaml
capture:
  on: true
  method: virtual_nic
  traffic: system
  resolver: hijack
  stack: mixed
  mtu: 1400
  offload: true
  exclude:
    cidr:
      - 127.0.0.0/8
      - ::1/128
  tun:
    interface_name: rpktun0
    address:
      - 172.19.0.1/30
      - fdfe:dcba:9876::1/126
    inet6: true
    auto_route: true
    auto_redirect: false
    strict_route: false
    iproute2_table_index: 2024
    iproute2_rule_index: 9100
    auto_redirect_output_mark: "0x200000"
    route_exclude_address:
      - 127.0.0.0/8
      - ::1/128
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 223.5.5.5/32
      - 1.1.1.1/32
    endpoint_independent_nat: true
    udp_timeout: 5m
    include_android_user: [0]
    exclude_package:
      - com.android.captiveportallogin
```

完整文件见
[`android-root-tun.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tun.yaml)。

### 启动顺序

root TUN 启动不是简单打开一个文件描述符。当前实现按下面的顺序建立所有权：

1. 打开 `/dev/net/tun`。
2. 使用 `TUNSETIFF` 创建或绑定 `interface_name`。
3. 记录崩溃恢复账本。
4. 设置接口 MTU、地址和启用状态。
5. 检查私有路由表没有被 netd 或其他进程占用。
6. 通过 rtnetlink 写入 static 和 link scope 的 TUN 路由。
7. 在 netd 优先级之前安装 `iif lo`，UID range 和 fwmark 规则。
8. 旁路规则使用 `goto 10000` 交还 netd，不缓存 Wi-Fi 或蜂窝表号。
9. 安装 GID 的内核级绕行规则。
10. 启动 TUN dispatcher，接管设备读写。

如果 root TUN 成功打开，即使宿主已经注入 VpnService fd，也优先使用 root TUN。
此时 native 自己管理接口和路由，不需要 `VpnService.protect`。

### 字段行为

| 字段 | root TUN 行为 |
| --- | --- |
| `interface_name` | 请求的 TUN 名称，最终名称以内核返回值为准 |
| `address` | 第一条 IPv4 和第一条 IPv6 地址进入执行计划 |
| `inet6` | 控制 IPv6 地址、路由和数据面 |
| `auto_route` | 安装接管路由和出站绕行规则 |
| `strict_route` | 安装更严格的防泄漏路由，首次部署建议关闭 |
| `iproute2_table_index` | root TUN 私有路由表，默认回填为 2022 |
| `iproute2_rule_index` | root TUN 规则优先级，必须小于 Android netd 的 10000，默认 9000 |
| `auto_redirect_output_mark` | Android 默认 `0x200000`，只能使用 netd reserved 位 21 到 28 |
| `route_address` | 只把指定目的 CIDR 导入 TUN |
| `route_exclude_address` | 明确绕过 TUN 的静态 CIDR |
| `route_address_set` | 使用规则集生成的动态接管集合 |
| `route_exclude_address_set` | 使用规则集生成的动态绕行集合 |
| `endpoint_independent_nat` | 控制 UDP NAT 映射复用 |
| `udp_timeout` | 控制 UDP 会话老化 |
| `exclude_mptcp` | 尝试让 MPTCP 流量绕行 |

`auto_redirect` 必须保持 `false`。Android root TUN 本身已经是完整接管路径，
Linux `auto_redirect` 的 TCP NAT 和 UDP TUN 混合逻辑在 Android 上会被明确拒绝。

Android 不使用 Linux 的 `main` 表作为物理出口。系统网络由 netd 按 netId，UID，
绑定接口和 VPN 状态动态选择，实际表号通常随接口 ifindex 和网络切换变化。Root TUN
只拥有 `iproute2_table_index` 指定的私有表。代理出站，排除地址和排除 UID 命中后
会跳到 netd 的规则区继续计算，因此 Wi-Fi，蜂窝，双卡，工作资料和按应用默认网络
切换时不需要重建一组写死的物理表规则。

Linux 常用的 `0x2024` 在 Android 上不是安全的默认值，因为其低 16 位会被解释为
netId。省略字段时核心自动使用 `0x200000`，旧配置显式写入 `0x2024` 时也会自动
迁移为这个安全值。其他显式值包含 netId，权限，vendor 或 wakeup 位时启动会失败，
避免生成表面成功但最终落入 netd unreachable 规则的配置。

### UID、GID、Android user 和包名

root TUN 可以使用：

```yaml
capture:
  tun:
    include_uid: []
    include_uid_range:
      - "10000:99999"
    exclude_uid:
      - 1000
    exclude_uid_range: []
    include_gid: []
    include_gid_range: []
    exclude_gid: []
    exclude_gid_range: []
    include_android_user:
      - 0
      - 10
    include_package: []
    exclude_package:
      - com.android.captiveportallogin
```

语义如下：

| 字段 | 语义 |
| --- | --- |
| `include_uid` | 只接管列出的 UID |
| `include_uid_range` | 只接管闭区间中的 UID |
| `exclude_uid` | 让列出的 UID 绕过 |
| `exclude_uid_range` | 让闭区间中的 UID 绕过 |
| GID 对应字段 | 与 UID 规则相同，但匹配 socket GID |
| `include_android_user` | Android user N 映射为 `N * 100000` 到 `N * 100000 + 99999` |
| `include_package` | 包名白名单 |
| `exclude_package` | 包名黑名单 |

内核级包名绕行会读取 `/data/system/packages.list` 把包名解析为 app UID。多用户设备
再结合 `include_android_user` 添加 user 偏移。包名无法解析时，对应内核规则会跳过
并记录日志，因此生产环境应检查启动日志中的解析结果。

显式 `include_uid` 或 `include_uid_range` 存在时，它们优先定义 UID 白名单。
`include_android_user` 不会再替代这组显式 UID 条件。

内核级 identity bypass 只在 `auto_route: true` 时安装，因为它依赖同一套 fwmark
策略路由。关闭 `auto_route` 后，宿主必须自己建立等价的绕行规则。

## root TPROXY

### 完整配置

```yaml
capture:
  on: true
  method: tproxy
  traffic: system
  resolver: hijack
  stack: mixed
  exclude:
    cidr:
      - 127.0.0.0/8
      - ::1/128
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  tun:
    inet6: true
    auto_redirect: false
    route_exclude_address:
      - 223.5.5.5/32
      - 1.1.1.1/32
    auto_redirect_output_mark: "0x2024"
```

完整文件见
[`android-root-tproxy.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-tproxy.yaml)。

TPROXY 不创建 TUN，因此不要配置 `capture.mtu`。`tun` 子块仍承载透明接管共用的
IPv6、绕行 CIDR 和出站 mark 字段。

### 当前固定资源

| 资源 | 当前值 |
| --- | --- |
| TCP 透明监听 | `0.0.0.0:7894`，IPv6 开启时同时监听 `[::]:7894` |
| UDP 透明监听 | 与 TCP 使用同一端口 |
| TPROXY mark | `0x2d0` |
| 策略路由表 | `0x2d0` |
| 本地路由设备 | `lo` |
| IPv4 防火墙 | `iptables -t mangle` |
| IPv6 防火墙 | `ip6tables -t mangle` |

启动时先验证有效 `CAP_NET_ADMIN`，再绑定 TCP 和 UDP listener，随后安装策略路由和
防火墙链。规则安装失败时会删除已安装的链和策略路由。停止时先终止 listener，再
撤销规则。

TPROXY 规则会绕过：

1. `capture.exclude.cidr`。
2. `tun.route_exclude_address`。
3. IPv4 和 IPv6 的内置本地、私网、组播、文档地址与 Tailnet 网段。
4. 带出站 mark 的 WutherCore socket。

当前显式 TPROXY 规则生成器同时安装 PREROUTING 和 OUTPUT 链，不使用 `traffic`
选择单一 hook。不要依赖 `traffic: system` 把规则缩小到只有本机进程。需要限制
入口接口或转发来源时，应在设备自己的上游防火墙链中完成。

当前 TPROXY 规则生成器不把这些字段翻译成内核规则：

| 不应依赖的字段 | 原因 |
| --- | --- |
| `include_package`、`exclude_package` | TPROXY 规则没有包名到 UID 的翻译阶段 |
| UID 和 GID 过滤 | 当前 TPROXY 链只生成 CIDR 绕行 |
| interface 和 MAC 过滤 | 当前 TPROXY 链没有生成对应匹配 |
| `route_address` | 当前 TPROXY 防火墙入口不使用接管白名单 |
| 动态 route set | 当前 TPROXY 入口没有同步动态集合 |

需要按应用接管时优先使用 root TUN。需要限制 TPROXY 范围时，用静态
`exclude.cidr` 和 `route_exclude_address` 明确绕行，并通过设备防火墙控制哪些链
进入 WutherCore。

检查内核能力：

```bash
adb shell su -c 'iptables -t mangle -j TPROXY -h'
adb shell su -c 'ip6tables -t mangle -j TPROXY -h'
adb shell su -c 'grep -i TPROXY /proc/net/ip_tables_matches'
```

运行后检查：

```bash
adb shell su -c 'ip rule show'
adb shell su -c 'ip -6 rule show'
adb shell su -c 'iptables -t mangle -S WUTHERCORE_PREROUTING'
adb shell su -c 'iptables -t mangle -S WUTHERCORE_OUTPUT'
adb shell su -c 'ss -lntup | grep 7894'
```

## root REDIRECT

### 完整配置

```yaml
capture:
  on: true
  method: redirect
  traffic: system
  resolver: off
  stack: system
  exclude:
    cidr:
      - 127.0.0.0/8
      - ::1/128
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
  tun:
    inet6: true
    auto_redirect: false
    route_exclude_address:
      - 223.5.5.5/32
      - 1.1.1.1/32
    include_android_user:
      - 0
    exclude_uid:
      - 1000
```

完整文件见
[`android-root-redirect.yaml`](https://github.com/MiChongs/WutherCore/blob/main/examples/advanced/android-root-redirect.yaml)。

REDIRECT 只接管 TCP。UDP 和普通 UDP DNS 不会进入 REDIRECT listener，因此该模式
不适合要求完整 UDP 代理的设备。需要 UDP 时使用 root TUN 或 root TPROXY。

### `traffic` 与过滤器

| `traffic` | nftables hook | 可用过滤 |
| --- | --- | --- |
| `system` | `output` | UID、UID 范围、GID、GID 范围、Android user |
| `apps` | `output` | 与 `system` 相同 |
| `lan` | `prerouting` | interface、MAC |

本机 OUTPUT 没有可靠的入口接口和源 MAC，所以 `system` 或 `apps` 配置 interface
或 MAC 过滤会失败。转发流量的 PREROUTING 没有可靠的 socket owner，所以
`traffic: lan` 配置 UID、GID 或 Android user 过滤会失败。

当前 REDIRECT 原子规则后端明确拒绝：

1. `exclude.process`。
2. `include_package` 和 `exclude_package`。
3. `route_address_set` 和 `route_exclude_address_set`。

包名需要先解析成 UID，再写入 `include_uid` 或 `exclude_uid`。不能把包名字段写进
配置后假定它已经生效。

REDIRECT 会先绑定实际 TCP listener，获得端口后生成 nftables 批处理，先执行
`nft --check`，再原子提交。规则发布失败时 listener 会被关闭，不留下半套 NAT
状态。停止时保留清理账本，只有 nftables 撤销成功后才报告完成。

检查规则：

```bash
adb shell su -c 'nft list table inet wuthercore_redirect'
adb shell su -c 'ss -lntp'
```

## VpnService

VpnService 是非 root 路径，也可作为 root TUN 打开失败时的 fallback。宿主必须按
完整顺序执行：

1. 调用 `VpnBridge.vpnServiceConfigJson(configPath)`。
2. 把返回的 addresses、routes、dns_servers 写入 `VpnService.Builder`。
3. 根据返回值设置 allowed 或 disallowed applications。
4. 把返回的 MTU 传给 `Builder.setMtu`。
5. 调用 `establish()`。
6. 对 `ParcelFileDescriptor` 调用 `detachFd()`。
7. 调用 `VpnBridge.setVpnService(service)` 注册 socket protect。
8. 调用 `VpnBridge.setVpnFdWithMtu(fd, mtu)` 注入 fd 和真实 MTU。
9. 启动 native 核心。

native 会逐值比较注入的 MTU 与 `capture.mtu`。旧的 `setVpnFd(fd)` 只为 ABI 兼容
保留，新宿主必须使用 `setVpnFdWithMtu`。

VpnService fd 已由 Android framework 配置接口、地址和路由。native 检测到它是
预配置设备后，会跳过 Linux 接口、路由和防火墙管理。所有代理出站 socket 必须先
执行 `VpnService.protect(fd)`，否则会再次进入自己的 VPN。

应用过滤在 VpnService 路径分为两层：

| 层 | 行为 |
| --- | --- |
| Android Builder | 使用 allowed 或 disallowed applications 决定哪些应用进入 TUN |
| native 数据面 | 使用 UID、GID、包名和 Android user 信息执行流级策略 |

Builder 不允许同时使用 allowed 和 disallowed 列表。配置同时出现
`include_package` 和 `exclude_package` 时，导出逻辑优先使用 allowed 模式并报告
被忽略的排除列表。

## `method: auto`

Android 上的 `method: auto` 固定解析为 TUN，不会自动改成 TPROXY 或 REDIRECT。
随后由 TUN opener 决定设备来源：

```text
尝试 root /dev/net/tun
  -> 成功，使用 root TUN
  -> 失败，检查是否有注入的 VpnService fd
  -> 有 fd，使用 VpnService
  -> 无 fd，启动失败
```

如果要使用 TPROXY 或 REDIRECT，必须显式写：

```yaml
capture:
  on: true
  method: tproxy
```

或：

```yaml
capture:
  on: true
  method: redirect
```

## 构建

三种 root 模式和 VpnService 都需要 `with_tun`：

```powershell
pwsh -File scripts/build-all.ps1 `
  -Tags "standard" `
  -Targets "aarch64-linux-android"
```

只构建 TUN、API、VLESS、REALITY、gRPC 和 uTLS：

```powershell
pwsh -File scripts/build-all.ps1 `
  -Tags "with_api,with_tun,with_vless,with_reality,with_grpc,with_utls" `
  -Targets "aarch64-linux-android"
```

构建后检查组件：

```bash
wuther-core components
wuther-core components --json
```

如果输出没有 `with_tun`，任何 Android capture 配置都会在启动前被组件门禁拒绝。

## 启动前检查

### 通用

```bash
wuther-core check config.yaml
wuther-core explain config.yaml
wuther-core components
```

### root TUN

```bash
test -c /dev/net/tun
ip link show
ip rule show
```

### root TPROXY

```bash
iptables --version
ip6tables --version
iptables -t mangle -j TPROXY -h
```

### root REDIRECT

```bash
nft --version
nft list ruleset
```

## 运行状态和回滚

root TUN、TPROXY 和 REDIRECT 都使用资源所有权账本。启动过程中任何一步失败，已经
取得所有权的接口、listener、路由和防火墙规则会按逆序清理。清理失败会保留账本，
后续 stop 可以继续重试，不会把残留规则当作已成功撤销。

运行后至少核对：

```bash
ip link show rpktun0
ip rule show
ip route show table all
ip -6 route show table all
iptables-save
nft list ruleset
```

只检查进程存在不能证明接管已经成功。应同时确认接口或透明 listener 存在，策略
路由已安装，出站节点可达，DNS 没有循环，停止后规则能够恢复。

## 常见错误

### `su` 可用但 root TUN 仍失败

原因是当前 native 进程仍是普通应用 UID。把整个 daemon 放进 root service 启动，
不要依赖进程内部的一次 `su -c id` 探测。

### `method: auto` 没有进入 TPROXY

这是设计行为。Android 的 auto 只选择 TUN。TPROXY 和 REDIRECT 必须显式配置。

### root TUN 意外使用了 VpnService

检查 `/dev/net/tun` 权限、有效 capability 和 `TUNSETIFF` 错误。root open 失败后
才会消费已注入的 VpnService fd。

### TPROXY 启动时缺少 `CAP_NET_ADMIN`

给当前 daemon 真正授予有效 capability，或直接由 root service 启动。只允许
`su` 子命令不足以创建透明 socket和策略路由。

### REDIRECT 下 UDP 不工作

REDIRECT 的能力声明就是 TCP only。改用 root TUN 或 root TPROXY。

### 包名过滤没有生效

root TUN 需要能够读取并解析 Android 包到 UID 的映射。REDIRECT 要求先把包名转换
成 UID。TPROXY 当前不生成包名或 UID 过滤规则。

### 开启 `tun.auto_redirect` 被拒绝

它是 Linux root managed TUN 的专用混合数据面，不是 Android root 模式开关。
Android 请使用 root TUN，显式 TPROXY，显式 REDIRECT 或 VpnService。
