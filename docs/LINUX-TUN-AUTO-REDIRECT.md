# Linux TUN `auto_redirect`

`auto_redirect` 是 Linux root-managed TUN 的混合透明接管模式：

- 本机 TCP 由 nftables `nat output` 的 `redirect` 送入 WutherCore 的临时 TCP listener；
- listener 通过 `SO_ORIGINAL_DST` 恢复原始目标，再交给现有路由与出站引擎；
- 本机 UDP 仍由策略路由送入 TUN，由 `TunDispatcher` 处理；
- `auto_redirect` 不为 ICMP 和其他非 TCP/UDP 协议安装导流 rule；它们继续按已有主路由策略处理，本功能不承诺代理或转发 ICMP；
- `iif lo` policy rule 只匹配本机产生的 TCP/UDP，不接管转发或 LAN 流量。

这个契约参考 sing-box、mihomo 使用的 sing-tun REDIRECT 数据面，但只承诺下文列出的安全子集，不等同于完整兼容它们的所有 TUN 选项。

## 前置条件

- Linux；Android、macOS、Windows 不支持此模式。
- 以 root 运行，或具备配置 TUN、路由和 nftables 所需的等价 capability。
- 可用的 `iproute2`（`ip` 命令）和 nftables（`nft` 命令）。
- 内核支持 TUN、nftables NAT REDIRECT 和 `SO_ORIGINAL_DST`。
- TUN 接口的 MTU、IPv4 地址、启用时的 IPv6 地址和 link-up 必须全部配置成功。
- 自定义路由表必须是私有表；Linux 的 `default/main/local` 表号 253–255 会被拒绝。
- 本功能使用的四个连续 rule priority 必须空闲，且 capture priority 必须位于 `4..=32765`，排在 Linux 默认 `main` rule（32766）之前；不会覆盖同优先级的外部规则。
- 实际出站表必须有可用的同地址族 default route。启用双栈时，IPv4/IPv6 default route 必须使用同一个出站接口，因为当前 socket 接口绑定不是按地址族拆分的。

生产激活只使用 nftables。安装前会探测表名冲突并执行 `nft -c`；实际规则通过一次 nft batch 原子提交。iptables 规则生成器目前只用于测试，不会作为失败后的生产回退路径。

## 最小配置

```yaml
version: 1
profile: desktop

listen:
  panel: false

capture:
  on: true
  method: virtual_nic
  traffic: system
  exclude:
    cidr:
      - "127.0.0.0/8"
      - "::1/128"
  tun:
    interface_name: rpktun0
    address:
      - "172.19.0.1/30"
      - "fdfe:dcba:9876::1/126"
    inet6: true
    auto_route: true
    auto_redirect: true
    iproute2_table_index: 2022
    iproute2_rule_index: 9000
    auto_redirect_output_mark: "0x2024"
    route_exclude_address:
      - "192.168.0.0/16"
      - "100.64.0.0/10"
      - "fd7a:115c:a1e0::/48"
    loopback_address:
      - "127.0.0.1"
      - "::1"

route:
  preset: direct
```

`auto_redirect_output_mark` 可以省略。省略或显式配置为 `0` 时使用默认值 `0x2024`。配置中的地址、CIDR、mark 和 UID/GID range 会严格解析；活动配置中存在非法字面量时，启动会直接失败，不会静默缩小 bypass 集。

`capture.exclude.cidr`、`route_exclude_address` 和 `loopback_address` 会合并、按地址族去重，并作为策略路由 bypass。代理自身带 output mark 的 socket 也会使用安装时探测并记录的真实出站路由表，避免再次进入 TUN。

启动还会核对私有表只含本次成功写入、指向当前 TUN 的两条 split-default route；重复前缀、非零 metric、外部 gateway/nexthop 或非 `boot` protocol 也不视为自有路由。私有表存在额外路由、实际出站表缺少 default route、rule priority 碰撞或单个探测目标仅命中 host route 时都会失败并回滚。

## 支持边界

| 项目 | 当前行为 |
| --- | --- |
| 平台 | 仅 root-managed Linux |
| 流量范围 | 仅 `traffic: system` |
| TCP | nftables NAT REDIRECT + `SO_ORIGINAL_DST` |
| UDP | TUN |
| ICMP/其他协议 | 不安装 `auto_redirect` 导流 rule；按已有主路由处理，不承诺代理/转发 |
| IPv4 | 支持 |
| IPv6 | TUN v6、系统 v6 和独立 v6 listener 都可用时支持 |
| 静态 `route_address` / `route_exclude_address` | 支持 |
| `capture.exclude.cidr` / `loopback_address` | 支持并参与 policy bypass |
| output mark | 支持；`0` 归一化为默认值 |

以下组合会在任何内核写入前被拒绝：

- `auto_route: false`、`strict_route: true` 或非 `virtual_nic`；
- `traffic: lan`、Android/VpnService 或 platform-preconfigured TUN；
- `route_address_set`、`route_exclude_address_set` 等动态集合；
- interface、MAC、process、MPTCP、UID/GID、Android user/package 过滤；
- 显式 input/reset mark、NFQUEUE 或 fallback rule index。

动态规则集并不是被忽略：配置校验会明确报错。在 SRS/MRS/provider 能提供版本化 IP 快照和更新订阅、capture 层能原子同步 nft set 之前，禁止把这类配置当作已经生效。

## 启停与失败恢复

构造 `Runtime` 不会修改进程级 fwmark。supervisor 在启动 capture 前通过原子 compare-and-set 独占非零 output mark；已有 owner 时拒绝启动。只有平台 ingress、policy rule 和 TUN 都已成功回滚后才释放 mark；若清理失败，mark 与精确账本一起保留在 `CleanupFailed` 状态供 `stop()` 重试。主程序在启动错误后会主动执行一次清理重试，重试仍失败时拒绝继续启动普通 Mixed/API/DNS 数据面。

启动按以下顺序进行：

1. 打开并完整配置 TUN；
2. 预绑定 IPv4 和可用时的 IPv6 TCP listener；
3. 等待 `TunDispatcher` 接管 TUN；
4. 启动 listener task；
5. 安装并核验 split-default route，先写真实网络 bypass 依赖，再写本机 TCP/UDP capture rule；
6. 最后原子安装 nftables REDIRECT 表。

停止顺序相反：先撤销 nftables 入口，再停 listener，然后先删除全部 capture rule，确认成功后才拆 output-mark/bypass 依赖和 route，最后关闭 TUN。任一 capture rule 删除失败都会形成阶段屏障，不会继续拆掉它依赖的防回环规则。删除失败的项会保留在所有权账本中，停止返回错误；后续重试只处理残余资源，避免误删外部规则或在 dispatcher 已关闭时留下黑洞。

程序不会接管已存在的同名 nftables 表。若上次进程被强制终止，请先确认表确实属于已退出的 WutherCore 实例，再由管理员处理；不要在不确认所有权时自动覆盖。

## 排查

```bash
ip -4 rule show
ip -6 rule show
ip -4 route show table 2022
ip -6 route show table 2022
nft list table inet wuther_auto_redirect
```

重点检查：

- policy rule 是否带 `iif lo` 和 `ipproto tcp` / `ipproto udp`；
- TCP rule 是否指向 listener 当前的临时端口；
- IPv4/IPv6 bypass 是否查安装时记录的真实出站表；
- 没有 catch-all rule、TPROXY、NFQUEUE 或 ICMP 导流规则；
- 日志中没有 `nft -c`、route add、rule add 或 `SO_ORIGINAL_DST` 错误。

## 上游语义依据

- [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [mihomo TUN configuration](https://wiki.metacubex.one/en/config/inbound/tun/)
- [sing-tun nftables REDIRECT rules](https://github.com/SagerNet/sing-tun/blob/e5d2fab03586e41fbcb0ca8c5ff4db18e5d3365e/redirect_nftables_rules.go#L648-L674)
- [sing-tun REDIRECT listener](https://github.com/SagerNet/sing-tun/blob/e5d2fab03586e41fbcb0ca8c5ff4db18e5d3365e/redirect_server.go)
- [Linux transparent proxy documentation](https://docs.kernel.org/networking/tproxy.html)
