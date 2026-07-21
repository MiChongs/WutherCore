# 组网后端基础设施

`core-mesh` 为 Tailscale、Cloudflare、ZeroTier、NetBird、WireGuard、Nebula 等组网产品提供统一的能力、资源和生命周期边界。具体后端不得直接在主程序启动过程中修改系统；它必须先报告观测结果和资源声明，再由 `MeshSupervisor` 完成统一预检。

本阶段只交付通用基础设施，没有把“进程能够启动”冒充成任何具体产品的完整支持。当前 `wuther-core` 注册的是空 `BackendRegistry`，只把 capture 的宿主保留资源注入监督器；具体产品的配置、认证、进程接入和数据面适配仍需在后续独立变更中接入官方控制面/数据面依赖、实现能力探测，并完成对应平台的集成测试。

## 生命周期

每次启动遵循同一事务：

1. 冻结注册时的后端 ID、产品类型和所有权，后续不信任适配器动态改变身份。
2. 对全部后端执行只读 `probe`。
3. 合并后端声明与 WutherCore capture 等强类型宿主保留资源。
4. 在任何副作用发生前完成冲突检测。
5. 按注册顺序执行 `reconcile`。
6. 任一步失败时，对已经成功启动的后端逆序释放。
7. 正常退出时同样逆序关闭，并尝试收集全部关闭错误。

默认后端调用时限分别为：调用 gate 2 秒、`probe` 10 秒、`reconcile` 120 秒、`status` 5 秒、`detach`/`terminate` 30 秒。零值调用时限会归一化为 1 毫秒；只有零值 `monitor_interval` 表示禁用监控。每个后端的调用由独立 gate 串行化，适配器 future 的超时、取消和 panic 都会转换为脱敏失败。

调用方取消或丢弃 `start`/`stop` future 不会中断已经开始的事务 worker。活动启动被停止时，worker 会对已启动后端和 in-flight 后端执行有界逆序回滚。`reconcile` 返回的资源声明必须与通过预检的 observation 完全相同，不能在预检后扩大资源集合。

后台监控器默认每 5 秒执行一次只读状态观测，并重新验证冻结身份、运行相位、返回规模与动态资源冲突。状态调用失败、超时、panic、身份无法验证、返回非运行相位、越过有界观察预算或运行期出现新冲突时，监督器把 `running` 置为 false，并逆注册顺序释放对应后端由 WutherCore 拥有的生命周期对象。`managed_child`/`embedded` 的成功释放会消除它们拥有的系统资源；`attach_external` 的成功 `detach` 只隔离本进程的观察器和临时附件，绝不代表外部 daemon 的 DNS、路由或防火墙状态已经消失。

因此外部适配器的 `probe` 资源声明不是瞬时状态，而是连接期间所有可能 daemon 状态的保守固定 envelope；`reconcile` 和每次 `status` 必须返回同一声明集合（排序和重复项不影响比较）。监督器会拒绝运行中扩大或缩小 envelope。当前 `wuther-core` 还持续订阅监督器快照：一旦已经启动的监督器变为非运行或状态通道关闭，会主动停止 capture、其他后端、runtime 和监听器，形成应用级 fail-stop。直接复用 `core-mesh` 的其他宿主同样必须消费这个非运行信号并停止自己的宿主资源，不能把 external `detach` 描述为已经消除了 daemon 资源。

隔离失败会保留错误并进入 pending-release，后续监控 tick 必须先重试释放，不能因为 daemon 又报告健康就重新信任它。隔离状态和动态冲突会锁存；只有完成一次完整且成功的 `stop`，随后重新 `start`，才会重新获取资源，避免未知状态下自动恢复造成争用。显式 stop 和析构清理都会先取消并 drain 在途监控任务，再在同一个 maintenance 边界重读 started 集合，避免 monitor/stop 对同一外部资源并发释放。

状态通过 `/v1/mesh/status` 返回。这个 GET 端点只读取完整的内部 `MeshSnapshot`，再生成独立的 `PublicMeshSnapshot`；它不调用外部 daemon、不推进快照 generation，也不产生系统副作用。启动、停止和后台监控器负责更新内部快照。公开快照中的后端映射按 ID 稳定序列化，宿主 reservations 排序并去重；适配器提供的附件和资源声明保留输入顺序，需要可重现输出的适配器必须自行稳定排序。诊断按 `(level, code)` 保留最新一条并设置数量与字符串硬上限，防止长期重试或恶意适配器让 watch 快照无界增长。

公开投影不复用适配器原始字符串：URL 必须成功解析，并且只保留 scheme、host 和 port；userinfo、path、query 和 fragment 一律删除，非法 URL 不回显。Unix socket、named pipe 与 `Opaque` endpoint 默认变为没有 value 的 `hidden`。version 和产品/接口/协议等自定义字符串按 UTF-8 字节设上限并清理控制字符；diagnostic 只保留 level 与通过结构化校验的 code，message 使用固定公开文本；资源共享状态只公开 `exclusive`/`coordinated_shared`，不序列化 `coordination_key`，冲突原因也不包含密钥值。

内部快照结构同样没有命令环境或秘密文件字段，但仍保留生命周期判断所需的 observation，不得直接作为不受信任的 API DTO。协调 claim 和 conflict 的错误 `Display`/`Debug` 同样必须脱敏。适配器依然不得把令牌、原始 CLI stderr 或其他秘密写入业务字段；`BackendError` 的 sensitive source 不进入 `Display`、`Debug` 或公开投影。

## 所有权边界

| 所有权 | 含义 | 关闭行为 |
|---|---|---|
| `attach_external` | 用户或操作系统管理的 daemon/service；资源声明必须是整个 attach 生命周期的固定保守 envelope | 通过 `ExternalNetworkBackend::detach` 只停止 WutherCore 自己的 watcher、连接和临时附件；禁止停止服务、注销节点或删除系统配置；异常时由宿主消费 `running=false` 并执行应用级 fail-stop |
| `managed_child` | WutherCore 创建的独立子进程 | 通过 `OwnedNetworkBackend::terminate` 先尝试优雅关闭，超时后终止整个 Unix 进程组或 Windows Job，并等待回收 |
| `embedded` | 进程内实例或受控 helper | 通过 `OwnedNetworkBackend::terminate` 仅释放该实例拥有的资源 |

`detach`/`terminate` 是 at-least-once 操作，适配器必须实现幂等。调用超时只能说明监督器没有观察到完成，不能证明外部副作用未发生；后续 stop、故障恢复或 pending-release 重试可能再次调用释放。

托管子进程必须使用参数数组而不是 shell 拼接，并显式配置就绪探针。监督器持续观察子进程退出；意外退出会被发布为状态，并按照有界退避策略重启，无需等待下一次 `reconcile`。认证材料写入随机秘密文件；Unix 权限固定为 `0600`，Windows 沿用当前用户的继承 ACL。秘密文件至少保留到进程组完成回收，并在最后一个 `ManagedProcessSpec`/`SecretFile` 持有者析构时删除；脱敏值在最后一个 `Redactor` clone 析构时 zeroize，调用方自己的原始秘密缓冲区不由本模块清理。日志使用有界缓冲区，跨读取分块执行秘密值脱敏。

正常路径必须显式等待 `MeshSupervisor::stop` 和托管进程的 `ManagedDaemon::close` 并检查返回值；只有成功返回才表示对应的有界释放或进程组回收已经完成。Unix 上对已经自然消失的进程组返回 `ESRCH` 属于幂等成功，不会把“目标已不存在”误报成清理失败。对象析构只提供不 panic 的紧急 best-effort：监督器会取消活动事务，并在可用 Tokio runtime 上安排残留释放；托管进程会请求进程组终止并尽力安排回收。运行时已经关闭或不存在时，不能把 `Drop` 当作完成异步清理的证明。后端/readiness/shutdown hook 的 panic 会被转换为固定公开错误并触发进程组回收，但 Rust 全局 panic hook 可能先输出 panic payload；适配器不得把秘密放进 panic payload，嵌入应用也应按自身日志边界配置全局 hook。

## 能力与附件

能力描述后端实际能做什么，例如 L3 接口、内嵌拨号、子网路由、出口节点、私网/公网入口、身份查询、DNS namespace、事件流和高可用。能力不由产品名称推断，后端只能报告已经探测并验证的能力。

附件描述运行时实际产生的数据面：

- 接口名称、地址、索引与 MTU；
- 路由前缀、路由表、metric 与所属接口；
- 本地控制、拨号、健康和指标端点；
- HTTP、HTTPS、TCP、UDP、SSH、RDP 等入口映射。

后续路由、DNS 和 capture 同步必须消费这些动态附件，不能继续把某个产品的固定地址段当作完整网络视图。

## 系统资源仲裁

后端可声明以下资源：

- 路由管理器、IPv4/IPv6 默认路由和路由表；
- DNS、防火墙和 hosts 数据库；
- 精确接口名、OS 动态分配接口的全局管理权、本地监听 socket；
- 接口地址前缀、路由前缀；
- 防火墙 mark 区间。

冲突检测理解资源语义，而不只是比较枚举是否相等：

- `0.0.0.0:PORT` 与同协议、同端口的任意 IPv4 监听冲突；
- `[::]:PORT` 保守按可能的 dual-stack 监听处理；
- IPv4/IPv6 CIDR 按包含关系检测重叠；
- 地址前缀与其他后端的路由前缀也会检测重叠；
- IPv4/IPv6 默认路由与对应地址族的 `/0` 路由前缀等价并冲突；
- 路由表声明与显式使用相同（或未知）路由表的路由前缀冲突；
- 两个路由前缀只有在显式路由表相同，或任一方路由表未知时，才按 CIDR 重叠冲突；两个明确且不同的路由表可以拥有相同前缀；
- 全局路由/防火墙管理声明覆盖对应的细粒度路由、路由表和 mark 声明；
- 接口管理权与任何具体接口名冲突，用于 macOS utun、Android VpnService 等只有 activation 时才知道最终名称的平台；
- IPv4-mapped IPv6 listener 会归一化到对应 IPv4 地址空间，并与 IPv4 concrete/wildcard 及 dual-stack IPv6 wildcard 保守检测冲突；
- 防火墙 mark 使用闭区间重叠判断。

不同 owner 的重叠声明默认冲突。只有双方都使用相同且非空的 `coordination_key` 时才允许共享。这个 key 表示双方已经实现同一套原子更新与回滚协议，不是绕过检查的配置开关。

## 后端实现约束

一个后端适配器必须实现公共的 `NetworkBackend`，并根据所有权额外实现 `ExternalNetworkBackend` 或 `OwnedNetworkBackend`：

- `descriptor`：提供只读取一次并冻结的 ID、产品类型和所有权；
- `probe`：只读探测版本、状态、能力、附件和资源声明；
- `reconcile`：只使用已经通过预检的观测结果建立本进程所需状态；
- `status`：返回当前脱敏快照；
- `detach`/`terminate`：严格遵守所有权边界并释放本适配器拥有的资源。

`probe` 返回的 ID、产品类型和所有权必须与注册信息一致。监督器会在状态发布前验证这些字段，避免后端把资源错误归属给其他 owner。

`attach_external` 不能依赖运行后才发现的 daemon 配置来扩充资源声明。适配器必须在只读 `probe` 阶段保守覆盖连接期间可能出现的 DNS、默认路由、子网路由、接口、监听和防火墙资源；如果无法给出安全 envelope，就必须在该宿主组合上返回 Unsupported/Conflict，而不是接入后再赌动态 `detach` 能停止外部 daemon。

适配器错误只允许把稳定错误码和经过清理的内部消息写入完整快照。公开投影会再次校验错误码并用固定文本替换任意 message。原始 stderr、命令行、环境变量和认证响应只能作为内存中的敏感错误源保留，`Display`、`Debug` 和公开序列化均不得输出。所有 `probe`、`reconcile`、`status` 观察在进入冲突检测或 watch 快照前都必须通过统一的附件、资源、诊断、嵌套集合、单字符串和总字符串预算验证；越界结果按固定 `invalid_status` 处理，不能让后端调用 deadline 之外的本地 O(n²) 冲突计算失去上界。

## 宿主保留资源

主程序在启动组网后端前调用 `core_capture::host_resource_claims` 取得无 owner 的 `ResourceClaim`，再使用 `HostSubsystemId("wuther.capture")` 包装为专用的 `HostResourceClaim`。`MeshSupervisor` 构造函数只接受这个强类型宿主输入，并在边界内部转换为快照使用的 `OwnedResourceClaim`。宿主 owner 与后端 owner 使用不同命名空间；即使字符串恰好相同，也会被视为不同 owner 并执行冲突检测。宿主保留资源只参与仲裁，不会收到后端生命周期调用。

同一预检还会用独立的 `wuther.dns`、`wuther.mixed`、`wuther.api` owner 声明进程实际启动的固定监听。DNS 按 mihomo 语义同时声明 TCP/UDP，空地址和端口 `0` 都表示禁用；Mixed 只声明其固定 TCP 端口，SOCKS5 UDP ASSOCIATE 的 relay 继续使用独立动态 socket；API 只在 `ui.on` 且 panel 已配置时声明 TCP。Mixed 与 API 的端口 `0` 无法形成精确预检，因此启动会在任何网络修改前失败。Mixed 绑定失败也不再回退到 `9001..=9099`，保证快照中的 reservation 与真实 socket 始终一致。不同进程子系统必须使用不同 owner，否则冲突器按“同一 owner 的重复声明”跳过后会掩盖进程内部端口碰撞。

Capture 自己的 DNS hijack listener 仍属于 `wuther.capture`，不会与上面的可配置独立 DNS server 混为一谈。`hijack_dns=true` 时，Windows 声明 TCP/UDP `127.0.0.1:53` 与 `[::1]:53`，其他受支持平台声明 TCP/UDP `127.0.0.1:5454`；启动和预检共同读取同一份纯地址选择函数。

| 平台/模式 | 当前实际声明 |
| --- | --- |
| Linux TUN | 接口与地址；`auto_route` 的 route manager、配置表、split-default、输出 mark，catch-all 时再声明逻辑默认路由；身份过滤声明 firewall；`strict_route` 声明双栈逻辑默认路由；`auto_redirect` 声明安装时 nft/TPROXY/NAT fallback 的保守并集 |
| Linux TPROXY | route/firewall manager、表与代理 mark `0x2d0`、可配置 output mark（正常配置默认 `0x2024`）、IPv4 local default 及 TCP/UDP `0.0.0.0:7894`；启用 IPv6 时再声明 `::/0` local default、逻辑默认路由及 TCP/UDP `[::]:7894` |
| Linux Redirect | 只声明 firewall manager |
| Android TUN | root `/dev/net/tun` 的精确接口名与 VpnService 的 OS 动态接口管理权、地址及两条配置路径的保守并集；后者按 `VpnService.Builder` 实际静态路由声明 unknown-table route prefix，包含 `auto_route=false + route_address`，启用 DNS hijack 时声明 DNS manager |
| Android TPROXY/Redirect | 不在预检中执行 `su`、`modprobe` 或 capability 探测；统一声明所有运行期 tier 的 fail-closed 并集：firewall、表 100、mark 1、双栈 local-default 与逻辑默认路由 |
| Windows TUN | 接口与地址；`auto_route=false` 不声明路由，catch-all 声明实际双栈默认路由（IPv6 同时受 resolver 与 TUN IPv6 地址门控），纯 `route_address` 声明过滤、去重后的精确前缀，`route_address_set` 按实际行为回到 catch-all；启用 DNS hijack 时再声明 DNS manager |
| macOS TUN | OS 动态 utun 接口管理权、地址、当前实际安装的 IPv4 默认路由；不把请求名冒充真实 utunN，也不虚构尚未实现的 PF/DNS |
| iOS/其他 | iOS NetworkExtension 的接口与路由由宿主应用拥有，因此只在 DNS hijack 时声明 capture 私有 listener；其他未支持平台返回空声明 |

这里故意反映“当前安装代码实际做什么”，而不是理想配置语义。Android TUN 在 native open 成功前无法知道最终使用 root TUN 还是宿主预配置的 VpnService fd，因此预检复用与 `VpnService.Builder` 相同的纯路由计算并声明两条路径的并集；Android framework 自行选择的接口名和路由表分别用 `InterfaceManager` 与 `table=None` 表示未知范围，以便与任意具体接口/重叠路由保守冲突。macOS 同样在打开设备后才得到真实 utunN，因此只声明动态接口管理权而不声明配置中的请求名。Android 透明模式的运行期 capability 探测可能在预检之后加载 TPROXY 模块，所以预检不能依据“模块当前未加载”缩小声明，而是始终覆盖所有可能成功的 tier。现有 Linux/Android 安装路径仍有部分 IPv6 操作没有完全遵守 resolver 的 `ipv6_enabled`；资源声明会保守覆盖这些真实操作，该历史行为需要在后续独立平台修复中统一，不能在本基础设施变更里静默改变。Linux `auto_redirect` 只有安装时才选择 fallback，所以预检采用保守并集，可能有意提前报告冲突。关闭 capture 或选择 `none` 时不声明资源，且声明路径不会触发任何 Android 能力探测。宿主 reservations 表示启动意图和仲裁边界，不是 capture 安装已经成功的证明；后续启动失败仍由 capture 自己回滚并报告。
