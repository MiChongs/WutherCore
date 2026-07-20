目标：小白能看懂，专家能扩展；配置字段独立于 Mihomo，能力面对齐
Mihomo，Smart 更可解释、更稳定、更高性能。

版本：0.3 Friendly YAML 设计版 \| 语言：Rust \| 日期：2026-04-25

> 本版把配置复杂度从"内核字段堆叠"改成"少量用户意图 + 自动推断 +
> 明确默认值"。用户只需要理解
> listen、feeds、nodes、groups、route、resolver、capture、smart、ui、mesh
> 这 10 个词。

# 目录

- 1\. 本版改动结论

- 2\. 设计原则：小白友好但不牺牲能力

- 3\. Friendly YAML 总览

- 4\. 四套可直接使用的模板

- 5\. 字段完整说明

- 6\. Smart 核心完整实现方案

- 7\. DNS / Resolver 模块

- 8\. TUN / TProxy / Mixed 入站设计

- 9\. Tailscale 集成

- 10\. Clash/Mihomo API 对齐与原生 API

- 11\. Rust 架构与性能优化

- 12\. 多平台适配

- 13\. 配置编译器与迁移工具

- 14\. 测试、验收与开发路线

- 15\. 附录：字段速查与参考资料

# 1. 本版改动结论

上一版 YAML
偏工程化，字段数量多，第一次接触的人会不知道应该先改哪里。本版改成"默认强大，显式简单"的配置体验。

  -------------- --------------------------- ------------------------------------
  **目标**       **旧思路**                  **新版做法**

  第一次使用     让用户理解大量内核字段      只填写 feeds；profile
                                             自动补全端口、分流、DNS、Smart
                                             和面板。

  选择节点       要求用户理解多种策略组      groups.main.choose:
                                             smart；系统自动学习和选择。

  规则分流       让用户写大量规则行          route.preset: cn_smart；复杂规则才写
                                             route.steps。

  DNS            暴露                        resolver.mode:
                 fake-ip、fallback、policy   smart；高级项按需展开。
                 等细节                      

  透明代理       让用户理解                  capture.method:
                 TUN、TProxy、redirect 差异  auto；路由器用户再指定 tproxy 或
                                             virtual_nic。

  Tailscale      用户手工排除网段和进程      mesh.tailscale.keep_tailnet_direct
                                             默认开启，自动排除 Tailnet。
  -------------- --------------------------- ------------------------------------

## 1.1 配置字段独立，不复用 Mihomo 字段

本生态只对齐能力，不复制 Mihomo YAML 字段和模板。兼容 Mihomo/Clash
的地方放在 API 兼容层和迁移工具里。

  ---------------------- ---------------- ----------------------------------------------
  **用户想表达的意思**   **本生态字段**   **说明**

  本地代理端口           listen.local     一个端口同时支持 HTTP(S) 与 SOCKS5。

  订阅                   feeds            订阅源、在线节点清单或本地节点清单。

  手动节点               nodes            可以直接粘贴节点链接，也可以写结构化节点。

  节点选择               groups           把节点放在一个组里，选择
                                          manual、smart、fast、stable、spread、chain。

  分流                   route            使用 preset 或接近自然语言的 steps。

  域名解析               resolver         负责 DNS、Fake 地址、缓存和防泄漏。

  TUN/TProxy             capture          负责系统透明接管。

  控制面板/API           ui               原生 API 与 Clash/Mihomo 兼容 API 都放在这里。
  ---------------------- ---------------- ----------------------------------------------

# 2. 设计原则：小白友好但不牺牲能力

## 2.1 只让用户理解 10 个词

  ---------- -------------------------- ----------------------------------------------------------
  **词**     **小白理解方式**           **内核实际含义**

  listen     软件在哪个端口等你连接     HTTP/SOCKS/Mixed/控制面板/API 入站监听。

  feeds      机场订阅链接               远程或本地节点 Provider，支持过滤、重命名、健康检查。

  nodes      自己手动添加的节点         结构化或 URI 出站代理定义。

  groups     一堆节点怎么选             Selector/UrlTest/Fallback/LoadBalance/Relay/Smart
                                        的统一抽象。

  route      哪些网站直连，哪些走代理   规则引擎、规则集、进程规则、端口规则、网络规则。

  resolver   域名怎么查                 DNS 缓存、DoH/DoT/DoQ、Fake 地址、防泄漏、规则联动。

  capture    是否接管全设备流量         TUN、TProxy、redirect、DNS 劫持、路由表和防火墙规则。

  smart      自动选最合适节点           基于历史数据、探测、ASN、域名记忆和模型的智能调度。

  ui         面板和 API                 原生 API、Clash/Mihomo 兼容 API、Dashboard、鉴权。

  mesh       和内网/VPN 协同            Tailscale、WireGuard、局域网、远程开发网络的保护与集成。
  ---------- -------------------------- ----------------------------------------------------------

## 2.2 三层配置模型

  ---------------- ---------------------- ---------------- ---------------------------------------------------
  **层级**         **谁使用**             **写多少字段**   **能力**

  Level 1 极简     第一次使用的小白       通常 4 行        订阅、自动分流、Smart、DNS、面板全部自动开启。

  Level 2 日常     桌面/手机/软路由用户   约 15\~35 行     自定义端口、分组、地区偏好、透明代理、Tailscale。

  Level 3 专家     运维、开发、网关场景   按模块展开       完整协议、规则集、DNS
                                                           策略、TUN/TProxy、API、性能参数。
  ---------------- ---------------------- ---------------- ---------------------------------------------------

## 2.3 默认值必须可靠

  ------------------------------------ --------------- --------------- ----------------
  **字段**                             **desktop       **router 默认** **server 默认**
                                       默认**                          

  listen.local                         7890            7890            关闭

  listen.panel                         9090            9090            127.0.0.1:9090

  listen.share                         false           home            false

  route.preset                         cn_smart        cn_smart        global

  resolver.mode                        smart           smart           secure

  capture.on                           false           true            false

  capture.method                       auto            auto            关闭

  smart.on                             true            true            true

  mesh.tailscale.keep_tailnet_direct   true            true            true
  ------------------------------------ --------------- --------------- ----------------

> 默认值的硬性要求：同一个配置文件在同一个 profile
> 下，每次启动得到同一份运行时配置。所有自动选择必须写入运行日志，用户能知道系统为什么这样做。

# 3. Friendly YAML 总览

## 3.1 YAML 基本规则

1\. 字段名全部小写，多个单词用下划线，例如 keep_tailnet_direct。

2\. 缩进只用空格，不用 Tab；推荐每层 2 个空格。

3\. 链接、密码、包含冒号或井号的文本必须加引号。

4\. 时间统一写成 30s、5m、12h、7d。

5\. 开关只使用 true 或 false，不使用 yes/no，避免 YAML 隐式转换。

## 3.2 最小有效配置

这个文件可以直接启动。用户只需要替换订阅链接。

version: 1

profile: desktop

feeds:

my_airport: \"https://example.com/your-subscription\"

内核自动补全后的行为：本地代理端口 7890、面板端口 9090、main 分组使用
Smart、国内直连、国外走 main、DNS 使用
resolver.smart、不开启全局透明代理。

## 3.3 标准结构

version: 1

profile: desktop

name: \"my daily config\"

listen:

local: 7890

panel: 9090

share: false

feeds:

my_airport: \"https://example.com/sub\"

nodes:

\- \"vless://user@example.com:443?security=tls#manual-node\"

groups:

main:

choose: smart

use: \[my_airport, nodes\]

prefer: \[HK, JP, SG, TW, US\]

route:

preset: cn_smart

final: main

resolver:

mode: smart

capture:

on: false

smart:

on: true

goal: balanced

ui:

on: true

secret: \"change-this-token\"

mesh:

tailscale:

on: true

keep_tailnet_direct: true

## 3.4 配置编译后的内部流程

user.yaml

-\> 语法解析

-\> profile 默认值合并

-\> feeds/nodes 展开

-\> 协议链接解析

-\> groups 生成选择器

-\> route 生成规则图

-\> resolver 生成 DNS 策略

-\> capture 生成平台接管计划

-\> smart 生成评分器和学习任务

-\> runtime graph 启动

# 4. 四套可直接使用的模板

## 4.1 模板 A：小白桌面版

适用：Windows、macOS、Linux 桌面客户端。用户只需要把浏览器或系统代理指向
127.0.0.1:7890。

version: 1

profile: desktop

feeds:

my_airport: \"https://example.com/sub\"

## 4.2 模板 B：日常增强版

version: 1

profile: desktop

listen:

local: 7890

panel: 9090

share: false

feeds:

my_airport:

url: \"https://example.com/sub\"

every: 12h

keep:

name_has: \[HK, JP, SG, TW, US\]

rename:

remove: \[\"倍率\", \"剩余流量\"\]

groups:

main:

choose: smart

use: \[my_airport\]

prefer: \[HK, JP, SG\]

media:

choose: smart

use: \[my_airport\]

prefer: \[US, JP, SG\]

route:

preset: custom

steps:

\- \"home -\> direct\"

\- \"ads -\> block\"

\- \"cn -\> direct\"

\- \"netflix -\> media\"

\- \"youtube -\> media\"

\- \"telegram -\> main\"

\- \"any -\> main\"

resolver:

mode: smart

ui:

on: true

secret: \"change-this-token\"

## 4.3 模板 C：软路由透明代理版

version: 1

profile: router

listen:

local: 7890

panel: 9090

share: home

feeds:

my_airport: \"https://example.com/sub\"

groups:

main:

choose: smart

use: \[my_airport\]

prefer: \[HK, JP, SG, TW\]

capture:

on: true

method: auto

traffic: lan

resolver: hijack

exclude:

cidr:

\- 10.0.0.0/8

\- 172.16.0.0/12

\- 192.168.0.0/16

\- 100.64.0.0/10

\- \"fd7a:115c:a1e0::/48\"

route:

preset: cn_smart

final: main

resolver:

mode: smart

fake: auto

mesh:

tailscale:

on: true

keep_tailnet_direct: true

## 4.4 模板 D：仅手动节点，无订阅

version: 1

profile: desktop

nodes:

\- \"ss://example-link#HK-01\"

\- \"trojan://password@example.com:443?sni=example.com#US-01\"

\- name: \"JP-Manual\"

link: \"vless://uuid@example.com:443?security=tls#JP-Manual\"

groups:

main:

choose: smart

use: \[nodes\]

route:

preset: cn_smart

final: main

# 5. 字段完整说明

## 5.1 顶层字段

  ---------- -------------- ------------ ------------------------------ --------------------------------------------------------
  **字段**   **是否必填**   **默认值**   **允许值/格式**                **行为**

  version    必填           无           1                              配置格式版本。启动时必须校验，未来升级通过迁移器处理。

  profile    建议填写       desktop      desktop/router/server/mobile   决定默认端口、透明代理、DNS、防泄漏策略。

  name       可选           文件名       字符串                         显示在面板和日志中。

  listen     可选           按 profile   对象                           本地代理端口、面板端口、局域网共享。

  feeds      可选           {}           对象                           订阅源。feeds 与 nodes 至少有一个非空。

  nodes      可选           \[\]         数组                           手动节点。支持 URI 和结构化对象。

  groups     可选           自动生成     对象                           选择节点的方法。
                            main                                        

  route      可选           preset:      对象                           分流策略。
                            cn_smart                                    

  resolver   可选           mode: smart  对象                           DNS/域名解析策略。

  capture    可选           按 profile   对象                           透明代理/TUN/TProxy。

  smart      可选           on: true     对象                           智能选择引擎。

  ui         可选           on: true     对象                           Dashboard 和 API。

  mesh       可选           {}           对象                           Tailscale 等网状网络集成。
  ---------- -------------- ------------ ------------------------------ --------------------------------------------------------

## 5.2 listen：本地入口

listen:

local: 7890 \# 一个端口同时接收 HTTP(S) 和 SOCKS5

panel: 9090 \# Web 面板和 API

share: false \# false/home/all

auth:

\- \"user:password\"

  ------------ ---------------- ---------- ----------------------------------
  **字段**     **类型**         **默认**   **说明**

  local        端口或对象       7890       Mixed 入口。对象写法支持
                                           host、port、auth、udp。

  panel        端口、地址或     9090       控制面板/API 入口。写 false
               false                       表示关闭。

  share        false/home/all   false      false 仅本机；home 仅私有网段；all
                                           监听所有地址。

  auth         数组             \[\]       HTTP/SOCKS/Mixed
                                           的用户密码。为空表示不启用认证。
  ------------ ---------------- ---------- ----------------------------------

## 5.3 feeds：订阅源

feeds:

my_airport: \"https://example.com/sub\"

backup:

url: \"https://example.com/backup-sub\"

every: 12h

via: direct

keep:

name_has: \[HK, JP, SG\]

drop:

name_has: \[Expire, Traffic\]

rename:

add_prefix: \"B-\"

remove: \[\"倍率\", \"剩余\"\]

  ---------------- ----------- ------------------------------------------------
  **字段**         **默认**    **说明**

  url              无          订阅地址。支持 http、https、file。

  every            12h         刷新周期。最小 5m，最大 30d。

  via              direct      更新订阅时使用 direct 或某个 group。

  keep.name_has    \[\]        只保留名字包含这些词的节点。空数组表示不过滤。

  drop.name_has    \[\]        丢弃名字包含这些词的节点。drop 优先级高于 keep。

  rename           {}          对节点显示名做可读化处理，不改变节点连接参数。
  ---------------- ----------- ------------------------------------------------

## 5.4 nodes：手动节点

nodes:

\- \"ss://example-link#HK-01\"

\- name: \"US-VLESS\"

link: \"vless://uuid@example.com:443?security=tls#US-VLESS\"

\- name: \"SSH-Jump\"

protocol: ssh

address: \"203.0.113.10:22\"

login:

user: root

password: \"change-me\"

network:

udp: false

  --------------- ------------------------------------------------------------------
  **字段**        **说明**

  字符串节点      把整条 URI 当作一个节点，自动解析协议、地址、认证、TLS、传输层。

  name            节点显示名，必须唯一。URI 中的片段名可自动成为 name。

  link            节点 URI。link 与 protocol/address 二选一。

  protocol        协议名，例如
                  ss、ssr、vmess、vless、trojan、hysteria2、tuic、wireguard、ssh。

  address         host:port。IPv6 使用 \[addr\]:port。

  login           认证信息，例如 uuid、password、user、private_key。

  secure          TLS、Reality、ECH、证书指纹、uTLS 指纹等安全层。

  transport       tcp、ws、grpc、h2、httpupgrade、quic、xhttp 等传输层。

  network         udp、tfo、mptcp、interface、mark、ip_family、multiplex。
  --------------- ------------------------------------------------------------------

## 5.5 协议覆盖范围

  -------------- ---------------------------------------------------- ------------------------------------------
  **类别**       **协议/能力**                                        **实现要求**

  基础代理       HTTP、HTTPS、SOCKS4、SOCKS4a、SOCKS5、Mixed          支持认证、UDP over
                                                                      SOCKS5、IPv4/IPv6、连接日志。

  经典加密代理   Shadowsocks、Shadowsocks 2022、ShadowsocksR、Snell   支持 UDP、插件/混淆、AEAD、2022
                                                                      多用户密钥。

  V 系协议       VMess、VLESS、Trojan                                 支持 TLS、Reality、ECH、uTLS
                                                                      指纹、WS、gRPC、H2、HTTPUpgrade、XHTTP。

  QUIC/UDP       Hysteria、Hysteria2、TUIC、MASQUE                    支持拥塞控制、带宽参数、UDP
  新协议                                                              代理、连接迁移。

  隧道/专线      WireGuard、SSH、TrustTunnel、AnyTLS、Mieru、Sudoku   使用协议专属适配器，不用通用 TCP
                                                                      代理伪装。

  内置出口       direct、block、resolver                              直连、拒绝、DNS 出口必须与规则引擎统一。
  -------------- ---------------------------------------------------- ------------------------------------------

## 5.6 groups：节点怎么选

groups:

main:

choose: smart \# manual/smart/fast/stable/spread/chain

use: \[my_airport, nodes\]

prefer: \[HK, JP, SG\]

fallback:

choose: stable

use: \[my_airport\]

check: \"https://www.gstatic.com/generate_204\"

relay:

choose: chain

path: \[SSH-Jump, main\]

  ----------- ------------------- ---------------------------------------------------------
  **choose    **小白含义**        **运行时策略**
  值**                            

  manual      我自己选            Dashboard 或 API 设置当前节点，配置重载后保持选择。

  smart       系统自动选最合适    Smart
                                  引擎按目标网站、ASN、历史成功率、延迟、负载、偏好评分。

  fast        选延迟低的          周期性探测 URL，选择延迟最低的可用节点。

  stable      坏了再换            主节点失败后切换备用节点，恢复后按策略回切。

  spread      分摊流量            按连接、域名或会话做负载均衡，支持 sticky。

  chain       串联节点            多个出口按顺序拨号，替代旧式 relay，支持链路能力校验。
  ----------- ------------------- ---------------------------------------------------------

## 5.7 route：分流

route:

preset: custom

steps:

\- \"home -\> direct\"

\- \"ads -\> block\"

\- \"cn -\> direct\"

\- \"github -\> main\"

\- \"telegram -\> main\"

\- \"domain:example.com -\> direct\"

\- \"ip:203.0.113.0/24 -\> main\"

\- \"process:Code -\> main\"

\- \"any -\> main\"

  ------------- ---------------------------------------------------------
  **preset**    **明确行为**

  cn_smart      局域网、私有地址、国内域名和国内 IP
                直连；广告可选拦截；其它流量走 final。

  global        除了局域网、Tailnet 和保留地址，全部走 final。

  direct        全部直连；仍保留 DNS 缓存和日志。

  privacy       局域网和 Tailnet 直连；其它全部走 final；禁止 DNS 泄漏。

  custom        完全按 steps 自上而下匹配；必须包含 any 兜底。
  ------------- ---------------------------------------------------------

  ---------------------------------------------- ------------------------------------------------
  **steps 左侧目标**                             **含义**

  home                                           局域网、回环、本机、私有地址、mDNS/Bonjour
                                                 常见域。

  cn                                             中国大陆常用域名/IP 规则集。

  ads                                            广告/跟踪规则集。

  telegram/youtube/netflix/github/apple/google   内置常用服务别名，版本化维护。

  domain:example.com                             精确域名。

  suffix:example.com                             域名后缀。

  ip:1.2.3.0/24                                  CIDR 网段。

  port:443                                       目标端口。

  network:udp                                    网络类型。

  process:Code                                   进程名，仅支持桌面系统和部分移动平台。

  any                                            兜底匹配。
  ---------------------------------------------- ------------------------------------------------

## 5.8 resolver：域名解析

resolver:

mode: smart \# system/secure/fake/smart

fake: auto \# off/auto/force

cache: 24h

mainland: ali

overseas: cloudflare

servers:

ali: \"https://dns.alidns.com/dns-query\"

cloudflare: \"https://1.1.1.1/dns-query\"

local: \"system\"

  --------------- ---------- ---------------------------------------------
  **字段**        **默认**   **明确行为**

  mode: system    \-         只使用系统 DNS，不启用 Fake 地址，不劫持。

  mode: secure    \-         优先 DoH/DoT/DoQ；失败时按 profile
                             决定是否回退系统 DNS。

  mode: fake      \-         为需要代理的域名返回 Fake
                             地址，由内核还原真实域名。

  mode: smart     默认       国内域名走 mainland，海外域名走
                             overseas；必要时启用 Fake 地址。

  fake            auto       auto 只在 capture 开启或应用需要时启用；force
                             强制 Fake 地址。

  cache           24h        DNS 缓存时间；负缓存默认 1m。
  --------------- ---------- ---------------------------------------------

## 5.9 capture：透明代理

capture:

on: true

method: auto \# auto/virtual_nic/tproxy/redirect

traffic: lan \# system/lan/apps

resolver: hijack \# off/hijack

stack: native \# native/gvisor/smoltcp

mtu: 9000

offload: true

exclude:

cidr:

\- 100.64.0.0/10

\- \"fd7a:115c:a1e0::/48\"

process:

\- tailscaled

  ----------- ---------------------------------- ------------------------------------------------
  **字段**    **允许值**                         **行为**

  method      auto/virtual_nic/tproxy/redirect   auto 根据平台选择；virtual_nic 是 TUN；tproxy 是
                                                 Linux UDP+TCP 透明代理；redirect 是 TCP-only
                                                 兼容模式。

  traffic     system/lan/apps                    system 接管本机；lan 接管路由器转发流量；apps
                                                 只接管指定应用。

  resolver    off/hijack                         hijack 把 DNS 请求交给 resolver，防止系统 DNS
                                                 泄漏。

  stack       native/gvisor/smoltcp              native 优先使用系统栈；gvisor
                                                 提供用户态栈；smoltcp 用于嵌入式/低资源设备。

  offload     true/false                         在 Linux 可启用
                                                 GSO/批量读写；不支持的平台自动关闭并记录原因。
  ----------- ---------------------------------- ------------------------------------------------

## 5.10 ui：面板与 API

ui:

on: true

secret: \"change-this-token\"

dashboard: \"auto\"

api:

native: true

clash_compat: true

cors: \[\"http://127.0.0.1:9090\"\]

  ------------------ ---------- ---------------------------------------------
  **字段**           **默认**   **行为**

  on                 true       是否启用面板和 API。

  secret             空         生产环境必须设置；空值只允许 127.0.0.1。

  dashboard          auto       auto 使用内置面板；也可指定目录。

  api.native         true       启用 /v1 原生 API。

  api.clash_compat   true       启用 Clash/Mihomo 兼容 API，便于现有
                                Dashboard 生态接入。
  ------------------ ---------- ---------------------------------------------

## 5.11 mesh：Tailscale 与其它网状网络

mesh:

tailscale:

on: true

mode: auto \# auto/localapi/userspace/tsnet/off

keep_tailnet_direct: true

expose_as_node: false

userspace_proxy:

socks: \"127.0.0.1:1055\"

http: \"127.0.0.1:1056\"

  --------------------- ----------- -----------------------------------------
  **字段**              **默认**    **行为**

  mode: auto            auto        优先检测本机 tailscaled；无 TUN
                                    权限时检测 userspace
                                    SOCKS/HTTP；服务端可启用 tsnet。

  keep_tailnet_direct   true        100.64.0.0/10、fd7a:115c:a1e0::/48 和
                                    Tailnet 子网默认直连，不参与代理选择。

  expose_as_node        false       为 true 时把 Tailscale userspace proxy
                                    暴露成一个可选择出口。

  userspace_proxy       自动探测    指定 tailscaled userspace SOCKS/HTTP
                                    代理地址。
  --------------------- ----------- -----------------------------------------

# 6. Smart 核心完整实现方案

## 6.1 用户侧配置必须简单

smart:

on: true

goal: balanced \# balanced/speed/stability/low_cost/privacy

learn: 14d

sticky: site \# off/site/session

explain: true

小白只需要知道：smart 会自动选择节点。专家需要知道：Smart
每次选择都可以解释，且所有评分因子都能在 API 中看到。

## 6.2 Smart 的输入数据

  -------------- --------------------------------------------------------- ------------------------------------------------
  **数据类型**   **采集字段**                                              **用途**

  连接上下文     域名、eTLD+1、SNI、目标 IP、目标端口、网络类型            判断这次连接属于哪个站点、哪个网络、哪个应用。
                 TCP/UDP、进程名、入口类型                                 

  目标网络       ASN、国家/地区、IP 前缀、是否 QUIC、是否流媒体            建立 domain/ASN/IP-prefix 的历史最优出口。

  节点状态       在线状态、延迟                                            过滤不可用节点并计算评分。
                 p50/p95、抖动、失败率、最近失败原因、并发连接、流量速率   

  历史结果       连接耗时、TLS                                             学习不同网站和节点组合的真实表现。
                 握手耗时、TTFB、连接时长、字节数、断开原因、重试次数      

  用户偏好       prefer、avoid、低倍率优先、地区偏好、手动 pin             让自动选择符合人的意图。
  -------------- --------------------------------------------------------- ------------------------------------------------

## 6.3 选择流程

1\. 候选收集：从 group.use 展开 feeds 和 nodes，去重，保留最新健康状态。

2\. 能力过滤：目标是 UDP 时剔除不支持 UDP 的节点；需要 IPv6 时剔除无
IPv6 出口的节点。

3\. 硬性策略过滤：执行用户
avoid、倍率/流量限制、地区限制、黑名单、维护状态。

4\. 读取缓存：优先查询 domain 级缓存，其次 ASN
缓存，再次地区缓存。缓存命中但节点近期失败时立即降级。

5\. 评分排序：对剩余节点计算 0\~100 分，分数最高者成为首选。

6\. 探测补偿：当前两名分数差小于 3
分时，使用最新探测结果和连接负载做二次判断。

7\.
失败重试：连接失败后记录原因，短期冷却该节点，并在同一候选集中选择下一名。

8\. 结果解释：把最终分数、扣分原因、命中的缓存和替代节点写入
/v1/smart/why。

## 6.4 明确评分公式

final_score =

0.32 \* latency_score +

0.26 \* success_score +

0.16 \* stability_score +

0.10 \* site_memory_score +

0.08 \* load_score +

0.05 \* preference_score +

0.03 \* cost_score -

cooldown_penalty -

capability_penalty

  -------------------- ------------------------------- ------------------------------
  **评分项**           **计算方式**                    **说明**

  latency_score        100 - clamp(p50_latency_ms / 6, 延迟越低分越高；使用
                       0, 100)                         p50，避免单次异常影响。

  success_score        100 \* EWMA(success_rate,       近期失败权重更高。
                       half_life=6h)                   

  stability_score      100 - clamp(jitter_ms / 3 +     抖动和超时共同扣分。
                       timeout_rate\*100, 0, 100)      

  site_memory_score    domain/ASN 历史命中率 \* 100    某网站历史表现好的节点优先。

  load_score           100 -                           避免所有连接挤到一个节点。
                       clamp(active_conn_ratio\*100,   
                       0, 80)                          

  preference_score     地区/名称偏好命中给             用户 prefer
                       60\~100，否则 50                不等于硬绑定，只是加分。

  cost_score           低倍率/低成本节点给更高分       低流量成本场景有用。

  cooldown_penalty     最近失败 30s 内 20\~80 分       防止失败节点立刻被再次选中。

  capability_penalty   能力不匹配直接剔除；弱匹配扣 30 例如 UDP over TCP
                       分                              只能作为弱匹配。
  -------------------- ------------------------------- ------------------------------

## 6.5 goal 对评分的影响

  ----------- ----------------------------- -----------------------------
  **goal**    **权重变化**                  **适用场景**

  speed       提高 latency_score 和         网页、游戏、短连接。
              load_score 权重               

  stability   提高 success_score 和         远程办公、SSH、视频会议。
              stability_score 权重          

  low_cost    提高                          流量有限的订阅。
              cost_score，限制高倍率节点    

  privacy     降低 site_memory              隐私敏感场景。
              暴露面，只保留本地匿名统计    

  balanced    使用默认权重                  大多数用户。
  ----------- ----------------------------- -----------------------------

## 6.6 缓存与学习

  ------------------ ---------------------- ---------- ------------------------------------------
  **缓存**           **Key**                **TTL**    **失效条件**

  domain_best        eTLD+1 + group +       10m        节点失败、规则变化、订阅刷新、手动切换。
                     network                           

  asn_best           ASN + group + network  30m        连续失败 2 次或探测分下降超过 20。

  region_best        国家/地区 + group      1h         地区偏好变化或节点池变化。

  negative           node + failure_type    30s\~5m    冷却到期或健康检查恢复。

  precomputed_topk   group + network + goal 5s         节点状态变化或负载突增。
  ------------------ ---------------------- ---------- ------------------------------------------

## 6.7 机器学习模型

  ----------- -------------------------------------- --------------------------------------
  **阶段**    **实现**                               **上线条件**

  MVP         启发式评分 + EWMA + domain/ASN 记忆    默认启用。

  增强        LightGBM/LambdaMART                    必须能输出特征贡献解释。
              排序模型，本地训练或离线内置基础模型   

  在线学习    按用户本地结果增量更新校准参数         必须可关闭，默认只保留本地匿名统计。

  异常检测    识别节点假延迟、间歇性丢包、DNS        影响评分但不能直接删除节点。
              污染、QUIC 被阻断                      
  ----------- -------------------------------------- --------------------------------------

## 6.8 Smart 更完整的扩展点

1\. 把 DNS 结果、目标
ASN、进程名、入口类型纳入选择；不是只按节点延迟选择。

2\. 同时优化 TCP 与 UDP；QUIC/Hysteria/TUIC 节点使用协议专属健康指标。

3\. 对每次选择提供 explain 输出，面板能显示"为什么选它"。

4\. 支持 Tailscale 保护：Tailnet 目标永远不被 Smart 误选到公网代理。

5\. 支持低倍率/流量成本目标，适合机场倍率不一致的场景。

6\. 支持站点粘性，避免同一网站频繁换出口导致登录状态异常。

## 6.9 Smart API

GET /v1/smart/why?host=youtube.com&group=main

POST /v1/smart/pin

POST /v1/smart/avoid

POST /v1/smart/reset

GET /v1/smart/cache

GET /v1/smart/nodes/main

  ------------------- ---------------------------------------------------
  **接口**            **返回/行为**

  /v1/smart/why       返回候选节点分数、命中缓存、扣分原因、最终节点。

  /v1/smart/pin       把某个域名或服务固定到指定节点/分组。

  /v1/smart/avoid     临时避开某个节点、地区或订阅源。

  /v1/smart/reset     清空学习数据或指定 group 的缓存。

  /v1/smart/cache     查看 domain_best、asn_best、negative 等缓存。
  ------------------- ---------------------------------------------------

# 7. DNS / Resolver 模块

## 7.1 Resolver 的职责边界

1\. 解析域名，但不决定最终出口；最终出口由 route + groups + smart 决定。

2\. 为代理节点本身解析地址时，必须绕开代理分流循环。

3\. 透明代理开启时，必须劫持或接管系统 DNS，避免域名泄漏。

4\. Fake 地址必须能反查到原始域名，并且在连接关闭后按 TTL 清理。

5\. 所有 DNS 查询都必须进入日志和指标系统，便于排错。

## 7.2 Resolver 流程

query(domain, qtype)

-\> hosts/system hosts 命中则返回

-\> route 预判该域名属于 direct/proxy/block

-\> direct 域名使用 mainland servers

-\> proxy 域名使用 overseas servers 或规则指定 servers

-\> capture 场景按 fake 策略返回 Fake 地址

-\> 写入 cache 和 domain map

-\> 把 DNS 结果喂给 Smart 作为目标特征

## 7.3 防泄漏规则

  ---------------------- ----------------------------------------------------
  **场景**               **必须行为**

  capture.on=true        默认 resolver: hijack，UDP/TCP 53 进入 resolver。

  route.preset=privacy   禁止使用系统 DNS
                         解析海外域名；失败时返回错误而不是回退明文 DNS。

  节点域名解析           使用 bootstrap servers 或用户指定
                         server，不走当前代理节点自身。

  Tailscale MagicDNS     Tailnet 域名直连到 Tailscale resolver，不走公网
                         DoH。

  Fake 地址              Fake 池不得覆盖局域网、Tailnet、保留地址。
  ---------------------- ----------------------------------------------------

# 8. TUN / TProxy / Mixed 入站设计

## 8.1 Mixed 入站

listen.local 是用户唯一需要记住的普通代理入口。它同时接收 HTTP(S) 与
SOCKS5。

  ----------------- -----------------------------------------------------
  **能力**          **行为**

  HTTP CONNECT      支持 HTTPS 代理，记录目标域名/地址。

  HTTP 普通代理     支持浏览器和包管理器。

  SOCKS5 TCP        支持用户名密码认证和 IPv4/IPv6。

  SOCKS5 UDP        默认按节点能力决定是否启用。

  认证              listen.auth 非空时开启；share=all 且无 secret/auth
                    时启动失败。
  ----------------- -----------------------------------------------------

## 8.2 TUN / virtual_nic

  ---------------- ------------------------------------------------------
  **设计点**       **明确实现**

  设备创建         Linux 使用 /dev/net/tun；Windows 使用 Wintun/系统 VPN
                   API；macOS 使用 utun；Android 使用 VpnService。

  协议栈           native 优先；gvisor 作为跨平台用户态栈；smoltcp
                   用于嵌入式。

  路由             auto 模式自动写路由；strict
                   模式阻止未接管流量造成泄漏。

  DNS              resolver: hijack 时拦截 53 端口和 Fake 地址流量。

  性能             批量读写、GSO、分片缓存、sharded NAT、per-core
                   runtime、零拷贝 Bytes。
  ---------------- ------------------------------------------------------

## 8.3 TProxy

  ---------------- ------------------------------------------------------
  **设计点**       **明确实现**

  平台             仅 Linux/Android/OpenWrt。其它平台 method=tproxy
                   启动失败并给出替代建议。

  协议             TCP 与 UDP 都支持；redirect 只作为 TCP-only 兼容模式。

  防火墙           nftables 优先，iptables fallback。自动创建独立
                   chain，退出时清理。

  原始目标地址     TCP 使用 getsockopt 获取；UDP 使用透明 socket +
                   conntrack 映射。

  路由标记         mark 值由内核统一分配，检测冲突，允许专家覆盖。

  OpenWrt          检查 kmod-nft-tproxy 或 iptables-mod-tproxy，不满足时
                   doctor 明确提示安装包。
  ---------------- ------------------------------------------------------

## 8.4 性能目标

  ------------------- ---------------------------------------------------
  **项目**            **目标**

  Mixed 入口          10k 并发空闲连接下 p99 调度延迟小于 2ms。

  路由决策            热缓存 p99 小于 50 微秒。

  Smart 决策          500 节点候选集下热缓存 p99 小于 200 微秒。

  TUN 转发            Linux native stack 下单流吞吐不低于同硬件直连的
                      90%。

  TProxy UDP          10k UDP 映射下清理周期不阻塞主转发线程。

  DNS                 缓存命中 p99 小于 100 微秒；DoH 查询走异步并发。
  ------------------- ---------------------------------------------------

# 9. Tailscale 集成

## 9.1 默认行为

1\. 默认识别 Tailscale IPv4 CGNAT 网段 100.64.0.0/10。

2\. 默认识别 Tailscale IPv6 ULA 前缀 fd7a:115c:a1e0::/48。

3\. 默认排除 tailscale0 接口和 tailscaled 进程，避免 capture 路由回环。

4\. Tailnet 目标默认 direct，不进入 Smart，不被 Fake 地址覆盖。

5\. 用户开启 expose_as_node 后，Tailscale userspace proxy
才会成为可选出口。

## 9.2 集成模式

  ----------- ----------------------- -------------------------------------
  **mode**    **触发条件**            **行为**

  localapi    本机安装 tailscaled 且  读取状态、接口名、MagicDNS、Tailnet
              LocalAPI 可用           地址，自动排除路由。

  userspace   无 TUN 权限或容器环境   把 tailscaled 的 SOCKS5/HTTP proxy
                                      接入为 mesh 出口或直连保护通道。

  tsnet       服务端/嵌入式场景       以内嵌库方式加入
                                      Tailnet，适合远程管理面板。

  auto        默认                    按 localapi -\> userspace -\> tsnet
                                      capability 顺序探测。

  off         用户明确关闭            不做 Tailnet 自动保护；doctor
                                      仍提示可能冲突。
  ----------- ----------------------- -------------------------------------

## 9.3 路由冲突处理

启动检查：

1\. 检测是否存在 tailscale0 或 tailscaled

2\. 检测 capture 是否会接管 100.64.0.0/10

3\. 检测 resolver 是否会污染 MagicDNS

4\. 检测 default route 是否覆盖 Tailnet 子网

5\. 自动写入 exclude 计划，或给出明确错误

# 10. Clash/Mihomo API 对齐与原生 API

## 10.1 设计原则

1\. 配置字段独立；API 兼容层可以对齐 Clash/Mihomo Dashboard 生态。

2\. 原生 API 使用 /v1，字段名与本生态一致。

3\. 兼容 API 保持 Dashboard 可用，但内部模型不被兼容层绑架。

4\. 所有写操作必须带 secret；监听外网时 secret 不能为空。

## 10.2 原生 API

  ------------------------ ----------------------------------------------
  **接口**                 **说明**

  GET /v1/status           版本、运行时间、profile、平台能力。

  GET /v1/traffic          实时上下行、连接数、DNS 查询数。

  GET /v1/nodes            展开后的节点列表和能力。

  GET /v1/groups           分组、当前选择、Smart 分数。

  PATCH /v1/groups/{name}  手动切换 manual 分组或 pin Smart。

  GET /v1/connections      连接列表、规则命中、出口节点。

  DELETE                   关闭连接。
  /v1/connections/{id}     

  GET /v1/resolver/query   调试 DNS 查询。

  GET /v1/route/check      输入域名/IP，返回命中步骤和出口。

  GET /v1/capture/state    TUN/TProxy/防火墙/路由状态。

  GET /v1/smart/why        解释 Smart 选择。
  ------------------------ ----------------------------------------------

## 10.3 兼容 API

开启 ui.api.clash_compat 后，提供常见 Clash/Mihomo Dashboard
所需接口，例如日志、流量、配置、节点、连接、DNS
查询等。兼容层负责字段转换，不要求用户 YAML 使用 Clash/Mihomo 字段。

  ------------------- ---------------------------------------------------
  **兼容接口类别**    **转换来源**

  日志/流量           runtime metrics 和 tracing。

  配置读取/局部更新   friendly YAML runtime
                      graph；禁止直接写入不兼容字段。

  代理/策略组         nodes + groups 的展开视图。

  连接管理            connection table。

  DNS 查询            resolver API。
  ------------------- ---------------------------------------------------

# 11. Rust 架构与性能优化

## 11.1 模块划分

  ------------------- -------------------------------------------------------
  **crate/module**    **职责**

  core-config         Friendly YAML 解析、默认值合并、schema 校验、迁移。

  core-runtime        运行时 graph、生命周期、热重载、任务编排。

  core-inbound        Mixed、HTTP、SOCKS、TUN、TProxy、redirect、listener。

  core-outbound       所有代理协议适配器和直连/拒绝出口。

  core-route          规则引擎、规则集、进程/端口/IP/域名匹配。

  core-resolver       DNS、Fake 地址、缓存、DoH/DoT/DoQ、MagicDNS。

  core-smart          Smart 评分、学习、缓存、模型、解释。

  core-api            原生 API、兼容 API、鉴权、Dashboard 静态资源。

  core-capture        TUN/TProxy/防火墙/路由表平台适配。

  core-mesh           Tailscale/WireGuard/局域网协同。

  core-observe        tracing、metrics、pprof、日志、事件总线。
  ------------------- -------------------------------------------------------

## 11.2 关键 trait

trait OutboundAdapter {

fn name(&self) -\> &str;

fn capabilities(&self) -\> Capabilities;

async fn dial_tcp(&self, ctx: DialContext) -\> Result\<TcpStream\>;

async fn dial_udp(&self, ctx: DialContext) -\> Result\<UdpSession\>;

}

trait Selector {

async fn choose(&self, ctx: FlowContext) -\> Result\<Arc\<dyn
OutboundAdapter\>\>;

fn explain(&self, ctx: FlowContext) -\> SelectionExplain;

}

trait RuleMatcher {

fn match_flow(&self, ctx: &FlowContext) -\> RouteDecision;

}

## 11.3 性能策略

1\. 所有连接路径使用 Bytes/BytesMut，避免重复分配和复制。

2\. 连接表、DNS map、Smart 指标采用分片结构，避免全局锁。

3\. 路由规则编译为 trie、CIDR radix tree、Aho-Corasick/RegexSet 和预排序
matcher。

4\. Smart 预计算 group top-k，连接到来时只做 O(log n) 或 O(1) 选择。

5\. TUN/TProxy 使用批量读写；Linux 可选 io_uring；不支持时回退 Tokio
net。

6\. 热重载使用新旧 graph 双缓冲，旧连接继续使用旧 graph，新连接切到新
graph。

7\. 日志使用异步 channel 和采样，禁止在转发热路径同步写磁盘。

## 11.4 "性能更好"的验收方法

文档不把"更快"写成口号，而写成可跑的
benchmark。每次发布必须附带同硬件、同配置、同节点、同网络条件的报告。

  ------------------- -------------------- ------------------------------
  **基准**            **工具**             **通过线**

  配置加载 5000 节点  criterion +          冷启动解析小于
                      本地订阅样本         150ms，热重载小于 80ms。

  Mixed TCP 并发      wrk/hey + CONNECT    10k 并发无连接泄漏，p99
                      target               调度延迟小于 2ms。

  DNS 缓存命中        criterion            p99 小于 100 微秒。

  路由匹配 100k 规则  criterion            热缓存 p99 小于 50 微秒。

  Smart 500 节点选择  criterion            热缓存 p99 小于 200 微秒。

  TUN 吞吐            iperf3 + netns       Linux native 单流不低于直连
                                           90%。
  ------------------- -------------------- ------------------------------

# 12. 多平台适配

  ------------- -------------- --------------------- -------------- ------------------- --------------------------------
  **平台**      **普通代理**   **TUN/virtual_nic**   **TProxy**     **DNS 劫持**        **备注**

  Windows       支持           Wintun/系统 VPN API   不支持         防火墙 + Fake 地址  需处理多宿主 DNS 泄漏。

  macOS         支持           utun/Network          不支持         pf + resolver       应用商店版本需沙箱适配。
                               Extension                                                

  Linux         支持           /dev/net/tun          支持           nftables/iptables   性能主战场，支持 GSO/io_uring。

  OpenWrt       支持           kmod-tun              支持           dnsmasq/nftables    doctor 检查内核模块。

  Android       支持           VpnService            部分内核支持   VpnService DNS      按应用接管需要系统 API。

  iOS           支持           Network Extension     不支持         NE DNS              后台限制和证书策略需单独设计。

  Docker/容器   支持           有权限才支持          有 NET_ADMIN   内置 resolver       无 TUN 时推荐 userspace 模式。
                                                     才支持                             
  ------------- -------------- --------------------- -------------- ------------------- --------------------------------

# 13. 配置编译器与迁移工具

## 13.1 编译器职责

1\. 把短写法变成长写法，例如 feeds.my_airport: URL 变成完整对象。

2\. 合并 profile 默认值，但保留用户原始文件不被污染。

3\. 把节点 URI 解析成结构化节点。

4\. 把 route.steps 编译成高性能 matcher。

5\. 检查 group 引用、节点能力、DNS 策略、capture 平台支持。

6\. 输出 runtime graph 和 explain plan。

## 13.2 错误信息必须人能看懂

错误：groups.main.use 引用了 \"airport2\"，但没有找到这个 feeds 或
nodes。

位置：config.yaml 第 12 行

原因：可用来源只有 my_airport、nodes。

修复：把 airport2 改成 my_airport，或新增 feeds.airport2。

错误：capture.method=tproxy 不能在 Windows 使用。

位置：config.yaml 第 24 行

修复：改成 method: auto 或 method: virtual_nic。

## 13.3 Mihomo 配置迁移

运行时不接受 Mihomo
字段作为本生态配置，但提供一次性迁移工具，把旧配置转换成 Friendly YAML。

wuther-core migrate mihomo old-config.yaml -o friendly.yaml

wuther-core check friendly.yaml

wuther-core explain friendly.yaml

  ----------------------- -----------------------------------------------
  **迁移内容**            **转换结果**

  普通端口/Mixed 端口     listen.local。

  订阅 Provider           feeds。

  手动代理                nodes。

  策略组                  groups，并转换 choose 值。

  规则                    route.steps 或 route.preset。

  DNS                     resolver。

  TUN/TProxy              capture。

  外部控制 API            ui。
  ----------------------- -----------------------------------------------

# 14. 测试、验收与开发路线

## 14.1 测试矩阵

  ----------------- -------------------------------------------------------------
  **测试类别**      **必须覆盖**

  配置测试          短写法、长写法、错误提示、迁移、默认值、热重载。

  协议测试          每个协议的 TCP/UDP、TLS、Reality/ECH、传输层、失败路径。

  规则测试          domain、suffix、CIDR、process、port、network、preset、steps
                    顺序。

  DNS 测试          DoH/DoT/DoQ、Fake 地址、缓存、节点域名解析、防泄漏。

  Smart 测试        冷启动、缓存命中、失败降级、站点粘性、解释输出、模型关闭。

  透明代理测试      TUN、TProxy、redirect、DNS hijack、IPv6、路由排除。

  Tailscale 测试    tailnet 直连、userspace proxy、MagicDNS、capture 排除。

  API 测试          原生 API、兼容 API、鉴权、Dashboard。

  性能测试          criterion、iperf3、wrk、pprof、内存泄漏。
  ----------------- -------------------------------------------------------------

## 14.2 开发路线

  ---------------- -------------------------------------------------------- ----------------------------
  **阶段**         **交付物**                                               **验收标准**

  M1               Friendly YAML、Mixed、HTTP、SOCKS、direct/block、基础    模板 A
  配置与普通代理   route                                                    可运行；错误提示合格。

  M2 协议完整化    SS/SSR/VMess/VLESS/Trojan/Hysteria2/TUIC/WireGuard/SSH   协议矩阵单元测试通过。
                   等                                                       

  M3 Resolver      DoH/DoT/DoQ、Fake 地址、防泄漏、缓存                     透明代理 DNS 不泄漏。

  M4 Capture       TUN/TProxy/redirect、平台适配、OpenWrt doctor            模板 C 可运行。

  M5 Smart         评分、学习、缓存、解释 API、Dashboard 展示               500 节点 p99 小于 200 微秒。

  M6 API 与生态    原生 API、Clash/Mihomo 兼容 API、迁移工具                主流 Dashboard
                                                                            可读取节点和连接。

  M7 Tailscale     LocalAPI、userspace、tsnet、路由保护                     Tailnet 目标不被代理和
                                                                            Fake。

  M8 性能冲刺      io_uring/GSO/批量 I/O/锁优化                             发布 benchmark 报告。
  ---------------- -------------------------------------------------------- ----------------------------

# 15. 附录：字段速查与参考资料

## 15.1 字段速查

  ------------ ----------------------------------- ------------------------------------------------------
  **模块**     **最常用字段**                      **专家字段**

  listen       local、panel、share                 auth、host、udp、tls

  feeds        url/every                           keep、drop、rename、via、health

  nodes        字符串 URI、name、link              protocol、address、login、secure、transport、network

  groups       choose、use、prefer                 avoid、check、sticky、path、max_fail

  route        preset、final、steps                sets、geo、process、script、strict

  resolver     mode、fake、servers                 policy、bootstrap、ecs、magic_dns、pool

  capture      on、method、traffic                 stack、mtu、offload、mark、exclude、include

  smart        on、goal、sticky                    weights、cache、model、probe、privacy

  ui           on、secret                          dashboard、api、cors、listen

  mesh         tailscale.on、keep_tailnet_direct   mode、userspace_proxy、tsnet、routes
  ------------ ----------------------------------- ------------------------------------------------------

## 15.2 参考资料

Mihomo 配置索引、入站、出站、DNS、规则、API
文档：[[https://wiki.metacubex.one/en/config/]{.underline}](https://wiki.metacubex.one/en/config/)

Mihomo Mixed / Transparent Proxy Port
文档：[[https://wiki.metacubex.one/en/config/inbound/port/]{.underline}](https://wiki.metacubex.one/en/config/inbound/port/)

Mihomo TUN
文档：[[https://wiki.metacubex.one/en/config/inbound/tun/]{.underline}](https://wiki.metacubex.one/en/config/inbound/tun/)

Mihomo DNS
文档：[[https://wiki.metacubex.one/en/config/dns/]{.underline}](https://wiki.metacubex.one/en/config/dns/)

Mihomo
代理协议通用字段与协议页面：[[https://wiki.metacubex.one/en/config/proxies/]{.underline}](https://wiki.metacubex.one/en/config/proxies/)

Mihomo API
文档：[[https://wiki.metacubex.one/en/api/]{.underline}](https://wiki.metacubex.one/en/api/)

Clash Party Smart Core
工作原理详解：[[https://clashparty.org/docs/guide/smart-core-principles]{.underline}](https://clashparty.org/docs/guide/smart-core-principles)

Tailscale userspace networking
官方文档：[[https://tailscale.com/docs/concepts/userspace-networking]{.underline}](https://tailscale.com/docs/concepts/userspace-networking)

Tailscale IP
地址与保留地址范围官方文档：[[https://tailscale.com/docs/concepts/ip-and-dns-addresses]{.underline}](https://tailscale.com/docs/concepts/ip-and-dns-addresses)

Tailscale 与其它 VPN 共存
FAQ：[[https://tailscale.com/docs/reference/faq/other-vpns]{.underline}](https://tailscale.com/docs/reference/faq/other-vpns)
