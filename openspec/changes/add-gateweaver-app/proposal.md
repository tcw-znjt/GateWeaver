# Proposal

## Why

家庭/实验室网络中，用户常希望让部分指定设备的上网流量经过 NAS（fnOS）做过滤、代理、加速或统计（即"旁路由"效果）。传统做法需要逐台登录目标设备手动修改默认网关，或依赖主路由的 DHCP 下发能力——繁琐、易漏，且很多 IoT 设备根本不给改网关的入口。

本项目构建一个可上架飞牛（fnOS）应用中心的软件 **GateWeaver**：对 LAN 内用户指定的目标设备，在不改动其任何配置的前提下，通过 ARP 欺骗使其默认网关"指向" fnOS 本机，并由 fnOS 将流量转发回真实路由器，实现旁路由效果；关闭或卸载后自动恢复原状。

## What Changes

- 新增 fnOS `.fpk` 应用包：`manifest` + `script/{config,install,start,stop,upgrade,uninstall}` 生命周期脚本，Native 应用形态（root、host 网络），满足 ARP 注入与转发的权限要求。
- 新增 **ARP 网关接管引擎**：仅针对白名单内的目标设备（IP/MAC）周期性注入伪造 ARP 应答（"网关 IP → fnOS 的 MAC"），持续维持接管状态，并能在撤销时通告正确的网关映射。
- 新增 **流量转发模块**：开启内核 IP 转发，将被接管设备的流量转发至真实上游网关；默认保留源 IP 直接路由，可选 MASQUERADE 模式兼容有反向路径过滤（uRPF/anti-spoofing）的主路由。
- 新增 **Web 管理台**（REST API + 内嵌前端）：局域网邻居发现（扫描可选目标）、目标列表增删、全局开关、上游网关探测/指定、运行状态与事件日志、一键恢复。
- 新增 **安全与自愈机制**：严格白名单目标（绝不无差别泛洪）、stop/uninstall/崩溃后的恢复（fnOS 宕机时目标设备 ARP 表项自然过期回退真网关）、防自伤（永不接管 fnOS 自身与上游网关路径）、首次使用的授权提示（仅可用于用户有权管理的网络设备）。

## Capabilities

### New Capabilities

- `fnos-app-package`: `.fpk` 打包结构、生命周期脚本行为、root/host-network 权限与安装前置检查（sysctl、iptables 可用性、冲突检测）。
- `arp-gateway-takeover`: ARP 网关欺骗引擎——目标选择与匹配、伪造应答的注入与维持、撤销恢复、fnOS 多网口/桥接场景下的接口选择。
- `traffic-forwarding`: 被接管流量的上游转发——直转与 MASQUERADE 两种模式、回环与自伤避免、转发状态监测。
- `management-console`: Web 管理台与其 REST API——配置 CRUD、设备发现、状态/日志查看、鉴权与访问边界（仅 LAN 可达）。
- `safety-and-recovery`: 安全边界与恢复语义——白名单强制、全局 kill switch、异常退出后的网络自愈、升级时的连续性。

### Modified Capabilities

（无——全新项目，`openspec/specs/` 目前为空。）

## Impact

- 全新代码仓库（当前仅有 `openspec/` 规划目录）：将新增 Go 后端（守护进程 + 内嵌 Web UI）、`.fpk` 打包工程与构建脚本。
- 对宿主系统的影响：修改 `net.ipv4.ip_forward`；调用 `iptables`/`nft` 维护转发规则；在目标网口上发送原始以太网帧（AF_PACKET）；卸载后需全部还原。
- 外部依赖：飞牛应用开放平台打包规范（`fnpack`，官方文档 developer.fnnas.com，社区镜像 ckcoding/fnnas-docs）；Go 生态的原始网络库（如 `golang.org/x/sys/unix` / `mdlayher/raw`）。
- 风险：ARP 接管本质是局域网层攻击手法，误用会中断他人网络——通过白名单、目标范围限制、快速恢复与首次使用授权声明来约束使用边界。
