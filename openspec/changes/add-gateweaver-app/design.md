# Design

## Context

见 `proposal.md - Why`。当前仓库为全新项目（仅 `openspec/` 规划目录，无代码）。外部约束：

- 飞牛 fnOS 基于 Debian，应用以 `.fpk` 分发：`manifest`（应用元数据）+ `script/{config,install,start,stop,upgrade,uninstall,status}` 生命周期脚本 + `app/`（程序与 UI 资源，UI 必须位于 `app/ui` 下）。官方打包 CLI 为 `fnpack`（`fnpack create` 生成骨架），官方文档 developer.fnnas.com，社区镜像 [ckcoding/fnnas-docs](https://github.com/ckcoding/fnnas-docs)。
- fnOS 支持两类应用：Docker 应用与 Native 应用（root 运行、可 host 网络，参考社区先例 [MiBeeNvr#201](https://github.com/Mi-Bee-Studio/MiBeeNvr/issues/201)）。
- 官方应用中心暂无自助上架通道：分发以"手动安装 `.fpk`"为主，上架需走官方社群审核。
- 目标架构：x86_64 NAS 为主（arm64 视 fnpack 支持情况）。

ARP 接管在纯二层广播域内生效；WiFi 客户机通常可行（AP 桥接），但受 client isolation、静态 ARP、网关侧 ARP 防护影响——对应 spec 中"未见接管流量"状态与 fail-open 设计。

## Goals / Non-Goals

**Goals:**
- 单机 Go 二进制守护进程（注入引擎 + 转发管理 + REST API + 内嵌 Web UI），以 Native `.fpk` 交付。
- 接管→转发→恢复全生命周期闭环，任何退出路径（stop/崩溃/宕机/上游故障）都不遗留网络损伤。
- 可在真实 LAN 上逐目标灰度：任一时刻只有被明确点名的设备受影响。

**Non-Goals:**
- 不做透明网关全家桶：DNS 劫持、TLS 中间人、内容过滤、代理/分流规则引擎均不在本期（接管到 fnOS 后用户可自行在 fnOS 上叠加 Docker 服务处理流量——这正是本应用的用途场景）。
- 不做 DHCP 模式（接管后抢发 DHCP 以选项 3 改网关）留作后续能力；不做跨网段/多层交换环境的接管。
- 不做面向互联网多租户的账号体系；管理台是单管理员 LAN 工具。
- 不追求对抗强防护环境（802.1X、DAI/Snore 级防护），只如实报告接管未生效。

## Decisions

### D1: Native fpk + root 直跑，而非 Docker 应用
ARP 注入需要 `AF_PACKET` 原始套接字、混杂邻居观测与 `iptables/nft` 规则操作、`sysctl` 修改。Native 应用以 root 在 host 网络直接具备全部能力；Docker 方案需要 `--network host --privileged`，在 fnOS Docker 里配置更重且生命周期脚本仍绕不开。fpk 生命周期脚本是系统级改动（ip_forward、规则）的天然归属点。备选（Docker 应用 + compose 模板）被否：权限等价但打包/升级语义更弱，且 stop 钩子不如 fpk 脚本可控。

### D2: Go 单二进制，手工构造 ARP 帧
守护进程用 Go 实现：CGO_ENABLED=0 静态编译进 fnOS（无运行时时依赖），goroutine 模型天然匹配"每目标一个注入循环 + 一个嗅探响应循环"。ARP 帧（以太网头 + ARP，opcode 2 伪造 reply / 嗅探 who-has）用 `golang.org/x/sys/unix` 的 `AF_PACKET` 手工编解码（帧结构固定，<100 行），不引入 libpcap/gopacket 重依赖。备选：Python+scapy（部署依赖多、常驻进程资源占用高）、C（开发效率）。转发与恢复通告复用同一帧编码器。

### D3: 注入策略 = 周期重申 + 被动应答双轨，按目标节流
仅靠周期广播式重申会在目标 ARP 老化窗口内漏过流量；仅靠被动应答会被"目标缓存未失效期间无查询"饿死。双轨：(a) 每目标独立 ticker，默认 20s 单播伪造 reply（spa=网关 IP，sha=本机 MAC，tpa/target=目标 MAC/IP，从绑定接口发出）；(b) 一个 `recvfrom` 嗅探循环捕获白名单目标发出的 `who-has <gwIP>`，即时应答。每目标令牌桶限速（默认 ≤2 帧/秒），满足 spec 的速率底线。恢复 = 向目标单播一条 `spa=网关 IP，sha=真实网关 MAC` 的 reply，双发（立即 + 1s 后）。

### D4: 真实网关 MAC 的发现与维护
引擎启动时对本机默认路由的 gw IP 做一次正常 ARP 解析并缓存；此后随上游健康探测（见 D6）顺带校验，MAC 变化即更新并记录事件。恢复通告与"网关自身流量排除"都依赖该映射。用户也可在管理台手动固定网关 MAC（应对静默网关）。

### D5: 转发：默认直连路由 + 按需 nft/iptables 伪装表
直连模式只需 `ip_forward=1` 与 FORWARD 放行：目标包（dst=外网，via fnOS）按默认路由出，回程由真实网关直接 LAN 交付目标 IP——天然非对称但可达。uRPF 环境改伪装模式：仅对被接管目标 IP 集合 `POSTROUTING ... MASQUERADE`。实现上以专用 nftables 表/链（或 iptables + comment 标记 `gateweaver`）承载，集合由引擎动态增删，保证"只影响目标"。fnOS 的 LAN 接口 `rp_filter` 在接管期设为 2（loose），退出恢复——否则伪装模式回程与直连模式部分路径会被内核丢弃。备选（tc/eBPF 转发）被否：过度设计。

### D6: 上游健康探测与 fail-open
探测循环：每 5s 向网关 IP 发一次可达确认（ARP ping + 可选 connect 上游常用端口），连续 3 次失败判定故障 → 全局放开（撤销全部注入、禁用规则、状态置 fault）→ 恢复探测成功后按原配置自动重新接管。该循环同时承担 D4 的网关 MAC 复核。

### D7: 状态与配置：JSON 文件 + 原子写，不引数据库
配置规模是"几十个目标 + 十几个全局参数"，`<数据目录>/config.json`（`os.Rename` 原子替换 + fsync）足够；事件/审计日志为追加式 JSONL（滚动 5MB）。运行态（每目标状态、计数）仅驻内存，经 API 暴露。备选 SQLite 被否：多一层依赖与锁复杂度，收益为零。

### D8: 管理台：单二进制内嵌 embed.FS 静态前端 + REST API
前端为零构建链的静态单页（原生 JS 或 Preact 内联，中文界面），Go `embed` 打进二进制——fnOS 设备侧无 Node 依赖。API：`/api/*` REST + Bearer 会话 token；登录口令 scrypt 哈希存 config。监听默认 `127.0.0.1` + 显式 LAN 接口地址绑定（spec 的访问边界），端口默认 9666（避开 fnOS 自身 5666）。

### D9: 生命周期脚本职责切分
`install`：检查 root/`ip`/`iptables(nft)` 存在性，建数据目录，**不改系统状态**；`start`：启动守护进程（引擎默认关闭，等待全局开关）；`stop`：调 daemon `/api/recover` 同步恢复→退出→由脚本兜底清理规则与 ip_forward；`uninstall`：删除本应用标记的全部规则、恢复 sysctl、删数据目录（按 fnOS 规范询问保留）。`status` 脚本读取 pid 文件与 health 端点。sysctl 原值在首次改动前写入数据目录留底。

## Risks / Trade-offs

- [误伤自家网络：ARP 接管本质攻击手法，配置错误可致用户全网瘫痪] → 白名单硬约束（引擎级，非仅 UI 级）、上游 fail-open 默认开、任一退出路径同步恢复、"未见接管流量"状态如实呈现；README 与 UI 首屏声明仅用于自有设备。
- [主路由对 fnOS 的伪造 reply 也学习，导致网关侧 ARP 被污染、全网出走] → 注入帧目的 MAC 只填目标单播 MAC（不做广播 reply），从机制上避免波及路由器；嗅探循环仅应答白名单目标的查询。
- [WiFi client isolation / 静态 ARP 设备接管失败] → spec 层已要求状态可观测 + 不重试干扰；文档明示限制。
- [ip_forward 是全局共享开关，卸载时直接归零可能踩别的 Docker 容器] → 只在本应用开启时恢复，且恢复前检测是否有其他使用者（存在监听端口/活跃连接启发式，存疑则保持原值并日志提示）。
- [fnpack/manifest 细节与官方文档偏差] → 实现首日对照 developer.fnnas.com 文档与 conversun/fnos-apps 现成包修正骨架（tasks 第 0 组）。
- [与 fnOS 系统自带 ARP/网络管理服务冲突（如网络唤醒、网卡 bonding）] → 事件日志 + 接口选择交用户显式确认。
- [法律/平台合规：应用商店可能拒绝上架攻击性网络工具] → 功能定位表述为"自有设备旁路由/家长控制/流量分析"；预置上架被拒预案：手动安装分发渠道。

## Migration Plan

1. 开发验证：`fnpack create` 骨架 → 本地 Go 构建 → `fnpack build` 产出 `.fpk` → 测试机 fnOS"手动安装"。
2. LAN 灰度：先接管一台测试机（手机）验证 注入→外网连通→恢复 闭环，再扩量；每一步以管理台状态 + `tcpdump arp` 双重确认。
3. 回滚策略：应用中心"停止"即全网恢复（fail-open）；彻底回滚 = 卸载 fpk，脚本清理 sysctl/规则；配置在数据目录，重装即恢复。

## Open Questions

- manifest 中 root/网络权限字段的精确写法、`upgrade` 钩子是否保证带网络执行——实现首日读官方文档即定，不影响本设计结构与 spec 行为。
- 官方上架通道审核尺度未知：以手动安装为目标交付，上架作为后续尝试。
