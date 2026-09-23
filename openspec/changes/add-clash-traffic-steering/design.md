# Design

## Context

见 proposal.md。既有结构：`fwd.RuleMgr` 维护 `GW_FORWARD`/`GW_POSTROUTING` 两链并按目标集合 diff 同步；
`app.App.Apply` 把配置投影为引擎目标 + 转发规则；`fwd.Health` 已是"探测→回调"模式（上游网关用）。
Clash 为外部独立应用，本设计只加"改道规则 + 探测降级"，不碰 Clash 生命周期。

## Goals / Non-Goals

**Goals:** 目标级路径切换、RFC1918 绕行、Clash 故障逐设备降级直连、全部改动可被 stop/uninstall 拆除。
**Non-Goals:** 不捆绑/启动/改配 Clash；不做 eBPF/XDP 改道；v1 UDP 默认关闭；不处理 ICMP 改道。

## Decisions

### D1: 链结构——nat 两链 + 可选 mangle 一链
- `nat:PREROUTING → GW_CLASH_DNS`：每 clash ip 两条（udp/tcp 53 → REDIRECT dns-port）。先于 TCP 链挂载，保证访问私网 DNS 也被劫持。
- `nat:PREROUTING → GW_CLASH_TCP`：先 3 条 RFC1918 `-d <net> -j RETURN` 绕行，再每 clash ip `-s ip -p tcp -j REDIRECT --to-port <tcp>`。
- `mangle:PREROUTING → GW_CLASH_UDP`（仅 UDPPort>0）：每 ip `-s ip -p udp -j TPROXY --on-ip <addr> --on-port <udp> --tproxy-mark 0x1/0x1`，配 `ip rule fwmark 1 table 100` + `ip route local default dev lo table 100`（幂等检查后添加，拆除时按"是否本应用添加"记录）。
- REDIRECT vs DNAT：addr 为空或本机地址 → REDIRECT；否则 `DNAT --to-destination <addr>:port`（Docker bridge 部署 Clash 场景）。

### D2: RuleMgr 扩展为"集合三元组"同步
`SyncFull(ctx, directIPs, clashIPs []string, masq bool, clash ClashParams)`。内部三张记账表（direct/masq/clash 各自的已下发项），diff 增删；既有 `Sync` 语义并入，`present` 单表变多表。卸载 `Cleanup` 扩为 5 链 + 钩子 + 条件删 ip rule/route。

### D3: Clash 健康探测复用 Health 模式
`fwd.ClashHealth`：对 `addr:tcpPort` 与 `addr:dnsPort` 做 TCP 拨通（Dialer 接口注入便于单测），5s×3 失败判障 → app 回调把 via-clash 集合并入 direct 集合（即"降级=用直连规则替换改道规则"，单一真源仍是目标配置）；恢复后回切。降级期间 Clash 目标仍需 `GW_FORWARD` ACCEPT（它们的包走内核转发），实现上 direct 集合 = 非 Clash 目标 ∪（降级时的 Clash 目标）。

### D4: 配置模型
`Config`: `ClashEnabled bool`、`ClashAddr string`（空=本机）、`ClashTCPPort/ClashDNSPort/ClashUDPPort int`、`ClashFailDirect bool`(默认 true)；`Target.ViaClash bool`。默认端口 7893/7874/0（Clash 官方 redir/dns 常用值，文档说明需用户在 Clash 侧开对应端口）。

### D5: 管理台
设置页新增 Clash 分组；目标行内路径下拉；总览加"Clash"行与降级横幅。前端沿用零依赖单页。

## Risks / Trade-offs

- [DNAT 到 Docker bridge 时回程需 masq] → Clash 容器通常自带 MASQUERADE；文档提示选 `经 Clash` + 地址为容器 IP 时确认 Docker 网络正常出网。
- [TPROXY 策略路由与主路由/其他程序冲突] → UDP 默认关闭；仅添加 fwmark 专属 rule/table，不碰 main 表。
- [fake-ip 模式下设备缓存旧公网解析] → 文档提示切换后在设备上重连 Wi-Fi 或等 DNS 过期；Clash 侧 TTL 控制。
- [探测端口可达但 Clash 半挂起] → 已知限制（TCP 层探测的固有边界），日志与状态如实呈现，用户可手动"全部恢复"。

## Migration Plan

纯增量：升级后 `via_clash` 默认 false，行为与 v0.1 完全一致；用户在设置中开启并逐设备选择。回滚 = 装旧版 .fpk（规则由 stop/uninstall 拆除）。

## Open Questions

- 无（Clash 侧要求已写入 README 部署说明）。
