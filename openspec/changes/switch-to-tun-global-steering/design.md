# Design

## Context

见 proposal.md。v0.2 代码中 `RuleMgr.Sync` 已是 (direct, clash) 双集合签名、config 含 `clash_*`/`via_clash` 字段、api/前端有 Clash 分组——本变更全部拆除并代之以 TunGuard。Clash 侧（root + TUN）由 `tools/fork-clash-meta/` 的 fork 材料负责，GateWeaver 不管理 Clash 进程。

## Goals / Non-Goals

**Goals:** 0.1.1 行为基线 + TUN 引导守护；v0.2 配置升级自动清洗；探测去抖动；撤销/恢复全自动。
**Non-Goals:** 不启动/监控 Clash 进程本身；不处理 mihomo 崩溃后 TUN 路由残留对 **NAS 本机** 的影响（属 fork 侧 strict-route 职责）；不做多 TUN 接口探测。

## Decisions

### D1: TunGuard 双信号探测，复用既有探测骨架
`fwd.TunGuard`：每 5s 执行 ① `ip route get <probeIP>`（默认 probeIP=223.5.5.5，Runner 注入）断言 `dev <TunIface>`；② Dialer TCP 拨 controller 地址。两信号**都真**记成功，任一失败计一次；连续 3 次失败判障、连续 2 次成功判恢复（不对称阈值：撤导谨慎、恢复更快）。备选：只看路由——否决：mihomo 半死（进程在但假死）时路由仍在；只看 controller——否决：auto-route 被外部改掉时误判健康。

### D2: 撤销语义 = 复用 RestoreAll + "withdrawn" 运行态
判障且 `TunFailWithdraw=true`：`Engine.RestoreAll("tun guard")`（发恢复通告、停注入循环），App 记 `tunWithdrawn=true`；引擎参数 `GlobalOn = 配置全局开 && upstreamOK && tunOK`，故撤销期间任何路径都不会再注入。恢复：`Apply(snapshot)` 重启各目标循环。TunGuard 关闭时 `tunOK` 恒真（回退 0.1.1）。

### D3: 配置升级清洗
`Config` 删除 `clash_*` 与 `Target.ViaClash`；`Load` 容忍旧 JSON 多余字段（encoding/json 默认忽略），不再持久化它们——满足"升级自动删除"。新增 `tun_guard_enabled/tun_iface/controller_addr/tun_fail_withdraw`。

### D4: RuleMgr 回退但兜底清理保留
`Sync(ctx, directIPs, masq)` 回 0.1.1 形态；`Cleanup` 与 fpk `cmd/main` **保留** 对 `GW_CLASH_*`/fwmark 的删除命令（幂等），用于 v0.2 用户升级 v0.3 后一次 stop/uninstall 即清干净旧残留。

### D5: 前端
设置页删除 Clash 分组 → 换成 "TUN 接管守护" 分组（开关/接口名/controller/撤销开关）；目标表删路径列；总览加 "TUN 接管" 行与失效横幅。

## Risks / Trade-offs

- [mihomo kill -9 残留 TUN 默认路由 → NAS 本机也黑洞] → GateWeaver 只能保护"被接管设备已撤销引导"；NAS 自身由 fork 配 `strict-route` + 应用重启自清，README/fork 文档明示。
- [probeIP 不可达但 TUN 正常（如断外网）] → 路由决策与真实连通无关，`ip route get` 仍返回 tun ✓，无误判。
- [controller 端口被 fork 改址] → 可配置；探测失败即判障，宁可撤销。

## Migration Plan

v0.2 → v0.3：升级安装后旧 `clash_*` 字段随首次保存消失；残留 `GW_CLASH_*` 链在下一次 stop/uninstall 或首次 `Rules.Sync` 全量对齐时拆除（Cleanup 兜底）。回滚：装回旧 fpk。

## Open Questions

- fork 内 TUN `stack` 选 system 还是 mixed（性能差异），由 fork README 以实测决定，不影响 GateWeaver。
