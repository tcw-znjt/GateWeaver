# Proposal

## Why

v0.2 的"逐设备 REDIRECT 改道"依赖 Clash 暴露 redir/dns 端口，实际环境里被两件事卡死：qiyueqixi/clash-meta FPK 以非 root 运行（TPROXY 不可用、面板保存会冲掉手工 `redir-port`），且改道语义始终不如"流量进 NAS 后和本地流量走同一条路"直接。用户旧环境（OpenWrt + Clash TUN 全局接管 + ARP 欺骗）验证过后一种模型更好用。

本变更将 GateWeaver 回退到 0.1.1 的简单模型（ARP 接管 + 内核转发），转送流量能否到达 Clash 完全交给 **mihomo TUN 全局接管**（fork 后的 root 版 clash-meta 负责）；GateWeaver 新增 **TUN 引导守护（TunGuard）**：TUN 路由或 Clash 控制面失效时自动撤销全部 ARP 引导（设备直连真网关，宁断墙不断网），恢复后自动重新引导。**取代未归档的 `add-clash-traffic-steering` 变更**（其逐设备 `via_clash`、redir/DNS/TPROXY 规则全部移除）。

## What Changes

- **移除** v0.2 的 Clash 引流机制：`Target.via_clash`、`clash_*` 端口配置、`GW_CLASH_TCP/GW_CLASH_DNS/GW_CLASH_UDP` 链与 TPROXY 策略路由、ClashHealth 端口探测、前端 Clash 设置分组与路径下拉。（BREAKING：v0.2 → v0.3 配置升级时自动忽略并删除这些字段）
- **新增 TunGuard**：周期探测 ① 默认路由是否经由配置的 TUN 接口（`ip route get`）② mihomo controller 是否 TCP 可达；连续失败达阈值 → 撤销全部引导；恢复 → 按持久化配置自动重新引导；开关与降级行为可配置。
- **管理台**：总览展示"TUN 接管"状态（正常/失效已撤销/未启用）与事件日志；设置页提供 TunGuard 开关、TUN 接口名、controller 地址。
- **仓库新增 fork 材料**：`tools/fork-clash-meta/` 提供补丁脚本与构建说明，把 qiyueqixi/clash-meta 重打包为 root + TUN 版（本仓库不构建它）。

## Capabilities

### New Capabilities

- `tun-transit-guard`: TUN 全局接管模式下的引导守护——探测 TUN 路由与 Clash 控制面，失效时撤销 ARP 引导、恢复时重引导，并对外可观测。

### Modified Capabilities

（无——`clash-traffic-steering` 仅存在于未归档的 v0.2 变更中，未进入主 spec；其能力整体作废，由本变更的 proposal 声明取代。）

## Impact

- 代码：`internal/config`（删 clash 字段、加 tun 字段）、`internal/fwd`（RuleMgr 回退为直连/伪装两链；删 ClashParams；新增 tun.go TunGuard）、`internal/app`（编排）、`internal/api` + 内嵌前端；fpk `cmd/main` 兜底清理保留对 v0.2 残留链的删除（升级兼容）。
- 运行时：被接管流量全部经 TUN 进 Clash（含 NAS 自身流量，与旧 OpenWrt 模型一致）；Clash 非 root 版不再满足要求，需 fork root 版。
- 风险：mihomo 被 kill -9 后 auto-route 残留会导致全网黑洞——TunGuard 的"撤销引导"只保护被接管设备，NAS 自身流量需 fork 里 `strict-route`/开机自愈兜底（写入 fork README）。
