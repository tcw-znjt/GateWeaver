# Proposal

## Why

v0.1 已实现"设备网关引导至 NAS 并直连主路由"，但对"翻墙"场景而言直连转发只是把流量送到原出口。
Clash 作为**独立应用**运行在 fnOS 上（本变更不捆绑、不管理 Clash 本身），GateWeaver 需要把被接管
设备的流量**按设备逐个**改道进 Clash（TCP REDIRECT + DNS 劫持，UDP 可选 TPROXY），未选择走 Clash
的设备维持原直连转发路径。

## What Changes

- 新增 **Clash 引流能力**：对 `via_clash` 的目标设备，在 `PREROUTING` 按源 IP 下发 TCP REDIRECT
  与 DNS(53) 劫持规则（目标端口取自配置），可选 UDP TPROXY（含 fwmark 策略路由）；私网目的地址
  （RFC1918）在改道链内放行回直连，避免误伤访问 NAS/内网服务。
- 目标模型新增 `via_clash` 字段：**每台设备独立选择**路径（走 Clash / 原方案直连）；全局新增 Clash
  开关、地址与端口配置。
- 新增 **Clash 健康探测与降级**：周期性探测 Clash 端口可达性；不可达时自动把"应走 Clash"的设备
  临时降级为直连转发路径（不断网），恢复后自动重新引流；行为可配置。
- 管理台：设置页新增 Clash 配置；目标行新增路径选择控件；总览展示 Clash 状态（正常/降级/关闭）。

## Capabilities

### New Capabilities

- `clash-traffic-steering`: 按设备把接管流量改道至本机/本 NAS 网络内的独立 Clash 服务，含私网绕行、
  DNS 劫持、可选 UDP TPROXY、Clash 故障时逐设备降级直连。

### Modified Capabilities

- `management-console`: 新增 Clash 全局配置项、目标级路径选择与 Clash 状态展示（以 ADDED 需求追加，
  不改变既有需求）。

## Impact

- 代码：`internal/config`（新字段）、`internal/fwd`（规则链扩展 + Clash 健康探测）、`internal/app`
  （路径划分与降级编排）、`internal/api` + 内嵌前端（配置与展示）、`fpk/cmd/main` 兜底清理新增链。
- 网络：新增 `GW_CLASH_TCP`/`GW_CLASH_DNS`（nat）与可选 `GW_CLASH_UDP`（mangle）链及 fwmark 策略
  路由；卸载/停止全部拆除。
- 依赖边界：Clash 由用户自行安装并保持 `allow-lan` + redir/dns/tproxy 端口开启；GateWeaver 不启动、
  不下载、不改配 Clash。
