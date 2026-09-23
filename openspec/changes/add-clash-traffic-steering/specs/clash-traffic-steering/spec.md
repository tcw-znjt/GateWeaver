# Spec Delta

## Purpose

定义按设备的 Clash 流量改道行为：仅对选择"走 Clash"的被接管设备下发 REDIRECT/DNS 劫持（可选 UDP
TPROXY），私网目的绕行，Clash 故障时逐设备降级为直连转发，且不影响选择"原方案"的设备。

## ADDED Requirements

### Requirement: 目标级路径选择

每个被接管目标 SHALL 具有互斥的转送路径：`直连转发`（既有行为：内核转发至上游网关）或 `经 Clash 引流`。路径 SHALL 由用户逐设备设置并可热切换；切换时 MUST 只对目标设备生效，其他设备与路径不受影响。

#### Scenario: 同网段混合路径
- **WHEN** 设备 A 设为"经 Clash"、设备 B 设为"直连转发"，两者均被接管
- **THEN** 系统仅对 A 的 TCP/DNS 流量下发改道规则；B 的流量仍按原方案直接转发至真实网关

#### Scenario: 路径切换即时改规则
- **WHEN** 用户把设备 A 从"直连"改为"经 Clash"
- **THEN** A 的直连放行规则与改道规则的归属 SHALL 在不重启服务的前提下完成迁移，A 的后续新建连接经 Clash

### Requirement: 改道范围仅覆盖声明的目标设备

Clash 改道规则（REDIRECT/TPROXY/DNS 劫持）SHALL 以源 IP 精确限定于"经 Clash"集合；未接管设备与未选择 Clash 的接管设备 MUST NOT 命中任何改道规则。

#### Scenario: 非目标流量零命中
- **WHEN** 改道规则存在且网段内非目标设备发起 TCP 连接
- **THEN** 该连接不被改道，正常直连转发

### Requirement: 私网与本机服务绕行

"经 Clash"设备发往 RFC1918 私网目的（10/8、172.16/12、192.168/16）的 TCP 流量 SHALL 绕过改道按直连送达，保证访问 NAS/打印机/内网服务不经 Clash；发往公网 DNS 服务器 IP 的 53 端口流量 SHALL 被劫持至配置的 Clash DNS 端口。

#### Scenario: 访问 NAS 不被改道
- **WHEN** 经 Clash 的设备访问 `http://192.168.1.10:5666`（fnOS 管理页）
- **THEN** 请求直达 fnOS，不经过 Clash 链路

#### Scenario: 公网 DNS 被劫持
- **WHEN** 经 Clash 的设备向任意公网地址查询 DNS（UDP/53）
- **THEN** 查询被送达 Clash 的 DNS 端口

### Requirement: Clash 故障逐设备降级直连（fail-open）

系统 SHALL 周期探测 Clash 服务端口可达性。探测失败达到阈值时，"经 Clash"的目标 SHALL 自动切换到直连转发路径（网络可用、仅失去 Clash 分流），Clash 恢复后 SHALL 自动重新引流；探测与降级/恢复事件 SHALL 记入日志并在状态中可见。降级行为 SHALL 可全局关闭。

#### Scenario: Clash 停止期间不断网
- **WHEN** 一台"经 Clash"的设备工作期间 Clash 进程被停止
- **THEN** 该设备在探测阈值内转为直连路径、可继续经真实网关上网，状态显示"Clash 不可达-已降级"

#### Scenario: Clash 恢复自动重引流
- **WHEN** Clash 重新启动且端口探测连续成功
- **THEN** 该设备自动恢复改道规则，无需人工操作

### Requirement: UDP 处理策略可配置

UDP 改道（TPROXY + fwmark 策略路由）SHALL 为可选配置（默认关闭）：关闭时仅 TCP+DNS 经 Clash、UDP 按直连转发；开启时系统 SHALL 维护对应的 mangle 规则与策略路由，停止/卸载/降级时 SHALL 全部拆除。

#### Scenario: 默认部署仅 TCP+DNS 经 Clash
- **WHEN** 未配置 UDP 端口
- **THEN** 不创建任何 mangle/TPROXY 规则，UDP 流量按原直连路径转发

### Requirement: 停止与卸载的改道清理

应用停止、全局恢复或卸载时，系统 SHALL 移除全部 Clash 改道规则、相关链与策略路由；Clash 自身的监听与路由状态 MUST NOT 被本应用改动。

#### Scenario: 一键恢复不留改道规则
- **WHEN** 用户点击"全部恢复"
- **THEN** 所有 REDIRECT/DNS/TPROXY 规则被删除，"经 Clash"设备与其余设备行为一致（回直连）
