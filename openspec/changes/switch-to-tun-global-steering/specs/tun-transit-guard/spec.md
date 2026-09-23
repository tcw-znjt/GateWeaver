# Spec Delta

## Purpose

定义 TUN 全局接管模式下 GateWeaver 的引导守护行为：以"默认路由经 TUN 接口 + Clash 控制面可达"为健康判据，失效时撤销全部 ARP 引导使设备直连真网关，恢复后按持久化配置自动重新引导，全程可观测。

## ADDED Requirements

### Requirement: TUN 接管健康判定

系统 SHALL 周期性联合探测两项条件并以此判定"引导安全"：① 主路由表默认路由出口为配置的 TUN 接口（探测命令对公网地址做路由决策）；② mihomo controller 地址 TCP 可达。两项在连续失败达到阈值（默认 3 次 × 5s）前 SHALL 维持现状，避免瞬时抖动误撤。

#### Scenario: 双条件齐备视为健康
- **WHEN** 默认路由经 tun 接口且 controller TCP 连接成功
- **THEN** 系统判定健康，被接管设备流量继续经 NAS→TUN 进入 Clash

#### Scenario: 任一条件连续失效判障
- **WHEN** Clash 进程停止（controller 不可连）持续达阈值
- **THEN** 系统判定 TUN 接管失效

### Requirement: 失效撤销引导（fail-open）

判定 TUN 接管失效且降级开关（默认开）启用时，系统 SHALL 立即向全部在管目标发送恢复通告撤销引导，使其直连真实网关（断墙但不断网）；期间 MUST NOT 对任何目标注入；配置与目标列表 SHALL 完整保留。

#### Scenario: Clash 挂掉设备自动回正
- **WHEN** 被接管设备运行期间 Clash 停止
- **THEN** 各目标在阈值时间内收到恢复通告并回正到真实网关，可正常直连上网

### Requirement: 恢复自动重引导

TUN 接管恢复健康后，系统 SHALL 按持久化配置自动重新引导所有处于启用状态的目标，无需人工操作；撤销与恢复事件 SHALL 记入日志并在状态中呈现。

#### Scenario: Clash 重启后恢复接管
- **WHEN** Clash 重新启动且 TUN 路由就绪、controller 可达
- **THEN** 系统自动重新注入，各目标状态回到注入中/已生效

### Requirement: TUN 守护可配置且默认语义清晰

设置 SHALL 提供：TunGuard 总开关（默认开）、TUN 接口名（默认 `tun`）、controller 地址（默认 `127.0.0.1:19090`）、失效撤销开关（默认开）。TunGuard 关闭时系统行为回退为纯 0.1.1 模型（只做 ARP 接管 + 内核直连转发，不因 TUN 状态改变引导）。

#### Scenario: 关闭守护回退纯转发
- **WHEN** TunGuard 开关关闭
- **THEN** 系统不再探测 TUN/controller，被接管流量按内核路由表原样转发（此时用户自行保证出口行为）

#### Scenario: 热改接口名即时生效
- **WHEN** 用户把 TUN 接口名从 tun 改为 utun 并保存
- **THEN** 探测按新接口名执行，无需重启服务

### Requirement: TUN 接管状态可观测

总览 SHALL 展示 TUN 接管状态：未启用 / 正常（含接口与 controller 地址）/ 失效（已撤销引导），状态变化 SHALL 产生事件日志记录。

#### Scenario: 撤销状态可见
- **WHEN** TunGuard 因判障撤销了全部引导
- **THEN** 总览显示"失效（已撤销引导）"，事件日志含撤销时间与原因
