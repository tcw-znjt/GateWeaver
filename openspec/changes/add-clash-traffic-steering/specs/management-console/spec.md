# Spec Delta

## Purpose

管理台能力在 v0.1 基础上新增 Clash 相关配置与展示需求（仅 ADDED，不修改既有需求）。

## ADDED Requirements

### Requirement: Clash 配置管理

管理台 SHALL 提供 Clash 集成配置的查看与修改并热生效：全局开关、Clash 地址（本机重定向或指定 IP:端口的 DNAT 形态）、TCP 重定向端口、DNS 端口、UDP TPROXY 端口（0=关闭）、故障降级直连开关。非法端口/地址 SHALL 被拒绝且不改变现有配置。

#### Scenario: 配置端口后即时生效
- **WHEN** 用户把 Clash TCP 端口从 7893 改为 7895 并保存
- **THEN** 已选择"经 Clash"的目标其改道规则立即指向 7895，无需重启

### Requirement: 目标路径选择控件

目标列表 SHALL 为每台设备展示并可切换其转送路径（经 Clash / 直连转发）；添加目标时 SHALL 可指定初始路径。

#### Scenario: 列表内直接切换
- **WHEN** 用户在目标行把路径从"直连"切到"Clash"
- **THEN** 配置持久化、规则即时迁移，行内显示当前路径

### Requirement: Clash 运行状态展示

总览 SHALL 展示 Clash 集成状态：关闭 / 正常（含探测目标地址）/ 不可达（已按策略降级直连）；状态变化 SHALL 产生对应事件日志。

#### Scenario: 降级可见
- **WHEN** Clash 端口探测失败触发降级
- **THEN** 总览显示"Clash 不可达-已降级"，事件日志含降级记录
