# Tasks

## 1. 拆除 v0.2 引流机制

- [x] 1.1 config：删 `clash_*` 与 `Target.ViaClash`，新增 4 个 tun 字段（默认 tun_guard_enabled=true、tun_iface="tun"、controller_addr="127.0.0.1:19090"、tun_fail_withdraw=true），Validate 适配；单测含"旧 JSON 多余字段容忍"
- [x] 1.2 fwd/RuleMgr：Sync 回退 (directIPs, masq) 两参；Cleanup 与链创建不再含 clash；**保留**对 GW_CLASH_* 与 fwmark 的幂等拆除；测试更新
- [x] 1.3 app/api/前端：删 splitPaths/via_clash 路径、ClashHealth 引用、设置页 Clash 分组、目标路径下拉；契约与 UI 资源构建通过

## 2. TunGuard

- [x] 2.1 fwd/tun.go：TunGuard（Runner+Dialer 注入，5s tick，3 败判障 / 2 成判恢复，双信号）；fake 单测覆盖抖动不误撤、判障/恢复回调
- [x] 2.2 app 编排：tunOK 并入引擎 GlobalOn；判障→RestoreAll+withdrawn；恢复→Apply；api overview 输出 tun 状态、config PUT 支持 tun 字段热生效；契约测试
- [x] 2.3 前端：设置页 TUN 守护分组、总览 TUN 行与失效横幅

## 3. fork 材料与文档

- [x] 3.1 tools/fork-clash-meta/：补丁脚本（privilege run-as→root；config.default.yaml 注入 tun 块 + strict-route 建议注释）与 README（clone/构建/安装/回滚步骤）
- [x] 3.2 README：GateWeaver "TUN 全局接管"章节（拓扑、Clash 侧要求、故障模型）

## 4. 验证与发布

- [x] 4.1 全量 vet/test/交叉编译/fnpack 出包通过
- [ ] 4.2 提交推送、tag v0.3.0、CI/Release 全绿含双架构 .fpk
