# Tasks

## 1. 配置与规则层

- [x] 1.1 config 新增 Clash 字段与 `Target.ViaClash`，Validate 覆盖端口/地址，单测通过
- [x] 1.2 fwd.RuleMgr 扩展 `SyncFull(directIPs, clashIPs, masq, ClashParams)`：DNS/TCP 链 + RFC1918 绕行 + REDIRECT/DNAT 两形态 + 可选 mangle TPROXY 与策略路由；Cleanup 全拆；fake-runner 单测断言命令序列
- [x] 1.3 fwd.ClashHealth TCP 探测（注入 Dialer），阈值判障/恢复回调，单测覆盖降级与回切

## 2. 编排与 API

- [x] 2.1 app.Apply 路径划分：非 Clash 目标 ∪ 降级态 Clash 目标 → direct 集合；Clash 探测回调触发 Apply 重算；单测/契约测试覆盖"降级并集"
- [x] 2.2 api：PUT /api/config 扩展 Clash 字段、目标 POST/PUT 支持 via_clash、overview 输出 clash 状态；契约测试覆盖热生效与非法值拒绝

## 3. 前端与配套

- [x] 3.1 设置页 Clash 分组、目标行路径下拉、总览 Clash 状态与降级横幅（前端资源内嵌构建通过）
- [x] 3.2 fpk/cmd/main 兜底清理扩展 GW_CLASH_TCP/GW_CLASH_DNS/GW_CLASH_UDP 与 fwmark 策略路由；README 增加"配合 Clash 部署"章节（Clash 侧要求：allow-lan/redir-port/dns/tproxy）

## 4. 验证与发布

- [x] 4.1 全量 vet + 单测 + 双架构交叉编译 + 本地 fnpack 出包通过
- [ ] 4.2 提交推送、打 tag v0.2.0、CI/Release 全绿且 Release 含双架构 .fpk
