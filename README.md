# GateWeaver

面向飞牛 fnOS 应用中心的**旁路由接管**应用：将局域网内**指定设备**的默认网关引导至 fnOS 本机，
使其外网流量经过 NAS（可用于过滤、代理、加速、流量分析），停止或卸载后自动恢复网络原状。

> ⚠️ **使用边界**：ARP 网关接管本质是局域网层攻击技术。本应用仅可用于**您拥有或已获明确授权管理**
> 的网络与设备；对他人的网络设备使用可能违法。应用内置白名单目标、授权确认、一键恢复与故障自愈来
> 约束影响面，但请自行评估所在司法辖区的合规性。

## 工作原理

1. **ARP 网关接管**：对白名单内的目标设备（以 MAC 为主键），周期单播伪造 ARP 应答
   （"网关 IP → fnOS 的 MAC"），并即时应答目标发出的网关查询。注入仅以单播发往目标，
   不会污染主路由与其他设备。
2. **流量转发**：内核开启 IP 转发后，被接管设备的流量按默认路由送达真实网关。
   - `直连路由` 模式：保留源 IP（回程由主路由直接交付设备，链路非对称但可达）；
   - `地址伪装` 模式：对**且仅对**目标设备做 MASQUERADE，兼容开启 uRPF/防欺骗的主路由。
3. **恢复与自愈**：
   - 正常停止（应用中心停止/卸载/一键恢复）：立即向每个目标单播恢复通告（真实网关映射），秒级回正；
   - 异常（进程被杀/断电/宕机）：注入停止，目标设备 ARP 表项自然老化后回退真实网关（fail-open）；
   - 上游故障：探测到主路由不可达时自动撤销全部接管，恢复后自动重接管。

## 功能一览（Web 管理台，默认端口 9666）

- 局域网设备发现（ARP 邻居表 + 可选 CIDR 主动探测），一键设为目标
- 目标增删/单独启停、全局开关、一键恢复
- 每目标接管状态（未启用 / 注入中 / 已生效 / 未见流量）与流量计数
- 上游网关显示（自动探测/手动固定）、送达模式、注入间隔与限速、fail-open 开关
- 事件与审计日志；首次使用授权声明确认

## 配合 Clash 使用（TUN 全局接管模型，v0.3+）

推荐架构：Clash.Meta 以 **root + TUN 全局接管** 运行（用 `tools/fork-clash-meta/` 一键重打包
qiyueqixi/clash-meta），被接管设备的流量与 NAS 本地流量走同一条路进 Clash——与旧 OpenWrt +
OpenClash 体验一致，无需 redir/tproxy 端口：

1. 按 `tools/fork-clash-meta/README.md` 安装 root+TUN 版 clash-meta；`ip route show default`
   应显示默认路由 `dev tun`。
2. GateWeaver 设置 → "TUN 接管守护"：开启，接口名/controller 与 Clash 实际一致（默认 `tun`、
   `127.0.0.1:19090`）。
3. 目标管理添加设备并启用全局开关：设备流量 → NAS → tun → Clash 分流。
4. **故障保护**：Clash 挂掉/TUN 路由丢失 → TunGuard 自动撤销全部 ARP 引导（设备直连真网关，
   断墙不断网）；Clash 恢复 → 自动重新引导。关闭守护开关则退回纯转发模型（v0.1.1 行为）。

## 限制

- 目标设备须与 fnOS 处于**同一二层网段**（跨 VLAN/三层隔离不可接管）；
- 使用静态 ARP 或网关侧启用 ARP 防护（DAI 等）的设备无法被接管——管理台会如实显示"未见流量"；
- 开启无线 AP 客户端隔离的网络中接管可能无效；
- fnOS 上运行需 root 与 host 网络（`.fpk` 声明见 `fpk/manifest`、`fpk/script/config`）。

## 构建

```bash
# 依赖：Go ≥ 1.27；fnpack 官方 CLI 由 build.sh 自动获取（developer.fnnas.com/docs/cli/fnpack）
make test        # 单元测试（跨平台可跑）
make linux       # 交叉编译 Linux amd64 二进制 → dist/gateweaver
bash build.sh    # 产出 dist/GateWeaver_v<ver>_<arch>.fpk（FPK_ARCH=arm64 切换架构）
```

仓库结构：

```
src/            Go 模块（守护进程 + 管理台 + 引擎，内嵌前端；含 cmd/genicon 图标生成）
fpk/            飞牛应用工程（官方 fnpack 布局）：manifest、config/{privilege,resource}、
                cmd/{main,install_*,upgrade_*,uninstall_*,config_*}、app/ui 启动项
.github/        CI（测试/跨平台编译/fpk 打包）与 Release 工作流（tag 触发，双架构 .fpk）
openspec/       规格与变更管理（proposal/specs/design/tasks）
```

打包说明：`fnpack` 由 [官方开发者平台](https://developer.fnnas.com/docs/cli/fnpack) 提供（Windows/Linux 二进制，
`static2.fnnas.com/fnpack/` 自动下载），`build.sh` 会在 `dist/` 产出可直接"手动安装"的 `.fpk`。

## 安装（手动安装 .fpk）

fnOS 应用中心 → 手动安装 → 上传 `.fpk`。安装后应用默认**不接管任何设备**：
打开管理台 → 设置口令 → 确认授权声明 → 发现/添加目标 → 开启全局开关。

## 常见问题

- **部分设备"未见流量"**：该设备可能设了静态 ARP 或主路由开了 ARP 防护；改用主路由 DHCP
  指定网关为 fnOS 的替代方案（规划中的后续能力）。
- **接管后某设备断网**：管理台点"一键恢复"；若主路由启用了反向路径过滤，把送达模式改为"地址伪装"。
- **升级/重启**：应用会自动恢复先前处于启用状态的目标（配置持久化于 fnOS 数据目录）。

## License

MIT
