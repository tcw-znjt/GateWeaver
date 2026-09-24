# clash-meta root+TUN fork 说明

**已 fork 并接入自动构建（首选路径）**：
https://github.com/tcw-znjt/clash-meta —— 打 tag 即由 Actions 产出 root+TUN 版 fpk
（Release 页直接下载 `clash.meta_<版本>_x86.fpk / _arm.fpk`，含 SHA256SUMS）。
fork 共 4 处补丁：privilege→root、config.default.yaml 注入 tun 块、build-fpk.py 校验放行 root、
sw.js 预缓存哈希按 LF 重算 + .gitattributes 固定 html/json eol=lf（Linux 可复现构建）。

---

以下为本地手工打补丁的备用路径（目的同上）：让 Clash.Meta(mihomo) 以 **root + TUN 全局接管** 运行，配合 GateWeaver 的 ARP 引导，
实现"被接管设备的流量与 NAS 本地流量走同一条路进 Clash"（等价于旧 OpenWrt + OpenClash 模型）。

上游：https://github.com/qiyueqixi/clash-meta （非 root、无 TUN，不能直接用）

## 步骤

```bash
# 1. 在 Linux/WSL 里（需要 git、python3、fnpack）
bash patch_fork.sh                # clone + 打两处补丁
cd clash-meta-root
python3 scripts/build-fpk.py      # 上游构建脚本（fnpack 需在 PATH；参数以 --help 为准）

# 2. fnOS 应用中心：卸载旧 clash.meta（选择"保留配置与订阅"），手动安装新 fpk
#    若旧 config.yaml 仍在：应用中心停止 → 删除/备份 <应用文件>/clash.meta/config/config.yaml
#    → 重新启用（向导按 root+TUN 默认配置生成）
```

## 补丁做了什么

| 文件 | 改动 | 原因 |
|---|---|---|
| `config/privilege` | `run-as: package → root` | TUN 创建、`ip rule/route` 自动管理需要 NET_ADMIN/root |
| `app/config.default.yaml` | 追加 `tun:` 块（`auto-route: true`、`dns-hijack: any:53`）+ `strict-route: false` | auto-route 使**过境流量**的路由决策命中 tun；dns-hijack 由 TUN 内置完成，GateWeaver 无需再做 53 劫持；strict-route=false 保住 NAS 与局域网互访 |

## 运行模型（与 GateWeaver 的分工）

```
设备 --ARP引导--> NAS --路由(默认 dev tun)--> mihomo TUN --> 节点/DIRECT
```

- Clash：TUN、路由接管、DNS、分流规则（全部它自己管）
- GateWeaver：ARP 引导 + ip_forward/FORWARD 放行 + **TunGuard 守护**
- GateWeaver 配对设置：设置 → TUN 接管守护 → 开；`TUN 接口名` 填 mihomo 的接口名（默认 `tun`，
  `ip addr` 里看实际前缀）；controller 默认 `127.0.0.1:19090`（上游包就监听本机回环，正好）。

## 已知风险（务必读）

1. **mihomo 被 `kill -9`**：auto-route 添加的默认路由可能残留 → **NAS 本机与所有过境流量一起黑洞**。
   自救：SSH 执行 `ip route del default 2>/dev/null; ip rule del pref 0` 或重启网络/机器；
   被接管设备一侧 GateWeaver TunGuard 会自动撤销 ARP 引导（设备直连真网关不受牵连）。
   建议只在需要时 `kill -TERM`/面板停止。
2. 面板"配置"热保存走 controller API，**不会**动 yaml 里的 tun 段；但订阅向导重新生成 config 时
   会带上补丁的默认值（这就是为什么补丁打在 config.default.yaml 而不是运行时文件）。
3. 上游升级后需重放 `patch_fork.sh`（幂等：已打过则跳过）。

## 验证清单

```bash
ip route show default            # 应出现 dev tun（mihomo 起来后）
ss -lnt | grep 19090             # controller 监听
# 被接管设备：ip.sb 出口=节点 IP；关掉 clash.meta → GateWeaver 总览 15s 内变
# "失效已撤销引导"，设备 arp -a 网关 MAC 回正、可直连上网；再开 clash.meta → 自动重新引导
```
