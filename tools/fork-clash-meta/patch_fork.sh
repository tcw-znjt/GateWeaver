#!/usr/bin/env bash
# 把 qiyueqixi/clash-meta 重打包为 root + TUN 全局接管版。
# 在 Linux（或 WSL）执行；需要 git / python3 / fnpack（官方 CLI，developer.fnnas.com）。
#
# 用法：  bash patch_fork.sh [upstream_repo_url]
# 产物：  clash-meta-root/fnos-appstore-mihomo 目录（再按上游 scripts/build-fpk.py 出包）
set -euo pipefail
REPO="${1:-https://github.com/qiyueqixi/clash-meta.git}"

[ -d clash-meta-root ] || git clone "$REPO" clash-meta-root
cd clash-meta-root/fnos-appstore-mihomo

echo "==> 1/3 privilege: run-as package -> root"
python3 - <<'PY'
import json
p = 'config/privilege'
d = json.load(open(p))
d.setdefault('defaults', {})['run-as'] = 'root'
json.dump(d, open(p, 'w'), indent=4)
print(open(p).read())
PY

echo "==> 2/3 config.default.yaml: 注入 TUN 全局接管"
python3 - <<'PY'
c = open('app/config.default.yaml').read()
if 'tun:' not in c:
    c += """
tun:
  enable: true
  stack: system            # 兼容性最稳；CPU 占用高可试 mixed / gvisor
  auto-route: true         # 接管系统默认路由：本机与"过境流量"的路由决策都会命中 tun
  auto-detect-interface: true
  dns-hijack:
    - any:53               # TUN 内置 DNS 劫持，GateWeaver 无需再做 53 端口规则
strict-route: false        # false=允许本机直连私网/局域网目的（NAS 互访不受影响）
"""
open('app/config.default.yaml', 'w').write(c)
print(c)
PY

echo "==> 3/3 交回上游构建脚本出包（需要 fnpack 在 PATH）"
echo "    cd ../ && pip install -r requirements.txt 2>/dev/null || true; python3 scripts/build-fpk.py"
echo "    若上游 build-fpk.py 参数有变，以其 --help 为准；产物 fpk 用 fnOS '手动安装' 覆盖旧版即可。"
echo
echo "提醒：旧版 config.yaml 已存在时上游启动逻辑不会覆盖（README 语），首次换 root-TUN 版请"
echo "      备份后删除 <应用文件>/clash.meta/config/config.yaml 让向导重新生成，或手工补 tun 段。"
