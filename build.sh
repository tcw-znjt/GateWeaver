#!/usr/bin/env bash
# GateWeaver 构建：图标 → Linux 二进制 → 组装 fpk 工程目录 → fnpack 打包 .fpk。
# 本机（Windows，tools/bin/fnpack.exe）与 Linux CI（自动下载 fnpack）均可产出真实 .fpk。
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-0.1.0}"
FPK_ARCH="${FPK_ARCH:-amd64}"   # amd64 | arm64
FPK_NAME="GateWeaver_v${VERSION}_${FPK_ARCH}"
mkdir -p dist build

echo "==> 1/4 图标"
( cd src && go run ./cmd/genicon ../dist )
cp -f dist/ICON_256.PNG fpk/ICON_256.PNG
cp -f dist/ICON.png     fpk/ICON.PNG
cp -f dist/ICON_256.PNG fpk/app/ui/images/icon_256.png
cp -f dist/ICON_64.PNG  fpk/app/ui/images/icon_64.png

echo "==> 2/4 编译 Linux 二进制（amd64 + arm64）"
for arch in amd64 arm64; do
  ( cd src && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
      -ldflags "-s -w -X gateweaver/internal/api.Version=$VERSION" \
      -o "../build/gateweaver-linux-$arch" ./cmd/gateweaver )
done

echo "==> 3/4 组装打包工程 build/pkg"
rm -rf build/pkg
cp -r fpk build/pkg
mkdir -p build/pkg/app/server
cp build/gateweaver-linux-$FPK_ARCH build/pkg/app/server/gateweaver
chmod +x build/pkg/app/server/gateweaver build/pkg/cmd/* 2>/dev/null || true
sed -i "s/^version  *=.*/version               = $VERSION/" build/pkg/manifest

echo "==> 4/4 fnpack 打包"
if uname -s | grep -qi linux; then
  FNPACK=tools/bin/fnpack-linux
  if [ ! -x "$FNPACK" ]; then
    mkdir -p tools/bin
    curl -fsSL -o "$FNPACK" "https://static2.fnnas.com/fnpack/fnpack-1.2.1-linux-amd64"
    chmod +x "$FNPACK"
  fi
else
  FNPACK=tools/bin/fnpack.exe
  [ -e "$FNPACK" ] || { echo "缺少 $FNPACK：见 https://developer.fnnas.com/docs/cli/fnpack" >&2; exit 1; }
fi
( cd build/pkg && ../../"$FNPACK" build )
if [ -f build/pkg/GateWeaver.fpk ]; then
  mv build/pkg/GateWeaver.fpk "dist/${FPK_NAME}.fpk"
  echo "==> 产出 dist/${FPK_NAME}.fpk"
else
  echo "!! fnpack 未产出 GateWeaver.fpk，请检查上方输出" >&2
  exit 1
fi
