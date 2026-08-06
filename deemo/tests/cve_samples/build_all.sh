#!/bin/bash
# 批量编译所有 CVE 样本 — 每个样本编译为三个版本:
#   1. 默认 (未加壳, 带调试信息)  2. stripped (去符号)  3. optimized (-O2)
# 用法: bash build_all.sh [x86_64|arm|aarch64]

ARCH=${1:-x86_64}
CC=""

case $ARCH in
    x86_64)  CC="gcc -m64"; TARGET="elf64-x86-64" ;;
    arm)     CC="arm-linux-gnueabihf-gcc"; TARGET="elf32-littlearm" ;;
    aarch64) CC="aarch64-linux-gnu-gcc"; TARGET="elf64-littleaarch64" ;;
    *)       CC="gcc"; TARGET="elf64-x86-64" ;;
esac

SAMPLES_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SAMPLES_DIR/build/$ARCH"
mkdir -p "$BUILD_DIR"

compile_one() {
    local src="$1"
    local name=$(basename "$(dirname "$src")")
    local out_base="$BUILD_DIR/$name"

    # 版本 1: 默认 (debug info)
    $CC -g -o "$out_base"_default.elf "$src" 2>/dev/null && \
        echo "  [OK] $name (default)"

    # 版本 2: stripped
    $CC -o "$out_base"_stripped.elf "$src" 2>/dev/null && \
        strip "$out_base"_stripped.elf 2>/dev/null && \
        echo "  [OK] $name (stripped)"

    # 版本 3: optimized (-O2)
    $CC -O2 -o "$out_base"_O2.elf "$src" 2>/dev/null && \
        echo "  [OK] $name (O2)"
}

echo "=== Building CVE samples for $ARCH ==="
for dir in "$SAMPLES_DIR"/cve_*/; do
    if [ -f "$dir/vuln.c" ]; then
        compile_one "$dir/vuln.c"
    fi
done

echo "=== Done. Binaries in $BUILD_DIR ==="
ls -la "$BUILD_DIR"/*.elf 2>/dev/null | wc -l
echo "binaries built."
