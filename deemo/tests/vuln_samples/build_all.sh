#!/bin/bash
# 编译所有CVE漏洞样本 — 自动检测编译器并编译
# 用法: bash build_all.sh [gcc|clang]
# 输出: 每个样本目录下的可执行文件

set -e
CC=${1:-gcc}
CFLAGS="-w -O0 -g -fno-stack-protector -z execstack -no-pie"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

compile_one() {
    local src="$1"
    local out="${src%.c}"
    echo "  [$CC] $src -> $out"
    $CC $CFLAGS -o "$out" "$src" 2>&1 || echo "  WARN: compile failed for $src (may need libs)"
}

echo "=== Building CVE samples with $CC ==="
for dir in "$BASE_DIR"/CVE-*/; do
    name=$(basename "$dir")
    echo "-- $name --"
    for src in "$dir"*.c; do
        [ -f "$src" ] && compile_one "$src"
    done
done
echo "=== Done ==="
