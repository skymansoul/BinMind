#!/bin/bash
# 编译所有CVE测试样本 — Linux/Mac/Win(MinGW)自适应

BASE="$(cd "$(dirname "$0")" && pwd)"
CC=${CC:-gcc}

# 检测平台并选择合适的编译标志
case "$(uname -s 2>/dev/null || echo Windows)" in
    Linux|Darwin)
        CFLAGS="-O0 -g -fno-stack-protector -z execstack -no-pie"
        CFLAGS_O2="-O2 -fno-stack-protector -no-pie"
        ;;
    *)
        # Windows/MinGW: 去掉 ELF 特有的链接选项
        CFLAGS="-O0 -g"
        CFLAGS_O2="-O2"
        ;;
esac

echo "=== Building CVE regression samples (CC=$CC) ==="

for dir in "$BASE"/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    src="$dir/${name}.c"
    [ -f "$src" ] || continue
    echo "  Building $name..."
    $CC $CFLAGS -o "$dir/${name}_O0.exe" "$src" 2>/dev/null || \
    $CC $CFLAGS -o "$dir/${name}_O0" "$src" 2>/dev/null || \
    echo "    [SKIP] compile failed (may need Linux env)"
    $CC $CFLAGS_O2 -o "$dir/${name}_O2.exe" "$src" 2>/dev/null || \
    $CC $CFLAGS_O2 -o "$dir/${name}_O2" "$src" 2>/dev/null || true
    strip "$dir/${name}_O0" 2>/dev/null || true
    strip "$dir/${name}_O2" 2>/dev/null || true
    strip "$dir/${name}_O0.exe" 2>/dev/null || true
    strip "$dir/${name}_O2.exe" 2>/dev/null || true
done

echo "=== Done ==="
