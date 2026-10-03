#!/bin/bash
# 编译配置: 默认 | 无mitigation | ASAN
set -e
BASE="STACK_BOF_01"
echo "=== Building ${BASE} ==="
gcc -o vuln vuln.c -fno-stack-protector -z execstack -o "${BASE}_default"
gcc -o vuln vuln.c -fno-stack-protector -z execstack -o "${BASE}_no_mitigation"
gcc -o "${BASE}_asan" vuln.c -fsanitize=address -g -O0 2>/dev/null || echo "(ASAN not supported, skipping)"
echo "Build complete: ${BASE}_default, ${BASE}_no_mitigation, ${BASE}_asan"
