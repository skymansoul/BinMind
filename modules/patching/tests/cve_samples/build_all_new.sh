#!/bin/bash
# 批量编译所有新CVE样本 (TP007-TP016, FP004-FP008)
# 用法: cd tests/cve_samples && bash build_all.sh

SAMPLES=(
    CVE-2025-TP007_cross_func_alloc
    CVE-2025-TP008_mul_size
    CVE-2025-TP009_indirect_taint
    CVE-2025-TP010_loop_write
    CVE-2025-TP011_call_ret_size
    CVE-2025-TP012_realloc_expand
    CVE-2025-TP013_struct_field
    CVE-2025-TP014_array_idx
    CVE-2025-TP015_chained_arith
    CVE-2025-TP016_strlen_offby
    CVE-2025-FP004_and_mask_guard
    CVE-2025-FP005_loop_bound_safe
    CVE-2025-FP006_minsize_guard
    CVE-2025-FP007_cross_call_valid
    CVE-2025-FP008_cmova_capped
)

CC=gcc
CFLAGS="-g -O0"

for s in "${SAMPLES[@]}"; do
    echo "Compiling $s..."
    $CC $CFLAGS -o "$s/vuln_debug.exe" "$s/vuln.c" 2>&1 || echo "FAILED: $s"
done
echo "Done."
