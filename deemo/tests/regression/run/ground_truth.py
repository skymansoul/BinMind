"""
权威 Ground Truth 数据 — 108样本 × 4类型的预期检测结果.
与 cross_type_benchmark.py 同步, 基于CVE验证 + 手动审计.

"""

from typing import Dict

# 样本名 → 预期检测结果 (1=vulnerable, 0=safe)
EXPECTED: Dict[str, int] = {
# Heap Overflow (34 samples)
    'CVE-2014-0160':1,'CVE-2016-6301':1,'CVE-2017-11176':1,'CVE-2018-6552':1,
    'CVE-2019-1010298':1,'CVE-2020-10711':1,'CVE-2021-3156':1,'CVE-2022-0185':1,
    'CVE-2022-23222':1,'CVE-2023-0461':1,'CVE-2024-21894':1,
    'HEAP-OVERFLOW-BASIC-01':1,'HEAP-OVERFLOW-LOOP-02':1,'HEAP-OVERFLOW-COND-03':1,
    'HEAP-OVERFLOW-MULTI-06':1,'HEAP-OVERFLOW-REALLOC-07':1,
    'heap_aliased_ptr':1,'heap_dynamic_index':1,'heap_int_overflow_to_heap':1,
    'heap_loop_overflow':1,'heap_no_guard_check':1,'heap_off_by_one':1,
    'heap_realloc_misuse':1,'heap_simple_overflow':1,'heap_strcpy_overflow':1,
    'heap_struct_write':1,'HEAP-OVERFLOW-FP-04':1,'HEAP-OVERFLOW-ALIGN-05':1,
    'heap_slack_space':1,'cve_2021_3156_sudoedit':1,'cve_2022_0185_kernel_heap':1,
    'cve_2023_23001_custom':1,'cross_func_write':1,'heap_guard_protected':0,
# Heap FP Reduction (15 samples)
    'fp_01_alignment_safe':1,'fp_02_path_constrained':0,'fp_03_struct_field':0,
    'fp_04_realloc_shrink':0,'fp_05_min_constrained':0,
    'fp_06_sample':0,'fp_07_sample':0,'fp_08_sample':1,'fp_09_sample':1,
    'fp_10_sample':0,'fp_11_sample':1,'fp_12_sample':1,'fp_13_sample':0,
    'fp_14_sample':0,'fp_15_sample':1,
# UAF (15 samples)
    'uaf_simple_double_free':1,'uaf_alias_ptr':1,'uaf_loop_free':1,
    'uaf_cond_free':1,'uaf_realloc_free':1,'uaf_array_index':1,
    'uaf_callback_free':1,'uaf_interproc_sim':1,'uaf_list_node':1,
    'uaf_mmap_free':1,'uaf_nested_free':1,'uaf_queue_pop':1,
    'uaf_signal_handler':1,'uaf_struct_field':1,'uaf_thread_race_sim':1,
# Int Overflow (intof_* 15 samples)
    'intof_add_overflow':1,'intof_alloc_size':1,'intof_api_return':1,
    'intof_array_index':1,'intof_basic_mul':1,'intof_bitfield_extract':1,
    'intof_cond_narrow':1,'intof_loop_counter':1,'intof_memcpy_len':1,
    'intof_recursive_call':1,'intof_shift_op':1,'intof_signed_cast':1,
    'intof_struct_field':1,'intof_ternary_size':1,'intof_widen_cast':1,
# Int Overflow (io_* 15 samples)
    'io_mul_overflow':1,'io_add_wrap':1,'io_sign_mismatch':1,
    'io_truncation':1,'io_shift_wrap':1,'io_alloc_size':1,
    'io_array_index':1,'io_crypto_nonce':1,'io_length_field':1,
    'io_loop_counter':1,'io_mixed_types':1,'io_narrow_cast':1,
    'io_offset_wrap':1,'io_parse_len':1,'io_size_calc':1,
# Format String (30 samples)
    'fmt_direct_user':1,'fmt_constant_safe':0,'fmt_stack_leak':1,
    'fmt_n_write':1,'fmt_positional':1,'fmt_basic_direct':1,
    'fmt_conditional_fmtstr':1,'fmt_double_percent':0,'fmt_double_printf':1,
    'fmt_external_input':1,'fmt_got_overwrite':1,'fmt_heap_fmt':1,
    'fmt_heap_fmtstr':1,'fmt_indirect_arg':1,'fmt_indirect_fmt':1,
    'fmt_inline_const':0,'fmt_loop_printf':1,'fmt_loop_write':1,
    'fmt_n_bytes_written':1,'fmt_nested_call':1,'fmt_offset_leak':1,
    'fmt_positional_arg':1,'fmt_snprintf_safe':0,'fmt_snprintf_trunc':1,
    'fmt_stack_write':1,'fmt_syslog_direct':1,'fmt_vprintf_proxy':1,
    'fmt_vprintf_wrap':1,'fmt_width_leak':1,'fmt_wrapper_func':1,
}

# 类别→类型映射
CAT_TYPE = {
    'heap-overflow': 'heap_overflow', 'heap-fp-reduction': 'heap_overflow',
    'uaf': 'uaf', 'int-overflow': 'integer_overflow', 'format-string': 'format_string',
}

# 样本目录→类别
SAMPLE_ROOTS = [
    ('tests/samples/heap_overflow', 'heap-overflow'),
    ('tests/samples/heap_fp_reduction', 'heap-fp-reduction'),
    ('tests/samples/uaf', 'uaf'),
    ('tests/samples/int_overflow', 'int-overflow'),
    ('tests/samples/integer_overflow', 'int-overflow'),
    ('tests/samples/format_string', 'format-string'),
]
