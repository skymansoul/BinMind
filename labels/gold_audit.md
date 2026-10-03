# gold.jsonl 真值可信度审计链 (flawfinder 交叉验证)

- 审计时间: 2026-09-16 19:05:10
- 审计工具: flawfinder (函数级启发式 C/C++ 静态扫描器, 开源)
- 样本量: 136 条标签 / 136 份源码

## 局限声明 (如实披露)

- 本机无独立第三方人工标注; gold.jsonl 原有标签为 legacy 手写迁移;
  本次新增 safe 样本为 by_construction (构造即真值)。
- flawfinder 不追踪指针生命周期、路径约束与上下文语义, 其结论是
  交叉印证 (corroboration), 不是 ground truth 权威认定;
- machine_checked 表示"独立工具结论与标签方向一致", 不等于标签绝对正确。

## 分层结果汇总

| confidence_tier | 数量 | 含义 |
|---|---|---|
| machine_checked | 82 | flawfinder 独立复核与标签一致 |
| by_construction | 12 | 构造即真值 + flawfinder 复核无高危 |
| legacy | 42 | 独立工具未确认 (类型不覆盖), 保持原层级 |
| *_disputed | 0 | 独立工具与标签分歧, 需人工复核 |

方向一致率 (machine_checked + by_construction): 94/136 = 0.691

## 逐样本审计记录

| sample_id | type | label | tier | hits | maxL | CWEs | 说明 |
|---|---|---|---|---|---|---|---|
| fmt_basic_direct | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_conditional_fmtstr | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_constant_safe | format_string | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fmt_direct_user | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_double_percent | format_string | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fmt_double_printf | format_string | 1 | machine_checked | 2 | 4 | - | flawfinder 确认危险模式 (2 条, max L4) |
| fmt_external_input | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_got_overwrite | format_string | 1 | machine_checked | 4 | 4 | - | flawfinder 确认危险模式 (4 条, max L4) |
| fmt_heap_fmt | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_heap_fmtstr | format_string | 1 | machine_checked | 3 | 4 | - | flawfinder 确认危险模式 (3 条, max L4) |
| fmt_indirect_arg | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_indirect_fmt | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_inline_const | format_string | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fmt_loop_printf | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_loop_write | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_n_bytes_written | format_string | 1 | machine_checked | 2 | 4 | - | flawfinder 确认危险模式 (2 条, max L4) |
| fmt_n_write | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_nested_call | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_offset_leak | format_string | 1 | machine_checked | 3 | 4 | - | flawfinder 确认危险模式 (3 条, max L4) |
| fmt_positional | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_positional_arg | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_snprintf_safe | format_string | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fmt_snprintf_trunc | format_string | 1 | machine_checked | 3 | 4 | - | flawfinder 确认危险模式 (3 条, max L4) |
| fmt_stack_leak | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_stack_write | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_syslog_direct | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_vprintf_proxy | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| fmt_vprintf_wrap | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_width_leak | format_string | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fmt_wrapper_func | format_string | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| CVE-2014-0160 | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| CVE-2016-6301 | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| CVE-2017-11176 | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| CVE-2018-6552 | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| CVE-2019-1010298 | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| CVE-2020-10711 | heap_overflow | 1 | machine_checked | 4 | 2 | - | flawfinder 确认危险模式 (4 条, max L2) |
| CVE-2021-3156 | heap_overflow | 1 | machine_checked | 3 | 2 | - | flawfinder 确认危险模式 (3 条, max L2) |
| CVE-2022-0185 | heap_overflow | 1 | machine_checked | 3 | 2 | - | flawfinder 确认危险模式 (3 条, max L2) |
| CVE-2022-23222 | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| CVE-2023-0461 | heap_overflow | 1 | machine_checked | 6 | 2 | - | flawfinder 确认危险模式 (6 条, max L2) |
| CVE-2024-21894 | heap_overflow | 1 | machine_checked | 3 | 4 | - | flawfinder 确认危险模式 (3 条, max L4) |
| HEAP-OVERFLOW-ALIGN-05 | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| HEAP-OVERFLOW-BASIC-01 | heap_overflow | 1 | machine_checked | 4 | 2 | - | flawfinder 确认危险模式 (4 条, max L2) |
| HEAP-OVERFLOW-COND-03 | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| HEAP-OVERFLOW-FP-04 | heap_overflow | 1 | machine_checked | 3 | 2 | - | flawfinder 确认危险模式 (3 条, max L2) |
| HEAP-OVERFLOW-LOOP-02 | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| HEAP-OVERFLOW-MULTI-06 | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| HEAP-OVERFLOW-REALLOC-07 | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| cross_func_write | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| cve_2021_3156_sudoedit | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| cve_2022_0185_kernel_heap | heap_overflow | 1 | machine_checked | 3 | 2 | - | flawfinder 确认危险模式 (3 条, max L2) |
| cve_2023_23001_custom | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| fp_01_alignment_safe | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fp_02_path_constrained | heap_overflow | 0 | machine_checked | 1 | 2 | - | flawfinder 无高危告警 (max L2) |
| fp_03_struct_field | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_04_realloc_shrink | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_05_min_constrained | heap_overflow | 0 | machine_checked | 1 | 2 | - | flawfinder 无高危告警 (max L2) |
| fp_06_sample | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_07_sample | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_08_sample | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fp_09_sample | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| fp_10_sample | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_11_sample | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| fp_12_sample | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| fp_13_sample | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_14_sample | heap_overflow | 0 | machine_checked | 0 | 0 | - | flawfinder 零告警 |
| fp_15_sample | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| heap_aliased_ptr | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| heap_dynamic_index | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| heap_guard_protected | heap_overflow | 0 | machine_checked | 1 | 2 | - | flawfinder 无高危告警 (max L2) |
| heap_int_overflow_to_heap | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| heap_loop_overflow | heap_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| heap_no_guard_check | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| heap_off_by_one | heap_overflow | 1 | machine_checked | 4 | 4 | - | flawfinder 确认危险模式 (4 条, max L4) |
| heap_realloc_misuse | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| heap_simple_overflow | heap_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| heap_slack_space | heap_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| heap_strcpy_overflow | heap_overflow | 1 | machine_checked | 1 | 4 | - | flawfinder 确认危险模式 (1 条, max L4) |
| heap_struct_write | heap_overflow | 1 | machine_checked | 2 | 4 | - | flawfinder 确认危险模式 (2 条, max L4) |
| intof_add_overflow | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_alloc_size | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_api_return | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| intof_array_index | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_basic_mul | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_bitfield_extract | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| intof_cond_narrow | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| intof_loop_counter | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_memcpy_len | integer_overflow | 1 | machine_checked | 2 | 2 | - | flawfinder 确认危险模式 (2 条, max L2) |
| intof_recursive_call | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| intof_safe_alloc_check | integer_overflow | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_safe_array_guard | integer_overflow | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_safe_bounded_add | integer_overflow | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_safe_const_size | integer_overflow | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_safe_mul_check | integer_overflow | 0 | by_construction | 2 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_safe_widen_size_t | integer_overflow | 0 | by_construction | 2 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| intof_shift_op | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_signed_cast | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_struct_field | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| intof_ternary_size | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| intof_widen_cast | integer_overflow | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| io_add_wrap | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_alloc_size | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_array_index | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_crypto_nonce | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_length_field | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_loop_counter | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_mixed_types | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_mul_overflow | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_narrow_cast | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_offset_wrap | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_parse_len | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_shift_wrap | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_sign_mismatch | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_size_calc | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| io_truncation | integer_overflow | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| uaf_alias_ptr | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_array_index | uaf | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| uaf_callback_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_cond_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_interproc_sim | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_list_node | uaf | 1 | machine_checked | 3 | 2 | - | flawfinder 确认危险模式 (3 条, max L2) |
| uaf_loop_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_mmap_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_nested_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_queue_pop | uaf | 1 | legacy | 0 | 0 | - | flawfinder 未确认 (不覆盖该类型或上下文), 保持 legacy |
| uaf_realloc_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_safe_free_last | uaf | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_safe_loop_fresh | uaf | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_safe_null_guard | uaf | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_safe_reassign | uaf | 0 | by_construction | 2 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_safe_struct_owner | uaf | 0 | by_construction | 1 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_safe_two_bufs | uaf | 0 | by_construction | 2 | 2 | - | flawfinder 无高危告警 (max L2); 构造即真值 |
| uaf_signal_handler | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_simple_double_free | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_struct_field | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |
| uaf_thread_race_sim | uaf | 1 | machine_checked | 1 | 2 | - | flawfinder 确认危险模式 (1 条, max L2) |

## 分歧清单

- 无 (无 *_disputed 样本)
