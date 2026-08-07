"""LSP测试样本的ground truth定义."""
from __future__ import annotations

LSP_EXPECTED = {
    'lsp_01_path_guard_safe': False,
    'lsp_02_path_guard_overflow': True,
    'lsp_03_assert_bound_safe': False,
    'lsp_04_min_bound_safe': False,
    'lsp_05_allocator_padding_safe': False,
    'lsp_06_allocator_padding_overflow': True,
    'lsp_07_ternary_guard_safe': False,
    'lsp_08_double_guard_safe': False,
    'lsp_09_double_guard_overflow': True,
    'lsp_10_shared_var_plus_guard_safe': False,
    'lsp_11_calloc_padding_safe': False,
    'lsp_12_no_guard_inconclusive': None,
    'lsp_13_offset_padding_safe': False,
    'lsp_14_offset_padding_overflow': True,
    'lsp_15_while_guard_safe': False,
    'lsp_16_if_else_guard_overflow': True,
    'lsp_17_arith_var_guard_safe': False,
    'lsp_18_complex_guard_safe': False,
}

__all__ = ['LSP_EXPECTED']
