#
# Binary Diff — 面向两个二进制文件的语义级差异分析
#
# 传统二进制 diff（bindiff, diaphora）依赖精确的字节级或助记符级比较
# 对编译器版本变化、寄存器重分配、指令重排极其敏感——同一源码用 -O2 vs -Os
# 编译产生的二进制差异可超过 60%，但语义差异接近零。本模块的 diff 策略：
#
#   层级 1: 指令语义哈希 — 将每条指令映射到 (op_type, operand_types, flags_effect)
#           的归一化三元组，对寄存器重命名不敏感
#   层级 2: 基本块匹配 — 将基本块视为"指令三元组的序列"，用序列对齐（Smith-Waterman
#           的简并变体）匹配块对，容忍少量指令插入/删除
# 层级 3: 函数差异 — 基于匹配的基本块对构建函数级编辑脚本（块插入/删除/修改）
#           并用调用图上下文过滤噪音（如内联导致的块移动）
#
# 非显而易见的决策：
# 不使用图同构（NP-hard），改用块级序列匹配 + 调用图验证
# 指令哈希不编码寄存器编号——只编码操作数类型（reg/imm/mem）
# 容忍少量指令差异（≤2 条）的基本块仍视为"匹配"——编译器常插入/删除
#     无关的栈帧管理指令

from .instruction_hash import semantic_hash_insn, hash_basic_block
from .block_matcher import match_blocks, BlockMatch
from .func_differ import diff_functions, FuncDiffResult, diff_pipeline
from .patch_classifier import classify_patch, PatchType
from .exploit_ranker import score_patch, rank_patches, ExploitabilityReport
