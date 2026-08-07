# 修改记录:
# 2025-07-18 14:36 - 增加 loop_unroll 的跨函数展开检测
# 2025-07-23 10:51 - idiom_subst 新增除常数的 magic number 逆推

"""编译器产物归一化 — 消除不同编译器/优化级别的语义等价语法差异。

三个独立模块:
  loop_unroll — 循环展开检测与折叠, 将编译器扩展的重复模式还原为循环结构
  idiom_subst  — 编译器惯用法识别与替换, 将优化产生的等价形式还原为规范形式
  reg_class    — 寄存器类抽象映射, 将架构特定寄存器映射到语义类别

归一化在中间表示层执行, 先升为 VEX-like IR (若可用),
否则回退到汇编级模式匹配。归一化后不同编译器的输出在结构上
更可比 — 这对跨编译器的二进制相似度比较和 GNN 特征提取都有直接收益。

架构依据:
  - ref: VEXIR2Vec 的 VEX-IR 归一化引擎,
    通过编译器优化消除架构和编译器引入的变异。本项目在此基础上
    增加循环展开的显式折叠和寄存器类映射, 这两点在 VEXIR2Vec 中
    未处理。
  - ref: LLVM InstCombine 的设计哲学 — 将 n 种等价形式折叠为 1 种规范形式,
    而非扩展 1 种形式到 n 种。循环展开折叠遵循相反方向: n→1。
  - ref: BinDiff (zynamics/Google) 的指令归一化规则集, 特别是
    立即数泛化和条件跳转规范化, 本项目将其推广到更细粒度的指令级替换。
"""

from . import loop_unroll, idiom_subst, reg_class
from .loop_unroll import detect_unrolled_loops, fold_unrolled_loop
from .idiom_subst import substitute_idioms, IDIOM_RULES
from .reg_class import map_to_class, REG_CLASS_TABLE

__all__ = [
    'detect_unrolled_loops', 'fold_unrolled_loop',
    'substitute_idioms', 'IDIOM_RULES',
    'map_to_class', 'REG_CLASS_TABLE',
]
