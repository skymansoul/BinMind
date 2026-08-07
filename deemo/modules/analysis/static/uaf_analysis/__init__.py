"""二进制级 UAF (Use-After-Free) 检测 — objdump 反汇编 → 释放后使用分析.

模块:
  binary_uaf_scanner: 在 objdump 输出上追踪 free() 调用及后续指针解引用
"""

