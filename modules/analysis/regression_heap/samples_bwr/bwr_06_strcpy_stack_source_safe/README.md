# bwr_06_strcpy_stack_source_safe

- 类别: 安全
- 判定: 源为栈缓冲tmp[16], 经lea[rbp-X]恢复上界16 ≤ malloc(32)可用区 → 安全
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
