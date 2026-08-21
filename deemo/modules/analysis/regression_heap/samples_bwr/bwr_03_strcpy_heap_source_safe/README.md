# bwr_03_strcpy_heap_source_safe

- 类别: 安全
- 判定: 源为malloc(32)堆缓冲, 目标malloc(64); 栈槽别名解析恢复上界32≤64 → 安全
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
