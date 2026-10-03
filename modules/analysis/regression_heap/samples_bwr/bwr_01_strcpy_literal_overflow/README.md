# bwr_01_strcpy_literal_overflow

- 类别: 堆溢出(确定)
- 判定: strcpy 源字面量恢复上界15 > malloc(4)可用区 → 确认溢出; 基线跳过无界写会漏报
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
