# bwr_04_sprintf_literal_overflow

- 类别: 堆溢出(确定)
- 判定: sprintf 格式串'%s!'+实参'hello' → 最大输出7 > malloc(4)可用区 → 确认溢出
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
