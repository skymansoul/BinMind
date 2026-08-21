# bwr_05_snprintf_argfix

- 类别: 堆溢出(确定)
- 判定: snprintf size 实参在第2位(32) > malloc(8)可用区; PCST修正参数索引后检出
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
