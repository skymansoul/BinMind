# bwr_08_read_dstfix

- 类别: 堆溢出(确定)
- 判定: read 目标缓冲在第2实参, 写入64 > malloc(32)可用区; PCST修正dst索引后检出
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
