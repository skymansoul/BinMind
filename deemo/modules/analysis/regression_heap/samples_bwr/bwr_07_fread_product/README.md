# bwr_07_fread_product

- 类别: 堆溢出(确定)
- 判定: fread size*nmemb=4096 > malloc(256)可用区; PCST取乘积实参后检出
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
