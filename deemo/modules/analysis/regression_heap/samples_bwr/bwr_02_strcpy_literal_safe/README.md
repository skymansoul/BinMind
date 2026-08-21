# bwr_02_strcpy_literal_safe

- 类别: 安全
- 判定: strcpy 源字面量上界6 ≤ malloc(64)可用区 → BWR判定安全不告警
- 构建: `make`
- 检测方式: BWR有界写尺寸恢复 / PCST按调用点参数语义表
