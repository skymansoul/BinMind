"""格式化字符串判定词汇表 — 格式源验证 (FSV) 的输出契约。

FORMAT_STRING 进入报告; SAFE 由字面量/字面量来源证明; UNCERTAIN
(格式为不可证来源的变量) 默认抑制 — 这是误报主来源。
"""

FORMAT_STRING = 'FORMAT_STRING'
SAFE = 'SAFE'
UNCERTAIN = 'UNCERTAIN'

CONF_FORMAT = 0.90
CONF_UNCERTAIN = 0.20
REPORT_MIN = 0.60

SEVERITY = {FORMAT_STRING: 'High', SAFE: 'Info', UNCERTAIN: 'Low'}

REPORT_SET = frozenset([FORMAT_STRING])
