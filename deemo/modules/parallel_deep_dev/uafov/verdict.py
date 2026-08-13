"""UAF 判定词汇表 — 生命周期耦合验证的输出契约。

UAF/DOUBLE_FREE 进入报告; SAFE 由重绑定/空化/分支互斥证明后
丢弃; UNCERTAIN 默认抑制(误报主来源)。
"""

UAF = 'UAF'
DOUBLE_FREE = 'DOUBLE_FREE'
SAFE = 'SAFE'
UNCERTAIN = 'UNCERTAIN'

CONF_UAF = 0.90
CONF_DOUBLE_FREE = 0.85
CONF_UNCERTAIN = 0.20
REPORT_MIN = 0.60

SEVERITY = {UAF: 'Critical', DOUBLE_FREE: 'Critical', SAFE: 'Info',
            UNCERTAIN: 'Low'}

REPORT_SET = frozenset([UAF, DOUBLE_FREE])
