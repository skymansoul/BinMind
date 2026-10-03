# 数据层测试路径配置 — 测试以 src.XXX 形式导入数据层实现,
# 需将 modules/data 加入导入路径使 src 包可解析。

import os
import sys

_data_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _data_root not in sys.path:
    sys.path.insert(0, _data_root)
