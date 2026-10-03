"""uaf_analysis — 别名感知UAF检测 + 危险度评分。"""
from modules.vuln.detection.uaf_analysis.alias_tracker import (
    track_aliases_and_detect_uaf, UafFindingEnhanced, AliasClass)
