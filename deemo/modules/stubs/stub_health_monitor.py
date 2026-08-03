"""
桩健康监控 — 运行时调用追踪 + 渐进式废弃调度。

模块位置: stubs/stub_health_monitor.py
"""

import time, json, os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import logging
_log = logging.getLogger(__name__)


@dataclass
class StubCallRecord:
    """桩调用记录：名称、目标、调用频次、时间窗口。"""
    stub_name: str
    compat_target: str
    call_count: int = 0
    caller_modules: Dict[str, int] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    deprecation_candidate: bool = False


class StubHealthMonitor:
    """
    桩健康监控器 — 运行时透明调用追踪。

    功能:
      1. 记录每个桩的调用频率和调用者模块
      2. 调用频率低于阈值时自动标记为废弃候选
      3. 输出桩到新 API 的迁移指南
    """

    def __init__(self, deprecation_threshold_days: int = 90, min_calls: int = 5):
        self._records: Dict[str, StubCallRecord] = {}
        self._threshold_days = deprecation_threshold_days
        self._min_calls = min_calls

    def record_call(self, stub_name: str, compat_target: str, caller_module: str = "unknown"):
        """写入一次桩调用事件，更新计数和时间戳。"""
        now = time.time()
        if stub_name not in self._records:
            self._records[stub_name] = StubCallRecord(
                stub_name=stub_name, compat_target=compat_target,
                first_seen=now,
            )
        rec = self._records[stub_name]
        rec.call_count += 1
        rec.caller_modules[caller_module] = rec.caller_modules.get(caller_module, 0) + 1
        rec.last_seen = now

    def evaluate_deprecation(self) -> List[StubCallRecord]:
        """按天数阈值和最小调用数评估废弃候选。"""
        now = time.time()
        candidates = []
        for rec in self._records.values():
            days_since_last = (now - rec.last_seen) / 86400.0
            if days_since_last > self._threshold_days or rec.call_count < self._min_calls:
                rec.deprecation_candidate = True
                candidates.append(rec)
        return sorted(candidates, key=lambda r: r.last_seen)

    def generate_migration_guide(self) -> str:
        """输出旧桩 → 新 API 的迁移指引文本。"""
        lines = ["# 桩迁移指南", f"生成时间: {time.strftime('%Y-%m-%d')}", ""]
        for name, rec in sorted(self._records.items()):
            new_path = rec.compat_target.replace(".", "/")
            lines.append(f"## {name}")
            lines.append(f"- 旧导入: `from modules.{name} import X`")
            lines.append(f"- 新导入: `from modules.core.compat.{new_path} import X`")
            lines.append(f"- 调用次数: {rec.call_count}")
            lines.append(f"- 调用者: {', '.join(f'{m}({c})' for m, c in rec.caller_modules.items())}")
            if rec.deprecation_candidate:
                lines.append(f"- **废弃候选** (最后调用: {time.strftime('%Y-%m-%d', time.localtime(rec.last_seen))})")
            lines.append("")
        return "\n".join(lines)

    def save_snapshot(self, path: str):
        with open(path, "w") as f:
            json.dump({
                name: {"calls": r.call_count, "last_seen": r.last_seen,
                       "compat": r.compat_target, "callers": r.caller_modules}
                for name, r in self._records.items()
            }, f, indent=2)

    def load_snapshot(self, path: str):
        if not os.path.isfile(path):
            return
        with open(path) as f:
            data = json.load(f)
        for name, info in data.items():
            self._records[name] = StubCallRecord(
                stub_name=name, compat_target=info.get("compat", ""),
                call_count=info.get("calls", 0),
                caller_modules=info.get("callers", {}),
                last_seen=info.get("last_seen", 0),
            )


__all__ = ["StubCallRecord", "StubHealthMonitor"]
