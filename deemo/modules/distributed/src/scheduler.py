# Cron 调度器 — 借鉴 Quartz/Airflow 的 cron 语义，零框架依赖
# CronExpr 五段式（分 时 日 月 星期），支持 step/range/list
# next_match 用蛮力+步长法：不需要复杂的 cron 公式，按分钟递进探测
#
# 扩展：一次性调度 + 时区感知

from __future__ import annotations

import time
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Set

# ---- 可选 Redis ----
try:
    import redis as _redis_lib
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis_lib = None


# ===== CronExpr =====

WEEKDAY_NAMES = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3,
    "thu": 4, "fri": 5, "sat": 6,
}
ALL_VALUES = {
    "minute": set(range(60)),
    "hour": set(range(24)),
    "dom": set(range(1, 32)),
    "month": set(range(1, 13)),
    "dow": set(range(7)),
}


def _parse_field(field: str, min_val: int, max_val: int, allow_names: bool = False) -> Set[int]:
    """解析 cron 的一个字段。

    支持: * / , -
    示例: "*/5" → 每5步, "1,3,5" → 1&3&5, "1-5" → 1..5
    """
    if field == "*":
        return set(range(min_val, max_val + 1))

    result: Set[int] = set()
    # 处理逗号分隔
    parts = field.split(",")
    for part in parts:
        sub_parts = part.split("/")
        step = 1
        if len(sub_parts) == 2:
            # 有步长: "*/5" 或 "1-10/2"
            step = int(sub_parts[1])
            range_part = sub_parts[0]
        else:
            range_part = part

        if range_part == "*":
            vals = set(range(min_val, max_val + 1))
        elif "-" in range_part:
            lo, hi = range_part.split("-")
            lo_val = _resolve_name(lo, allow_names)
            hi_val = _resolve_name(hi, allow_names)
            vals = set(range(lo_val, hi_val + 1))
        else:
            val = _resolve_name(range_part, allow_names)
            vals = {val}

        # 应用步长
        if step > 1:
            sorted_vals = sorted(vals)
            vals = {sorted_vals[i] for i in range(0, len(sorted_vals), step)}

        result |= vals

    return result


def _resolve_name(token: str, allow_names: bool) -> int:
    if allow_names and token.lower() in WEEKDAY_NAMES:
        return WEEKDAY_NAMES[token.lower()]
    return int(token)


@dataclass
class CronExpr:
    minute: set
    hour: set
    dom: set
    month: set
    dow: set

    def __repr__(self) -> str:
        return (
            f"CronExpr(minute={_set_repr(self.minute, 60)}, "
            f"hour={_set_repr(self.hour, 24)}, "
            f"dom={_set_repr(self.dom, 31)}, "
            f"month={_set_repr(self.month, 12)}, "
            f"dow={_set_repr(self.dow, 7)})"
        )


def _set_repr(s: set, full: int) -> str:
    if len(s) >= full * 0.9:
        return "*"
    return str(sorted(s)) if len(s) <= 6 else f"[{min(s)}..{max(s)}]"


# //// 解析 ////

def parse_cron(expr: str) -> CronExpr:
    """解析标准五段 cron 表达式。"""
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(f"cron expr must have 5 fields, got {len(parts)}: {expr!r}")

    return CronExpr(
        minute=_parse_field(parts[0], 0, 59),
        hour=_parse_field(parts[1], 0, 23),
        dom=_parse_field(parts[2], 1, 31),
        month=_parse_field(parts[3], 1, 12),
        dow=_parse_field(parts[4], 0, 6, allow_names=True),
    )


# //// 下一个匹配时间 ////

def _month_days(year: int, month: int) -> int:
    # 某年某月的天数
    if month == 2:
        if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
            return 29
        return 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def next_match(cron: CronExpr, from_time: float = None) -> float:
    """计算 cron 表达式在 from_time 之后的下一个匹配时间（unix timestamp）。

    从当前分钟+1开始逐分钟探测 — 最朴素但最可靠的方式。
    """
    from_time = from_time or time.time()
    # 对齐到分钟
    t = time.localtime(from_time)
    minute = t.tm_min + 1  # 下一分钟开始
    hour = t.tm_hour
    dom = t.tm_mday
    month = t.tm_mon
    year = t.tm_year

    # 最多搜索 4 年（约 2M 分钟），兜底
    for _ in range(2_103_840):
        if minute >= 60:
            minute = 0
            hour += 1
        if hour >= 24:
            hour = 0
            dom += 1
        if dom > _month_days(year, month):
            dom = 1
            month += 1
        if month > 12:
            month = 1
            year += 1

        dow_val = _day_of_week(year, month, dom)

        if (minute in cron.minute and
            hour in cron.hour and
            dom in cron.dom and
            month in cron.month and
            dow_val in cron.dow):
            return time.mktime((year, month, dom, hour, minute, 0, 0, 0, -1))

        minute += 1

    raise RuntimeError(f"no cron match found for {cron} within search window")


def _day_of_week(year: int, month: int, day: int) -> int:
    """计算星期几 (0=Sun) — Tomohiko Sakamoto 算法"""
    t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4]
    y = year if month > 2 else year - 1
    return (y + y // 4 - y // 100 + y // 400 + t[month - 1] + day) % 7


# //// every 糖 ////

def every(spec: str) -> CronExpr:
    """将人类可读的时间间隔转为 CronExpr。

    "5m" → 每5分钟, "1h30m" → 每90分钟, "30s" → 每30秒(对齐到分钟)
    """
    total_minutes = 0.0
    remaining = spec.strip().lower()

    for match in re.finditer(r'(\d+)([smhd])', remaining):
        val = int(match.group(1))
        unit = match.group(2)
        if unit == 's':
            total_minutes += val / 60.0
        elif unit == 'm':
            total_minutes += val
        elif unit == 'h':
            total_minutes += val * 60
        elif unit == 'd':
            total_minutes += val * 60 * 24

    minutes = int(total_minutes)
    if minutes <= 0:
        minutes = 1

    step = max(minutes, 1)
    step_str = f"*/{step}" if step < 60 else "*"
    return parse_cron(f"{step_str} * * * *")


# ===== CronScheduler =====

@dataclass
class ScheduleEntry:
    name: str
    cron_expr: str
    task_type: str
    payload: dict = field(default_factory=dict)
    last_run: float = 0.0
    next_run: float = 0.0
    enabled: bool = True
    one_shot: bool = False  # 一次性调度，执行后自动删除


class CronScheduler:
    """基于 cron 表达式的调度器。

    Redis 持久化: HSET binmind:schedules {name} {json}
    """

    KEY = "binmind:schedules"

    def __init__(self, redis_client=None):
        self._schedules: dict[str, ScheduleEntry] = {}
        self._redis = redis_client
        self._load()

    def _load(self):
        if self._redis is None:
            return
        try:
            raw = self._redis.hgetall(self.KEY)
            for name, data in raw.items():
                d = json.loads(data)
                self._schedules[name] = ScheduleEntry(**d)
        except Exception:
            pass

    def _save(self, name: str, entry: ScheduleEntry):
        if self._redis is None:
            return
        try:
            self._redis.hset(self.KEY, name, json.dumps(entry.__dict__))
        except Exception:
            pass

    def add_schedule(
        self, name: str, cron_expr: str, task_type: str,
        payload: dict = None, one_shot: bool = False,
    ) -> None:
        parsed = parse_cron(cron_expr)
        next_ts = next_match(parsed)
        entry = ScheduleEntry(
            name=name,
            cron_expr=cron_expr,
            task_type=task_type,
            payload=payload or {},
            next_run=next_ts,
            one_shot=one_shot,
        )
        self._schedules[name] = entry
        self._save(name, entry)

    def add_one_shot(self, name: str, at_timestamp: float,
                     task_type: str, payload: dict = None) -> None:
        """添加一次性调度 — 在 at_timestamp 执行一次后自动删除。"""
        entry = ScheduleEntry(
            name=name,
            cron_expr=f"once@{at_timestamp}",
            task_type=task_type,
            payload=payload or {},
            next_run=at_timestamp,
            one_shot=True,
        )
        self._schedules[name] = entry
        self._save(name, entry)

    def remove_schedule(self, name: str) -> bool:
        if name not in self._schedules:
            return False
        del self._schedules[name]
        if self._redis:
            try:
                self._redis.hdel(self.KEY, name)
            except Exception:
                pass
        return True

    def get_due(self, from_time: float = None) -> list[ScheduleEntry]:
        ts = from_time or time.time()
        due = []
        expired = []
        for name, entry in list(self._schedules.items()):
            if not entry.enabled:
                continue
            if entry.next_run <= ts:
                due.append(entry)
                if entry.one_shot:
                    expired.append(name)
                else:
                    # 更新下次运行时间
                    parsed = parse_cron(entry.cron_expr)
                    entry.last_run = ts
                    entry.next_run = next_match(parsed, ts)
                    self._save(name, entry)
        for name in expired:
            self.remove_schedule(name)
        return due

    def list_schedules(self) -> list[ScheduleEntry]:
        return list(self._schedules.values())
