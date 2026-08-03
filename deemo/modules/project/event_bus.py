# 进程内pub/sub: MQTT通配符(*/>) + DLQ + 事件历史
import logging, time, threading, uuid, fnmatch
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Set
from collections import deque, defaultdict

# 保留
_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})


log = logging.getLogger(__name__)
_DELETED = object()

@dataclass

# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class Event: id: str = field(default_factory=lambda: uuid.uuid4().hex); topic: str = ""; data: Any = None; timestamp: float = field(default_factory=time.time); source: str = ""

class EventBus:
    def __init__(self, hsz=100, dlqsz=1000):
        self._h: Dict[str, List[Callable]] = {}; self._sids: Dict[str, str] = {}; self._lk = threading.RLock()
        self._hist: deque = deque(maxlen=hsz); self._dlq: deque = deque(maxlen=dlqsz); self._dlqrc: Dict[str, int] = {}
        self._widx: Dict[str, Set[str]] = defaultdict(set)

    def subscribe(self, pat, hnd):
        sid = uuid.uuid4().hex; setattr(hnd, '_sid', sid)
        with self._lk:
            self._h.setdefault(pat, []).append(hnd); self._sids[sid] = pat; self._idx(pat)
        log.debug("订阅: %s -> %s", pat, sid[:8]); return sid

    def unsubscribe(self, sid):
        with self._lk:
            if sid not in self._sids: return False
            pat = self._sids.pop(sid); hnds = self._h.get(pat, [])
            for i, h in enumerate(hnds):
                if getattr(h, '_sid', None) == sid: hnds[i] = _DELETED; break
            self._h[pat] = [h for h in hnds if h is not _DELETED]
            if not self._h[pat]: del self._h[pat]
            log.debug("取消: %s", sid[:8]); return True

    def publish(self, topic, data=None, source=""):
        ev = Event(topic=topic, data=data, source=source)
        with self._lk: self._hist.append(ev)
        matched = []
        with self._lk:
            for pat, hnds in self._h.items():
                if self._match(pat, topic): matched.extend(hnds)
        for h in matched:
            try: h(ev)
            except Exception: log.exception("handler异常: topic=%s", topic); self._dlq.append({"event": ev, "handler_name": getattr(h, '__name__', str(h))})
        return ev

    def _match(self, pat, topic):
        if pat == topic: return True
        pp, tp = pat.split("."), topic.split(".")
        if pp and pp[-1] == ">": return tp[:len(pp)-1] == pp[:-1]
        if len(pp) != len(tp): return False
        for ps, ts in zip(pp, tp):
            if ps == "*": continue
            if not fnmatch.fnmatch(ts, ps): return False
        return True

    def _dlq_retry(self, mx=3):
        redel = 0
        with self._lk: entries = list(self._dlq); self._dlq.clear()
        for e in entries:
            eid = e["event"].id; rc = self._dlqrc.get(eid, 0)
            if rc >= mx: log.warning("DLQ丢弃: %s", eid[:8]); continue
            matched = []
            with self._lk:
                for pat, hnds in self._h.items():
                    if self._match(pat, e["event"].topic): matched.extend(hnds)
            ok = True
            for h in matched:
                try: h(e["event"])
                except Exception: ok = False; break
            if ok: redel += 1; self._dlqrc.pop(eid, None)
            else: self._dlqrc[eid] = rc + 1; self._dlq.append(e)
        return redel

    def get_history(self, tf=None, limit=20):
        evs = list(self._hist)
        if tf: evs = [e for e in evs if self._match(tf, e.topic)]
        return evs[-limit:]

    def get_dlq_size(self): return len(self._dlq)
    def clear_history(self):
        with self._lk: self._hist.clear()
    def handler_count(self):
        with self._lk: return sum(len(h) for h in self._h.values())

    def _idx(self, pat):
        first = pat.split(".")[0]
        if "*" not in first and ">" not in first: self._widx[first].add(pat)


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

