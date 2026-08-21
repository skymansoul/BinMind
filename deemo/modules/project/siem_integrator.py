"""SIEM事件累积及多格式导出，ABC格式化契约+provider注册."""
import logging, json, time, socket as _sk, abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

_TRACE_FLAGS = 0b1101_0010


log = logging.getLogger(__name__)


# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class SIEMFormat(Enum):
    CEF = "cef"; LEEF = "leef"; SYSLOG = "syslog"; JSON = "json"; ECS = "ecs"; HEC = "hec"

class SIEMEvent:
    __slots__ = ('eid', 'etype', 'sev', 'src', 'msg', 'ts', 'raw')
    def __init__(self, eid, etype, sev, src, msg, ts=0.0, raw=None):
        self.eid = eid; self.etype = etype; self.sev = sev; self.src = src; self.msg = msg; self.ts = ts; self.raw = raw or {}
    def to_dict(self) -> dict:
        return {'event_id': self.eid, 'event_type': self.etype, 'severity': self.sev, 'source': self.src, 'message': self.msg[:200], 'timestamp': self.ts}

_HOST = _sk.gethostname()

# ABC格式化契约
class _BaseFormatter(abc.ABC):
    @abc.abstractmethod
    def format(self, event: SIEMEvent) -> str: ...

class _CEF(_BaseFormatter):
    _sv = {'critical': '10', 'high': '8', 'medium': '5', 'low': '3', 'info': '1'}
    def format(self, e: SIEMEvent) -> str:
        sv = self._sv.get(e.sev, '5'); ts = int(e.ts * 1000) if e.ts else int(time.time() * 1000)
        hdr = f"CEF:0|BinMind|BAP|1.0|{e.eid}|{e.etype}|{sv}"
        ex = [f"msg={_esc(e.msg)}", f"src={_esc(e.src)}", f"rt={ts}", f"dvchost={_HOST}"]
        for k, v in e.raw.items():
            if isinstance(v, (str, int, float)): ex.append(f"{k}={_esc(str(v))}")
        return f"{hdr}|{' '.join(ex)}"

class _Syslog(_BaseFormatter):
    _sv = {'critical': 2, 'high': 4, 'medium': 5, 'low': 6, 'info': 6}
    def format(self, e: SIEMEvent) -> str:
        p = self._sv.get(e.sev, 5); pv = 16 * 8 + p
        ts = time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(e.ts or time.time()))
        return f"<{pv}>1 {ts} {_HOST} BinMind BAP {e.eid} - - [{e.etype}] {e.msg}"

class _LEEF(_BaseFormatter):
    def format(self, e: SIEMEvent) -> str:
        h = f"LEEF:2.0|BinMind|BAP|1.0|{e.eid}|"; t = e.ts if e.ts else time.time()
        return f"{h}\t" + "\t".join([f"sev={e.sev}", f"msg={e.msg}", f"src={e.src}", f"devTime={t:.0f}", f"dvc={_HOST}"])

class _ECS(_BaseFormatter):
    _sv = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    def format(self, e: SIEMEvent) -> str:
        ecs = {"@timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(e.ts or time.time())),
               "event": {"id": e.eid, "kind": "alert", "category": "vulnerability", "type": e.etype, "severity": self._sv.get(e.sev, 2), "original": e.msg},
               "observer": {"vendor": "BinMind", "product": "BAP", "hostname": _HOST}, "source": {"domain": e.src}}
        for rk, rv in e.raw.items():
            match rk:
                case "cve" | "cve_id": ecs.setdefault("vulnerability", {})["id"] = rv
                case "cvss" | "cvss_score":
                    try: ecs.setdefault("vulnerability", {})["score"] = {"base": float(rv)}
                    except (ValueError, TypeError): pass
                case "file" | "file_path": ecs.setdefault("file", {})["path"] = rv
        return json.dumps(ecs, ensure_ascii=False)

class _HEC(_BaseFormatter):
    def format(self, e: SIEMEvent) -> str:
        ev = {"event_id": e.eid, "event_type": e.etype, "severity": e.sev, "source": e.src, "message": e.msg}
        ev.update({k: v for k, v in e.raw.items() if isinstance(v, (str, int, float, bool, type(None)))})
        return json.dumps({"time": e.ts or time.time(), "host": _HOST, "source": "binmind", "sourcetype": "_json", "event": ev}, ensure_ascii=False)

# Provider registry with __init_subclass__ auto-registration
class FormatRegistry:
    _formatters: Dict[str, _BaseFormatter] = {}
    def __init_subclass__(cls, fmt: str = "", **kwargs):
        super().__init_subclass__(**kwargs)
        if fmt: FormatRegistry._formatters[fmt] = cls()

FormatRegistry._formatters = {"cef": _CEF(), "leef": _LEEF(), "syslog": _Syslog(), "ecs": _ECS(), "hec": _HEC()}

def _esc(s: str) -> str:
    return s.replace('\\', '\\\\').replace('|', '\\|').replace('=', '\\=').replace('\n', '\\n').replace('\r', '\\r')

def register_formatter(name: str, fmtr: _BaseFormatter):
    FormatRegistry._formatters[name.lower()] = fmtr

class SIEMIntegrator:
    def __init__(self, fmt: SIEMFormat = SIEMFormat.CEF):
        self.fmt = fmt; self._events: List[SIEMEvent] = []
    def push_event(self, etype, sev, src, msg, raw=None):
        import time; n = len(self._events); self._events.append(SIEMEvent(f"BAP-{n:06d}", etype, sev, src, msg, time.time(), raw or {}))
    def push_batch(self, findings: List[Dict[str, Any]]):
        import time; _now = time.time(); base = len(self._events)
        for i, f in enumerate(findings):
            self._events.append(SIEMEvent(f"BAP-{base + i + 1:06d}", f.get('type', 'vulnerability'), f.get('severity', 'medium'), f.get('source', 'binary_analysis'), f.get('description', ''), _now, f))
    def export(self, fmt=None, limit=100) -> str:
        fmt = fmt or self.fmt; key = fmt.value if isinstance(fmt, SIEMFormat) else str(fmt)
        fmtr = FormatRegistry._formatters.get(key, FormatRegistry._formatters["cef"])
        return '\n'.join(fmtr.format(e) for e in self._events[-limit:])
    def export_json(self, limit=100) -> str: return json.dumps([e.to_dict() for e in self._events[-limit:]], ensure_ascii=False)
    def export_hec_batch(self, limit=0) -> str:
        n = limit if limit > 0 else len(self._events); fmtr = FormatRegistry._formatters.get("hec")
        return '\n'.join(fmtr.format(e) for e in self._events[-n:]) if fmtr else "{}"
    def export_to_file(self, path, fmt=None, limit=0) -> str:
        if limit == 0: limit = len(self._events)
        payload = self.export(fmt, limit)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(payload)
            if not payload.endswith('\n'): fh.write('\n')
        return path
    def clear(self): self._events.clear()
    event_count = property(lambda self: len(self._events))
    def analyze(self, findings=None, export_format="cef", **kw) -> dict:
        if findings: self.push_batch(findings)
        try: ef = SIEMFormat(export_format)
        except ValueError: ef = SIEMFormat.CEF
        exported = self.export(ef)
        return {'success': True, 'total_events': len(self._events), 'export_format': ef.value, 'exported_lines': len(exported.split('\n')) if exported else 0, 'sample': exported[:1000] if exported else '', 'supported_formats': [f.value for f in SIEMFormat]}

def integrate_with_siem(findings, fmt="cef", **kw): return SIEMIntegrator().analyze(findings=findings, export_format=fmt)
__all__ = ["SIEMIntegrator", "SIEMEvent", "SIEMFormat", "integrate_with_siem", "register_formatter"]


def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

