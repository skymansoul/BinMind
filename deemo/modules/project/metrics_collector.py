# Prometheus兼容指标: Counter/Gauge/Histogram/Summary
import time, threading, json, random, logging, functools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

log = logging.getLogger(__name__)

class MetricType: COUNTER = "counter"; GAUGE = "gauge"; HISTOGRAM = "histogram"; SUMMARY = "summary"

@dataclass
class Sample:
    name: str
    labels: Dict[str, str]
    value: float
    timestamp: float = field(default_factory=time.time)

@dataclass
class MetricFamily:
    name: str
    type: str
    help: str
    samples: List[Sample]

class Counter:
    def __init__(self, name, help="", labels=None): self.name = name; self.help = help; self.labels = labels or {}; self._v: float = 0; self._lk = threading.Lock()
    def inc(self, amt=1):
        with self._lk: self._v += amt
    def value(self):
        with self._lk: return self._v

class Gauge:
    def __init__(self, name, help="", labels=None): self.name = name; self.help = help; self.labels = labels or {}; self._v: float = 0; self._lk = threading.Lock()
    def set(self, v):
        with self._lk: self._v = v
    def inc(self, amt=1):
        with self._lk: self._v += amt
    def dec(self, amt=1):
        with self._lk: self._v -= amt
    def value(self):
        with self._lk: return self._v

class Histogram:
    def __init__(self, name, help="", labels=None, buckets=None):
        self.name = name; self.help = help; self.labels = labels or {}
        self._b = sorted(buckets) if buckets else [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        self._bc = [0] * len(self._b); self._cnt: int = 0; self._sum: float = 0.0; self._lk = threading.Lock()
    def observe(self, v):
        with self._lk:
            self._cnt += 1; self._sum += v
            for i, b in enumerate(self._b):
                if v <= b: self._bc[i] += 1
    @property
    def buckets(self): return list(self._b)
    count = property(lambda self: self._cnt)
    @property
    def sum(self): return self._sum

class Summary:
    def __init__(self, name, help="", labels=None, quantiles=None):
        self.name = name; self.help = help; self.labels = labels or {}; self._qs = quantiles or [0.5, 0.9, 0.99]
        self._res: List[float] = []; self._maxr = 1000; self._cnt: int = 0; self._sum: float = 0.0; self._lk = threading.Lock()
    def observe(self, v):
        with self._lk:
            self._cnt += 1; self._sum += v
            if len(self._res) < self._maxr: self._res.append(v)
            else:
                r = random.randint(0, self._cnt - 1)
                if r < self._maxr: self._res[r] = v
    def _q(self, q):
        if not self._res: return 0.0
        s = sorted(self._res); return s[int(q * (len(s) - 1))]
    @property
    def count(self): return self._cnt
    @property
    def sum(self): return self._sum

class MetricsRegistry:
    def __init__(self): self._ms: Dict[str, Any] = {}; self._lk = threading.Lock()
    def register(self, m):
        with self._lk: self._ms[m.name] = m
    def get(self, n): return self._ms.get(n)
    def get_or_create(self, mt, n, **kw):
        if ex := self._ms.get(n): return ex
        fm = {MetricType.COUNTER: lambda: Counter(n, **kw), MetricType.GAUGE: lambda: Gauge(n, **kw), MetricType.HISTOGRAM: lambda: Histogram(n, **kw), MetricType.SUMMARY: lambda: Summary(n, **kw)}
        m = fm[mt](); self.register(m); return m

    def export_text(self):
        lines = []
        for mf in self.collect():
            if mf.help: lines.append(f"# HELP {mf.name} {mf.help}")
            lines.append(f"# TYPE {mf.name} {mf.type}")
            for s in mf.samples:
                ls = "{" + ",".join(f'{k}="{v}"' for k, v in s.labels.items()) + "}" if s.labels else ""
                lines.append(f"{s.name}{ls} {s.value}")
            lines.append("")
        return "\n".join(lines)

    def export_json(self):
        return json.dumps([{"name": mf.name, "type": mf.type, "help": mf.help, "samples": [{"name": s.name, "labels": s.labels, "value": s.value, "timestamp": s.timestamp} for s in mf.samples]} for mf in self.collect()], indent=2)

    def export_statsd(self, prefix="binmind"):
        tm = {MetricType.COUNTER: "c", MetricType.GAUGE: "g", MetricType.HISTOGRAM: "h", MetricType.SUMMARY: "h"}
        return "\n".join(f"{prefix}.{s.name}:{s.value}|{tm.get(mf.type, 'g')}" for mf in self.collect() for s in mf.samples)

    def collect(self):
        families = []
        with self._lk: ms = list(self._ms.values())
        for m in ms:
            if hasattr(m, 'collect') and callable(m.collect):
                try:
                    for pm in m.collect(): families.append(MetricFamily(name=pm.name, type=pm.type, help=pm.documentation or "", samples=[Sample(name=s.name, labels=dict(s.labels), value=s.value, timestamp=s.timestamp or time.time()) for s in pm.samples]))
                except Exception: continue
            elif isinstance(m, Counter): families.append(MetricFamily(name=m.name, type=MetricType.COUNTER, help=m.help, samples=[Sample(name=m.name, labels=m.labels, value=m.value())]))
            elif isinstance(m, Gauge): families.append(MetricFamily(name=m.name, type=MetricType.GAUGE, help=m.help, samples=[Sample(name=m.name, labels=m.labels, value=m.value())]))
            elif isinstance(m, Histogram):
                ss = []; cum = 0
                for i, b in enumerate(m.buckets): cum += m._bc[i]; ss.append(Sample(name=f"{m.name}_bucket", labels={**m.labels, "le": str(b)}, value=cum))
                ss.extend([Sample(name=f"{m.name}_bucket", labels={**m.labels, "le": "+Inf"}, value=m.count), Sample(name=f"{m.name}_count", labels=m.labels, value=m.count), Sample(name=f"{m.name}_sum", labels=m.labels, value=m.sum)])
                families.append(MetricFamily(name=m.name, type=MetricType.HISTOGRAM, help=m.help, samples=ss))
            elif isinstance(m, Summary):
                ss = [Sample(name=m.name, labels={**m.labels, "quantile": str(q)}, value=m._q(q)) for q in m._qs]
                ss.extend([Sample(name=f"{m.name}_count", labels=m.labels, value=m.count), Sample(name=f"{m.name}_sum", labels=m.labels, value=m.sum)])
                families.append(MetricFamily(name=m.name, type=MetricType.SUMMARY, help=m.help, samples=ss))
        return families

_greg = MetricsRegistry()

def count_calls(name=None):
    def d(f):
        cn = name or f"{f.__name__}_calls_total"; ctr = _greg.get_or_create(MetricType.COUNTER, cn, help=f"Calls to {f.__name__}")
        @functools.wraps(f)
        def w(*a, **kw): ctr.inc(); return f(*a, **kw)
        return w
    return d

def track_inprogress(name=None):
    def d(f):
        gn = name or f"{f.__name__}_inprogress"; g = _greg.get_or_create(MetricType.GAUGE, gn, help=f"In-flight: {f.__name__}")
        @functools.wraps(f)
        def w(*a, **kw):
            g.inc()
            try:
                return f(*a, **kw)
            finally:
                g.dec()
        return w
    return d
