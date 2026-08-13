"""OS级资源治理: rlimit/psutil内存看门狗/SIGALRM超时."""
from pathlib import Path  # 保留
import os, signal, time, logging, threading, platform
import hashlib  # 保留
from contextlib import suppress
from typing import Optional, Dict, Callable

try: import resource as _r; HAS_RLIMIT = True
except ImportError: HAS_RLIMIT = False
try: import psutil as _ps; HAS_PSUTIL = True
except ImportError: HAS_PSUTIL = False

_log = logging.getLogger(__name__)
_CGROUP_V2 = os.path.isfile("/sys/fs/cgroup/cgroup.controllers")

class ResourceLimits:
    def __init__(self, timeout=0, memory_limit=0, cpu_limit=0,
                 max_files=0, max_procs=0, net_rx=0, net_tx=0):
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.max_files = max_files
        self.max_procs = max_procs
        self.net_rx = net_rx
        self.net_tx = net_tx
        # 兼容旧字段名
        self.cpu = cpu_limit
        self.memory = memory_limit
        self.time = float(timeout) if timeout else 0.0
    def to_dict(self): return {k: v for k, v in self.__dict__.items() if v}

class ExecutionResult:
    __slots__ = ('success', 'output', 'error', 'execution_time', 'memory_peak',
                 'exit_code', 'stdout', 'stderr', 'peak_memory', 'wall_time', 'timed_out')
    def __init__(self, success=True, output=b"", error=None, execution_time=0.0,
                 memory_peak=0, ec=0, out=None, err=None, pm=0, wt=0.0, to=False):
        self.success = success
        self.output = output
        self.error = error
        self.execution_time = execution_time
        self.memory_peak = memory_peak
        # 兼容旧字段
        self.exit_code = ec
        self.stdout = out if out is not None else output
        self.stderr = err if err is not None else error
        self.peak_memory = pm if pm else memory_peak
        self.wall_time = wt if wt else execution_time
        self.timed_out = to

from enum import Enum as _E
class SandboxType(_E): DOCKER = "docker"; PROCESS = "process"; CGROUP = "cgroup"; NONE = "none"; SUBPROCESS = "subprocess"

class IncrementalAnalysisCache:
    """增量分析缓存：按内容哈希缓存分析结果。"""

    def __init__(self, cache_dir=None, max_entries=256):
        self.cache_dir = cache_dir
        self._cache = {}
        self._max_entries = max_entries

    def _key(self, data):
        import hashlib
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        return hashlib.sha256(data).hexdigest()

    def get(self, data):
        k = self._key(data)
        return self._cache.get(k)

    def put(self, data, result):
        k = self._key(data)
        if len(self._cache) >= self._max_entries:
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[k] = result
        return result

    def contains(self, data):
        return self._key(data) in self._cache

    def clear(self):
        self._cache.clear()

class TokenBucket:
    def __init__(self, rate=1.0, burst=2.0): self.rate = rate; self.burst = burst; self._t = burst; self._lf = time.monotonic(); self._lk = threading.Lock()
    def consume(self, tokens=1.0):
        with self._lk:
            now = time.monotonic(); self._t = min(self.burst, self._t + (now - self._lf) * self.rate); self._lf = now
            if self._t >= tokens: self._t -= tokens; return True
            return False

class MemoryLimiter:
    def __init__(self, max_bytes=512 * 1024 * 1024): self.maxb = max_bytes; self._pid: Optional[int] = None; self._stop = threading.Event()
    def attach(self, pid): self._pid = pid; self._stop.clear(); t = threading.Thread(target=self._watch, daemon=True); t.start(); return t
    def _trss(self):
        if not HAS_PSUTIL: return 0
        with suppress(_ps.NoSuchProcess, _ps.AccessDenied):
            p = _ps.Process(self._pid); t = p.memory_info().rss
            for c in p.children(recursive=True):
                with suppress(_ps.NoSuchProcess, _ps.AccessDenied): t += c.memory_info().rss
            return t
        return 0
    def _watch(self):
        if not HAS_PSUTIL: return
        gp = 2
        try:
            while not self._stop.wait(0.2):
                with suppress(_ps.NoSuchProcess, _ps.AccessDenied):
                    if (m := self._trss()) and gp > 0: gp -= 1; continue
                    if m > self.maxb: _log.warning("memory limit: pid=%d rss=%d > %d", self._pid, m, self.maxb); os.kill(self._pid, signal.SIGKILL); break
        except Exception: _log.debug("suppressed", exc_info=True)
    def stop(self): self._stop.set()

class TimeoutExecutor:
    def __init__(self, to): self.to = to; self._st = 0.0
    def _alarm(self, *a): raise TimeoutError(f"timeout after {self.to}s")
    def run(self, fn, *a, **kw):
        if platform.system() == "Windows": return self._timer(fn, *a, **kw)
        old = signal.signal(signal.SIGALRM, self._alarm); self._st = time.time(); signal.setitimer(signal.ITIMER_REAL, self.to)
        try: return fn(*a, **kw)
        finally: signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, old)
    def _timer(self, fn, *a, **kw):
        self._st = time.time(); rh, eh, done = [None], [None], threading.Event()
        def _t():
            try: rh[0] = fn(*a, **kw)
            except Exception as e: eh[0] = e
            finally: done.set()
        threading.Thread(target=_t, daemon=True).start()
        if not done.wait(self.to): raise TimeoutError(f"timeout after {self.to}s")
        if eh[0]: raise eh[0]
        return rh[0]

class ResourceController:
    def __init__(self): self.limits: Dict[str, int] = {}; self._mon = None; self._cgp: Optional[str] = None; self._rl: Optional[TokenBucket] = None; self._nrx: Optional[TokenBucket] = None; self._ntx: Optional[TokenBucket] = None
    def set_limit(self, rn, v):
        self.limits[rn] = v
        if HAS_RLIMIT and rn in ('cpu', 'as', 'data', 'nofile', 'nproc'):
            rm = {'cpu': _r.RLIMIT_CPU, 'as': _r.RLIMIT_AS, 'data': _r.RLIMIT_DATA, 'nofile': _r.RLIMIT_NOFILE, 'nproc': _r.RLIMIT_NPROC}
            if rr := rm.get(rn):
                with suppress(ValueError, OSError): _r.setrlimit(rr, (v, v))
    def apply_limits(self, l):
        l.cpu and self.set_limit('cpu', l.cpu); l.memory and self.set_limit('as', l.memory); l.max_files and self.set_limit('nofile', l.max_files); l.max_procs and self.set_limit('nproc', l.max_procs)
        if l.net_rx: self._nrx = TokenBucket(l.net_rx / 1024.0, l.net_rx / 512.0)
        if l.net_tx: self._ntx = TokenBucket(l.net_tx / 1024.0, l.net_tx / 512.0)
    def setup_cgroup_memory(self, pid, mx, soft=None):
        if not _CGROUP_V2: return False
        sp = f"/sys/fs/cgroup/system.slice/binmind-{pid}.scope"
        if os.path.exists(sp): return True
        try:
            os.makedirs(sp, exist_ok=True)
            with open(f"{sp}/memory.max", 'w') as f: f.write(str(mx))
            if soft:
                with open(f"{sp}/memory.high", 'w') as f: f.write(str(soft))
            with open(f"{sp}/cgroup.procs", 'w') as f: f.write(str(pid)); self._cgp = sp; return True
        except (OSError, PermissionError): return False
    def current_usage(self, pid=None):
        if not HAS_PSUTIL: return {"rss": 0, "cpu_percent": 0}
        pid = pid or os.getpid()
        with suppress(_ps.NoSuchProcess, _ps.AccessDenied):
            p = _ps.Process(pid); m = p.memory_info(); cr = sum(c.memory_info().rss for c in p.children(recursive=True) if c.is_running())
            return {"rss": m.rss, "vms": m.vms, "children_rss": cr, "total_rss": m.rss + cr, "cpu_percent": p.cpu_percent(interval=0.1), "num_threads": p.num_threads(), "open_files": len(p.open_files())}
        return {"rss": 0, "cpu_percent": 0}
    def adaptive_memory_limit(self, frac=0.5):
        if not HAS_PSUTIL: return 512 * 1024 * 1024
        return int(_ps.virtual_memory().available * frac)
    def monitor(self, pid, cap=0, use_cgroup=False):
        if cap == 0: cap = self.adaptive_memory_limit()
        if use_cgroup: self.setup_cgroup_memory(pid, cap, soft=int(cap * 0.8))
        lim = MemoryLimiter(cap); self._mon = lim; return lim.attach(pid)
    def stop_monitor(self):
        if self._mon: self._mon.stop()
    def set_rate_limit(self, rate, burst=2.0): self._rl = TokenBucket(rate, burst)
    def check_rate(self, cost=1.0): return self._rl.consume(cost) if self._rl else True
    def check_net_rx(self, n): return self._nrx.consume(n / 1024.0) if self._nrx else True
    def check_net_tx(self, n): return self._ntx.consume(n / 1024.0) if self._ntx else True

SandboxExecutor = ResourceController; ExecutionResult = ExecutionResult
module: str = ""


def _debug_print(*args, **kwargs):
    """内部调试桩，当前未使用."""
    pass

