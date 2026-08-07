# 多工具扫描流水线: DAG拓扑+层并行+SHA-256/Jaccard双重去重
from __future__ import annotations
import logging, time, hashlib, json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque

log = logging.getLogger(__name__)
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}

@dataclass
class ScanTask:
    name: str
    scanner_func: Callable
    depends_on: List[str] = field(default_factory=list)
    timeout: int = 300
    config: Dict = field(default_factory=dict)
    priority: int = 0

@dataclass
class ScanResult:
    task_name: str
    findings: List[Dict]
    duration_ms: float
    success: bool
    error: Optional[str] = None

@dataclass
class ScanPipeline:
    name: str
    tasks: List[ScanTask]
    results: Dict[str, ScanResult] = field(default_factory=dict)

class ScanOrchestrator:
    def __init__(self, mw=4): self._pool = ThreadPoolExecutor(max_workers=mw); self._tasks: Dict[str, ScanTask] = {}; self._store: Dict[str, Dict[str, ScanResult]] = {}

    def add_scanner(self, t):
        if t.name in self._tasks: log.warning("覆盖: %s", t.name)
        self._tasks[t.name] = t

    def build_dag(self):
        indeg = {n: 0 for n in self._tasks}; adj = defaultdict(list)
        for n, t in self._tasks.items():
            for d in t.depends_on:
                if d in self._tasks: adj[d].append(n); indeg[n] += 1
        q = deque([n for n, d in indeg.items() if d == 0]); tiers = []; proc = 0
        while q:
            tier = list(q); tiers.append(tier); nq = deque()
            for n in tier:
                proc += 1
                for m in adj[n]: indeg[m] -= 1
                if indeg[m] == 0: nq.append(m)
            q = nq
        if proc != len(self._tasks): log.error("循环依赖: %s", [n for n, d in indeg.items() if d > 0]); return []
        return tiers

    def execute(self, name="default"):
        tiers = self.build_dag()
        if not tiers: return ScanPipeline(name=name, tasks=list(self._tasks.values()))
        results = {}
        for tier in tiers:
            futs = {}
            for tn in tier: futs[self._pool.submit(self._tasks[tn].scanner_func, self._tasks[tn].config)] = tn
            for fut in as_completed(futs):
                tn = futs[fut]; st = time.time()
                try: fd = fut.result(timeout=self._tasks[tn].timeout); dur = (time.time() - st) * 1000; results[tn] = ScanResult(tn, fd or [], dur, True)
                except Exception as e: dur = (time.time() - st) * 1000; results[tn] = ScanResult(tn, [], dur, False, str(e)); log.exception("扫描器异常 [%s]", tn)
        deduped = self._dedup(results); merged = self._merge(deduped)
        pipe = ScanPipeline(name=name, tasks=list(self._tasks.values()), results=deduped); self._store[name] = deduped
        log.info("流水线 [%s] 完成: %d 结果, 合并 %d 发现", name, len(results), len(merged)); return pipe

    def _dedup(self, results):
        deduped = {}; seen = set(); all_f = []
        for n, sr in results.items():
            kept = []
            for f in sr.findings:
                fh = self._fh(f)
                if fh not in seen: seen.add(fh); kept.append(f); all_f.append((n, f))
            sr.findings = kept; deduped[n] = sr
        final_all = []; removed = set(); i = 0
        while i < len(all_f):
            if i in removed: i += 1; continue
            fi = all_f[i][1]; j = i + 1
            while j < len(all_f):
                if j not in removed and self._jac(fi, all_f[j][1]) >= 0.85: removed.add(j); fi.setdefault("merged_from", []).append(all_f[j][1].get("rule_id", ""))
                j += 1
            final_all.append(all_f[i]); i += 1
        fbt = defaultdict(list)
        for tn, f in final_all: fbt[tn].append(f)
        for n, sr in deduped.items(): sr.findings = fbt.get(n, [])
        log.debug("去重: %d 精确 + %d 模糊", len(seen), len(removed)); return deduped

    def _merge(self, results):
        all_f = []
        for sr in results.values(): all_f.extend(sr.findings)
        all_f.sort(key=lambda f: SEV.get(f.get("severity", "info").lower(), 5)); return all_f

    def _fh(self, f):
        return hashlib.sha256(f"{f.get('rule_id', '')}{f.get('file', '')}{f.get('line', '')}{f.get('title', '')}".encode()).hexdigest()

    def _jac(self, a, b):
        ta = f"{a.get('title', '')} {a.get('description', '')}"; tb = f"{b.get('title', '')} {b.get('description', '')}"
        sa = set(ta.lower().split()); sb = set(tb.lower().split())
        if not sa and not sb: return 1.0
        inter = sa & sb; union = sa | sb; return len(inter) / len(union) if union else 0.0

    def _topo_sort(self, tasks):
        indeg = {n: 0 for n in tasks}; adj = defaultdict(list)
        for n, t in tasks.items():
            for d in t.depends_on: adj[d].append(n); indeg[n] += 1
        q = deque([n for n, d in indeg.items() if d == 0]); order = []
        while q:
            n = q.popleft()
            order.append(n)
            for m in adj[n]:
                indeg[m] -= 1
                if indeg[m] == 0:
                    q.append(m)
        return order if len(order) == len(tasks) else []

    def _detect_cycles(self, adj):
        color = {n: 0 for n in adj}
        for n in list(adj.keys()):
            if color.get(n, 0) != 0: continue
            stack = [(n, 0)]
            while stack:
                node, idx = stack.pop()
                if idx == 0: color[node] = 1
                nbs = adj.get(node, [])
                if idx < len(nbs): stack.append((node, idx + 1)); nb = nbs[idx]; c = color.get(nb, 0)
                if c == 1: return True
                if c == 0: stack.append((nb, 0))
                else: color[node] = 2
        return False
