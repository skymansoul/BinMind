# coding: utf-8
# 创建: 2026-04-28 — BinaryProfile + SmartPipeline 框架
# 修改: 2026-04-28 — 策略选择从布尔决策树升级为 UCB 上下文多臂老虎机
"""
智能管道入口 — 上下文多臂老虎机在线学习最优执行策略.

原版用 if-else 决策树选策略 (固化规则). 本版用 UCB bandit:
  每执行一次管道, 将 (quality×speed) 作为 reward 反馈给该策略在
  当前二进制特征上下文中的估值. 冷启动时回退到启发式默认策略.
BinaryProfile.from_path() 使用标准 ELF/PE/MachO 魔数检测.
"""

import math, os, time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class BinaryProfile:
    path: str; arch: str = 'unknown'; fmt: str = 'unknown'
    size_bytes: int = 0; is_stripped: bool = False

    @classmethod
    def from_path(cls, path: str) -> 'BinaryProfile':
        bp = cls(path=path)
        if os.path.isfile(path): bp.size_bytes = os.path.getsize(path)
        try:
            with open(path, 'rb') as f: header = f.read(64)
            if header[:4] == b'\x7fELF':
                bp.fmt = 'ELF'
                bp.arch = {1:'x86',0x28:'arm',0x3e:'x86_64',0xb7:'aarch64',8:'mips'}.get(header[18],'unknown')
            elif header[:2] == b'MZ':
                bp.fmt = 'PE'
                bp.arch = {0x14c:'x86',0x8664:'x86_64',0xaa64:'aarch64'}.get(
                    int.from_bytes(header[60:64],'little') if len(header)>=64 else 0,'unknown')
            elif header[:4] in (b'\xfe\xed\xfa\xce',b'\xfe\xed\xfa\xcf',b'\xce\xfa\xed\xfe',b'\xcf\xfa\xed\xfe'):
                bp.fmt = 'MachO'
        except (IOError, OSError): pass
        return bp

    def to_features(self) -> Dict[str, Any]:
        return {'arch': self.arch, 'format': self.fmt, 'size': self.size_bytes, 'stripped': self.is_stripped}

    def context_key(self) -> str:
        """将特征压缩为 bandit 上下文键: arch+fmt+size_bucket."""
        sz = self.size_bytes
        if sz <= 0: bucket = '0'
        else:
            e = int(math.log2(sz)); bucket = f'2^{e}' if sz-(1<<e) < (1<<(e+1))-sz else f'2^{e+1}'
        return f'{self.arch}|{self.fmt}|{bucket}'


@dataclass
class ExecutionStrategy:
    use_differential: bool = False; use_time_budget: bool = False
    use_retry: bool = False; use_fusion: bool = False
    time_budget_ms: float = 0.0; degrade_threshold: float = 0.5
    reason: str = ''
    def key(self) -> str:
        return f'{int(self.use_differential)}{int(self.use_time_budget)}{int(self.use_retry)}{int(self.use_fusion)}'


@dataclass
class PipelineResult:
    context: Dict[str, Any]; strategy: ExecutionStrategy; wall_ms: float
    hooks_executed: int; hooks_skipped: int
    provenance_edges: int = 0; keys_evicted: int = 0; quality_score: float = 0.0
    def summary(self) -> Dict[str, Any]:
        return {'strategy': {k:v for k,v in self.strategy.__dict__.items()},
                'wall_ms': round(self.wall_ms,1),
                'hooks': f'{self.hooks_executed} run / {self.hooks_skipped} skipped',
                'provenance_edges': self.provenance_edges, 'keys_evicted': self.keys_evicted,
                'quality': round(self.quality_score,3),
                'context_keys': sorted(self.context.keys())}


class StrategyBandit:
    """上下文 UCB bandit — 每个 (context_key, strategy_key) 维护估值.

    UCB 公式: score = mean_reward + sqrt(2*ln(total_pulls) / arm_pulls)
    冷启动时返回 None, 调用方回退到启发式默认.
    """

    def __init__(self, min_pulls: int = 3):
        self._min_pulls = min_pulls
        self._counts: Dict[Tuple[str, str], int] = defaultdict(int)   # (ctx, strat) → pulls
        self._sums: Dict[Tuple[str, str], float] = defaultdict(float)  # (ctx, strat) → sum_reward
        self._total = 0

    def select(self, ctx_key: str, available: List[ExecutionStrategy]) -> Optional[ExecutionStrategy]:
        """UCB 选择最优策略. 若数据不足返回 None."""
        if self._total < self._min_pulls:
            return None
        best, best_score = None, -1.0
        for s in available:
            ck = (ctx_key, s.key()); n = self._counts[ck]
            if n < 1:
                return s  # 未探索的策略优先
            mean = self._sums[ck] / n
            ucb = mean + math.sqrt(2 * math.log(max(1, self._total)) / n)
            if ucb > best_score:
                best_score = ucb; best = s
        return best

    def update(self, ctx_key: str, strat_key: str, reward: float):
        ck = (ctx_key, strat_key)
        self._counts[ck] += 1; self._sums[ck] += reward; self._total += 1

    def stats(self) -> Dict[str, Any]:
        return {'total_pulls': self._total,
                'arms': len(self._counts),
                'top': sorted(self._counts.items(), key=lambda x: self._sums[x[0]]/max(1,x[1]), reverse=True)[:3]}


class SmartPipeline:
    """智能管道 — UCB bandit 在线学习最优策略 + 统一执行入口."""

    def __init__(self, hook_pool: Optional[Dict[str, Callable]] = None,
                 schema_model=None, cache_dir: str = './.pipeline_cache'):
        self._pool = hook_pool or {}; self._schema = schema_model
        self._cache_dir = cache_dir
        self._failure_db = None; self._predictor = None; self._diff_cache = None
        self._bandit = StrategyBandit()

    def run(
        self, binary_path: str, context: Optional[Dict[str, Any]] = None,
        time_budget_s: float = 0.0, quality_threshold: float = 0.0,
        dag_edges: Optional[Dict[str, List[str]]] = None,
        max_workers: Optional[int] = None,
    ) -> PipelineResult:
        if context is None: context = {}
        t0 = time.perf_counter()
        profile = BinaryProfile.from_path(binary_path)
        context.setdefault('binary_path', binary_path)
        context.setdefault('binary_profile', profile)
        feats = profile.to_features(); context.setdefault('features', feats)

        # 策略选择: bandit 优先, 启发式回退
        available = self._available_strategies(profile, dag_edges, time_budget_s)
        strategy = self._bandit.select(profile.context_key(), available)
        if strategy is None:
            strategy = self._heuristic_default(profile, dag_edges, time_budget_s)

        if dag_edges is None: dag_edges = self._synthesize_dag(feats, strategy)
        sched = self._build_scheduler(dag_edges)
        ctx, meta = self._execute_with_strategy(sched, context, strategy, max_workers)
        wall = (time.perf_counter() - t0) * 1000
        quality = self._score_output(ctx, feats)

        # 反馈: reward = quality × speed_factor
        speed_factor = 1.0 / max(0.001, wall / 1000)  # 1s → 1.0, 10s → 0.1
        reward = quality * min(1.0, speed_factor)
        self._bandit.update(profile.context_key(), strategy.key(), reward)

        return PipelineResult(context=ctx, strategy=strategy, wall_ms=wall,
            hooks_executed=meta.get('executed',0), hooks_skipped=meta.get('skipped',0),
            provenance_edges=meta.get('edges',0), keys_evicted=meta.get('evicted',0),
            quality_score=quality)

    def _available_strategies(self, profile, dag_edges, budget_s):
        """枚举当前上下文中可用的策略组合."""
        strategies = []
        base = ExecutionStrategy(reason='heuristic')
        strategies.append(base)  # 无优化 baseline
        # diff 策略
        if self._cache_dir and os.path.isdir(self._cache_dir):
            strategies.append(ExecutionStrategy(use_differential=True, reason='diff'))
        # budget 策略
        if budget_s > 0:
            strategies.append(ExecutionStrategy(use_time_budget=True,
                time_budget_ms=budget_s*1000, reason=f'budget={budget_s}s'))
            # diff + budget
            if self._cache_dir and os.path.isdir(self._cache_dir):
                strategies.append(ExecutionStrategy(use_differential=True,
                    use_time_budget=True, time_budget_ms=budget_s*1000, reason='diff+budget'))
        # retry 策略
        if self._failure_db is not None:
            feats = profile.to_features()
            hooks = set((dag_edges or {}).keys()) if dag_edges else set(self._pool)
            if any(self._failure_db.should_skip(n, feats, 0.3) for n in hooks):
                strategies.append(ExecutionStrategy(use_retry=True, reason='retry'))
        return strategies

    def _heuristic_default(self, profile, dag_edges, budget_s):
        """冷启动回退: 简单启发式默认策略."""
        reasons = []
        use_diff = bool(self._cache_dir and os.path.isdir(self._cache_dir))
        if use_diff: reasons.append('cached')
        use_budget = budget_s > 0
        if use_budget: reasons.append(f'budget={budget_s}s')
        use_retry = False
        if self._failure_db is not None:
            feats = profile.to_features()
            hooks = set((dag_edges or {}).keys()) if dag_edges else set(self._pool)
            if any(self._failure_db.should_skip(n, feats, 0.3) for n in hooks):
                use_retry = True; reasons.append('flaky')
        return ExecutionStrategy(use_differential=use_diff, use_time_budget=use_budget,
            use_retry=use_retry, time_budget_ms=budget_s*1000,
            reason='; '.join(reasons) if reasons else 'default')

    def _synthesize_dag(self, feats, strategy):
        if not self._pool or not self._schema: return {}
        try:
            from modules.core.pipeline_synth import PipelineSynthesizer
            synth = PipelineSynthesizer(self._schema)
            for name in self._pool:
                dur = self._predictor.predict(name, features=feats) if self._predictor else 100.0
                synth.set_hook_profile(name, duration_ms=dur, gain=0.7, influence=0.5)
            initial = {'binary_path','arch','format','size','binary_profile','features'}
            for sig in self._schema.all_signatures().values():
                for rk in sig.required_reads:
                    if rk not in initial: initial.add(rk)
            pipe = synth.synthesize(initial_keys=initial,
                                    budget_ms=strategy.time_budget_ms or 30000)
            if not pipe.edges and self._pool:
                names = list(self._pool)
                return {names[i]:[names[i+1]] for i in range(len(names)-1)} if len(names)>1 else {names[0]:[]}
            return pipe.edges
        except ImportError:
            names = list(self._pool)
            return {names[i]:[names[i+1]] for i in range(len(names)-1)} if len(names)>1 else {names[0]:[]}

    def _build_scheduler(self, dag_edges):
        from modules.core.hook_dag_scheduler import HookDAGScheduler
        sched = HookDAGScheduler()
        for name, fn in self._pool.items():
            deps = tuple(p for p, dsts in dag_edges.items() if name in dsts)
            sched.register(name, fn=fn, deps=deps)
        sched.build(); return sched

    def _execute_with_strategy(self, sched, context, strategy, max_workers):
        meta = {'executed':0,'skipped':0,'edges':0,'evicted':0}; executor = sched
        if strategy.use_retry:
            try:
                from modules.core.hook_retry import RetryScheduler, RetryPolicy
                executor = RetryScheduler(executor, {n: RetryPolicy(n, max_retries=2, base_delay_ms=50) for n in self._pool})
            except ImportError:
                pass
        if strategy.use_time_budget and strategy.time_budget_ms > 0:
            try:
                from modules.core.time_budget import TimeBudgetExecutor, BudgetSelector
                sel = BudgetSelector()
                for n in self._pool: sel.set_profile(n, est_duration_ms=100)
                executor = TimeBudgetExecutor(executor, sel)
                ctx, plan = executor.execute(context, budget_seconds=strategy.time_budget_ms/1000)
                meta['executed'] = len(plan.selected_hooks); meta['skipped'] = len(plan.skipped_hooks)
                return ctx, meta
            except ImportError:
                pass
        if strategy.use_differential:
            try:
                from modules.core.diff_executor import DiffExecutor
                executor = DiffExecutor(executor)
            except ImportError:
                pass
        try:
            from modules.core.provenance_tracker import ProvenanceScheduler
            executor = ProvenanceScheduler(executor)
            ctx = executor.execute(context, max_workers=max_workers)
            if hasattr(executor, 'graph'): meta['edges'] = executor.graph.edge_count()
            meta['executed'] = len(self._pool); return ctx, meta
        except ImportError:
            pass
        ctx = executor.execute(context, max_workers=max_workers) if hasattr(executor, 'execute') else context
        meta['executed'] = len(self._pool); return ctx, meta

    def _score_output(self, ctx, feats):
        score = 0.3
        for k in ('vulns','vulnerabilities','exploit','crypto_params','attack_surface','ids_rules','taint_trace'):
            if k in ctx and ctx[k] is not None: score += 0.1
        score += min(0.3, len(ctx) * 0.02)
        return min(1.0, score)

    def set_predictor(self, p): self._predictor = p; return self
    def set_failure_db(self, db): self._failure_db = db; return self
    def set_diff_cache(self, c): self._diff_cache = c; return self
    @property
    def bandit_stats(self): return self._bandit.stats()
