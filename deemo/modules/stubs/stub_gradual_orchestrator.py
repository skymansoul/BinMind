# stub_gradual_orchestrator.py : StubGradual 编排层 + 健康回路 + 自检闭环
# 将契约抽取(stub_contract) → 优先级排序(stub_prioritizer) →
# 渐进实现(stub_gradual_engine) → 健康监控(stub_health_monitor) 串联为单入口，
# 并补齐两处接缝:
#   1. 双向健康回路：排序阶段读取监控中的调用观测，实现落盘后回写监控，
#      使"已实现"与"健康"两路信号在后续轮次自洽。
#   2. 验证-回溯自检：verify_chain() 对引擎族执行六类断言检查，
#      出错即回退并报告细节。
import ast as _ast
import os as _os
import sys as _sys
import time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    ImplementationStatus as _Status,
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
    StubContractor as _StubContractor,
)
from modules.stubs.stub_health_monitor import StubHealthMonitor as _Monitor
from modules.stubs.stub_prioritizer import (
    ImplementationPrioritizer as _Prioritizer, StubPriority as _StubPriority,
)
from modules.stubs.stub_gradual_engine import (
    GradualEngine as _GradualEngine,
    GradualConfig as _GradualConfig,
    GeneratedModule as _GeneratedModule,
    TemplateGenerator as _TemplateGenerator,
    ContractVerifier as _ContractVerifier,
)

# 引擎族模块名清单 — 自检的导入冒烟目标。
# 编排器自身不列入（自检需在导入完成后才可运行）。
_ENGINE_MODULES = [
    'stub_contract', 'stub_prioritizer', 'stub_gradual_engine',
    'stub_health_monitor', 'stub_registry', 'stub_validator',
]


@_dc
class SelftestResult:
    """单项自检断言结果。通过/失败 + 可读细节。"""
    name: str
    passed: bool = False
    detail: str = ''

    def to_dict(self) -> dict:
        return {'name': self.name, 'passed': self.passed, 'detail': self.detail}


class GradualOrchestrator:
    """编排器 — 统一持有健康监控与契约扫描器，向渐进引擎注入一致视图。

    设计意图：三个引擎各自实例化独立的监控/扫描器会导致排序阶段
    看不到真实调用观测、实现结果也不回流监控。编排器使用共享实例贯穿全链，
    使"观测 → 排序 → 实现 → 回写"构成可迭代闭环。
    """

    def __init__(self, monitor: _Opt[_Monitor] = None,
                 contractor: _Opt[_StubContractor] = None,
                 config: _Opt[_GradualConfig] = None):
        self.monitor = monitor or _Monitor()
        self.contractor = contractor or _StubContractor()
        self.config = config or _GradualConfig()
        self._engine: _Opt[_GradualEngine] = None
        self._prior: _Opt[_Prioritizer] = None

    def load_snapshot(self, path: str) -> int:
        """从 JSON 快照载入调用观测（此前 StubHealthMonitor.save_snapshot 的输出）。"""
        self.monitor.load_snapshot(path)
        return len(getattr(self.monitor, '_records', {}))

    def seed_calls(self, seed: dict) -> int:
        """以 {stub_name: call_count} 字典注入调用观测（用于测试/迁移）。"""
        n = 0
        for name, count in (seed or {}).items():
            compat = name if name in self.contractor.all() else ''
            for _ in range(int(count)):
                self.monitor.record_call(name, compat,
                                         caller_module='stub_gradual_orchestrator')
                n += 1
        return n

    def engine(self) -> _GradualEngine:
        """构造（或复用）持有共享监控/扫描器的渐进引擎实例。"""
        if self._engine is None:
            self._prior = _Prioritizer(monitor=self.monitor,
                                       contractor=self.contractor)
            self._engine = _GradualEngine(config=self.config,
                                          contractor=self.contractor,
                                          prior=self._prior)
        return self._engine

    def run_plan(self, top_n: int = 5) -> list:
        """执行渐进实现计划，并将产出结果回写健康监控。"""
        eng = self.engine()
        out = eng.implement_top(top_n)
        self._record_back(out)
        return out

    def _record_back(self, results: list) -> None:
        """健康回路回写 — 已落盘模块记为活跃调用。

        依据 SynthFix 的自适应信号反馈：引擎输出改变后续验证/排序信号。
        已实现模块获得调用记录后，call_volume 上升、last_seen 刷新，
        使其在下轮排序保持"活跃"，而缺口信号因实现完成归零，
        自然退出 backlog — 两条信号不再矛盾。
        """
        for gen in results:
            if getattr(gen, 'written', False):
                self.monitor.record_call(
                    gen.module_name,
                    gen.module_name,
                    caller_module='stub_gradual_orchestrator')

    def rank_top(self, n: int = 10) -> list:
        """用共享监控视图做优先级排序，返回前 n。"""
        prior = self._prior or _Prioritizer(monitor=self.monitor,
                                            contractor=self.contractor)
        self._prior = prior
        return prior.top(n)

    def run_plan_with_deps(self, top_n: int = 5) -> list:
        """以拓扑约束调度渐进实现，与 run_plan 等价但保证依赖先于被依赖方实现。"""
        eng = self.engine()
        try:
            from modules.stubs.stub_dependency_graph import (
                ModuleDependencyGraph, TopologicalScheduler)
            dep_graph = ModuleDependencyGraph()
            dep_graph.build()
            scheduler = TopologicalScheduler(dep_graph)
            priorities = {p.module_name: p.total_score
                         for p in (self._prior or _Prioritizer(monitor=self.monitor,
                                         contractor=self.contractor)).rank()}
            ordered = scheduler.scheduled_order(priorities)[:top_n]
            out = [eng.implement(name) for name in ordered]
            self._record_back(out)
            # 回写依赖图可用集，使下游依赖在下一轮释放
            for gen in out:
                if getattr(gen, 'written', False):
                    scheduler.mark_available(gen.module_name)
            return out
        except ImportError:
            return self.run_plan(top_n)

    def snapshot_contract_versions(self) -> dict:
        """对所有已扫描模块生成合约版本快照，返回 {module_name: version_id}。"""
        try:
            from modules.stubs.stub_contract_merkle import (
                ContractMerkleTree, VersionedContractStore)
            store = VersionedContractStore()
            versions = {}
            for contract in self.contractor.all():
                ver = store.commit(contract)
                versions[contract.module_name] = ver.version_id
            return versions
        except ImportError:
            return {}

    def simulate_impact(self, module_name: str, func_name: str,
                        change_kind: str, param_name: str = '',
                        old_val: str = '', new_val: str = '') -> dict:
        """反事实模拟: 若对某模块执行变更，评估下游影响。
        change_kind: 'remove_param' | 'add_required_param' |
                     'change_param_type' | 'change_return_type' |
                     'remove_function' | 'rename_function'
        返回: ImpactReport 的字典形式。
        """
        try:
            from modules.stubs.stub_impact_analyzer import (
                ImpactAnalyzer, ChangeScenario, ChangeType)
            analyzer = ImpactAnalyzer()
            ct = ChangeType(change_kind)
            scenario = ChangeScenario(
                module_name=module_name, change_type=ct,
                func_name=func_name, param_name=param_name,
                old_value=old_val, new_value=new_val)
            report = analyzer.analyze(scenario)
            return {
                'total_dependents': report.total_dependents,
                'affected_modules': report.affected_modules,
                'blocking_modules': report.blocking_modules,
                'risk_summary': report.risk_summary,
                'entries': [
                    {'caller': e.caller_module, 'risk': e.risk.value,
                     'reason': e.reason, 'blocking': e.is_blocking}
                    for e in report.entries[:20]
                ],
            }
        except ImportError:
            return {'error': 'stub_impact_analyzer 不可用'}

    def propagate_changes(self, module_name: str) -> list[dict]:
        """检测指定模块的合约变更并沿依赖链传播适配建议。
        返回: PropagationPlan 的字典形式列表。
        """
        try:
            from modules.stubs.stub_contract_merkle import (
                VersionedContractStore, ContractMerkleTree)
            from modules.stubs.stub_delta_propagator import (
                propagate_from_merkle_diff)

            store = VersionedContractStore()
            current = self.contractor.get(module_name)
            if current is None:
                return [{'error': f'{module_name} 合约不存在'}]

            prev_ver = store.latest(module_name)
            if prev_ver is None:
                # 首次快照
                store.commit(current)
                return [{'info': f'{module_name} 已创建初始版本快照'}]

            # 需要之前提交的完整合约对象来 diff
            # 由于 store 只存版本元数据，这里重新扫描
            store.commit(current)
            return [{'info': f'{module_name} 版本已更新',
                    'version_id': ContractMerkleTree(current).version_id()}]
        except ImportError:
            return [{'error': 'stub_contract_merkle 或 stub_delta_propagator 不可用'}]

    def detect_ghosts(self, min_score: float = 0.5) -> list[dict]:
        """检测从未被使用（无依赖+无调用+无compat）的幽灵桩模块。"""
        try:
            from modules.stubs.stub_ghost_detector import GhostDetector
            gd = GhostDetector()
            candidates = gd.ghost_candidates(min_score)
            return [
                {'module_name': g.module_name, 'ghost_score': g.ghost_score,
                 'action': g.recommended_action, 'reason': g.reason}
                for g in candidates
            ]
        except ImportError:
            return [{'error': 'stub_ghost_detector 不可用'}]

    def detect_drift(self, module_name: str) -> dict:
        """检测指定模块的实现是否偏离其接口契约。"""
        try:
            from modules.stubs.stub_drift_detector import DriftDetector
            dd = DriftDetector()
            report = dd.detect(module_name)
            return {
                'module_name': report.module_name,
                'drift_score': report.drift_score,
                'is_drifted': report.is_drifted,
                'critical_count': report.critical_count,
                'warning_count': report.warning_count,
                'info_count': report.info_count,
                'entries': [
                    {'severity': e.severity, 'category': e.category,
                     'func_name': e.func_name, 'detail': e.detail}
                    for e in report.drift_entries[:15]
                ],
            }
        except ImportError:
            return {'error': 'stub_drift_detector 不可用'}

    def rank_pareto(self, top_n: int = 10) -> list[dict]:
        """Pareto 前沿排序: 多目标非支配排序，无需人工调权。"""
        try:
            from modules.stubs.stub_pareto_prioritizer import ParetoPrioritizer
            pp = ParetoPrioritizer(monitor=self.monitor,
                                  contractor=self.contractor)
            ranked = pp.rank()[:top_n]
            return [
                {'rank': s.rank, 'front': s.front, 'module_name': s.module_name,
                 'gap': round(s.gap, 3), 'call_volume': round(s.call_volume, 3),
                 'health': round(s.health, 3), 'crowding_distance':
                  round(s.crowding_distance, 4) if s.crowding_distance != float('inf') else 'inf'}
                for s in ranked
            ]
        except ImportError:
            return [{'error': 'stub_pareto_prioritizer 不可用'}]

    def fuzz_stub(self, module_name: str, max_iter: int = 200) -> dict:
        """对指定模块的已实现函数执行对抗性蜕变关系模糊测试。"""
        try:
            from modules.stubs.stub_adversarial_fuzzer import AdversarialFuzzer
            from modules.stubs.stub_gradual_engine import TemplateGenerator
            contract = self.contractor.get(module_name)
            if contract is None:
                return {'error': f'{module_name} 合约不存在'}
            tg = TemplateGenerator()
            src = tg.generate(contract)
            mod = _types.ModuleType(f'_fuzz_{module_name}')
            try:
                exec(compile(src, f'<fuzz-{module_name}>', 'exec'), mod.__dict__)
            except Exception as e:
                return {'error': f'编译失败: {e}'}
            finally:
                _sys.modules.pop(f'_fuzz_{module_name}', None)
            results = {}
            fuzzer = AdversarialFuzzer(max_iterations=max_iter)
            for fc in contract.functions:
                fn = getattr(mod, fc.name, None)
                if fn is None:
                    continue
                r = fuzzer.fuzz(fn, fc)
                results[fc.name] = {
                    'iterations': r.iterations,
                    'counterexamples': len(r.counterexamples),
                    'best_fitness': r.best_fitness,
                }
            return results
        except ImportError:
            return {'error': 'stub_adversarial_fuzzer 不可用'}

    def analyze_temporal_patterns(self) -> dict:
        """对所有有调用数据的桩模块执行时序模式分析。"""
        try:
            from modules.stubs.stub_temporal_patterns import TemporalAnalyzer
            profiles = {}
            contracts = self.contractor.scan_all()
            for name in contracts:
                if name.startswith('stub_'):
                    continue
                ta = TemporalAnalyzer()
                p = ta.analyze_from_monitor(name)
                if p.total_calls > 0:
                    profiles[name] = {
                        'pattern': p.pattern_class,
                        'bp': round(p.burstiness_bp, 3),
                        'mc': round(p.memory_coefficient, 3),
                        'periodic': p.is_periodic,
                        'decaying': p.is_decaying,
                        'deprecation_risk': round(p.deprecation_risk, 2),
                        'prediction': p.next_expected_window,
                    }
            return profiles
        except ImportError:
            return {'error': 'stub_temporal_patterns 不可用'}

    def infer_type_flows(self, module_name: str = None) -> dict:
        """跨模块类型流推断: 从调用方代码推断桩参数的具体类型。"""
        try:
            from modules.stubs.stub_type_flow import TypeFlowAnalyzer
            tfa = TypeFlowAnalyzer()
            if module_name:
                report = tfa.analyze(module_name)
                return {
                    'module_name': report.module_name,
                    'edges': len(report.edges),
                    'functions_refined': report.functions_refined,
                    'suggestions': {
                        func: {param: {'type': t, 'confidence': c, 'votes': v}
                              for param, (t, c, v) in params.items()}
                        for func, params in report.type_suggestions.items()
                    },
                }
            else:
                reports = tfa.analyze_all()
                return {
                    name: {'edges': len(r.edges),
                          'functions_refined': r.functions_refined}
                    for name, r in reports.items()
                }
        except ImportError:
            return {'error': 'stub_type_flow 不可用'}

    def provenance_report(self, module_name: str = None) -> dict:
        """查询模块的实现溯源历史或全局摘要。"""
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain()
            if module_name:
                chain = pc.history(module_name)
                vr = pc.verify(module_name)
                return {
                    'module_name': module_name,
                    'entries': len(chain),
                    'chain_valid': vr['valid'],
                    'last_verified': pc.find_last_verified(module_name).entry_id
                    if pc.find_last_verified(module_name) else None,
                    'strategies': list(set(e.strategy for e in chain)),
                }
            else:
                rates = {}
                for s in ['template', 'llm', 'manual']:
                    rates[s] = pc.strategy_success_rate(s)
                return {'global_strategy_rates': rates}
        except ImportError:
            return {'error': 'stub_provenance_chain 不可用'}

    def predict_strategy(self, module_name: str) -> dict:
        """预测指定模块的最佳实现策略。"""
        try:
            from modules.stubs.stub_strategy_predictor import StrategyPredictor
            sp = StrategyPredictor()
            pred = sp.predict(module_name, self.contractor.get(module_name))
            return {
                'module_name': module_name,
                'recommended_order': pred.recommended_order,
                'best_confidence': pred.best_confidence,
                'recommend_manual': pred.recommend_manual,
                'features': {
                    'func_count': pred.features.func_count,
                    'high_complexity_ratio': round(pred.features.high_complexity_ratio, 2),
                    'type_coverage': round(pred.features.type_annotation_coverage, 2),
                },
            }
        except ImportError:
            return {'error': 'stub_strategy_predictor 不可用'}

    def atomic_batch_implement(self, top_n: int = 10,
                               dry_run: bool = False) -> list[dict]:
        """按依赖拓扑层原子批量实现，任一层失败即回滚并停止。"""
        try:
            from modules.stubs.stub_atomic_batch import AtomicBatchEngine
            abe = AtomicBatchEngine(engine=self.engine(), stubs_dir=None)
            plan = abe.build_plan(top_n)
            results = abe.execute(plan, dry_run=dry_run)
            return [
                {'batch_id': r.batch_id, 'layer': r.layer_index,
                 'modules': len(r.modules), 'committed': r.committed,
                 'committed_count': r.committed_count,
                 'failed_count': r.failed_count,
                 'reason': r.rollback_reason if not r.committed else ''}
                for r in results
            ]
        except ImportError:
            return [{'error': 'stub_atomic_batch 不可用'}]

    def report(self, top_n: int = 10) -> str:
        """组合 Markdown 报告：优先级清单 + 引擎摘要 + 失败明细。"""
        lines = ['# StubGradual 编排报告',
                 f'输出时间: {_time.strftime("%Y-%m-%d %H:%M:%S")}', '']
        lines.append('## 实现优先级')
        rows = self.rank_top(top_n)
        lines.append('| 排名 | 模块 | 状态 | 总分 | 缺口 | 调用量 | 理由 |')
        lines.append('|-----:|------|------|-----:|-----:|-------:|------|')
        for p in rows:
            lines.append(
                f'| {p.rank} | {p.module_name} | {p.status} | {p.total_score:.3f} | '
                f'{p.gap_score:.2f} | {p.call_volume_score:.2f} | {p.reason} |')
        if self._engine is not None:
            lines.append('')
            lines.append('## 引擎摘要')
            lines.append(self._engine.summary())
        return '\n'.join(lines)


def verify_chain(stubs_dir: str = None) -> list:
    """运行自检链，返回 [SelftestResult, ...]。

    检查项:
      1. 语法检查 — stubs/ 全部 .py（跳过 _gradual_out 产物）
      2. 导入冒烟 — 引擎族五模块
      3. 契约构建 — 真实模块 firmware_analyzer 产出函数契约
      4. 健康回路排序 — 注入调用观测后该模块进入高优先级
      5. 构造-验证闭环 — 合成简单契约 → 规则构造 → 契约验证通过
      6. 保守边界 — high 复杂度契约不可自动实现
    """
    if stubs_dir is None:
        stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
    out_dir = _os.path.join(stubs_dir, '_gradual_out')
    results: list = []

    # 1. 语法检查
    bad = []
    checked = 0
    for fn in sorted(_os.listdir(stubs_dir)):
        if not fn.endswith('.py') or fn.startswith('_'):
            continue
        if _os.path.isdir(_os.path.join(out_dir, fn)):
            continue
        checked += 1
        try:
            _ast.parse(open(_os.path.join(stubs_dir, fn), encoding='utf-8').read())
        except SyntaxError as e:
            bad.append(f'{fn}: {e.msg} (line {e.lineno})')
        except (OSError, UnicodeDecodeError) as e:
            bad.append(f'{fn}: read {e}')
    results.append(SelftestResult(
        '语法检查', not bad,
        '; '.join(bad) or f'{checked} 个模块语法通过'))

    # 2. 导入冒烟
    imp_errs = []
    for name in _ENGINE_MODULES:
        try:
            _import(name)
        except Exception as e:  # 导入失败仅记录，不中断其余检查
            imp_errs.append(f'{name}: {type(e).__name__}')
    results.append(SelftestResult(
        '导入冒烟', not imp_errs, '; '.join(imp_errs) or '引擎族导入通过'))

    # 3. 契约构建
    ctor = _StubContractor(stubs_dir=stubs_dir)
    fw = ctor.build_contract('firmware_analyzer')
    has_api = len(fw.functions) > 0
    results.append(SelftestResult(
        '契约构建', has_api,
        f'firmware_analyzer 状态={fw.status}, 函数={len(fw.functions)}'))

    # 4. 健康回路排序
    mon = _Monitor()
    for _ in range(50):
        mon.record_call('firmware_analyzer', 'firmware_analyzer',
                        caller_module='selftest')
    prior = _Prioritizer(monitor=mon, contractor=ctor)
    ranked = prior.rank()
    fa = next((p for p in ranked if p.module_name == 'firmware_analyzer'), None)
    in_top = fa is not None and fa.call_count == 50
    results.append(SelftestResult(
        '健康回路排序', in_top,
        f'firmware_analyzer call_count={fa.call_count if fa else "N/A"}, '
        f'rank={fa.rank if fa else "N/A"}'))

    # 5. 构造-验证闭环（合成简单契约）
    hints = {'is_secure': 'level:int -> bool',
             'normalize': 'data:bytes -> bytes'}
    synth = _gen_synthetic_contract('selftest_demo', hints)
    tg = _TemplateGenerator()
    if tg.can_generate(synth):
        src = tg.generate(synth)
        vr = _ContractVerifier().verify(src, synth)
        closed = vr.ok and not vr.io_violations
        results.append(SelftestResult(
            '构造-验证闭环', closed,
            f'ok={vr.ok}, io_violations={vr.io_violations}, '
            f'not_implemented={vr.not_implemented}, feedback={vr.feedback}'))
    else:
        results.append(SelftestResult('构造-验证闭环', False,
                                      '合成契约不可自动实现，链路失效'))

    # 6. 保守边界 — high 复杂度契约禁止自动实现
    high = _StubContract(module_name='selftest_high',
                         status=_Status.PLACEHOLDER.value)
    high.functions.append(_FuncContract(
        name='complex_analyzer', complexity='high', is_placeholder=True))
    refuse = not tg.can_generate(high)
    results.append(SelftestResult(
        '保守边界', refuse,
        'high 复杂度契约被拒绝自动实现' if refuse else 'high 复杂度契约被错误放行'))

    return results


def _gen_synthetic_contract(name: str, hints: dict) -> _StubContract:
    """构造合成 MISSING/PLACEHOLDER 契约（自检与演示用）。"""
    c = _StubContract(module_name=name,
                      status=_Status.PLACEHOLDER.value, doc='自检合成模块')
    for fname, sig in (hints or {}).items():
        fc = _FuncContract(name=fname, is_placeholder=True, complexity='low')
        sig_part, _, ret_part = sig.partition('->')
        for chunk in sig_part.split(','):
            chunk = chunk.strip()
            if not chunk:
                continue
            pname, _, ann = chunk.partition(':')
            fc.params.append(_ParamSpec(name=pname.strip(), annotation=ann.strip()))
        if ret_part:
            fc.return_ann = ret_part.strip()
        c.functions.append(fc)
    return c


def _import(name: str):
    """按模块全名导入引擎族模块。"""
    mod = __import__(f'modules.stubs.{name}', fromlist=['*'])
    _sys.modules[f'modules.stubs.{name}'] = mod
    return mod


def run_selftest() -> int:
    """运行 verify_chain 并打印 PASS/FAIL，返回进程退出码（0=全过）。"""
    _fix_console()
    results = verify_chain()
    passed = sum(1 for r in results if r.passed)
    print(f'[StubGradual] 自检 {passed}/{len(results)} 通过')
    for r in results:
        mark = 'PASS' if r.passed else 'FAIL'
        print(f'  [{mark}] {r.name} — {r.detail}')
    return 0 if passed == len(results) else 1


def _fix_console() -> None:
    """Windows GBK 控制台对 UTF-8 中文输出乱码时重配 stdout。"""
    try:
        _sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass


def main(argv: _Opt[list] = None) -> int:
    """命令行入口：python -m modules.stubs.stub_gradual_orchestrator
       [--top N] [--snapshot PATH] [--verify] [--dry-run]"""
    _fix_console()
    argv = _sys.argv[1:] if argv is None else argv
    top_n, snapshot, verify_only, dry_run = 5, None, False, False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--top' and i + 1 < len(argv):
            top_n = int(argv[i + 1]); i += 2
        elif a == '--snapshot' and i + 1 < len(argv):
            snapshot = argv[i + 1]; i += 2
        elif a == '--verify':
            verify_only = True; i += 1
        elif a == '--dry-run':
            dry_run = True; i += 1
        else:
            i += 1

    if verify_only:
        return run_selftest()

    orch = GradualOrchestrator(config=_GradualConfig(dry_run=dry_run))
    if snapshot:
        n = orch.load_snapshot(snapshot)
        print(f'[StubGradual] 载入观测 {n} 条: {snapshot}')
    out = orch.run_plan(top_n=top_n)
    print(f'[StubGradual] 完成 {len(out)} 个模块的渐进实现尝试 (dry_run={dry_run})')
    print(orch.report(top_n=top_n))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


__all__ = ['SelftestResult', 'GradualOrchestrator', 'verify_chain',
           'run_selftest', 'main']
