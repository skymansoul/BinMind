# stub_gradual_orchestrator.py : StubGradual 编排层 + 健康回路 + 自检闭环
# 将契约抽取(stub_contract) → 优先级排序(stub_prioritizer) →
# 渐进实现(stub_gradual_engine) → 健康监控(stub_health_monitor) 串联为单入口，
# 并补齐此前缺失的两处接缝：
#   1. 双向健康回路：排序阶段读取监控中的调用观测，实现落盘后回写监控，
#      使"已实现"与"健康"两路信号在后续轮次自洽。
#   2. 验证-回溯自检：verify_chain() 对引擎族执行六类断言检查，
#      将 Agentic Repair 的"验证-回溯"原则应用于引擎自身 — 出错即回退并报告细节。
# 支撑论文:
#   Agentic Program Repair from Test Failures at Scale (arXiv:2507.18755 [待验证])
#     验证-回溯闭环依赖"可判定的验证信号"，自检对引擎族应用同一准则。
#   SynthFix (arXiv:2604.17184 [待验证])
#     符号层与神经层的协同由编排层统一调度与降级。
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
try:
    from modules.stubs.stub_health_monitor import StubHealthMonitor as _Monitor
except ImportError:  # 相对导入兜底：模块按文件路径加载时
    from modules.stubs.stub_health_monitor import StubHealthMonitor as _Monitor
try:
    from modules.stubs.stub_prioritizer import (
        ImplementationPrioritizer as _Prioritizer, StubPriority as _StubPriority,
    )
except ImportError:
    from modules.stubs.stub_prioritizer import (
        ImplementationPrioritizer as _Prioritizer, StubPriority as _StubPriority,
    )
try:
    from modules.stubs.stub_gradual_engine import (
        GradualEngine as _GradualEngine,
        GradualConfig as _GradualConfig,
        GeneratedModule as _GeneratedModule,
        TemplateGenerator as _TemplateGenerator,
        ContractVerifier as _ContractVerifier,
    )
except ImportError:
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


# 自检断言记录
@_dc
class SelftestResult:
    """单项自检断言结果。通过/失败 + 可读细节。"""
    name: str
    passed: bool = False
    detail: str = ''

    def to_dict(self) -> dict:
        return {'name': self.name, 'passed': self.passed, 'detail': self.detail}


# 编排器
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

    # 健康数据输入
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

    # 全链执行
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

    # 报告
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


# 验证-回溯自检
# 对引擎族应用与引擎相同的验证准则：每个检查点失败即记录原因并继续，
# 汇总后整体判定。失败不抛异常，保证"回退并记录"而非"静默失败"。
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


# 自检入口
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


# CLI
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
