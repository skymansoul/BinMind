# stub_atomic_batch.py — 原子批量实现引擎
# 对多个相互依赖的桩模块执行"全有或全无"的批量实现；任一批次成员失败，
# 则回滚该批次已落盘文件。基于依赖图的拓扑层级识别最小一致批次，
# 为逐模块实现补充跨模块的事务语义。
#
# 事务语义:
#   BEGIN BATCH  →  记录批次起点
#   IMPLEMENT(i) →  生成并验证，暂存到 _gradual_out/.atomic/
#   COMMIT       →  原子移动到 _gradual_out/ + 记录溯源 (ProvenanceChain)
#   ROLLBACK     →  删除 _gradual_out/.atomic/ 下该批次文件
import os as _os
import shutil as _shutil
import time as _time
from dataclasses import dataclass as _dc, field as _field


@_dc
class BatchResult:
    """单个原子批次的执行结果。"""
    batch_id: str = ''               # 批次标识
    layer_index: int = 0             # 拓扑层号
    modules: list = _field(default_factory=list)
    results: dict = _field(default_factory=dict)  # {module: 'committed'|'failed'}
    committed: bool = False
    rollback_reason: str = ''
    total_modules: int = 0
    committed_count: int = 0
    failed_count: int = 0
    duration_seconds: float = 0.0


@_dc
class AtomicBatchPlan:
    """完整的原子批量实现计划。"""
    total_layers: int = 0
    total_modules: int = 0
    batches: list = _field(default_factory=list)
    committed_layers: int = 0
    failed_at_layer: int = -1


class AtomicBatchEngine:
    """原子批量实现引擎。

    工作流程:
      1. build_plan() — 从依赖图提取拓扑层作为批次
      2. execute() — 逐层原子执行
      3. 每层: 全部成功 → 提交；任一失败 → 回滚该层并停止
    """

    def __init__(self, engine=None, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self._engine = engine  # GradualEngine 实例
        # 原子暂存目录
        self.atomic_dir = _os.path.join(stubs_dir, '_gradual_out', '.atomic')
        self._batch_counter = 0

    def build_plan(self, top_n: int = None) -> AtomicBatchPlan:
        """从依赖图拓扑层构建批次计划。"""
        plan = AtomicBatchPlan()

        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            from modules.stubs.stub_prioritizer import ImplementationPrioritizer
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
        except ImportError:
            return plan

        # 按拓扑深度分组
        layers = {}
        for name, node in g.nodes.items():
            # 跳过已实现的模块
            if node.status in ('implemented', 're_export', 'mixed'):
                continue
            d = node.topo_depth
            layers.setdefault(d, []).append(name)

        # 每层内按优先级排序
        try:
            prior = ImplementationPrioritizer()
            ranking = {p.module_name: p.total_score for p in prior.rank()}
        except Exception:
            ranking = {}

        plan.total_layers = len(layers)
        for depth in sorted(layers):
            layer_modules = layers[depth]
            layer_modules.sort(key=lambda n: -ranking.get(n, 0.0))
            plan.total_modules += len(layer_modules)
            plan.batches.append({
                'layer': depth,
                'modules': layer_modules,
                'feasible': True,  # 同拓扑层的模块互不依赖
            })
            if top_n is not None and plan.total_modules >= top_n:
                # 截断
                excess = plan.total_modules - top_n
                if excess > 0:
                    plan.batches[-1]['modules'] = (
                        plan.batches[-1]['modules'][:-excess])
                    plan.total_modules = top_n
                break

        return plan

    def execute(self, plan: AtomicBatchPlan,
                dry_run: bool = False) -> list[BatchResult]:
        """执行原子批量实现计划。"""
        results = []
        self._batch_counter = 0

        engine = self._get_engine()

        for batch_info in plan.batches:
            self._batch_counter += 1
            batch_id = f'batch-{self._batch_counter}-L{batch_info["layer"]}'

            br = BatchResult(
                batch_id=batch_id,
                layer_index=batch_info['layer'],
                modules=list(batch_info['modules']),
                total_modules=len(batch_info['modules']),
            )
            t0 = _time.time()

            if dry_run:
                # 预览模式: 不生成文件，仅报告计划
                for mod in batch_info['modules']:
                    br.results[mod] = 'would_implement'
                br.committed = True
                br.committed_count = len(batch_info['modules'])
                br.duration_seconds = _time.time() - t0
                results.append(br)
                plan.committed_layers += 1
                continue

            # 原子暂存目录
            batch_dir = _os.path.join(self.atomic_dir, batch_id)
            _os.makedirs(batch_dir, exist_ok=True)

            failed = None
            for mod in batch_info['modules']:
                try:
                    gen = engine.implement(mod)
                    if gen.status == 'generated' and gen.written:
                        # 移动到暂存目录
                        src = gen.path
                        dst = _os.path.join(batch_dir, f'{mod}.py')
                        if _os.path.isfile(src):
                            _shutil.move(src, dst)
                            gen.path = dst
                        br.results[mod] = 'committed'
                        br.committed_count += 1
                    else:
                        br.results[mod] = 'failed'
                        br.failed_count += 1
                        failed = mod
                        break  # 该层失败 → 不再继续
                except Exception as e:
                    br.results[mod] = f'error: {e}'
                    br.failed_count += 1
                    failed = mod
                    break

            br.duration_seconds = round(_time.time() - t0, 3)

            if failed is None:
                # 整层成功 → 提交: 移动到最终输出目录
                self._commit_batch(batch_dir, batch_id)
                br.committed = True
                plan.committed_layers += 1
            else:
                # 失败 → 回滚该层
                br.committed = False
                br.rollback_reason = f'{failed}: {br.results.get(failed, "unknown")}'
                self._rollback_batch(batch_dir)
                plan.failed_at_layer = batch_info['layer']

            results.append(br)

            if failed is not None:
                break  # 停止后续层（依赖链断裂）

        return results

    def _get_engine(self):
        if self._engine is not None:
            return self._engine
        try:
            from modules.stubs.stub_gradual_engine import GradualEngine
            return GradualEngine()
        except ImportError:
            return None

    def _commit_batch(self, batch_dir: str, batch_id: str) -> None:
        """提交批次: 将暂存文件移动到最终输出目录。"""
        output_dir = _os.path.join(self.stubs_dir, '_gradual_out')
        _os.makedirs(output_dir, exist_ok=True)
        if _os.path.isdir(batch_dir):
            for fn in _os.listdir(batch_dir):
                src = _os.path.join(batch_dir, fn)
                dst = _os.path.join(output_dir, fn)
                if _os.path.isfile(dst):
                    _os.remove(dst)
                _shutil.move(src, dst)
            # 清理暂存目录
            try:
                _os.rmdir(batch_dir)
            except OSError:
                pass

        # 记录溯源
        try:
            from modules.stubs.stub_provenance_chain import ProvenanceChain
            pc = ProvenanceChain(stubs_dir=self.stubs_dir)
            for fn in _os.listdir(output_dir):
                if fn.endswith('.py') and not fn.startswith('_'):
                    mod = fn[:-3]
                    try:
                        src = open(_os.path.join(output_dir, fn),
                                  encoding='utf-8').read()
                    except Exception:
                        src = ''
                    pc.record(mod, '', 'atomic_batch', True,
                             source_code=src,
                             notes=f'batch={batch_id}')
        except ImportError:
            pass

    @staticmethod
    def _rollback_batch(batch_dir: str) -> None:
        """回滚批次: 删除暂存目录。"""
        if _os.path.isdir(batch_dir):
            _shutil.rmtree(batch_dir, ignore_errors=True)

    def batch_report(self, results: list[BatchResult]) -> str:
        """生成 Markdown 批量执行报告。"""
        lines = ['# 原子批量实现报告', '']
        total_mods = sum(r.total_modules for r in results)
        total_ok = sum(r.committed_count for r in results)
        lines.append(f'- 总模块: {total_mods}')
        lines.append(f'- 成功: {total_ok}')
        lines.append(f'- 失败: {total_mods - total_ok}')
        lines.append('')
        lines.append('| 批次 | 层 | 模块数 | 成功 | 状态 |')
        lines.append('|------|---|-------|------|------|')
        for r in results:
            status = 'COMMITTED' if r.committed else f'ROLLBACK: {r.rollback_reason[:40]}'
            lines.append(
                f'| {r.batch_id} | L{r.layer_index} | '
                f'{r.total_modules} | {r.committed_count} | {status} |')
        return '\n'.join(lines)


def atomic_implement(top_n: int = 10, dry_run: bool = False) -> list[BatchResult]:
    """一行式原子批量实现。"""
    engine = AtomicBatchEngine()
    plan = engine.build_plan(top_n)
    return engine.execute(plan, dry_run=dry_run)


__all__ = [
    'BatchResult', 'AtomicBatchPlan', 'AtomicBatchEngine',
    'atomic_implement',
]
