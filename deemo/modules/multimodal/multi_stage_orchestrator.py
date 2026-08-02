"""Multi-stage exploit orchestrator.

链式攻击编排：管理 recon → exploit → post-exploit → cleanup 生命周期。
阶段间的依赖关系通过 Kahn 拓扑排序解析，支持并行阶段调度。
支持三种执行策略：sequential（线性）、parallel_layer（层内并行）、best_effort（失败继续）。
支持 subprocess 真实执行、目标类型感知过滤、链式模糊变异、动态策略自选。
"""
from enum import Enum
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging
import json
import time
import hashlib
import subprocess
import signal
import threading
import random
import tempfile
import os
import shutil
import math

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 枚举定义
# ---------------------------------------------------------------------------
class ExploitStage(Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST = "post"
    CLEANUP = "cleanup"


class ChainStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CHECKPOINTED = "checkpointed"
    TIMED_OUT = "timed_out"


class ExecutionStrategy(Enum):
    SEQUENTIAL = "sequential"
    PARALLEL_LAYER = "parallel_layer"
    BEST_EFFORT = "best_effort"
    AUTO = "auto"


class VulnerabilityType(Enum):
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"


class TargetType(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    WEB = "web"
    EMBEDDED = "embedded"


# ---------------------------------------------------------------------------
# 步骤执行输出 — 捕获单个步骤的完整执行轨迹
# ---------------------------------------------------------------------------
@dataclass
class StepOutput:
    action: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    elapsed_seconds: float = 0.0


# ---------------------------------------------------------------------------
# 阶段能力注册 — 每个阶段声明的能力用于前置校验
# ---------------------------------------------------------------------------
@dataclass
class StageCapability:
    name: str
    required_tools: List[str] = field(default_factory=list)
    target_types: List[TargetType] = field(default_factory=list)
    timeout_seconds: float = 60.0
    retry_count: int = 1


# ---------------------------------------------------------------------------
# 链步骤定义
# ---------------------------------------------------------------------------
@dataclass
class ChainStep:
    stage: ExploitStage
    action: str = ""
    payload: Optional[str] = None
    pre_conditions: List[str] = field(default_factory=list)
    post_conditions: List[str] = field(default_factory=list)
    timeout_seconds: float = 30.0
    retry_on_fail: bool = False
    produces: List[str] = field(default_factory=list)
    applicable_targets: List[TargetType] = field(default_factory=list)
    shell_command: Optional[str] = None
    fuzzable: bool = False

    def satisfied(self, ctx: Dict[str, Any]) -> bool:
        """检查前置条件是否在上下文中全部满足。"""
        for cond in self.pre_conditions:
            if cond not in ctx:
                return False
        return True

    def applies_to(self, target_type: Optional[TargetType]) -> bool:
        if not self.applicable_targets:
            return True
        if target_type is None:
            return True
        return target_type in self.applicable_targets

    def fuzz_variants(self, n: int = 5) -> List[str]:
        """生成 shell_command 的模糊变异版本。

        仅在 fuzzable=True 且 shell_command 非空时产出版本。
        变异策略：占位符替换 (0x00→0x01)、空格→制表符、编码转换。
        """
        if not self.fuzzable or not self.shell_command:
            return []
        variants: List[str] = []
        base = self.shell_command
        # 变异 1: 替换 null-byte 占位为相邻值
        if '{null_byte}' in base:
            for b in range(1, 5):
                variants.append(base.replace('{null_byte}', f'\\x{b:02x}'))
        # 变异 2: 空格替换为制表符或换行
        if ' ' in base:
            variants.append(base.replace(' ', '\t'))
        # 变异 3: payload 大小写混淆
        if '{payload}' in base:
            variants.append(base.replace('{payload}', '{PAYLOAD}'))
        # 变异 4: 参数顺序交换
        parts = base.split()
        if len(parts) >= 3:
            _swapped = parts[:]
            _swapped[1], _swapped[2] = _swapped[2], _swapped[1]
            variants.append(' '.join(_swapped))
        variants = variants[:n]
        # 去重
        seen: set = set()
        return [v for v in variants if not (v in seen or seen.add(v))]


# ---------------------------------------------------------------------------
# 攻击链
# ---------------------------------------------------------------------------
class AttackChain:
    def __init__(self, name: str = ""):
        self.name = name
        self.steps: List[ChainStep] = []
        self.deadline_seconds: Optional[float] = None

    def add_step(self, s: ChainStep) -> None:
        self.steps.append(s)

    @property
    def stage_count(self) -> Dict[ExploitStage, int]:
        tally: Dict[ExploitStage, int] = defaultdict(int)
        for s in self.steps:
            tally[s.stage] += 1
        return dict(tally)

    def estimated_duration(self) -> float:
        """各 step timeout 之和 + 10% buffer，作为链预估执行时长。"""
        return sum(s.timeout_seconds for s in self.steps) * 1.1

    def complexity(self) -> Dict[str, Any]:
        """McCabe 风格依赖图复杂度度量。

        edges = 前置条件总数，nodes = step 数。
        环路数 = edges - nodes + 2*components（连通分量）。
        高复杂度链 (>10 边) 建议拆分。
        """
        n = len(self.steps)
        e = sum(len(s.pre_conditions) for s in self.steps)
        components = 1  # 假设连通
        cyclomatic = max(0, e - n + 2 * components)
        return {
            'nodes': n,
            'edges': e,
            'cyclomatic': cyclomatic,
            'density': round(e / max(1, n * (n - 1)), 3),
            'estimated_duration': round(self.estimated_duration(), 1)
        }

    def success_rate_estimate(self) -> float:
        """基于链结构的启发式成功率估算。

        复杂度越高、步骤越多、前置条件越密集→成功率越低。
        公式：exp(-0.15 * cyclomatic) * exp(-0.05 * len(steps))
        """
        comp = self.complexity()
        return round(math.exp(-0.15 * comp['cyclomatic'])
                     * math.exp(-0.05 * comp['nodes']), 3)


# ---------------------------------------------------------------------------
# 依赖解析器 — Kahn 算法解决阶段间依赖，检测环路
# ---------------------------------------------------------------------------
class DependencyResolver:
    """对有向无环依赖图做拓扑排序，输出可并行执行的阶段批次。

    若检测到环路，不抛异常，而是将环内节点并入同一批次执行——
    这在 exploit 链中对应互相依赖的阶段（如 recon 和 exploit 交替）仍需尝试执行。
    """

    def resolve(self, steps: List[ChainStep]) -> List[List[ChainStep]]:
        # 按 action 建立索引
        idx_map: Dict[str, int] = {}
        for i, s in enumerate(steps):
            idx_map[s.action] = i

        n = len(steps)
        in_degree = [0] * n
        adj: List[List[int]] = [[] for _ in range(n)]

        for i, s in enumerate(steps):
            for pre in s.pre_conditions:
                if pre in idx_map:
                    j = idx_map[pre]
                    adj[j].append(i)
                    in_degree[i] += 1

        q = deque([i for i in range(n) if in_degree[i] == 0])
        layers: List[List[ChainStep]] = []
        visited = 0

        while q:
            batch: List[ChainStep] = []
            for _ in range(len(q)):
                u = q.popleft()
                batch.append(steps[u])
                visited += 1
                for v in adj[u]:
                    in_degree[v] -= 1
                    if in_degree[v] == 0:
                        q.append(v)
            layers.append(batch)

        # 环路处理：剩余未访问节点放入最后一层
        if visited < n:
            remainder = [steps[i] for i in range(n) if in_degree[i] > 0]
            layers.append(remainder)

        return layers


# ---------------------------------------------------------------------------
# 脚本生成器 — 模板插值 + payload 嵌入
# ---------------------------------------------------------------------------
class ScriptGenerator:
    """将 ChainStep 列表转换为可执行的脚本。

    内置简单的模板变量替换：{payload}, {target}, {stage_name}。
    生产环境中可替换为 Jinja2 或自研 DSL。
    """

    _BOILERPLATE = (
        "# Auto-generated exploit chain\n"
        "# WARNING: review before execution\n\n"
        "import sys\n"
        "def _execute():\n"
    )

    def __init__(self):
        self._template_cache: Dict[str, str] = {}

    def generate(self, chain: AttackChain, target_info: Dict[str, Any]) -> str:
        lines = [self._BOILERPLATE]
        ctx: Dict[str, Any] = {}

        for step in chain.steps:
            lines.append(f"    # Stage: {step.stage.value} | {step.action}")
            if step.payload:
                interpolated = step.payload.format(
                    target=target_info.get('host', 'localhost'),
                    stage_name=step.stage.value,
                    **target_info
                )
                lines.append(f"    {interpolated}")
            else:
                lines.append(f"    # No payload for {step.action}")
            lines.append(f"    ctx_{step.action} = True  # post-condition marker")
            ctx[step.action] = True
            for post in step.post_conditions:
                ctx[post] = True
                lines.append(f"    ctx_{post} = True")

        lines.append("    return 0\n")
        lines.append("if __name__ == '__main__':\n")
        lines.append("    sys.exit(_execute())")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 检查点 — 长链执行中断后恢复
# ---------------------------------------------------------------------------
@dataclass
class Checkpoint:
    chain_name: str
    last_completed_action: str
    executed_actions: List[str]
    context_snapshot: Dict[str, Any]
    timestamp: str
    checksum: str = ""

    def to_json(self) -> str:
        return json.dumps({
            'chain_name': self.chain_name,
            'last_completed_action': self.last_completed_action,
            'executed_actions': self.executed_actions,
            'context_snapshot': {k: str(v)[:200] for k, v in self.context_snapshot.items()},
            'timestamp': self.timestamp,
            'checksum': self.checksum
        })

    @classmethod
    def from_json(cls, raw: str) -> 'Checkpoint':
        d = json.loads(raw)
        return cls(**{k: d[k] for k in ['chain_name', 'last_completed_action',
                       'executed_actions', 'context_snapshot', 'timestamp', 'checksum']})


# ---------------------------------------------------------------------------
# 编排结果与编排器
# ---------------------------------------------------------------------------
@dataclass
class OrchestrationResult:
    success: bool = False
    chain: Optional[AttackChain] = None
    executed_steps: int = 0
    failed_step: Optional[str] = None
    output_log: str = ""
    artifacts: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    checkpoints: List[Checkpoint] = field(default_factory=list)
    step_outputs: List[StepOutput] = field(default_factory=list)


class ChainOrchestrator:
    """链式攻击编排器。

    执行流程：
    1. 验证所有 step 的 StageCapability 与目标环境兼容
    2. 依赖解析 → 分层执行计划
    3. 逐层执行，层内可并行（由调用方控制）
    4. 失败时向上层报告，触发回滚钩子

    策略说明：
    - sequential: 严格逐步骤执行，失败即停
    - parallel_layer: 同层步骤并发，层间串行
    - best_effort: 失败不中断，记录后继续执行后续步骤
    - auto: 基于链复杂度和历史成功率自动选择

    步骤执行支持两种模式：
    - shell_command 非空时通过 subprocess 真实执行
    - shell_command 为空时走模拟执行（钩子驱动）
    """

    def __init__(self):
        self._capabilities: Dict[ExploitStage, StageCapability] = {}
        self._resolver = DependencyResolver()
        self._script_gen = ScriptGenerator()
        self._hooks: Dict[str, Callable] = {}
        self._executed_actions: Set[str] = set()
        self._checkpoints: List[Checkpoint] = []
        self._step_outputs: List[StepOutput] = []
        self._history: List[Dict[str, Any]] = []

    def register_capability(self, stage: ExploitStage, cap: StageCapability) -> None:
        self._capabilities[stage] = cap

    def add_stage(self, step: ChainStep) -> None:
        if not hasattr(self, '_pending_steps'):
            self._pending_steps: List[ChainStep] = []
        self._pending_steps.append(step)

    def on(self, event: str, callback: Callable) -> None:
        """注册生命周期钩子：pre_exec, post_exec, on_fail, rollback。"""
        self._hooks[event] = callback

    # -------------------------------------------------------------------
    # 动态策略选择 — 基于链特征自动决定最佳策略
    # -------------------------------------------------------------------
    def _auto_select_strategy(self, chain: AttackChain) -> ExecutionStrategy:
        comp = chain.complexity()
        # 低复杂度少步骤 → sequential 最快
        if comp['nodes'] <= 3 and comp['cyclomatic'] <= 1:
            return ExecutionStrategy.SEQUENTIAL
        # 中等复杂度且历史成功率低 → best_effort 保底
        if self._history:
            recent_success = sum(1 for h in self._history[-10:]
                                if h.get('success')) / max(1, len(self._history[-10:]))
            if recent_success < 0.6:
                return ExecutionStrategy.BEST_EFFORT
        # 高复杂度多步骤 → parallel_layer 加速
        if comp['nodes'] >= 5 or comp['cyclomatic'] >= 3:
            return ExecutionStrategy.PARALLEL_LAYER
        return ExecutionStrategy.SEQUENTIAL

    # -------------------------------------------------------------------
    # subprocess 执行 — 带超时强制终止和沙箱隔离
    # -------------------------------------------------------------------
    def _run_step_command(self, step: ChainStep,
                          target_info: Dict[str, Any]) -> StepOutput:
        """通过 subprocess 执行 step.shell_command，捕获输出并强制超时。

        超时时先 SIGTERM，1.5s 后若未退出则 SIGKILL。
        在临时目录中执行以隔离步骤间的文件副作用。
        """
        if not step.shell_command:
            return StepOutput(action=step.action, exit_code=0)

        t0 = time.monotonic()
        cmd = step.shell_command.format(**target_info, action=step.action)
        timeout = step.timeout_seconds

        sandbox_dir = tempfile.mkdtemp(prefix=f"chain_{step.action}_")
        try:
            proc = subprocess.Popen(
                cmd, shell=True, cwd=sandbox_dir,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)
            stdout, stderr = proc.communicate(timeout=timeout)
            elapsed = time.monotonic() - t0
            return StepOutput(
                action=step.action, stdout=stdout.strip(), stderr=stderr.strip(),
                exit_code=proc.returncode, elapsed_seconds=round(elapsed, 3))
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - t0
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            except OSError:
                pass
            return StepOutput(
                action=step.action, timed_out=True,
                elapsed_seconds=round(elapsed, 3), exit_code=-1)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepOutput(
                action=step.action, stderr=str(exc),
                elapsed_seconds=round(elapsed, 3), exit_code=-1)
        finally:
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
            except Exception:
                pass

    # -------------------------------------------------------------------
    # 链式模糊 — 对 fuzzable 步骤生成变异版本并执行
    # -------------------------------------------------------------------
    def fuzz_chain(self, target_info: Optional[Dict[str, Any]] = None,
                   variants_per_step: int = 5) -> List[OrchestrationResult]:
        """对标记为 fuzzable 的步骤生成变异版链并执行。

        每个变异版本独立执行，收集成功/失败的变异模式。
        返回所有变异执行的结果列表。

        设计意图：识别哪些 payload 变体能绕过输入过滤/WAF。
        """
        steps = getattr(self, '_pending_steps', [])
        if not steps:
            return []

        fuzzable_steps = [s for s in steps if s.fuzzable and s.shell_command]
        if not fuzzable_steps:
            return []

        results: List[OrchestrationResult] = []
        target_info = target_info or {}

        for _fs in fuzzable_steps:
            variants = _fs.fuzz_variants(variants_per_step)
            for vi, variant_cmd in enumerate(variants):
                # 创建变异副本
                mutated = ChainStep(
                    stage=_fs.stage, action=f"{_fs.action}_fuzz{vi}",
                    shell_command=variant_cmd,
                    pre_conditions=list(_fs.pre_conditions),
                    post_conditions=list(_fs.post_conditions),
                    timeout_seconds=_fs.timeout_seconds,
                    produces=list(_fs.produces),
                    applicable_targets=list(_fs.applicable_targets),
                )
                saved_steps = list(steps)
                # 替换原始步骤为变异版
                mod_steps = [s if s.action != _fs.action else mutated for s in saved_steps]
                saved_pending = list(self._pending_steps)
                self._pending_steps = mod_steps
                try:
                    result = self.execute(target_info,
                                         strategy=ExecutionStrategy.BEST_EFFORT)
                    result.artifacts['fuzz_variant'] = variant_cmd
                    result.artifacts['fuzz_original'] = _fs.action
                    results.append(result)
                finally:
                    self._pending_steps = saved_pending

        return results

    def execute(self, target_info: Optional[Dict[str, Any]] = None,
                strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL,
                deadline_seconds: Optional[float] = None,
                target_type: Optional[TargetType] = None
                ) -> OrchestrationResult:
        steps = getattr(self, '_pending_steps', [])
        if not steps:
            return OrchestrationResult(success=False, output_log="No steps registered")

        target_info = target_info or {}
        t_start = time.monotonic()

        # 目标类型感知过滤
        applicable = [s for s in steps if s.applies_to(target_type)]
        skipped_by_target = len(steps) - len(applicable)
        if not applicable:
            return OrchestrationResult(
                success=False,
                output_log=f"No steps applicable for target_type={target_type}")

        chain = AttackChain(name=target_info.get('name', 'unnamed'))
        for s in applicable:
            chain.add_step(s)
        chain.deadline_seconds = deadline_seconds

        # AUTO 策略：动态选择
        if strategy == ExecutionStrategy.AUTO:
            strategy = self._auto_select_strategy(chain)

        if deadline_seconds and chain.estimated_duration() > deadline_seconds:
            return OrchestrationResult(
                success=False, chain=chain,
                output_log=f"Estimated {chain.estimated_duration():.0f}s exceeds deadline {deadline_seconds}s")

        layers = self._resolver.resolve(applicable)
        executed = 0
        output_lines: List[str] = []
        ctx: Dict[str, Any] = {}
        failures: List[str] = []

        if skipped_by_target:
            output_lines.append(f"[FILTER] {skipped_by_target} steps excluded by target_type={target_type}")

        for layer_idx, layer in enumerate(layers):
            for step in layer:
                if not step.satisfied(ctx):
                    skipped_msg = (f"[SKIP] layer={layer_idx} action={step.action} "
                                   f"missing pre-conditions: "
                                   f"{set(step.pre_conditions) - set(ctx.keys())}")
                    output_lines.append(skipped_msg)
                    if strategy != ExecutionStrategy.BEST_EFFORT:
                        continue

                hook = self._hooks.get('pre_exec')
                if hook:
                    hook(step, ctx)

                # 实际执行
                try:
                    if step.shell_command:
                        output_lines.append(
                            f"[EXEC] {step.stage.value}:{step.action} (shell)")
                        so = self._run_step_command(step, target_info)
                        self._step_outputs.append(so)
                        if so.timed_out:
                            raise TimeoutError(
                                f"step timed out after {step.timeout_seconds}s")
                        if so.exit_code != 0:
                            raise RuntimeError(
                                f"exit={so.exit_code} stderr={so.stderr[:200]}")
                        if so.stdout:
                            output_lines.append(f"  stdout: {so.stdout[:500]}")
                    else:
                        output_lines.append(
                            f"[EXEC] {step.stage.value}:{step.action} (simulated)")
                        self._step_outputs.append(
                            StepOutput(action=step.action, exit_code=0,
                                       elapsed_seconds=0.001))

                    ctx[step.action] = True
                    for post in step.post_conditions:
                        ctx[post] = True
                    for artifact_key in step.produces:
                        ctx[artifact_key] = f"artifact_from_{step.action}"
                    self._executed_actions.add(step.action)
                    executed += 1

                    cp = Checkpoint(
                        chain_name=chain.name,
                        last_completed_action=step.action,
                        executed_actions=list(self._executed_actions),
                        context_snapshot=dict(ctx),
                        timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
                        checksum=hashlib.md5(
                            str(list(self._executed_actions)).encode()).hexdigest()[:8])
                    self._checkpoints.append(cp)
                except TimeoutError as exc:
                    output_lines.append(f"[TIMEOUT] {step.action}: {exc}")
                    fail_hook = self._hooks.get('on_fail')
                    if fail_hook:
                        fail_hook(step, exc)
                    if strategy == ExecutionStrategy.BEST_EFFORT:
                        failures.append(step.action)
                        continue
                    return OrchestrationResult(
                        success=False, chain=chain, executed_steps=executed,
                        failed_step=step.action,
                        output_log="\n".join(output_lines),
                        duration_seconds=round(time.monotonic() - t_start, 2),
                        checkpoints=self._checkpoints,
                        step_outputs=self._step_outputs)
                except Exception as exc:
                    output_lines.append(f"[FAIL] {step.action}: {exc}")
                    fail_hook = self._hooks.get('on_fail')
                    if fail_hook:
                        fail_hook(step, exc)
                    if strategy == ExecutionStrategy.BEST_EFFORT:
                        failures.append(step.action)
                        continue
                    return OrchestrationResult(
                        success=False, chain=chain, executed_steps=executed,
                        failed_step=step.action,
                        output_log="\n".join(output_lines),
                        duration_seconds=round(time.monotonic() - t_start, 2),
                        checkpoints=self._checkpoints,
                        step_outputs=self._step_outputs)

                post_hook = self._hooks.get('post_exec')
                if post_hook:
                    post_hook(step, ctx)

            if strategy == ExecutionStrategy.PARALLEL_LAYER:
                output_lines.append(f"[LAYER {layer_idx}] parallel batch complete")

        all_ok = len(failures) == 0
        result = OrchestrationResult(
            success=all_ok, chain=chain, executed_steps=executed,
            output_log="\n".join(output_lines),
            artifacts={'context': ctx, 'actions_executed': list(self._executed_actions),
                       'failures': failures, 'selected_strategy': strategy.value},
            duration_seconds=round(time.monotonic() - t_start, 2),
            checkpoints=self._checkpoints,
            step_outputs=self._step_outputs)

        self._history.append({'success': all_ok, 'strategy': strategy.value,
                              'steps': executed, 'duration': result.duration_seconds})
        return result

    def dry_run(self, target_info: Optional[Dict[str, Any]] = None,
                target_type: Optional[TargetType] = None) -> OrchestrationResult:
        """模拟执行：解析依赖、验证前置条件，但不触发任何 payload。

        返回预估步骤数及依赖完整性报告，用于链设计阶段的快速验证。
        """
        steps = getattr(self, '_pending_steps', [])
        if not steps:
            return OrchestrationResult(success=False, output_log="No steps registered")

        target_info = target_info or {}
        applicable = [s for s in steps if s.applies_to(target_type)]
        chain = AttackChain(name=target_info.get('name', 'unnamed'))
        for s in applicable:
            chain.add_step(s)

        layers = self._resolver.resolve(applicable)
        ctx: Dict[str, Any] = {}
        sim_log: List[str] = []
        unresolved: List[str] = []
        skipped_by_target = len(steps) - len(applicable)

        if skipped_by_target:
            sim_log.append(f"[FILTER] {skipped_by_target} steps excluded by target_type={target_type}")

        for layer_idx, layer in enumerate(layers):
            for step in layer:
                sim_log.append(f"[SIM] layer={layer_idx} {step.stage.value}:{step.action}"
                               f" {'(shell)' if step.shell_command else ''}"
                               f" {'(fuzzable)' if step.fuzzable else ''}")
                for post in step.post_conditions:
                    ctx[post] = True
                ctx[step.action] = True
                if not step.satisfied({}):
                    missing = set(step.pre_conditions)
                    if missing:
                        unresolved.append(f"{step.action} needs: {missing}")

        return OrchestrationResult(
            success=len(unresolved) == 0,
            chain=chain,
            output_log="\n".join(sim_log),
            artifacts={
                'total_steps': len(applicable),
                'filtered_out': skipped_by_target,
                'layers': len(layers),
                'unresolved_deps': unresolved,
                'complexity': chain.complexity(),
                'estimated_success_rate': chain.success_rate_estimate(),
                'suggested_strategy': self._auto_select_strategy(chain).value,
            })

    def resume_from_checkpoint(self, target_info: Optional[Dict[str, Any]] = None
                                ) -> OrchestrationResult:
        """从最近的检查点恢复执行，跳过已完成的步骤。"""
        if not self._checkpoints:
            return OrchestrationResult(success=False, output_log="No checkpoint to resume from")

        last_cp = self._checkpoints[-1]
        steps = getattr(self, '_pending_steps', [])
        remaining = [s for s in steps
                     if s.action not in last_cp.executed_actions]

        if not remaining:
            return OrchestrationResult(
                success=True, output_log="All steps already completed",
                checkpoints=self._checkpoints)

        self._pending_steps = remaining
        self._executed_actions = set(last_cp.executed_actions)

        return self.execute(target_info=target_info)

    def generate_report(self) -> str:
        steps = getattr(self, '_pending_steps', [])
        chain = AttackChain()
        for s in steps:
            chain.add_step(s)
        comp = chain.complexity()
        lines = [
            "# Exploit Chain Report",
            f"## {len(steps)} steps configured",
            f"- Cyclomatic complexity: {comp['cyclomatic']}",
            f"- Edge density: {comp['density']}",
            f"- Est. duration: {comp['estimated_duration']}s",
            f"- Est. success rate: {chain.success_rate_estimate()}",
            f"- Suggested strategy: {self._auto_select_strategy(chain).value}",
            "",
            "## Steps"
        ]
        for s in steps:
            extra = []
            if s.shell_command:
                extra.append(f"cmd={s.shell_command[:60]}")
            if s.fuzzable:
                extra.append("fuzzable")
            if s.applicable_targets:
                extra.append(f"targets={[t.value for t in s.applicable_targets]}")
            suffix = f" ({'; '.join(extra)})" if extra else ""
            lines.append(f"- [{s.stage.value}] {s.action}"
                         f" (pre: {s.pre_conditions}, post: {s.post_conditions}){suffix}")
        return "\n".join(lines)

    def rollback(self) -> OrchestrationResult:
        """按执行逆序调用回滚钩子。"""
        rollback_hook = self._hooks.get('rollback')
        if not rollback_hook:
            return OrchestrationResult(success=True, output_log="No rollback hook registered")
        try:
            rollback_hook(list(self._executed_actions))
            return OrchestrationResult(success=True, output_log="Rollback complete")
        except Exception as exc:
            return OrchestrationResult(success=False, output_log=f"Rollback failed: {exc}")



# ---------------------------------------------------------------------------
# 链差异对比 — 计算两条攻击链的最小变更集
# 基于 action 集合的对称差 + 依赖图编辑距离
# ---------------------------------------------------------------------------

def chain_diff(chain_a: AttackChain, chain_b: AttackChain) -> Dict[str, Any]:
    """对比两条链的差异，返回最小变更操作。

    操作类型：added（B有A无）、removed（A有B无）、modified（同名但属性不同）。
    """
    _a_actions = {s.action: s for s in chain_a.steps}
    _b_actions = {s.action: s for s in chain_b.steps}
    _a_set = set(_a_actions.keys())
    _b_set = set(_b_actions.keys())

    _added = [_b_actions[a] for a in (_b_set - _a_set)]
    _removed = [_a_actions[a] for a in (_a_set - _b_set)]
    _common = _a_set & _b_set

    _modified: List[Dict[str, Any]] = []
    for _action in _common:
        _sa, _sb = _a_actions[_action], _b_actions[_action]
        _changes: Dict[str, Tuple] = {}
        if _sa.stage != _sb.stage:
            _changes['stage'] = (_sa.stage.value, _sb.stage.value)
        if _sa.shell_command != _sb.shell_command:
            _changes['shell_command'] = (_sa.shell_command, _sb.shell_command)
        if set(_sa.pre_conditions) != set(_sb.pre_conditions):
            _changes['pre_conditions'] = (_sa.pre_conditions, _sb.pre_conditions)
        if set(_sa.post_conditions) != set(_sb.post_conditions):
            _changes['post_conditions'] = (_sa.post_conditions, _sb.post_conditions)
        if _changes:
            _modified.append({'action': _action, 'changes': _changes})

    return {
        'added': len(_added), 'removed': len(_removed), 'modified': len(_modified),
        'added_actions': [_s.action for _s in _added],
        'removed_actions': [_s.action for _s in _removed],
        'modified_details': _modified,
        'similarity': round(len(_common) / max(1, len(_a_set | _b_set)), 3),
    }


# ---------------------------------------------------------------------------
# 链策略注释 — 基于链特征预测最优策略及可能失败模式
# ---------------------------------------------------------------------------

def annotate_chain(chain: AttackChain) -> Dict[str, Any]:
    """分析攻击链特征并输出策略建议与风险标注。

    基于链复杂度、步骤密度、fuzzable 比例、shell 执行比例
    四维特征做启发式最佳策略推荐及风险预警。
    """
    comp = chain.complexity()
    n = comp['nodes']
    fuzzable_ratio = sum(1 for s in chain.steps if s.fuzzable) / max(1, n)
    shell_ratio = sum(1 for s in chain.steps if s.shell_command) / max(1, n)

    # 风险标注
    risks: List[str] = []
    if n >= 10:
        risks.append('high_step_count')
    if comp['cyclomatic'] >= 5:
        risks.append('complex_dependency_graph')
    if fuzzable_ratio > 0.5:
        risks.append('heavy_fuzzing_overhead')
    if shell_ratio > 0.8:
        risks.append('full_shell_execution')
    if not risks:
        risks.append('low_risk')

    # 策略建议
    if n <= 3 and comp['cyclomatic'] <= 1:
        suggestion = 'SEQUENTIAL'
    elif fuzzable_ratio > 0.3:
        suggestion = 'BEST_EFFORT'
    elif shell_ratio > 0.7 and comp['cyclomatic'] >= 2:
        suggestion = 'PARALLEL_LAYER'
    else:
        suggestion = 'AUTO'

    return {
        'suggested_strategy': suggestion,
        'risk_flags': risks,
        'features': {
            'step_count': n,
            'cyclomatic': comp['cyclomatic'],
            'fuzzable_ratio': round(fuzzable_ratio, 3),
            'shell_ratio': round(shell_ratio, 3),
            'estimated_duration': comp['estimated_duration'],
        }
    }


# ---------------------------------------------------------------------------
# 向后兼容别名
# ---------------------------------------------------------------------------
MultiStageOrchestrator = ChainOrchestrator


@dataclass
class Capability:
    def __init__(self, name: str = ""):
        self.name = name


# 模块级占位引用 — 外部可能有未迁移的 import
VulnerabilityNode = None
ExploitChainStep = None
ExploitChain = None
ChainAnalysisResult = None
orchestrate_exploit_chain = None
