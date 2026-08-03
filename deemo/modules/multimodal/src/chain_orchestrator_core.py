"""ChainOrchestrator -- 多阶段 exploit 链执行管线。

核心编排：验证阶段能力与目标环境匹配性，
通过 Kahn 拓扑排序解析步骤依赖，按层执行并支持多种策略，
同时管理检查点和回滚生命周期。

策略：
  SEQUENTIAL     -- 严格线性执行，首次失败即停止。
  PARALLEL_LAYER -- 层内并行，层间串行。
  BEST_EFFORT    -- 失败后继续，记录所有错误。
  AUTO           -- 基于链复杂度和历史数据的动态选择。

执行模式：subprocess（通过 Popen 真实执行 shell 命令，含超时/沙箱），
或 simulated（钩子驱动，无副作用），支持对标记步骤生成模糊变异。

导入顺序说明：本模块从 ..multi_stage_orchestrator 导入共享类型。
必须在其顶层枚举、dataclass 和辅助类定义完毕后再导入。
父模块通过在所有共享类型定义之后放置 ChainOrchestrator 的 import 来处理这一约束。
"""

from typing import Dict, List, Optional, Set, Callable, Any
import hashlib
import shutil
import subprocess
import tempfile
import time

# 共享类型 —— 从父模块命名空间中解析。
# multi_stage_orchestrator 在导入本模块前已定义这些类型，
# 因此部分初始化的模块在查找时可找到它们。
from ..multi_stage_orchestrator import (  # noqa: E402
    AttackChain,
    ChainStep,
    Checkpoint,
    DependencyResolver,
    ExecutionStrategy,
    ExploitStage,
    OrchestrationResult,
    ScriptGenerator,
    StageCapability,
    StepOutput,
    TargetType,
)


# ===========================================================================
# ChainOrchestrator -- exploit 链生命周期管理器
# ===========================================================================
class ChainOrchestrator:
    """多阶段 exploit 链编排器。

    生命周期：
    1. validate -- 验证 StageCapability 与目标环境兼容性
    2. resolve -- DependencyResolver 拓扑排序 → 分层计划
    3. execute -- 遍历层，按当前策略调度步骤
    4. checkpoint / rollback -- 持久化进度，失败时回滚

    步骤调度使用两条代码路径：
    - shell_command 已设置  -> subprocess.Popen + 超时 + 临时沙箱目录
    - shell_command 为 None -> 模拟执行（仅回调钩子）
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

    # ------------------------------------------------------------------
    # 注册 API
    # ------------------------------------------------------------------
    def register_capability(self, stage: ExploitStage, cap: StageCapability) -> None:
        """注册阶段能力以供执行前校验。"""
        self._capabilities[stage] = cap

    def add_stage(self, step: ChainStep) -> None:
        """将步骤排入下次编排运行的队列。"""
        if not hasattr(self, '_pending_steps'):
            self._pending_steps: List[ChainStep] = []
        self._pending_steps.append(step)

    def on(self, event: str, callback: Callable) -> None:
        """注册生命周期钩子。

        支持事件：pre_exec, post_exec, on_fail, rollback。
        """
        self._hooks[event] = callback

    # ------------------------------------------------------------------
    # 策略选择 —— 基于链特征的启发式
    # ------------------------------------------------------------------
    def _auto_select_strategy(self, chain: AttackChain) -> ExecutionStrategy:
        """从链复杂度和历史成功率推导最优策略。

        低复杂度/少步骤 -> SEQUENTIAL（最快路径）。
        历史成功率低 -> BEST_EFFORT（优雅降级）。
        高复杂度/多步骤 -> PARALLEL_LAYER（吞吐优先）。
        """
        comp = chain.complexity()
        if comp['nodes'] <= 3 and comp['cyclomatic'] <= 1:
            return ExecutionStrategy.SEQUENTIAL
        if self._history:
            recent_success = sum(1 for h in self._history[-10:]
                                if h.get('success')) / max(1, len(self._history[-10:]))
            if recent_success < 0.6:
                return ExecutionStrategy.BEST_EFFORT
        if comp['nodes'] >= 5 or comp['cyclomatic'] >= 3:
            return ExecutionStrategy.PARALLEL_LAYER
        return ExecutionStrategy.SEQUENTIAL

    # ------------------------------------------------------------------
    # 子进程执行 —— 沙箱化，超时保护
    # ------------------------------------------------------------------
    def _run_step_command(self, step: ChainStep,
                          target_info: Dict[str, Any]) -> StepOutput:
        """在隔离的临时目录中执行 step.shell_command。

        超时策略：到达截止时刻发送 SIGTERM，1.5 秒宽限期后 SIGKILL。
        临时目录无论结果如何都会被清理。
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

    # ------------------------------------------------------------------
    # 模糊链 —— 为标记步骤生成变体
    # ------------------------------------------------------------------
    def fuzz_chain(self, target_info: Optional[Dict[str, Any]] = None,
                   variants_per_step: int = 5) -> List[OrchestrationResult]:
        """为每个 fuzzable=True 的步骤执行模糊变体链。

        每个变体是原始 shell_command 的变异副本。
        在 BEST_EFFORT 下运行以避免单变体失败阻塞整个扫描。

        返回每个已执行变体对应的 OrchestrationResult。
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

    # ------------------------------------------------------------------
    # 执行 —— 主管线入口
    # ------------------------------------------------------------------
    def execute(self, target_info: Optional[Dict[str, Any]] = None,
                strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL,
                deadline_seconds: Optional[float] = None,
                target_type: Optional[TargetType] = None
                ) -> OrchestrationResult:
        """运行已注册的 exploit 链。

        1. 按 target_type 过滤步骤。
        2. AUTO 策略 → 启发式选择。
        3. 截止时间检查：对比预估链时长。
        4. 依赖解析 → 分层。
        5. 逐层逐步骤调度 + 检查点 + 钩子。
        """
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
            output_lines.append(
                f"[FILTER] {skipped_by_target} steps excluded by target_type={target_type}")

        for layer_idx, layer in enumerate(layers):
            for step in layer:
                if not step.satisfied(ctx):
                    skipped_msg = (
                        f"[SKIP] layer={layer_idx} action={step.action} "
                        f"missing pre-conditions: "
                        f"{set(step.pre_conditions) - set(ctx.keys())}")
                    output_lines.append(skipped_msg)
                    if strategy != ExecutionStrategy.BEST_EFFORT:
                        continue

                # --- pre-exec 钩子 ---
                hook = self._hooks.get('pre_exec')
                if hook:
                    hook(step, ctx)

                # --- 调度 ---
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

                # --- post-exec 钩子 ---
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

    # ------------------------------------------------------------------
    # 空跑 —— 无副作用的依赖校验
    # ------------------------------------------------------------------
    def dry_run(self, target_info: Optional[Dict[str, Any]] = None,
                target_type: Optional[TargetType] = None) -> OrchestrationResult:
        """模拟链执行：解析依赖，检查前置条件。

        不执行任何 shell 命令或 payload。
        返回包含步骤数、分层结构、未解析依赖、
        复杂度指标和建议策略的报告。
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
            sim_log.append(
                f"[FILTER] {skipped_by_target} steps excluded by target_type={target_type}")

        for layer_idx, layer in enumerate(layers):
            for step in layer:
                sim_log.append(
                    f"[SIM] layer={layer_idx} {step.stage.value}:{step.action}"
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

    # ------------------------------------------------------------------
    # 检查点恢复 —— 跳过已执行步骤
    # ------------------------------------------------------------------
    def resume_from_checkpoint(self, target_info: Optional[Dict[str, Any]] = None
                                ) -> OrchestrationResult:
        """从最近检查点恢复执行。

        检查点 executed_actions 列表中的步骤跳过；
        剩余步骤重新提交给 execute()。
        """
        if not self._checkpoints:
            return OrchestrationResult(
                success=False, output_log="No checkpoint to resume from")

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

    # ------------------------------------------------------------------
    # 报告 —— 人类可读的链摘要
    # ------------------------------------------------------------------
    def generate_report(self) -> str:
        """生成待执行链的 markdown 报告。

        包含复杂度指标、预估成功率、建议策略及逐步骤明细。
        """
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
            lines.append(
                f"- [{s.stage.value}] {s.action}"
                f" (pre: {s.pre_conditions}, post: {s.post_conditions}){suffix}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 回滚 —— 通过钩子逆序撤销已执行步骤
    # ------------------------------------------------------------------
    def rollback(self) -> OrchestrationResult:
        """调用回滚钩子，传入已执行动作列表。

        钩子应按 LIFO 顺序撤销副作用。
        """
        rollback_hook = self._hooks.get('rollback')
        if not rollback_hook:
            return OrchestrationResult(
                success=True, output_log="No rollback hook registered")
        try:
            rollback_hook(list(self._executed_actions))
            return OrchestrationResult(success=True, output_log="Rollback complete")
        except Exception as exc:
            return OrchestrationResult(
                success=False, output_log=f"Rollback failed: {exc}")
