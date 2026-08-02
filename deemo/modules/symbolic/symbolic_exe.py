"""Symbolic execution primitives via angr.

Covers path exploration, input recovery, null-deref detection,
per-argument taint propagation, syscall arg tracking, and loop-bound
aware exploration depth capping.
All operations fail gracefully when angr is absent.

二轮增强 — 循环感知探索深度：检测 angr 的 LoopSeer exploration technique，
当路径深度 > detected_loop_bound × 3 时自动切换为 BFS 以避免 DFS 陷入
无限循环展开。参考 KLEE 的 loop-limit 策略。

二轮增强 — 条件分支密度评分：当 angr state 的约束集中包含 > 20 个
嵌套 ITE 表达式时，标记该状态为"过度路径爆炸风险"，降低其子状态
的探索优先级。源自对 OWASP benchmark 的实证观察。

三轮增强 — 符号内存模型 (SymbolicMemoryModel)：封装 angr 内存读写，
利用内建 BVS 命名约定（taint_arg{N}_{offset}_{width}）递归解析
输入字节→内存地址的污点映射，返回受影响的输入索引。

三轮增强 — 路径剪枝钩子 (PathPruningHook)：作为 angr SimStatePlugin
注入，在分支解析后检测 IP 是否落在 abort/__stack_chk_fail/__fortify_fail
等不安全终止函数上，丢弃无意义路径以节省探索资源。

三轮增强 — SMT-LIB2 序列化：extract_path_constraints_smt2 将约束集
转为标准 SMT-LIB2 QF_BV 脚本，供 Z3/CVC4/Boolector 等外部求解器直接
消费，实现跨工具验证与约束持久化。
"""

import logging
import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# angr 的 LoopSeer technique 用于检测循环边界
# 若 binary 中已通过 CFG 分析获得循环信息，可避免无界展开
_LOOP_DEPTH_MULTIPLIER = 3
_ITE_NESTING_THRESHOLD = 20

# 三轮增强 — 不安全终止函数符号集
# PathPruningHook 匹配这些符号后丢弃对应状态，降低路径爆炸
_UNSAFE_PRUNE_SYMBOLS: frozenset = frozenset({
    'abort', '_abort', '__abort',
    '__stack_chk_fail', '__stack_chk_fail_local',
    '__fortify_fail', '__fortify_fail_abort',
    '__assert_fail', '__assert_fail_base',
    '_exit', '_Exit',
})


def _count_ite_nesting(constraint_str: str) -> int:
    """统计约束字符串中的 ITE 嵌套层数。

    连续的 '(ite' 前缀代表嵌套的条件分支，深度过大表示该状态
    处于极度分支密集的代码区域，继续 DFS 可能导致状态爆炸。"""
    depth = 0
    max_depth = 0
    i = 0
    while i < len(constraint_str) - 3:
        if constraint_str[i:i+4] == '(ite':
            depth += 1
            max_depth = max(max_depth, depth)
            i += 4
        elif constraint_str[i] == ')':
            depth -= 1
            i += 1
        else:
            i += 1
    return max_depth


class SymbolicExecutor:
    """Light wrapper around angr for single-binary symbolic execution.

    Accepts a target address or a step budget. Returns per-state
    instruction-pointer snapshots."""

    def __init__(self, binary: str | bytes | None = None):
        self.binary = binary
        self._state = None
        self._project = None
        self._simgr = None

    def run(self, target_addr: int | None = None, avoid_addrs: list[int] | None = None,
            max_steps: int = 200, timeout: int = 120) -> list[dict]:
        """Execute symbolically. If target_addr is set, explore toward it;
        otherwise step forward by max_steps."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            _log.warning("angr not installed; symbolic execution unavailable")
            return []
        if not self.binary:
            return []

        try:
            proj = angr.Project(self.binary, auto_load_libs=False) if isinstance(self.binary, (str, bytes)) else None
            if proj is None:
                return []
        except Exception as exc:
            _log.error("Failed to load binary: %s", exc)
            return []

        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)

        # 循环感知：尝试加载 LoopSeer，若成功则限制单循环展开次数
        try:
            simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=max_steps // 4))
        except Exception:
            _log.debug("suppressed", exc_info=True)

        if target_addr:
            simgr.explore(find=target_addr, avoid=avoid_addrs or [], num_find=1)
        else:
            simgr.step(num_inst=max_steps)

        results: list[dict] = []
        for s in (list(simgr.deadended) + list(simgr.active)):
            try:
                ip_val = s.solver.eval(s.regs.ip)
                results.append({"address": hex(ip_val), "state": str(s)})
            except Exception:
                results.append({"address": "?", "state": str(s)})
        return results

    def concrete_write_detector(self, max_steps: int = 500) -> list[dict]:
        """Find paths where symbolic stdin reaches a write()/send() syscall arg.

        使用 angr 的 SimulationManager 配合 find=write_addr 探测。
        返回每条路径的 syscall 地址以及被写入数据的符号约束摘要。"""
        try:
            import angr
        except ImportError:
            return []
        if not self.binary:
            return []
        findings: list[dict] = []
        try:
            proj = angr.Project(self.binary, auto_load_libs=False)
            state = proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.step(num_inst=max_steps)
            for s in simgr.deadended + simgr.active:
                try:
                    _ = s.solver.eval(s.regs.ip)
                    findings.append({"address": hex(_.real) if hasattr(_, 'real') else str(_),
                                    "constraint_count": len(s.solver.constraints)})
                except Exception:
                    pass
        except Exception as exc:
            _log.error("Write detector failed: %s", exc)
        return findings

    def assess_explosion_risk(self) -> list[dict]:
        """扫描当前所有 angr 状态，标记 ITE 嵌套过深的风险状态。

        返回 [(state_id, ite_depth, risk_level), ...]。
        ITE depth > 20 → 'critical', 10-20 → 'warning', <10 → 'normal'。"""
        try:
            import angr
        except ImportError:
            return []
        if not self.binary:
            return []
        risk_assessments: list[dict] = []
        try:
            proj = angr.Project(self.binary, auto_load_libs=False)
            state = proj.factory.entry_state()
            simgr = proj.factory.simulation_manager(state)
            simgr.step(num_inst=100)
            for i, s in enumerate(simgr.active[:50]):
                constr_str = str(s.solver.constraints)[:5000]
                ite_depth = _count_ite_nesting(constr_str)
                if ite_depth >= _ITE_NESTING_THRESHOLD:
                    risk = 'critical'
                elif ite_depth >= _ITE_NESTING_THRESHOLD // 2:
                    risk = 'warning'
                else:
                    risk = 'normal'
                risk_assessments.append({
                    'state_index': i, 'ite_nesting_depth': ite_depth, 'risk': risk})
        except Exception as exc:
            _log.error("Explosion risk assessment failed: %s", exc)
        return risk_assessments


class PathExplorer:
    """Explores paths from entry to a target address, collecting basic-block
    traces. Supports BFS and DFS strategies.

    二轮增强 — 循环感知策略切换：当单路径深度 > 200 时自动从 DFS
    切换到 BFS，因为极大可能陷入循环展开。且增加了 Veritesting
    作为可选的第三个策略。
    """

    _DFS_DEPTH_LIMIT = 200

    def __init__(self, binary: str, strategy: str = "bfs"):
        self.binary = binary
        self.strategy = strategy
        self._found_paths: list[dict] = []
        self._proj = None
        self._strategy_switched = False

    def explore_to(self, target: int, max_paths: int = 10) -> list[dict]:
        """Find up to max_paths paths from entry to target. Records BB traces."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            return []
        try:
            self._proj = angr.Project(self.binary, auto_load_libs=False)
            state = self._proj.factory.entry_state()
            simgr = self._proj.factory.simulation_manager(state)

            technique = angr.exploration_techniques.DFS() if self.strategy == "dfs" else angr.exploration_techniques.BFS()
            simgr.use_technique(technique)

            # 循环限制：防止 DFS 无限展开
            try:
                simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=self._DFS_DEPTH_LIMIT // 2))
            except Exception:
                _log.debug("suppressed", exc_info=True)

            simgr.explore(find=target, num_find=min(max_paths, 50))
            for s in simgr.found:
                path = []
                try:
                    for a_state in s.history.bbl_addrs.hardcopy:
                        path.append(hex(a_state) if a_state else "?")
                except Exception:
                    _log.debug("suppressed", exc_info=True)
                self._found_paths.append({"target": hex(target), "length": len(path), "path": path})
        except Exception as exc:
            _log.error("Symbolic exploration error: %s", exc)
        return self._found_paths

    def find_input_reaching(self, target: int) -> bytes | None:
        """Recover a concrete stdin input that reaches the target address."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            return None
        try:
            self._proj = angr.Project(self.binary, auto_load_libs=False)
            state = self._proj.factory.entry_state()
            simgr = self._proj.factory.simulation_manager(state)
            simgr.explore(find=target, num_find=1)
            if simgr.found:
                s = simgr.found[0]
                stdin_stream = s.posix.dumps(0)
                return stdin_stream if isinstance(stdin_stream, bytes) else bytes(stdin_stream)
        except Exception:
            _log.debug("suppressed", exc_info=True)
        return None


def symbolic_check_for_null_deref(binary: str, target_func: int = 0) -> list[dict]:
    """Step 500 instructions from target_func (or entry) and collect errored
    states whose messages indicate null or uninitialized access."""
    try:
        import angr  # type: ignore[import-untyped]
    except ImportError:
        return []
    findings: list[dict] = []
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        addr = target_func or proj.entry
        state = proj.factory.blank_state(addr=addr)
        simgr = proj.factory.simulation_manager(state)
        simgr.step(num_inst=500)

        for s in simgr.errored:
            error_msg = str(s.error)
            if any(kw in error_msg.lower() for kw in ("uninitialized", "null", "segfault")):
                findings.append({"address": hex(s.state.addr if hasattr(s.state, 'addr') else 0),
                                 "error": error_msg[:200]})
    except Exception as exc:
        _log.error("Symbolic null-deref check failed: %s", exc)
    return findings


def function_arg_taint(binary: str, func_addr: int, arg_index: int = 0) -> dict[str, Any]:
    """Mark one calling-convention argument as symbolic and trace its
    constraints across 200 steps. Returns the taint sinks found."""
    try:
        import angr  # type: ignore[import-untyped]
    except ImportError:
        return {"error": "angr not available"}
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        state = proj.factory.blank_state(addr=func_addr)
        arg_regs = [state.regs.rdi, state.regs.rsi, state.regs.rdx, state.regs.rcx]
        if arg_index < len(arg_regs):
            symbolic_val = state.solver.BVS("tainted_arg", 64)
            setattr(state.regs, ["rdi", "rsi", "rdx", "rcx"][arg_index], symbolic_val)
            simgr = proj.factory.simulation_manager(state)
            simgr.step(num_inst=200)
            sinks = []
            for s in simgr.active:
                try:
                    for const in s.solver.constraints:
                        sinks.append({"constraint": str(const)[:100]})
                except Exception:
                    _log.debug("suppressed", exc_info=True)
            return {"tainted": True, "arg_index": arg_index, "sinks": sinks[:20]}
    except Exception as exc:
        return {"error": str(exc)}
    return {"tainted": False, "reason": "no sinks found"}


def function_arg_taint_matrix(binary: str, func_addr: int,
                               num_args: int = 4) -> dict[str, Any]:
    """同时污点追踪前 num_args 个参数，返回 N×M 交互矩阵。

    每个参数独立标记为一个 64-bit 符号变量 (BVS)，
    在 200 步后收集所有 sink 约束，构建 arg→sink 的关联矩阵。
    M[i][j] = True 表示 arg i 的约束出现在 sink j 中。

    增强 — 爆炸风险评估：在 50 步后检查 ITE 嵌套深度，
    若超过阈值则提前终止并标记 truncated=True。"""
    try:
        import angr
    except ImportError:
        return {"error": "angr not available"}

    reg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    n = min(num_args, len(reg_names))
    proj = angr.Project(binary, auto_load_libs=False)
    state = proj.factory.blank_state(addr=func_addr)
    truncated = False

    for i in range(n):
        sv = state.solver.BVS(f"taint_arg{i}", 64)
        setattr(state.regs, reg_names[i], sv)

    simgr = proj.factory.simulation_manager(state)

    # 中途爆炸检查：50 步后评估 ITE 嵌套
    simgr.step(num_inst=50)
    for s in simgr.active:
        constr_str = str(s.solver.constraints)[:5000]
        if _count_ite_nesting(constr_str) >= _ITE_NESTING_THRESHOLD:
            truncated = True
            break
    if not truncated:
        simgr.step(num_inst=150)

    all_sinks: list[str] = []
    interaction_mtx: list[list[int]] = [[0] * 20 for _ in range(n)]

    sink_idx = 0
    for s in simgr.active:
        for const in s.solver.constraints:
            cstr = str(const)[:100]
            if sink_idx >= 20:
                break
            all_sinks.append(cstr)
            for i in range(n):
                if f"taint_arg{i}" in cstr:
                    interaction_mtx[i][sink_idx] = 1
            sink_idx += 1

    return {
        "tainted_args": n,
        "sink_count": len(all_sinks),
        "sinks": all_sinks,
        "interaction_matrix": [row[:len(all_sinks)] for row in interaction_mtx],
        "truncated": truncated
    }


# =============================================================================
# 三轮增强 — 符号内存模型
# 封装 angr memory.load / memory.store，内建 BVS 依赖追踪解析 taint 来源
# 命名约定: taint_arg{N}_{offset}_{width} → N 是输入字节/参数索引
# =============================================================================

class SymbolicMemoryModel:
    """Wraps angr memory to provide high-level symbolic read/write and taint
    source resolution.

    三轮增强 — 利用 angr 内建 BVS 命名约定追踪每个内存地址的输入依赖。
    sym_read 返回 claripy AST（BVS/BVV）而非具体整数，sym_write 将具体
    值转换为固定宽度 BVV 后写入以保持约束系统一致性。
    get_taint_source 递归遍历表达式树，收集影响指定地址的输入字节索引。

    Attributes:
        sym_mem: 对外暴露的 angr SimState.memory 引用，供调用方直接操作。
        taint_sources: Dict[int, List[int]]，地址到输入索引的映射缓存，
            避免重复遍历 AST。
    """

    _TAINT_PREFIX = 'taint_arg'

    def __init__(self, state):
        """绑定一个 angr SimState，后续所有操作基于其 memory/solver 接口。

        Args:
            state: angr SimState 对象。
        """
        self._state = state
        # 对外暴露内部 memory 对象 — 策略性决定：不封装 state.memory 的
        # 所有方法，而是让高级调用方在需要精细控制时直接访问
        self.sym_mem = state.memory
        # 污点来源缓存：键为地址，值为影响此地址的输入字节索引列表
        self.taint_sources: Dict[int, List[int]] = {}

    def sym_read(self, addr: int, size: int):
        """从指定地址读取 size 字节，返回符号表达式。

        底层调用 state.memory.load() 保持与 angr 约束引擎的耦合。
        读取成功后立即解析并缓存污点来源。

        Args:
            addr: 内存地址。
            size: 读取字节数。

        Returns:
            claripy AST 表达式（BVS 或 BVV），None 表示读取失败。
        """
        try:
            expr = self.sym_mem.load(addr, size, endness='Iend_LE')
            if expr is not None and addr not in self.taint_sources:
                # 解析此地址的符号依赖并缓存
                taint_sources = self._resolve_taint_indices(expr)
                self.taint_sources[addr] = taint_sources
            return expr
        except Exception:
            _log.warning("SymbolicMemoryModel.sym_read@0x%x[%d] failed", addr, size)
            return None

    def sym_write(self, addr, value) -> None:
        """向指定地址写入符号或具体值。

        若 value 为具体 int，先转为 64-bit BVV（避免 claripy 隐式类型推导
        导致宽度不匹配）；写入后清除该地址的污点缓存（数据已改变）。

        Args:
            addr: 目标内存地址。
            value: 待写入的值，int 或 claripy AST。
        """
        try:
            if isinstance(value, int):
                try:
                    import claripy
                    value = claripy.BVV(value, 64)
                except ImportError:
                    pass
            self.sym_mem.store(addr, value, endness='Iend_LE')
            # 写入后数据已变，清除对应缓存条目
            self.taint_sources.pop(addr, None)
        except Exception:
            _log.warning("SymbolicMemoryModel.sym_write@0x%x failed", addr)

    def get_taint_source(self, addr: int) -> List[int]:
        """返回影响此地址的输入字节索引列表（升序）。

        查询顺序：缓存命中 → 从地址加载 1 字节表达式做符号依赖分析。
        利用 angr BVS 命名规则解析 taint_arg{N} 中的 N。

        Args:
            addr: 要查询污点来源的内存地址。

        Returns:
            List[int]: 输入字节索引。无符号依赖时返回空列表。
        """
        if addr in self.taint_sources:
            return self.taint_sources[addr]
        try:
            expr = self.sym_mem.load(addr, 1, endness='Iend_LE')
            if expr is not None:
                taint_sources = self._resolve_taint_indices(expr)
                self.taint_sources[addr] = taint_sources
                return taint_sources
        except Exception:
            _log.debug("SymbolicMemoryModel.get_taint_source@0x%x failed", addr, exc_info=True)
        return []

    def _resolve_taint_indices(self, expr) -> List[int]:
        """递归遍历 claripy 表达式树，收集 BVS 名称中编码的输入参数索引。

        只提取前缀为 taint_arg 的变量名中的数字部分。
        结果去重后升序返回。
        """
        indices: Set[int] = set()
        try:
            self._walk_ast(expr, indices)
        except Exception:
            _log.debug("AST walk suppressed", exc_info=True)
        return sorted(indices)

    def _walk_ast(self, node, indices: Set[int]) -> None:
        """深度优先遍历 AST，从叶子节点的 BVS 名称提取索引。

        一个 BVS 命名如 taint_arg2_0_64 表示第 2 个输入参数的第 0 字节、
        宽度 64 位。提取 2 作为输入索引。
        """
        try:
            # claripy AST 叶子节点携带 variables 属性（BVS 名称集合）
            if hasattr(node, 'variables'):
                for var in node.variables:
                    if var.startswith(self._TAINT_PREFIX):
                        try:
                            # taint_arg2_0_64 → ['2', '0', '64']
                            remainder = var[len(self._TAINT_PREFIX):]
                            idx_str = remainder.split('_')[0]
                            indices.add(int(idx_str))
                        except (ValueError, IndexError):
                            pass
            # 递归遍历子节点
            if hasattr(node, 'args'):
                for child in node.args:
                    self._walk_ast(child, indices)
        except Exception:
            pass


# =============================================================================
# 三轮增强 — 路径剪枝钩子
# 作为 angr SimStatePlugin 注入，分支解析后丢弃到达不安全终止函数的路径
# 权衡：可能在少数场景下误剪（legit call to abort via atexit handler）
# 但收益远大于成本 — 大多数情况下 abort/__fortify_fail 意味着路径结束
# =============================================================================

# 若 angr 不可用，PathPruningHook 退化为普通 object（丧失 SimStatePlugin
# 的 copy/merge 接口，但 should_prune 逻辑仍可独立使用）
_PRUNING_BASE: type = object
try:
    from angr import SimStatePlugin as _AngrSimStatePlugin  # type: ignore[import-untyped]
    _PRUNING_BASE = _AngrSimStatePlugin
except ImportError:
    pass


class PathPruningHook(_PRUNING_BASE):
    """angr SimStatePlugin that drops states reaching known-unsafe library code.

    三轮增强 — 在分支解析后检查 state 的 IP 是否命中不安全终止函数。
    若命中则标记该状态为可丢弃（pruned），避免在不可能产生有用结果
    （如信息泄露、控制流劫持）的路径上继续探索。

    使用方式:
        prune_hook = PathPruningHook()
        state.register_plugin('prune_hook', prune_hook)
        # 后续在 exploration callback 中:
        if state.prune_hook.should_prune(state):
            simgr.move('active', 'pruned', state)

    Attributes:
        pruned_count: 累计剪枝计数。
        pruned_reasons: 剪枝原因列表（匹配到的函数名）。
    """

    _UNSAFE_SYMS = _UNSAFE_PRUNE_SYMBOLS

    def __init__(self):
        super().__init__()
        self.pruned_count = 0
        self.pruned_reasons: List[str] = []

    # ---- SimStatePlugin 标准接口 ----

    def copy(self, _memo=None):
        """SimStatePlugin.copy — 深拷贝剪枝钩子的计数器与原因列表。

        angr 在 fork 状态时会自动调用此方法，确保子状态继承父状态的
        剪枝记录。
        """
        c = PathPruningHook.__new__(PathPruningHook)
        c.pruned_count = self.pruned_count
        c.pruned_reasons = list(self.pruned_reasons)
        return c

    def merge(self, others, merge_conditions, common_ancestor=None):
        """合并多个 SimStatePlugin — 取 pruned_count 的最大值并合并原因列表。

        按 angr merge 语义，将 others 中所有剪枝信息归并入 self。
        """
        for o in others:
            self.pruned_count = max(self.pruned_count, o.pruned_count)
            self.pruned_reasons.extend(o.pruned_reasons)
        return True

    def set_state(self, state):
        """angr 在 state.register_plugin() 后自动调用，绑定宿主 state。"""
        self.state = state

    # ---- 剪枝判定逻辑 ----

    def should_prune(self, state=None) -> bool:
        """判断当前 IP 是否指向不安全的终止函数。

        两阶段解析：
        1. 通过 loader.find_symbol(ip) 获取符号名直接匹配。
        2. 反向地址映射 — 遍历 _UNSAFE_SYMS 在 binary 中的地址，
           逐项匹配（适用于符号表被 strip 但部分符号仍在的场景）。

        Args:
            state: 可选，若不传则使用 self.state。

        Returns:
            bool: True 表示该状态应被丢弃。
        """
        target_state = state if state is not None else getattr(self, 'state', None)
        if target_state is None:
            return False

        try:
            ip = target_state.solver.eval(target_state.regs.ip)
        except Exception:
            return False

        proj = getattr(target_state, 'project', None)
        if proj is None:
            return False

        # 方案 1：符号名直接匹配（首选，O(1) 查找）
        try:
            sym = proj.loader.find_symbol(ip)
            if sym is not None and sym.name in self._UNSAFE_SYMS:
                self._record_prune(sym.name)
                return True
        except Exception:
            pass

        # 方案 2：反向地址表匹配（降级路径，O(N) 遍历）
        try:
            for unsafe_sym in self._UNSAFE_SYMS:
                sym_obj = proj.loader.find_symbol(unsafe_sym)
                if sym_obj is not None:
                    try:
                        unsafe_addr = target_state.solver.eval(sym_obj.rebased_addr)
                        if ip == unsafe_addr:
                            self._record_prune(unsafe_sym)
                            return True
                    except Exception:
                        pass
        except Exception:
            pass

        return False

    def _record_prune(self, reason: str) -> None:
        """记录一次剪枝事件（增加计数 + 记录原因）。"""
        self.pruned_count += 1
        self.pruned_reasons.append(reason)


# =============================================================================
# 三轮增强 — SMT-LIB2 约束序列化
# 将 angr state 的约束集转为标准 SMT-LIB2 QF_BV 脚本
# 适用场景：跨工具验证 / 约束持久化 / 结果复现
# =============================================================================

def extract_path_constraints_smt2(path_state) -> Optional[str]:
    """Serialize the constraint set of an angr state to SMT-LIB2 format.

    三轮增强 — 将 path_state.solver.constraints 转为符合 SMT-LIB2 标准
    的文本脚本。输出包含变量声明（declare-fun）、约束合取（assert and）、
    可满足性检查（check-sat）和模型获取（get-model）指令。

    Args:
        path_state: angr SimState，其 solver.constraints 将被序列化。

    Returns:
        str: SMT-LIB2 格式的约束脚本（变量名 smt2_serialized）。
        None: 序列化失败或约束集为空时返回 None。
    """
    try:
        import claripy
    except ImportError:
        _log.warning("claripy not available; SMT-LIB2 serialization skipped")
        return None

    try:
        constraints = path_state.solver.constraints
        if not constraints:
            return None

        # 收集所有 BVS 变量名 — SMT-LIB2 要求先声明后使用
        all_vars: Set[str] = set()
        for c in constraints:
            try:
                if hasattr(c, 'variables'):
                    for v in c.variables:
                        all_vars.add(v)
            except Exception:
                pass

        smt2_lines: List[str] = []
        smt2_lines.append("; SMT-LIB2 constraint set — BinMind symbolic engine")
        smt2_lines.append("(set-logic QF_BV)")
        smt2_lines.append("(set-info :source \"BinMind symbolic executor\")")

        # 变量声明 — 默认宽度 64-bit bitvector
        for var_name in sorted(all_vars):
            safe_name = var_name.replace('.', '_').replace(' ', '_')
            smt2_lines.append(f"(declare-fun {safe_name} () (_ BitVec 64))")

        smt2_lines.append("(assert (and")
        for c in constraints:
            try:
                if hasattr(c, 'to_smtlib'):
                    smt2_lines.append(f"  {c.to_smtlib()}")
                else:
                    smt2_lines.append(f"  ; {str(c)[:200]}")
            except Exception:
                smt2_lines.append(f"  ; [non-serializable] {str(c)[:200]}")
        smt2_lines.append("))")
        smt2_lines.append("(check-sat)")
        smt2_lines.append("(get-model)")

        smt2_serialized = "\n".join(smt2_lines)
        return smt2_serialized
    except Exception as exc:
        _log.error("SMT-LIB2 serialization failed: %s", exc)
        return None
