#!/usr/bin/env python3
"""
symbolic — 命令行入口 (BinMind symbolic CLI)

子命令:
执行 — 运行符号执行, 目标为二进制/IR
优化 — 运行路径优化 (裁剪, 合并, 展开)
solve — 独立约束求解 SMT-LIB 或 JSON

用法:
binmind-symbolic 执行 --ir demo.ir --entry 0x401000
binmind-symbolic 优化 --ir demo.ir
binmind-symbolic solve --constraints "x > 5 x < 10" --var x
"""
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


def _load_config(config_path: Optional[str] = None) -> Any:
    """加载配置, 回退到默认值"""
    try:
        from analysis.symbolic.src.config import load_config
        return load_config(config_path)
    except ImportError:
        _log.debug("Config module not available — using defaults")
        return None


# 子命令: 执行

def _cmd_execute(args: argparse.Namespace) -> int:
    """
    运行符号执行

    读取 IR 文件, 逐行解析 IR 指令, 喂给 SymbolicExecutor 跑符号执行
    """
    _log.info("Executing symbolic exploration...")

    # 校验输入
    if not args.ir or not os.path.exists(args.ir):
        print("Error: IR file not found: {}".format(args.ir), file=sys.stderr)
        return 1

    try:
        entry = int(args.entry, 0) if args.entry else 0
    except (ValueError, TypeError):
        print("Error: Invalid entry address: {}".format(args.entry), file=sys.stderr)
        return 1

    # 加载 IR
    ir_instructions = _load_ir_file(args.ir)
    if not ir_instructions:
        print("Warning: IR file contains no parseable instructions.", file=sys.stderr)

    # 构建 IR 取指器
    ir_map: Dict[int, Any] = {}
    for instr in ir_instructions:
        if hasattr(instr, 'address'):
            ir_map[instr.address] = instr

    def ir_fetcher(addr: int) -> Any:
        # 尝试提供 NOP 精确匹配
        return ir_map.get(addr)

    # 执行
    from analysis.symbolic.src.executor import (
        SymbolicExecutor, SymbolicState, ExecutionStrategy,
    )
    from analysis.symbolic.src.config import load_config as _lc

    cfg = _lc()
    strategy_map = {
        "bfs": ExecutionStrategy.BFS,
        "dfs": ExecutionStrategy.DFS,
        "coverage": ExecutionStrategy.COVERAGE_MAX,
        "llm": ExecutionStrategy.LLM_GUIDED,
    }
    strategy = strategy_map.get(args.strategy, ExecutionStrategy.DFS)

    executor = SymbolicExecutor(
        strategy=strategy,
        max_states=cfg.get("engine.max_states", 1024),
        max_depth=args.max_depth if args.max_depth else cfg.get("engine.max_depth", 1000),
        solver_timeout_ms=cfg.get("engine.solver_timeout_ms", 5000),
    )

    initial_state = SymbolicState(
        state_id=1,
        pc=entry,
        registers={},
        memory={},
        depth=0,
    )

    result = executor.explore(initial_state, ir_fetcher, max_steps=args.max_steps)

    # 报告
    print("=" * 60)
    print("Symbolic Execution Result")
    print("=" * 60)
    print("Paths explored: {}".format(result.paths_explored))
    print("Timeouts:       {}".format(result.timeouts))
    print("Solutions found: {}".format(result.solutions_found))
    print("Coverage entries: {}".format(len(result.coverage)))
    print("Peak states:    {}".format(result.total_states))
    print("Elapsed:        {:.2f}s".format(result.elapsed_seconds))
    print("=" * 60)

    if args.output:
        _save_json_result(args.output, result.to_dict())

    return 0


# 子命令: 优化

def _cmd_optimize(args: argparse.Namespace) -> int:
    """
    运行路径优化

    Z3 可用时启用求解裁剪, 不可用时降级为启发式简化
    """
    _log.info("Running path optimization...")

    from analysis.symbolic.src.optimizer import PathOptimizer, ConstraintSimplifier
    from analysis.symbolic.src.solver import ConstraintSolver

    solver = None
    try:
        solver = ConstraintSolver()
    except Exception:
        _log.info("Z3 not available — optimization in heuristic mode")

    simplifier = ConstraintSimplifier()
    optimizer = PathOptimizer(
        constraint_solver=solver,
        simplifier=simplifier,
        pruning_enabled=args.mode in ("prune", "all"),
        merging_enabled=args.mode in ("merge", "all"),
    )

    # 加载约束
    constraints: List[Dict] = []
    if args.constraints and os.path.exists(args.constraints):
        import json
        try:
            with open(args.constraints, "r", encoding="utf-8") as f:
                constraints = json.load(f)
        except Exception as e:
            print("Error loading constraints: {}".format(e), file=sys.stderr)
            return 1

    if constraints:
        simplified = simplifier.simplify(constraints)
        print("Constraints: {} original -> {} after simplification".format(
            len(constraints), len(simplified)))
        for c in simplified[:10]:
            print("  {}".format(c))
        if len(simplified) > 10:
            print("  ... and {} more".format(len(simplified) - 10))

    print("Optimization stats: {}".format(optimizer.get_stats()))
    return 0


# 子命令: 求解

def _cmd_solve(args: argparse.Namespace) -> int:
    """
    独立求解约束

    无需跑完整符号执行, 快速验证单条路径约束的可满足性
    """
    _log.info("Solving constraints...")

    from analysis.symbolic.src.solver import ConstraintSolver, SolverNotFound
    from analysis.symbolic.src.utils import parse_constraints, smtlib_to_z3

    solver = None
    try:
        solver = ConstraintSolver()
    except SolverNotFound:
        print("Error: Z3 is not installed. Cannot solve constraints.", file=sys.stderr)
        print("Install with: pip install z3-solver", file=sys.stderr)
        return 2

    constraints = []

    if args.smtlib:
        z3_expr = smtlib_to_z3(args.smtlib)
        if z3_expr is not None:
            constraints = [z3_expr]
        else:
            print("Error: Failed to parse SMT-LIB input.", file=sys.stderr)
            return 2
    elif args.constraints:
        if os.path.exists(args.constraints):
            import json
            try:
                with open(args.constraints, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                constraints = parse_constraints(raw)
            except Exception as e:
                print("Error: Failed to parse constraints file: {}".format(e), file=sys.stderr)
                return 2
        else:
            constraints = parse_constraints(args.constraints)

    if args.var:
        result = solver.solve(constraints, args.var)
        if result is not None:
            print("SAT: {} = {} (0x{:x})".format(args.var, result, result))
            return 0
        else:
            print("UNSAT: no solution for {}".format(args.var))
            return 1
    else:
        satisfiable = solver.is_satisfiable(constraints)
        print("Result: {}".format("SAT" if satisfiable else "UNSAT"))
        return 0 if satisfiable else 1


# 辅助: IR 文件加载

def _load_ir_file(path: str) -> List[Any]:
    """
    从 JSON-lines 文件加载 IR 指令

    每行一个 JSON 对象:
    {"op": "MOV", "operands": ["%eax", "$0x10"], "address": 0x401000}

    返回 IRInstruction 对象列表
    """
    from analysis.symbolic.src.executor import IRInstruction
    import json

    instructions = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    obj = json.loads(line)
                    instr = IRInstruction.from_dict(obj)
                    instructions.append(instr)
                except json.JSONDecodeError:
                    _log.debug("Skipping non-JSON line %d in IR file", line_no)
                except Exception as e:
                    _log.debug("Skipping malformed instruction at line %d: %s", line_no, e)
    except Exception as e:
        _log.warning("Failed to read IR file %s: %s", path, e)

    return instructions


def _save_json_result(path: str, data: Dict[str, Any]) -> None:
    """保存结果到 JSON 文件"""
    import json
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print("Result saved to: {}".format(path))
    except Exception as e:
        print("Error saving result: {}".format(e), file=sys.stderr)


# 主入口 CLI

def main(argv: Optional[List[str]] = None) -> int:
    """
    binmind-symbolic CLI 主入口

    解析参数, 配置日志, 分派子命令
    """
    p = argparse.ArgumentParser(
        prog="binmind-symbolic",
        description="BinMind symbolic execution CLI",
    )
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", action="store_true", help="Debug logging")
    p.add_argument("--output", "-o", default=None, help="Output file path")

    # 子命令
    sp = p.add_subparsers(dest="command", help="Sub-commands")

    # 执行
    sp_exec = sp.add_parser("execute", help="Run symbolic execution")
    sp_exec.add_argument("--ir", required=True, help="Path to IR file (JSON lines)")
    sp_exec.add_argument("--entry", default="0x0", help="Entry address (hex or decimal)")
    sp_exec.add_argument("--strategy", default="dfs",
                         choices=["bfs", "dfs", "coverage", "llm"],
                         help="Exploration strategy")
    sp_exec.add_argument("--max-steps", type=int, default=10000,
                         help="Maximum execution steps")
    sp_exec.add_argument("--max-depth", type=int, default=0,
                         help="Maximum path depth (0 = use config default)")

    # 优化
    sp_opt = sp.add_parser("optimize", help="Run path optimization")
    sp_opt.add_argument("--constraints", default=None, help="Path to constraints JSON file")
    sp_opt.add_argument("--mode", default="all",
                        choices=["prune", "merge", "simplify", "all"],
                        help="Optimization mode")

    # 求解
    sp_sol = sp.add_parser("solve", help="Solve constraints standalone")
    sp_sol.add_argument("--constraints", default=None,
                        help="Constraints (JSON string or file path)")
    sp_sol.add_argument("--var", default=None, help="Variable to solve for")
    sp_sol.add_argument("--smtlib", default=None, help="SMT-LIB2 expression")

    args = p.parse_args(argv)

    # 配置日志
    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                          format="%(asctime)s [%(levelname)s] %(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.INFO,
                          format="%(asctime)s [%(levelname)s] %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not args.command:
        p.print_help()
        return 1

    _log.info("Running command: %s", args.command)

    # 分派子命令
    if args.command == "execute":
        return _cmd_execute(args)
    elif args.command == "optimize":
        return _cmd_optimize(args)
    elif args.command == "solve":
        return _cmd_solve(args)
    else:
        print("Unknown command: {}".format(args.command), file=sys.stderr)
        p.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
