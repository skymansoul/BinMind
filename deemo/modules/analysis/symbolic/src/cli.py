#!/usr/bin/env python3
"""
symbolic — 命令行入口 (BinMind symbolic CLI)

Subcommands:
执行 — 运行 符号执行 a target binary/IR
优化 — 运行 path 优化 (pruning, merging, unrolling)
solve — standalone 约束求解 SMT-LIB or JSON

Usage:
binmind-symbolic 执行 --ir demo.ir --entry 0x401000
binmind-symbolic 优化 --ir demo.ir
binmind-symbolic solve --constraints "x > 5 x < 10" --var x
"""
# from collections import OrderedDict  # python3.7+不需要了
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


def _load_config(config_path: Optional[str] = None) -> Any:
    """Load config, falling back to defaults. O(|config_file|)"""
    try:
        from analysis.symbolic.src.config import load_config
        return load_config(config_path)
    except ImportError:
        _log.debug("Config module not available — using defaults")
        return None


# Subcommand: 执行

def _cmd_execute(args: argparse.Namespace) -> int:
    """
    运行 符号执行 a target

    这个命令会读取IR文件，逐行解析IR指令，然后喟给SymbolicExecutor跑符号执行
    """
    _log.info("Executing symbolic exploration...")

    # 校验 inputs
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

    # 构建 IR fetcher
    ir_map: Dict[int, Any] = {}
    for instr in ir_instructions:
        if hasattr(instr, 'address'):
            ir_map[instr.address] = instr

    def ir_fetcher(addr: int) -> Any:
        # try 提供 a NOP exact match
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


# Subcommand: 优化

def _cmd_optimize(args: argparse.Namespace) -> int:
    """
    运行 path 优化 constraints/states

    Edge case: Z3 installed, prune mode skip fully
    symbolic 检查 heuristic simplification
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

    # 加载 constraints provided
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


# Subcommand: solve

def _cmd_solve(args: argparse.Namespace) -> int:
    """
    Solve constraints standalone (execution needed)

    // 策略: 独立求解模式允许在不跑完整符号执行的情况下快速
    // 验证某条路径的约束是否可满足，这对路径可行性分析有用
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


# 辅助: IR file loading

def _load_ir_file(path: str) -> List[Any]:
    """
    加载 IR instructions a JSON-lines file

    格式化 (one JSON object per line):
    {"op": "MOV", "operands": ["%eax", "$0x10"], "address": 0x401000}

    返回 a list IRInstruction objects

    Time: O(|file_lines|). Space: O(|instructions|)
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
    """保存 result dict JSON. O(|data|)"""
    import json
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print("Result saved to: {}".format(path))
    except Exception as e:
        print("Error saving result: {}".format(e), file=sys.stderr)


# Main CLI

def main(argv: Optional[List[str]] = None) -> int:
    """
    Main 入口 for binmind-symbolic CLI

    解析 args, sets up 日志, 分派 subcommands

    Time: O(|argv|) for parsing. Space: O(1)

    Edge case: argv None, sys.argv used (standard argparse behavior)
    """
    p = argparse.ArgumentParser(
        prog="binmind-symbolic",
        description="BinMind symbolic execution CLI",
    )
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", action="store_true", help="Debug logging")
    p.add_argument("--output", "-o", default=None, help="Output file path")

    # Subcommands
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

    # solve
    sp_sol = sp.add_parser("solve", help="Solve constraints standalone")
    sp_sol.add_argument("--constraints", default=None,
                        help="Constraints (JSON string or file path)")
    sp_sol.add_argument("--var", default=None, help="Variable to solve for")
    sp_sol.add_argument("--smtlib", default=None, help="SMT-LIB2 expression")

    args = p.parse_args(argv)

    # Setup 日志
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

    # Route subcommand
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
