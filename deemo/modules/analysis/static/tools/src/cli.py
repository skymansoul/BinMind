#!/usr/bin/env python3
"""BinMind Tools CLI - static analysis, fuzzing, syscall classification,
semantic diff, audit subcommands
"""

import argparse
import logging
import os
import sys
from typing import Any, Optional

_log = logging.getLogger(__name__)


def _setup_logging(args: argparse.Namespace) -> None:
    """配置ure 日志 基于 command-line flags"""
    if args.debug:
        level = logging.DEBUG
        fmt = "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
    elif args.verbose:
        level = logging.INFO
        fmt = "%(asctime)s [%(levelname)s] %(message)s"
    else:
        level = logging.WARNING
        fmt = "%(levelname)s: %(message)s"

    # 检查 for 记录 file 配置
    log_file = getattr(args, "log_file", None)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(level=level, format=fmt, handlers=handlers)


# Subcommand 处理器s


def _cmd_static_scan(args: argparse.Namespace) -> int:
    """处理器 for 'static-scan' subcommand"""
    from .core import LLVMIRAnalyzer

    target = args.target
    if not target:
        _log.error("static-scan requires --target")
        return 1

    _log.info("Running static scan on: %s", target)

    # a real scenario, 读取 file, but for accept raw IR stdin
    # or --input
    input_path = getattr(args, "input", None)
    if input_path and os.path.isfile(input_path):
        with open(input_path, "r", encoding="utf-8") as f:
            ir_text = f.read()
    else:
        _log.info("Reading LLVM IR from stdin (Ctrl+D to end)...")
        ir_text = sys.stdin.read()

    if not ir_text.strip():
        _log.error("No IR input provided. Use --input or pipe IR text.")
        return 1

    analyzer = LLVMIRAnalyzer()
    results = analyzer.analyze(ir_text)

    print(f"=== Static Scan Results for: {target} ===")
    print(f"Total findings: {results['total_findings']}")
    print(f"  Unsafe casts:        {len(results['unsafe_casts'])}")
    print(f"  Missing bounds:      {len(results['missing_bounds_checks'])}")
    print(f"  Use-after-free:      {len(results['use_after_free'])}")

    for finding_type, findings in results.items():
        if finding_type == "total_findings" or not findings:
            continue
        for f in findings:
            print(f"  [{f.get('severity', '?')}] L{f.get('line', '?')}: {f.get('type', finding_type)}")
            if "source" in f:
                print(f"       {f['source'][:120]}")

    return 0 if results["total_findings"] == 0 else 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    """处理器 for 'fuzz' subcommand"""
    from .core import StateGuidedFuzzer, DifferentialFuzzer

    target = args.target
    if not target:
        _log.error("fuzz requires --target")
        return 1

    _log.info("Starting fuzz on: %s", target)

    mode = getattr(args, "mode", "state")
    input_file = getattr(args, "input", None)

    inputs: list[bytes] = []
    if input_file and os.path.isfile(input_file):
        with open(input_file, "rb") as f:
            inputs = [f.read()]
    else:
        # Default seed inputs
        inputs = [b"\x00", b"A" * 64, b"\xff" * 128]

    print(f"=== Fuzzing: {target} (mode={mode}) ===")

    if mode == "state":
        fuzzer = StateGuidedFuzzer()
        # Placeholder traces - real usage come an 仿真器
        traces: list[dict[str, Any]] = [
            {"state": {"pc": 0x1000, "rax": 0}, "input": b"\x00"},
            {"state": {"pc": 0x2000, "rax": 1}, "input": b"A" * 64},
        ]
        states = fuzzer.infer_states(traces)
        graph = fuzzer.build_transition_graph(states)
        print(f"Inferred {len(states)} states, {len(graph.get('edges', []))} transitions")
        for state_id, info in states.items():
            print(f"  State {state_id}: visited={info['visit_count']}")
    elif mode == "differential":
        compilers = getattr(args, "compilers", "gcc clang").split()
        fuzzer = DifferentialFuzzer()
        variants = fuzzer.compile_variants(target, compilers)
        results = fuzzer.fuzz_all(variants, inputs)
        divergences = fuzzer.compare_outputs(results)
        print(f"Compiled {len(variants)} variants, {len(divergences)} divergences found")
    else:
        _log.error("Unknown fuzz mode: %s (use 'state' or 'differential')", mode)
        return 1

    return 0


def _cmd_syscall(args: argparse.Namespace) -> int:
    """Handler for 'syscall' subcommand"""
    from .core import SyscallClassifier

    input_path = getattr(args, "input", None)
    if not input_path:
        _log.error("syscall requires --input")
        return 1

    _log.info("Classifying syscall sequence from: %s", input_path)

    with open(input_path, "r", encoding="utf-8") as f:
        sequence = [line.strip() for line in f if line.strip()]

    if not sequence:
        _log.error("Empty syscall sequence")
        return 1

    # Default malware profiles (placeholder - production come a 数据库)
    profiles: dict[str, list[tuple[str, ...]]] = {
        "ransomware": [
            ("open", "read", "write"),
            ("write", "close", "rename"),
            ("open", "write", "close"),
        ],
        "keylogger": [
            ("open", "read", "socket"),
            ("socket", "connect", "send"),
            ("read", "send", "close"),
        ],
        "dropper": [
            ("socket", "connect", "recv"),
            ("recv", "write", "execve"),
            ("open", "write", "chmod"),
        ],
    }

    classifier = SyscallClassifier(n=3)
    ngrams = classifier.extract_ngrams(sequence)
    vec = classifier.build_frequency_vector(ngrams)
    result = classifier.classify(sequence, profiles)

    print(f"=== Syscall Classification ===")
    print(f"Sequence length: {len(sequence)} calls")
    print(f"Unique 3-grams:  {len(ngrams)}")
    print(f"Classification:  {result}")

    # 显示 top profile scores
    seq_vec = vec
    for family, profile_ngrams in profiles.items():
        profile_vec = classifier.build_frequency_vector(profile_ngrams)
        score = classifier.cosine_similarity(seq_vec, profile_vec)
        marker = " <--" if family == result else ""
        print(f"  {family:15s}: similarity={score:.4f}{marker}")

    return 0


def _cmd_semantic_diff(args: argparse.Namespace) -> int:
    """处理器 for 'semantic-diff' subcommand"""
    from .core import SemanticDiffAnalyzer

    input_a = args.input
    input_b = getattr(args, "target", None)

    if not input_a or not input_b:
        _log.error("semantic-diff requires --input and --target (two binaries)")
        return 1

    _log.info("Computing semantic diff: %s vs %s", input_a, input_b)

    # 读取 files 分割 instruction lines
    def _read_instructions(path: str) -> list[str]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.strip() for line in f if line.strip()]

    try:
        insns_a = _read_instructions(input_a)
        insns_b = _read_instructions(input_b)
    except FileNotFoundError as e:
        _log.error("File not found: %s", e)
        return 1
    except Exception as e:
        _log.error("Error reading files: %s", e)
        return 1

    analyzer = SemanticDiffAnalyzer()
    hashes_a = analyzer.extract_hashes(insns_a)
    hashes_b = analyzer.extract_hashes(insns_b)
    similarity = analyzer.compute_similarity(hashes_a, hashes_b)

    # 构建 pseudo-binary dicts for diff method
    binary_a = {"functions": {"main": insns_a}}
    binary_b = {"functions": {"main": insns_b}}

    result = analyzer.diff(binary_a, binary_b)

    print(f"=== Semantic Diff Results ===")
    print(f"Binary A: {input_a} ({len(insns_a)} instructions)")
    print(f"Binary B: {input_b} ({len(insns_b)} instructions)")
    print(f"Jaccard similarity: {similarity:.4f}")
    print(f"Added:    {result['added']}")
    print(f"Removed:  {result['removed']}")
    print(f"Modified: {result['modified']}")
    print(f"Unchanged:{result['unchanged']}")

    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    """处理器 for 'audit' subcommand"""
    from .core import LLVMIRAnalyzer, BranchExploitability
    from .config import load_config, validate_config

    config_path = getattr(args, "config", None)
    if config_path and os.path.isfile(config_path):
        try:
            cfg = load_config(config_path)
            validate_config(cfg)
            _log.info("Config loaded and validated: %s", config_path)
        except Exception as e:
            _log.error("Config error: %s", e)
            return 1
    else:
        _log.info("No config file provided, using defaults")

    target = args.target
    if not target:
        _log.error("audit requires --target")
        return 1

    _log.info("Running full audit on: %s", target)

    print(f"=== Audit Report: {target} ===")

    # LLVM IR analysis
    input_path = getattr(args, "input", None)
    if input_path and os.path.isfile(input_path):
        with open(input_path, "r", encoding="utf-8") as f:
            ir_text = f.read()
        ir_analyzer = LLVMIRAnalyzer()
        ir_results = ir_analyzer.analyze(ir_text)
        print(f"\n[LLVM IR Analysis]")
        print(f"  Findings: {ir_results['total_findings']}")
        for severity in ("CRITICAL", "HIGH", "MEDIUM"):
            count = sum(
                1 for findings in ir_results.values()
                if isinstance(findings, list)
                for f in findings
                if f.get("severity") == severity
            )
            if count > 0:
                print(f"    {severity}: {count}")

    # CFG 漏洞利用ability
    print(f"\n[Exploitability Analysis]")
    expl = BranchExploitability()
    test_insns: list[dict[str, Any]] = [
        {"addr": 0x1000, "op": "push", "fallthrough": 0x1001},
        {"addr": 0x1001, "op": "mov", "fallthrough": 0x1002},
        {"addr": 0x1002, "op": "cmp", "fallthrough": 0x1003, "target": 0x2000},
        {"addr": 0x1003, "op": "call", "fallthrough": 0x1004},
        {"addr": 0x1004, "op": "ret"},
    ]
    cfg = expl.extract_cfg(test_insns)
    print(f"  Entry: 0x{cfg['entry']:x}")
    print(f"  Nodes: {len(cfg['nodes'])}")
    print(f"  Edges: {len(cfg['edges'])}")

    controllability = expl.analyze_controllability(cfg, 0x1002)
    print(f"  Controllable at 0x1002: reachable={controllability['reachable']}, "
          f"regs={controllability['controllable_regs']}")

    path = expl.find_exploit_path(cfg, 0x1000, 0x1004)
    if path:
        print(f"  Exploit path: {' -> '.join(hex(a) for a in path)}")

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Main CLI 入口"""
    p = argparse.ArgumentParser(
        prog="binmind-tools",
        description="BinMind Static Analysis Tools CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  binmind-tools static-scan --target binary.ll --input file.ll\n"
            "  binmind-tools fuzz --target binary.exe --mode state\n"
            "  binmind-tools syscall --input syscalls.txt\n"
            "  binmind-tools semantic-diff --input old.asm --target new.asm\n"
            "  binmind-tools audit --target binary.exe --input ir.ll --config default.yaml"
        ),
    )
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--output", "-o", default=None, help="Output file path")

    # 创建 sub解析器 - FIX: 使用 sp, sub解析器s
    sp = p.add_subparsers(dest="command", help="Available sub-commands")

    # static-scan: LLVM IR analysis
    p_scan = sp.add_parser("static-scan", help="Run LLVM IR static analysis scan. "
                          "Recieve (sic) IR from --input or stdin.")
    p_scan.add_argument("--target", "-t", required=False, default=None,
                        help="Target binary or project name for reporting")
    p_scan.add_argument("--input", "-i", default=None,
                        help="Input LLVM IR file path")

    # fuzz: state-guided or differential 模糊测试
    p_fuzz = sp.add_parser("fuzz", help="Run state-guided or differential fuzzing")
    p_fuzz.add_argument("--target", "-t", required=True,
                        help="Target binary path to fuzz")
    p_fuzz.add_argument("--input", "-i", default=None,
                        help="Input seed file path")
    p_fuzz.add_argument("--mode", "-m", default="state",
                        choices=["state", "differential"],
                        help="Fuzzing mode: state-guided or differential")

    # 系统调用: 系统调用 sequence 分类
    p_sys = sp.add_parser("syscall", help="Classify syscall sequences by malware family")
    p_sys.add_argument("--input", "-i", required=True,
                       help="Input file with syscall names (one per line)")

    # semantic-diff: binary semantic diff
    p_diff = sp.add_parser("semantic-diff", help="Compute semantic diff between two binaries")
    p_diff.add_argument("--input", "-i", required=True,
                        help="First binary instruction file")
    p_diff.add_argument("--target", "-t", required=True,
                        help="Second binary instruction file")

    # audit: full security audit
    p_audit = sp.add_parser("audit", help="Run full security audit on a binary")
    p_audit.add_argument("--target", "-t", required=True,
                         help="Target binary path to audit")
    p_audit.add_argument("--input", "-i", default=None,
                         help="Input LLVM IR file for IR analysis")

    args = p.parse_args(argv)
    _setup_logging(args)

    if not args.command:
        p.print_help()
        sys.exit(1)

    _log.info("Running: %s", args.command)

    # Dispatch subcommand 处理器s
    handlers = {
        "static-scan": _cmd_static_scan,
        "fuzz": _cmd_fuzz,
        "syscall": _cmd_syscall,
        "semantic-diff": _cmd_semantic_diff,
        "audit": _cmd_audit,
    }

    handler = handlers.get(args.command)
    if handler is None:
        _log.error("Unknown command: %s", args.command)
        p.print_help()
        return 1

    try:
        return handler(args)
    except Exception as e:
        _log.exception("Command '%s' failed: %s", args.command, e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
