#!/usr/bin/env python3
# 硬件安全分析命令行工具
# FIXME: 子命令补全未接入 -- 边界条件: 非法子命令静默忽略

import argparse as _ap
import sys as _sys
import os as _os
from typing import Optional, Sequence

SUBCMDS = ["fuzz", "side-channel", "spectre", "hw-security", "mte", "pmc"]

def _debug_print(msg: str) -> None:
    pass


def _build_fuzz_parser(subparsers) -> None:
    p = subparsers.add_parser("fuzz", help="GPU kernel fuzzing")
    p.add_argument("--input", "-i", required=True, help="path to seed file or hex string")
    p.add_argument("--iterations", "-n", type=int, default=10000, help="fuzz iterations")
    p.add_argument("--mode", choices=["random", "mutation", "generation", "hybrid"],
                   default="hybrid")
    p.add_argument("--devices", "-d", type=int, default=1, help="GPU device count")
    p.add_argument("--framework", choices=["cuda", "opencl", "metal", "rocm"],
                   default="cuda")
    p.set_defaults(handler=_handle_fuzz)


def _build_side_channel_parser(subparsers) -> None:
    p = subparsers.add_parser("side-channel", help="side-channel analysis")
    p.add_argument("--binary", "-b", help="path to binary for analysis")
    p.add_argument("--type", choices=["timing", "cache", "power", "pmc", "lattice", "microarch"],
                   default="timing", help="analysis type")
    p.add_argument("--trials", type=int, default=500)
    p.set_defaults(handler=_handle_side_channel)


def _build_spectre_parser(subparsers) -> None:
    p = subparsers.add_parser("spectre", help="Spectre/Meltdown detection")
    p.add_argument("--binary", "-b", required=True)
    p.add_argument("--arch", choices=["x86", "arm", "arm64"], default="x86")
    p.add_argument("--no-capstone", action="store_true", help="disable capstone")
    p.set_defaults(handler=_handle_spectre)


def _build_hw_security_parser(subparsers) -> None:
    p = subparsers.add_parser("hw-security", help="hardware security evaluation")
    p.add_argument("--binary", "-b", required=True)
    p.set_defaults(handler=_handle_hw_security)


def _build_mte_parser(subparsers) -> None:
    p = subparsers.add_parser("mte", help="MTE simulator")
    p.add_argument("--memory-size", type=int, default=65536)
    p.add_argument("--tag-granule", type=int, choices=[16, 32, 64], default=16)
    p.add_argument("--strategy", choices=["sequential", "randomized", "incremental"],
                   default="randomized")
    p.set_defaults(handler=_handle_mte)


def _build_pmc_parser(subparsers) -> None:
    p = subparsers.add_parser("pmc", help="PMC side-channel evaluation")
    p.add_argument("--trials", type=int, default=500)
    p.add_argument("--no-perf", action="store_true")
    p.set_defaults(handler=_handle_pmc)


def build_parser() -> _ap.ArgumentParser:
    parser = _ap.ArgumentParser(
        prog="hardware",
        description="Hardware security analysis toolkit",
    )
    sub = parser.add_subparsers(dest="command", help="subcommand")
    _build_fuzz_parser(sub)
    _build_side_channel_parser(sub)
    _build_spectre_parser(sub)
    _build_hw_security_parser(sub)
    _build_mte_parser(sub)
    _build_pmc_parser(sub)
    return parser


# 处理器


def _handle_fuzz(args) -> int:
    from .gpu.fuzzer import GPUFuzzerService, GPUFramework, FuzzMode

    svc = GPUFuzzerService(framework=args.framework)
    for i in range(args.devices):
        svc.add_device(f"gpu_{i}", f"Device #{i}", 24.0, 16384)

    seed = _load_seed(args.input)
    task_id = svc.submit_task(seed, args.iterations, args.mode)
    print(f"Task submitted: {task_id}")
    svc.start()
    import time
    time.sleep(min(5.0, args.iterations * 0.001))
    svc.stop()
    stats = svc.get_stats()
    print(f"Stats: {stats}")
    return 0


def _handle_side_channel(args) -> int:
    if args.type == "timing":
        from .side_channel.timing import TimingSideChannelDetector

        detector = TimingSideChannelDetector()
        if args.binary:
            results = detector.detect(args.binary)
            for r in results:
                print(f"[{r.severity}] {r.issue_type}: {r.description}")
        else:
            print("Timing detector ready (no binary specified)")
    elif args.type == "cache":
        from .side_channel.simulator import SideChannelSimulator

        sim = SideChannelSimulator()
        result = sim.analyze(func_name="probe", instructions=[])
        report = sim.generate_report()
        print(f"Risk: {report.get('risk_level')} -- {report.get('summary')}")
    elif args.type == "power":
        from .side_channel.simulator import PowerAnalysisSimulator

        ps = PowerAnalysisSimulator()
        trace = ps.generate_power_trace(["mov eax, 1", "add eax, 2", "xor ebx, ebx"])
        print(f"Power trace generated: {len(trace.power_values)} points")
    elif args.type == "lattice":
        from .side_channel.lattice import LatticeSideChannelAnalyzer

        analyzer = LatticeSideChannelAnalyzer()
        print(f"Lattice analyzer ready, n=256, q=3329")
    elif args.type == "microarch":
        from .side_channel.microarch import MicroarchSideChannelValidator

        v = MicroarchSideChannelValidator()
        print(f"Microarch validator ready, hit_threshold={v._hit_threshold}")
    else:
        print(f"Unknown type: {args.type}")
    return 0


def _handle_spectre(args) -> int:
    from .spectre.detector import SpectreGadgetDetector

    use_cs = not args.no_capstone
    detector = SpectreGadgetDetector(
        binary_path=args.binary,
        architecture=args.arch,
        use_capstone=use_cs,
    )
    result = detector.detect()
    print(f"Binary: {result.binary_path}")
    print(f"Arch: {result.architecture}")
    print(f"Gadgets: {result.total_gadgets} (C:{result.critical_gadgets} H:{result.high_gadgets})")
    print(f"Overall risk: {result.overall_risk.value if hasattr(result.overall_risk, 'value') else result.overall_risk}")
    for rec in result.recommendations[:5]:
        print(f"  - {rec}")
    return 0


def _handle_hw_security(args) -> int:
    from .hw_security.evaluator import evaluate_hardware_security, format_evaluation_report

    report = evaluate_hardware_security(args.binary)
    text = format_evaluation_report(report)
    print(text)
    return 0


def _handle_mte(args) -> int:
    from .mte.simulator import MTESimulator

    sim = MTESimulator(memory_size=args.memory_size, tag_granule=args.tag_granule)
    addr = 0x1000
    tag = sim.allocate(addr, 64, strategy=args.strategy)
    print(f"Allocated at 0x{addr:x}, tag={tag}")
    print(f"Tag at 0x{addr:x}: {sim.tag_at(addr)}")
    sim.store(addr, b"hello", tag)
    data = sim.load(addr, 5, tag)
    print(f"Loaded: {data}")
    snap = sim.snapshot()
    print(f"Allocations: {len(snap['allocations'])}, Freed: {len(snap['freed'])}")
    return 0


def _handle_pmc(args) -> int:
    from .side_channel.pmc import PMCSideChannelEvaluator

    ev = PMCSideChannelEvaluator(use_perf=not args.no_perf)
    print(f"PMC evaluator ready, perf={ev._perf_available}")
    return 0


def _load_seed(input_spec: str) -> bytes:
    if _os.path.isfile(input_spec):
        with open(input_spec, "rb") as f:
            return f.read()
    # 尝试十六进制解码
    try:
        return bytes.fromhex(input_spec)
    except ValueError:
        return input_spec.encode("utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler") or args.handler is None:
        parser.print_help()
        return 1
    return args.handler(args)


if __name__ == "__main__":
    _sys.exit(main())
