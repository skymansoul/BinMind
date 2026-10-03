#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
from typing import List, Optional

log = logging.getLogger(__name__)


def cmd_trace(args: argparse.Namespace) -> int:
    """对二进制运行行为追踪。"""
    from .engine import DynamicAnalysisEngine, EntropyScanPass, ImportAnalysisPass, PatternMatchPass, RiskScoringPass

    input_path: str = args.input
    if not input_path:
        log.error("Missing required argument: --input")
        return 1
    if not os.path.isfile(input_path):
        log.error("Input file not found: %s", input_path)
        return 1

    engine = DynamicAnalysisEngine()
    engine.add_pass(EntropyScanPass())
    engine.add_pass(ImportAnalysisPass())
    engine.add_pass(PatternMatchPass())
    engine.add_pass(RiskScoringPass())

    report = engine.analyze(input_path)
    _output_result(report, args)
    return 0


def cmd_memory_forensics(args: argparse.Namespace) -> int:
    """对转存文件或活动进程运行内存取证。"""
    from .memory import MemoryForensics

    mf = MemoryForensics()

    if args.dump:
        if not os.path.isfile(args.dump):
            log.error("Dump file not found: %s", args.dump)
            return 1
        result = mf.analyze_dump(args.dump)
        _output_result(result, args)
    elif args.pid:
        info = mf.analyze_live_process(int(args.pid))
        _output_result({"process": info.__dict__ if hasattr(info, "__dict__") else str(info)}, args)
    else:
        log.error("Specify --dump <file> or --pid <pid>")
        return 1

    return 0


def cmd_instrument(args: argparse.Namespace) -> int:
    """构造并运行 Frida 插桩脚本。"""
    from .instrumentation import FridaInstrumentation

    fi = FridaInstrumentation()
    fi.add_hook(fi.anti_debug_hook("IsDebuggerPresent"))
    fi.add_hook(fi.return_value_hook("CheckRemoteDebuggerPresent", 0))
    fi.add_hook(fi.api_trace_hook("NtCreateFile"))

    if args.generate:
        script = fi.generate_hook_script(output_format="javascript")
        output_path = args.output or "frida_hooks.js"
        with open(output_path, "w") as f:
            f.write(script)
        log.info("Hook script written to %s", output_path)
        print(f"Hook script written to {output_path}")
    else:
        script = fi.generate_hook_script(output_format="python")
        print(script)

    return 0


def cmd_emulate(args: argparse.Namespace) -> int:
    """使用 Unicorn 混合引擎仿真二进制"""
    from .emulation import UnicornHybrid

    binary_path: str = args.binary
    if not binary_path:
        log.error("Missing required argument: --binary")
        return 1
    if not os.path.isfile(binary_path):
        log.error("Binary not found: %s", binary_path)
        return 1

    arch = args.arch or "x64"
    emu = UnicornHybrid(arch=arch)

    try:
        with open(binary_path, "rb") as f:
            code = f.read()
    except OSError as e:
        log.error("Failed to read binary: %s", e)
        return 1

    emu.map_memory(0x400000, 0x100000)
    emu.write_memory(0x400000, code)
    emu.write_register("eip", 0x400000)

    timeout = getattr(args, "timeout", 30)
    result = emu.emulate(timeout_seconds=timeout)

    _output_result({
        "success": result.success,
        "instructions_executed": result.instructions_executed,
        "execution_time_seconds": result.execution_time_seconds,
        "state": result.state.value,
    }, args)
    return 0 if result.success else 1


def cmd_vmi(args: argparse.Namespace) -> int:
    """通过 VMI 对虚拟机进行内省。"""
    from .vmi import VMIAnalyzer

    vmi = VMIAnalyzer(backend=args.backend or "simulated")
    domain = args.domain or "default_vm"

    if not vmi.connect(domain):
        log.error("Failed to connect to domain %s", domain)
        return 1

    processes = vmi.list_processes()
    result = {
        "domain": domain,
        "process_count": len(processes),
        "processes": [{"pid": p.pid, "name": p.name} for p in processes],
    }

    vmi.disconnect()
    _output_result(result, args)
    return 0


def _output_result(result: dict, args: argparse.Namespace) -> None:
    """以 JSON 或人类可读文本输出结果。"""
    output_path: Optional[str] = getattr(args, "output", None)
    if output_path:
        try:
            with open(output_path, "w") as f:
                json.dump(result, f, indent=2, default=str)
            log.info("Result written to %s", output_path)
        except OSError as e:
            log.error("Failed to write output: %s", e)
    else:
        print(json.dumps(result, indent=2, default=str))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="binmind-dynamic",
        description="BinMind Dynamic Analysis CLI",
    )
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", action="store_true", help="Debug mode")
    p.add_argument("--output", "-o", default=None, help="Output file path")

    # 子命令解析器
    sp = p.add_subparsers(dest="command", help="sub-commands")

    # trace 子命令
    trace_p = sp.add_parser("trace", help="Collect and analyze API call traces")
    trace_p.add_argument("--input", "-i", default=None, help="Binary to analyze")
    trace_p.add_argument("--trace-count", type=int, default=50, help="Trace entries to simulate")

    # memory-forensics 子命令
    mem_p = sp.add_parser("memory-forensics", help="Memory forensics analysis")
    mem_p.add_argument("--dump", help="Memory dump file path")
    mem_p.add_argument("--pid", type=int, help="Live process PID")

    # instrument 子命令
    instr_p = sp.add_parser("instrument", help="Generate Frida instrumentation scripts")
    instr_p.add_argument("--target", "-t", help="Target process name")
    instr_p.add_argument("--generate", action="store_true", help="Write script to file")
    instr_p.add_argument("--output", "-o", default=None, help="Output file path")

    # emulate 子命令
    emu_p = sp.add_parser("emulate", help="Emulate a binary via Unicorn")
    emu_p.add_argument("--binary", "-b", default=None, help="Binary to emulate")
    emu_p.add_argument("--arch", default="x64", choices=["x86", "x64", "arm", "arm64", "mips"], help="Target architecture")
    emu_p.add_argument("--timeout", type=int, default=30, help="Emulation timeout (seconds)")

    # vmi 子命令
    vmi_p = sp.add_parser("vmi", help="Virtual Machine Introspection")
    vmi_p.add_argument("--domain", "-d", help="VM domain name")
    vmi_p.add_argument("--backend", default="simulated", choices=["libvmi", "qemu", "simulated"], help="VMI backend")
    vmi_p.add_argument("--output", "-o", default=None, help="Output file path")

    # 未知子命令在 argparse 层会抛 SystemExit(2)；此处先拦截，
    # 使 CLI 以返回码形式汇报而非抛异常，便于程序化调用方判断。
    _KNOWN_COMMANDS = {"trace", "memory-forensics", "instrument", "emulate", "vmi"}
    for tok in (argv or []):
        if tok.startswith("-"):
            continue
        if tok not in _KNOWN_COMMANDS:
            p.print_usage()
            return 1
        break

    args = p.parse_args(argv)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    elif args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if not args.command:
        p.print_help()
        return 1

    log.info("Running subcommand: %s", args.command)

    dispatch = {
        "trace": cmd_trace,
        "memory-forensics": cmd_memory_forensics,
        "instrument": cmd_instrument,
        "emulate": cmd_emulate,
        "vmi": cmd_vmi,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        log.error("Unknown command: %s", args.command)
        return 1

    try:
        return handler(args)
    except Exception:
        log.exception("Command '%s' failed", args.command)
        return 1


if __name__ == "__main__":
    sys.exit(main())
