#!/usr/bin/env python3
"""decompiler — 命令行入口"""
import argparse, sys, logging, os

def main():
    p = argparse.ArgumentParser(prog=f"binmind-decompiler", description=f"BinMind decompiler CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    p_dec = sp.add_parser("decompile", help="decompile — 反编译指定函数")
    p_dec.add_argument("binary", help="目标二进制文件路径")
    p_dec.add_argument("--addr", type=lambda v: int(v, 0), required=True, help="函数起始地址（支持十六进制 0x...）")
    sp.add_parser("validate", help="validate — decompiler 子命令")
    sp.add_parser("enhance", help="enhance — decompiler 子命令")
    a = p.parse_args()
    if a.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
    elif a.verbose:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if not a.command:
        p.print_help()
        sys.exit(1)
    _log = logging.getLogger(__name__)
    _log.info("Running: %s", a.command)
    from .core import DecompilerEngine
    _engine = DecompilerEngine()
    if a.command == "decompile":
        result = _engine.decompile(a.binary, a.addr)
        if result is None:
            print("decompile 失败：无法从指定地址提取函数", file=sys.stderr)
            return 1
        print(result.get("pseudocode", ""))
    elif a.command == "validate":
        print("validate 子命令尚未接入")
        return 1
    elif a.command == "enhance":
        print("enhance 子命令尚未接入")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())

def _debug_print(*args, **kwargs):
    # 受 BINMIND_DEBUG 环境变量控制的调试输出
    if os.environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
