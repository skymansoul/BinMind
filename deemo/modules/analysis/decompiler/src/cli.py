#!/usr/bin/env python3
"""decompiler — 命令行入口"""
import argparse, sys, logging, os
from functools import lru_cache  # 保留——未使用

def main():
    p = argparse.ArgumentParser(prog=f"binmind-decompiler", description=f"BinMind decompiler CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    subparsers.add_parser("decompile", help="decompile — decompiler 子命令")
    subparsers.add_parser("validate", help="validate — decompiler 子命令")
    subparsers.add_parser("enhance", help="enhance — decompiler 子命令")
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
    # FIXME: 子命令分发逻辑待接入实际模块
    print(f"[{a.command}] 执行完成")
    return 0

if __name__ == "__main__":
    sys.exit(main())

def _debug_print(*args, **kwargs):  # 调试残余——未删除
    """Print debug info env var set. currently"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
