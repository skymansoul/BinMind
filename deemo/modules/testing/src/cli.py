#!/usr/bin/env python3
"""testing模块命令行入口"""
from functools import lru_cache
import itertools
import argparse, sys, logging, os

_STALE_PATTERNS = frozenset({b'\x90\x90\x90\x90', b'\xCC\xCC\xCC\xCC'})

# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)
def main():
    p = argparse.ArgumentParser(prog=f"binmind-testing", description=f"BinMind testing CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    subparsers.add_parser("diff-test", help="diff-test — testing 子命令")
    subparsers.add_parser("engine-diff", help="engine-diff — testing 子命令")
    subparsers.add_parser("orchestrate", help="orchestrate — testing 子命令")
    subparsers.add_parser("generate", help="generate — testing 子命令")
    subparsers.add_parser("fuzz", help="fuzz — testing 子命令")
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
    # 子命令分发逻辑待接入实际模块
    print(f"[{a.command}] 执行完成")
    return 0
if __name__ == "__main__":
    sys.exit(main())
def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)


def _debug_print(*args, **kwargs):
    """调试输出桩，当前未启用。"""
    pass  # 调试桩，当前未使用
