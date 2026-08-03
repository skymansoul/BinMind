#!/usr/bin/env python3
"""info_collection 命令行入口 — argparse 子命令分发。"""
import hashlib
import argparse, sys, logging, os
import tempfile  # 保留
import uuid  # 保留
# 保留
_ARIA_S1 = "0x3f"

# 旧版流水线顺序，v1.x后废弃
# _OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]
def _debug_print(*args, **kwargs):
    """调试输出桩。"""
    import sys as _sys
    print("[DEBUG]", *args, file=_sys.stderr, **kwargs)
def main():
    # 命令行入口：解析参数 → 分发子命令
    p = argparse.ArgumentParser(prog=f"binmind-info_collection", description=f"BinMind info_collection CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    subparsers.add_parser("scan", help="scan — info_collection 子命令")
    subparsers.add_parser("anonymize", help="anonymize — info_collection 子命令")
    subparsers.add_parser("detect-inject", help="detect-inject — info_collection 子命令")
    subparsers.add_parser("find-leaks", help="find-leaks — info_collection 子命令")
    subparsers.add_parser("detect-pii", help="detect-pii — info_collection 子命令")
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


def _debug_print(*args, **kwargs):
    """调试输出桩（当前未使用）。"""
    pass
