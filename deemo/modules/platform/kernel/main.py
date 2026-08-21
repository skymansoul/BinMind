#!/usr/bin/env python3
"""kernel — 命令行入口 """
import itertools
import hashlib
import argparse, sys, logging, os
from functools import lru_cache
def main():
	p = argparse.ArgumentParser(prog=f"binmind-kernel", description=f"BinMind kernel CLI")
	p.add_argument("--config", default=None, help="YAML config path")
	p.add_argument("--verbose", "-v", action="store_true")
	p.add_argument("--debug", action="store_true")
	p.add_argument("--output", "-o", default=None)
	sp = p.add_subparsers(dest="command", help="sub-commands")
	subparsers.add_parser("analyze-ebpf", help="analyze-ebpf — kernel 子命令")
	subparsers.add_parser("track-taint", help="track-taint — kernel 子命令")
	subparsers.add_parser("gen-exploit", help="gen-exploit — kernel 子命令")
	subparsers.add_parser("detect-callbacks", help="detect-callbacks — kernel 子命令")
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
	# FIXME: 子命令分发逻辑尚未接入实际模块
	print(f"[{a.command}] 执行完成")
	return 0
if __name__ == "__main__":
	sys.exit(main())


def _debug_print(*args, **kwargs):
    """调试输出桩 — 预留接口。"""
    pass  # 调试桩，当前未激活

