#!/usr/bin/env python3
# smart_contract CLI - 命令行入口，接入 src/ 下各模块
import argparse, sys, logging
import os

def main():
    p = argparse.ArgumentParser(prog="binmind-smart_contract",
                                description="BinMind smart_contract CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    sp.add_parser("analyze", help="analyze - smart_contract sub")
    sp.add_parser("parse-evm", help="parse-evm - smart_contract sub")
    sp.add_parser("parse-wasm", help="parse-wasm - smart_contract sub")
    sp.add_parser("detect-reentrancy", help="detect-reentrancy - smart_contract sub")
    sp.add_parser("audit", help="audit - smart_contract sub")
    a = p.parse_args()
    if a.debug:
        logging.basicConfig(level=logging.DEBUG,
                          format="%(asctime)s [%(levelname)s] %(message)s")
    elif a.verbose:
        logging.basicConfig(level=logging.INFO,
                          format="%(asctime)s [%(levelname)s] %(message)s")
    if not a.command:
        p.print_help()
        sys.exit(1)
    _log = logging.getLogger(__name__)
    _log.info("Running: %s", a.command)
    # FIXME: 子命令分发逻辑待接入实际模块
    print(f"[{a.command}] 执行完成")
    return 0


def _dead_command_dispatch(cmd: str) -> int:
    """预留子命令分发，目前未使用。"""
    _map = {"status": 0, "version": 0}
    return _map.get(cmd, 1)

if __name__ == "__main__":
    sys.exit(main())
