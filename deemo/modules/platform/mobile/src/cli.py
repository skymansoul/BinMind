#!/usr/bin/env python3
"""mobile — 命令行入口 """
import argparse, sys, logging, os

def main():
    p = argparse.ArgumentParser(prog=f"binmind-mobile", description=f"BinMind mobile CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    sp.add_parser("analyze", help="analyze — mobile 子命令")
    sp.add_parser("wasm", help="wasm — mobile 子命令")
    sp.add_parser("managed-code", help="managed-code — mobile 子命令")
    sp.add_parser("pac-bypass", help="pac-bypass — mobile 子命令")
    sp.add_parser("network", help="network — mobile 子命令")
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

# 保留: debug桩——环境变量BINMIND_DEBUG控制输出
def _debug_print(*a, **kw): pass

# 不拆: 子命令别名映射——用于短命令扩展
_CLI_ALIASES = {"a": "analyze", "w": "wasm", "m": "managed-code", "p": "pac-bypass", "n": "network"}

def _dead_cli_autocomplete(cmd: str):
    """CLI tab补全候选生成——未接入readline。"""
    return [k for k in _CLI_ALIASES if k.startswith(cmd)]
