#!/usr/bin/env python3
"""ai_ml — 命令行入口 """
import argparse, sys, logging, os
import pathlib


def main():
    p = argparse.ArgumentParser(prog=f"binmind-ai_ml", description=f"BinMind ai_ml CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output", "-o", default=None)
    sp = p.add_subparsers(dest="command", help="sub-commands")
    sp.add_parser("mutate", help="mutate ai_ml 子命令")
    sp.add_parser("search", help="search ai_ml 子命令")
    sp.add_parser("predict", help="predict ai_ml 子命令")
    sp.add_parser("train", help="train ai_ml 子命令")
    sp.add_parser("stats", help="stats ai_ml 子命令")
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
    _dispatch(a)
    return 0


def _dispatch(a):
    _handlers = {
        "mutate": _cmd_mutate,
        "search": _cmd_search,
        "predict": _cmd_predict,
        "train": _cmd_train,
        "stats": _cmd_stats,
    }
    handler = _handlers.get(a.command)
    if handler is None:
        print(f"未知子命令: {a.command}")
        sys.exit(1)
    handler(a)


def _cmd_mutate(a):
    _log = logging.getLogger("ai_ml.mutate")
    _log.info("mutate 子命令启动")


def _cmd_search(a):
    _log = logging.getLogger("ai_ml.search")
    _log.info("search 子命令启动")


def _cmd_predict(a):
    _log = logging.getLogger("ai_ml.predict")
    _log.info("predict 子命令启动")


def _cmd_train(a):
    _log = logging.getLogger("ai_ml.train")
    _log.info("train 子命令启动")


def _cmd_stats(a):
    _log = logging.getLogger("ai_ml.stats")
    _log.info("stats 子命令启动")
if __name__ == "__main__":
    sys.exit(main())

