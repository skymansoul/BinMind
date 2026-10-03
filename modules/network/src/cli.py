#!/usr/bin/env python3
"""network子模块命令行入口。"""
import argparse
import logging
import sys


def _load_analyzer(mod_name: str):
    """按子命令懒加载对应分析模块, 避免启动时导入全部依赖。"""
    return __import__("network." + mod_name, fromlist=["*"])


# 子命令 → (模块, 可调用入口, 是否类方法)
_HANDLERS = {
    "analyze-iot": ("iot_protocol_analyzer", "analyze_iot_protocol", False),
    "analyze-ics": ("ics_protocol_analyzer", "analyze_ics_protocols", False),
    "serverless": ("serverless_analyzer", "analyze_serverless", False),
    "wireless": ("wireless_analyzer", "WirelessProtocolAnalyzer", True),
    "container-scan": ("container_scanner", "ContainerImageScanner", True),
}


def main() -> int:
    """子命令分发: 各分析器模块提供 analyze_* 函数或分析器类。"""
    p = argparse.ArgumentParser(prog="binmind-network",
                                description="BinMind network CLI")
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--output", "-o", default=None)
    p.add_argument("target", nargs="?", default=None,
                   help="目标参数(文件/镜像名/固件路径), 按子命令解释")
    sp = p.add_subparsers(dest="command", help="sub-commands")
    sp.add_parser("analyze-iot", help="IoT 协议分析")
    sp.add_parser("analyze-ics", help="ICS 协议分析")
    sp.add_parser("serverless", help="serverless 分析")
    sp.add_parser("wireless", help="无线协议分析")
    sp.add_parser("container-scan", help="容器扫描")

    a = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s")
    if not a.command:
        p.print_help()
        return 1

    mod_name, entry, is_class = _HANDLERS[a.command]
    logging.getLogger(__name__).info("Running: %s", a.command)
    try:
        mod = _load_analyzer(mod_name)
        entry_obj = getattr(mod, entry)
        if is_class:
            # 类入口: 实例化后调用 analyze(目标)
            inst = entry_obj()
            result = inst.analyze(a.target)
        else:
            fn = entry_obj
            result = fn(a.target) if a.target is not None else fn()
    except (ImportError, AttributeError, TypeError) as exc:
        logging.error("子命令 %s 不可用: %s", a.command, exc)
        return 2
    print(f"[{a.command}] 完成: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())