from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    """构建命令行解析器，包含 info/analyze/audit/vulns/hash/fuzz 子命令。"""
    p = argparse.ArgumentParser(prog="binmind-binary-analysis")
    p.add_argument("--config", default=None, help="配置文件路径")
    p.add_argument("--verbose", "-v", action="store_true", help="输出调试日志")
    p.add_argument("--json", "-j", action="store_true", dest="json_output",
                   help="以 JSON 格式输出结果")

    sub = p.add_subparsers(dest="command")
    sub.add_parser("info", help="打印二进制文件基本信息")
    sub.add_parser("analyze", help="执行漏洞检测分析")
    sub.add_parser("audit", help="输出审计报告")
    sub.add_parser("vulns", help="列出已知漏洞")
    sub.add_parser("hash", help="计算各类哈希")
    sub.add_parser("fuzz", help="运行模糊测试")
    return p


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
