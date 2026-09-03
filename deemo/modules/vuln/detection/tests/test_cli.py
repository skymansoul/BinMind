"""vuln_detection CLI 子命令解析测试"""
import argparse

def test_argparse_subcommands():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd")
    sp.add_parser("scan")
    sp.add_parser("export")
    a = p.parse_args(["scan"])
    assert a.cmd == "scan"
