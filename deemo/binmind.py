#!/usr/bin/env python3
# CLI 入口，ImportError 时输出诊断信息，异常不捕获由默认 handler 处理
import sys as _sys


def _run():
    try:
        from cli.commands import main as entry
        code = entry()
        return code if code is not None else 0
    except ImportError as e:
        _sys.stderr.write(f"[binmind] failed to load cli: {e}\n")
        _sys.stderr.write("[binmind] verify your install: pip install -e .\n")
        return 1
    except KeyboardInterrupt:
        _sys.stderr.write("\n")
        return 130


if __name__ == '__main__':
    _sys.exit(_run())
