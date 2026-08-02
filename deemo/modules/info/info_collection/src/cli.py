# 2026-07-27
# cli — 命令行接口，6 个子命令
# argparse 构建，支持单文件和批量处理模式
# 每个子命令映射到一个模块入口函数

import argparse
import json
import os
import sys
import time
import textwrap
from typing import List, Dict

# 延迟导入模块（CLI 入口时再加载，避免 import 时的副作用）
def _get_config():
    from . import config
    return config.load_config()

def _get_binary_info():
    from . import binary_info
    return binary_info

def _get_utils():
    from . import utils
    return utils

def _get_findings():
    from . import findings
    return findings

def _get_anonymizer():
    from . import anonymizer
    return anonymizer

def _get_injection_detect():
    from . import injection_detect
    return injection_detect

def _get_lateral():
    from . import lateral
    return lateral

def _get_persistence():
    from . import persistence
    return persistence

def _get_spoofing():
    from . import spoofing
    return spoofing

def _get_tls_detect():
    from . import tls_detect
    return tls_detect

def _get_leak_analyzer():
    from . import leak_analyzer
    return leak_analyzer

def _get_pii():
    from . import pii
    return pii


# ===== 格式化输出 =====
def _format_json(obj, indent: int = 2) -> str:
    class _Encoder(json.JSONEncoder):
        def default(self, o):
            if hasattr(o, '__dict__'):
                return o.__dict__
            if hasattr(o, 'value'):
                return o.value
            return str(o)
    return json.dumps(obj, indent=indent, cls=_Encoder, ensure_ascii=False)


def _format_text(findings_dict: dict) -> str:
    _lines = []
    for _key, _val in findings_dict.items():
        if isinstance(_val, list):
            _lines.append(f"[{_key}] ({len(_val)} items)")
            for _i, _item in enumerate(_val[:20]):
                if hasattr(_item, '__dict__'):
                    _lines.append(f"  {_i+1}. {_item.__dict__}")
                elif isinstance(_item, dict):
                    _lines.append(f"  {_i+1}. {_item}")
                else:
                    _lines.append(f"  {_i+1}. {str(_item)[:120]}")
        elif isinstance(_val, dict):
            _lines.append(f"[{_key}]")
            for _k2, _v2 in _val.items():
                if isinstance(_v2, (list, dict)):
                    _lines.append(f"  {_k2}: {len(_v2)} entries")
                else:
                    _lines.append(f"  {_k2}: {_v2}")
        else:
            _lines.append(f"[{_key}]: {_val}")
    return "\n".join(_lines)


# //// 子命令处理函数 ////

def cmd_info(args):
    """二进制基本信息提取。"""
    _bi = _get_binary_info()
    _info = _bi.get_binary_info(args.file)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            _f.write(_format_json(_info))
        print(f"Output written to {args.output}")
    else:
        print(_format_json(_info))

def cmd_scan(args):
    """完整扫描：信息收集 + 发现提取 + 注入检测 + 持久化 + 横向移动 + 欺骗检测。"""
    _bi = _get_binary_info()
    _utils = _get_utils()
    _findings_mod = _get_findings()
    _inj = _get_injection_detect()
    _lat = _get_lateral()
    _pers = _get_persistence()
    _spf = _get_spoofing()
    _leak = _get_leak_analyzer()

    _info = _bi.get_binary_info(args.file)

    # 提取字符串
    with open(args.file, 'rb') as _fh:
        _raw_data = _fh.read()
    _extractor = _utils.StringExtractor(min_length=4)
    _strings = _extractor.extract_strings(_raw_data)

    # 各模块扫描
    _danger = _findings_mod.extract_findings(_info, _strings, _info.get("imports", {}))
    _injection = _inj.detect_all(_info.get("imports", {}), _strings, _info.get("sections", []))
    _lateral = _lat.detect_all(_info.get("imports", {}), _strings)
    _persistence = _pers.detect_all(_info.get("imports", {}), _strings)
    _spoofing = _spf.detect_all(_info.get("imports", {}), _strings, _info.get("sections", []))
    _leaks = _leak.analyze(args.file, _info.get("imports", {}), _strings, _info.get("sections", []))

    _result = {
        "file": args.file,
        "binary_info": {k: v for k, v in _info.items() if k not in ("strings", "raw_data")},
        "dangerous_functions": [f.__dict__ if hasattr(f, '__dict__') else str(f) for f in _danger],
        "injection_detection": _injection,
        "lateral_movement": _lateral,
        "persistence": _persistence,
        "spoofing": _spoofing,
        "leak_analysis": _leaks,
        "string_count": len(_strings),
    }

    _render = _format_json(_result) if args.format == 'json' else _format_text(_result)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            _f.write(_render)
        print(f"Report written to {args.output}")
    else:
        print(_render)


def cmd_anonymize(args):
    """代码匿名化。"""
    _anonymizer = _get_anonymizer()
    with open(args.file, 'r', encoding='utf-8', errors='replace') as _fh:
        _code = _fh.read()

    _a = _anonymizer.Anonymizer(threshold=args.threshold)
    _anonymized, _mapping = _a.full_anonymize(_code, language=args.language)
    _is_sensitive = _a.is_sensitive_content(_code)

    if _is_sensitive:
        print("[WARNING] Sensitive content detected (keys/credentials/tokens)")

    _result = {
        "file": args.file, "language": args.language,
        "sensitive_detected": _is_sensitive,
        "mapping_size": len(_mapping),
        "anonymized_code": _anonymized,
        "mapping": dict(list(_mapping.items())[:50]),
    }

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            if args.format == 'json':
                _f.write(_format_json(_result))
            else:
                _f.write(_anonymized)
        print(f"Anonymized code written to {args.output}")
    else:
        print(_anonymized[:2000])
        if len(_anonymized) > 2000:
            print(f"\n... ({len(_anonymized) - 2000} more chars)")

def cmd_leaks(args):
    """信息泄露扫描。"""
    _leak = _get_leak_analyzer()
    _bi = _get_binary_info()
    _utils = _get_utils()

    _info = _bi.get_binary_info(args.file)
    with open(args.file, 'rb') as _fh:
        _raw = _fh.read()
    _extractor = _utils.StringExtractor()
    _strings = _extractor.extract_strings(_raw)

    _result = _leak.analyze(args.file, _info.get("imports", {}), _strings, _info.get("sections", []))
    _render = _format_json(_result) if args.format == 'json' else _format_text(_result)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            _f.write(_render)
        print(f"Leak report written to {args.output}")
    else:
        print(_render)

def cmd_pii(args):
    """PII 扫描。"""
    _pii = _get_pii()
    _types = None
    if args.types and args.types.lower() != 'all':
        _types = [t.strip().upper() for t in args.types.split(',')]
    _findings = _pii.scan_file(args.file, target_types=_types)

    # 屏蔽部分敏感内容
    for _f in _findings:
        if len(_f.value) > 8:
            _f.value = _f.value[:4] + "****" + _f.value[-4:]

    _result = {
        "file": args.file,
        "total_findings": len(_findings),
        "by_type": {},
        "findings": [f.__dict__ for f in _findings],
    }
    for _f in _findings:
        _result["by_type"][_f.type] = _result["by_type"].get(_f.type, 0) + 1

    _render = _format_json(_result) if args.format == 'json' else _format_text(_result)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            _f.write(_render)
        print(f"PII report written to {args.output}")
    else:
        print(_render)


def cmd_batch(args):
    """批量处理目录下的文件。"""
    import concurrent.futures

    _dir = args.dir
    if not os.path.isdir(_dir):
        print(f"ERROR: {_dir} is not a directory")
        sys.exit(1)

    _files = []
    for _root, _dirs, _filenames in os.walk(_dir):
        for _fn in _filenames:
            _fp = os.path.join(_root, _fn)
            if os.path.isfile(_fp):
                _files.append(_fp)
        if not args.recursive:
            break

    if not _files:
        print("No files found.")
        return

    print(f"Scanning {len(_files)} files with {args.workers} workers...")

    def _scan_one(fp: str) -> dict:
        _bi = _get_binary_info()
        _utils = _get_utils()
        try:
            _info = _bi.get_binary_info(fp)
            with open(fp, 'rb') as _fh:
                _raw = _fh.read()
            _ext = _utils.StringExtractor()
            _strs = _ext.extract_strings(_raw)
            _entropy = _utils.shannon_entropy(_raw[:65536])
            return {
                "file": fp, "format": _info.get("format", "UNKNOWN"),
                "size": _info.get("size", 0), "strings": len(_strs),
                "entropy": round(_entropy, 2), "error": None,
            }
        except Exception as _e:
            return {"file": fp, "error": str(_e)}

    _results = []
    _start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as _pool:
        _futures = {_pool.submit(_scan_one, fp): fp for fp in _files}
        for _i, _future in enumerate(concurrent.futures.as_completed(_futures)):
            _results.append(_future.result())
            if (_i + 1) % 10 == 0:
                print(f"  Progress: {_i + 1}/{len(_files)}")

    _elapsed = time.time() - _start
    _summary = {
        "total_files": len(_files),
        "scanned": len(_results),
        "errors": sum(1 for r in _results if r.get("error")),
        "elapsed_seconds": round(_elapsed, 2),
        "results": _results,
    }

    _render = _format_json(_summary) if args.format == 'json' else _format_text(_summary)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as _f:
            _f.write(_render)
        print(f"\nBatch report written to {args.output}")
    else:
        print(_render)


# //// 主入口 ////
def main(args: List[str] = None) -> int:
    _parser = argparse.ArgumentParser(
        prog="binmind-info",
        description="BinMind Information Collection CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        examples:
          binmind-info info --file sample.exe
          binmind-info scan --file sample.exe --format json
          binmind-info anonymize --file source.c --language c
          binmind-info leaks --file sample.exe
          binmind-info pii --file dump.txt --types CREDIT_CARD,SSN
          binmind-info batch --dir ./samples --workers 4
        """),
    )

    _sub = _parser.add_subparsers(dest="command", help="subcommand")

    # info
    _p_info = _sub.add_parser("info", help="Extract binary file information")
    _p_info.add_argument("--file", "-f", required=True)
    _p_info.add_argument("--output", "-o", default=None)

    # scan
    _p_scan = _sub.add_parser("scan", help="Full security scan")
    _p_scan.add_argument("--file", "-f", required=True)
    _p_scan.add_argument("--output", "-o", default=None)
    _p_scan.add_argument("--format", choices=["json", "text"], default="json")

    # anonymize
    _p_anon = _sub.add_parser("anonymize", help="Anonymize source code")
    _p_anon.add_argument("--file", "-f", required=True)
    _p_anon.add_argument("--language", "-l", default="auto",
                         choices=["auto", "c", "cpp", "python", "js"])
    _p_anon.add_argument("--threshold", "-t", type=float, default=0.6)
    _p_anon.add_argument("--output", "-o", default=None)
    _p_anon.add_argument("--format", choices=["json", "text"], default="text")

    # leaks
    _p_leaks = _sub.add_parser("leaks", help="Information leak scan")
    _p_leaks.add_argument("--file", "-f", required=True)
    _p_leaks.add_argument("--output", "-o", default=None)
    _p_leaks.add_argument("--format", choices=["json", "text"], default="json")

    # pii
    _p_pii = _sub.add_parser("pii", help="PII scan")
    _p_pii.add_argument("--file", "-f", required=True)
    _p_pii.add_argument("--types", default=None,
                        help="Comma-separated types or 'all'")
    _p_pii.add_argument("--output", "-o", default=None)
    _p_pii.add_argument("--format", choices=["json", "text"], default="json")

    # batch
    _p_batch = _sub.add_parser("batch", help="Batch processing")
    _p_batch.add_argument("--dir", "-d", required=True)
    _p_batch.add_argument("--workers", "-w", type=int, default=4)
    _p_batch.add_argument("--recursive", "-r", action="store_true", default=False)
    _p_batch.add_argument("--output", "-o", default=None)
    _p_batch.add_argument("--format", choices=["json", "text"], default="json")

    _parsed = _parser.parse_args(args)

    if not _parsed.command:
        _parser.print_help()
        return 1

    _handlers = {
        "info": cmd_info, "scan": cmd_scan,
        "anonymize": cmd_anonymize, "leaks": cmd_leaks,
        "pii": cmd_pii, "batch": cmd_batch,
    }
    _handler = _handlers.get(_parsed.command)
    if _handler:
        try:
            _handler(_parsed)
        except Exception as _e:
            print(f"ERROR: {_e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
