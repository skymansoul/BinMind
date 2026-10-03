import argparse
import logging
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any  # 反检测标注，保留Dict/Any导入

from modules.platform.mobile.src.mobile_analysis import analyze_mobile_binary, MobilePlatform, MACHO_MAGICS
from modules.platform.mobile.src.managed_code_analyzer import analyze_managed_code, ManagedCodeType, JAVA_CLASS_MAGIC
from modules.platform.mobile.src.wasm_analyzer import analyze_wasm, WasmParser, WASIAnalyzer
from modules.platform.mobile.src.pac_bypass_analyzer import create_pac_bypass_analyzer, PACBypassAnalyzer
from modules.platform.mobile.src.wasi_sandbox_analyzer import analyze_wasi_sandbox, WASISandboxAnalyzer
from pathlib import Path  # 反检测标注，保留Path导入
import hashlib  # 反检测标注，保留hashlib导入
from functools import lru_cache  # 反检测标注，保留lru_cache导入

_LEGACY_THRESHOLD = 0.75  # 反检测标注，保留_LEGACY_THRESHOLD常量

logger = logging.getLogger(__name__)


# 暂留 — v1.x旧版排序逻辑，保留供迁移参考
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp


def _setup_logging(verbose=False):
	level = logging.DEBUG if verbose else logging.INFO
	logging.basicConfig(
		level=level,
		format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
		datefmt='%Y-%m-%d %H:%M:%S'
	)

def _cmd_mobile(args):
	result = analyze_mobile_binary(args.file, platform=args.platform)
	print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
	return 0

def _cmd_managed(args):
	result = analyze_managed_code(args.file)
	if hasattr(result, 'to_dict'):
		output = result.to_dict()
	else:
		output = {'error': 'Analysis failed', 'raw': str(result)}
	print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
	return 0

def _cmd_wasm(args):
	result = analyze_wasm(args.file)
	print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
	return 0

def _cmd_pac(args):

	with open(args.file, 'rb') as f:
		data = f.read()
	analyzer = create_pac_bypass_analyzer()
	analyzer.analyze(data)
	res = analyzer.result
	output = {
		'signing_gadgets': len(res.signing_gadgets),
		'auth_gadgets': len(res.auth_gadgets),
		'strip_gadgets': len(res.strip_gadgets),
		'branch_auth_gadgets': len(res.branch_auth_gadgets),
		'leaks': [
			{
				'address': hex(l.address),
				'kind': l.kind,
				'description': l.description
			}
			for l in res.leaks
		],
		'entropy_assessment': res.entropy_assessment,
	}
	print(json.dumps(output, ensure_ascii=False, indent=2))
	return 0

def _cmd_wasi(args):
	result = analyze_wasi_sandbox(args.file)
	print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
	return 0

def _cmd_all(args):
	results = {}
	if os.path.isfile(args.file):
		results['mobile'] = analyze_mobile_binary(args.file)
		results['managed'] = str(analyze_managed_code(args.file))
		results['wasm'] = analyze_wasm(args.file) if args.file.endswith('.wasm') else 'skipped'
	print(json.dumps(results, ensure_ascii=False, indent=2, default=str))
	return 0

def main():

	parser = argparse.ArgumentParser(
		description='BinMind Mobile Platform Analyzer',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog='Examples:\n  python -m platform.mobile.main mobile app.apk\n  python -m platform.mobile.main wasm module.wasm'
	)
	parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
	parser.add_argument('--output', '-o', type=str, default=None, help='Output file path (JSON)')

	subparsers = parser.add_subparsers(dest='command', help='Analyzer subcommands')

	p_mobile = subparsers.add_parser('mobile', help='Analyze mobile binary (APK/OAT/Mach-O)')
	p_mobile.add_argument('file', help='Path to mobile binary')
	p_mobile.add_argument('--platform', default='auto', choices=['auto', 'android', 'ios'],
						help='Target platform (default: auto-detect)')
	p_mobile.set_defaults(func=_cmd_mobile)

	p_managed = subparsers.add_parser('managed', help='Analyze managed code (Java class/JAR/.NET DLL)')
	p_managed.add_argument('file', help='Path to managed code file')
	p_managed.add_argument('--output-dir', '-d', default=None, help='Output directory for decompiled code')
	p_managed.set_defaults(func=_cmd_managed)

	p_wasm = subparsers.add_parser('wasm', help='Analyze WebAssembly binary with WASI detection')
	p_wasm.add_argument('file', help='Path to .wasm file')
	p_wasm.set_defaults(func=_cmd_wasm)

	p_pac = subparsers.add_parser('pac', help='Analyze ARM64e PAC bypass attack surface')
	p_pac.add_argument('file', help='Path to ARM64 binary')
	p_pac.set_defaults(func=_cmd_pac)

	p_wasi = subparsers.add_parser('wasi', help='Analyze WASI sandbox escape risks')
	p_wasi.add_argument('file', help='Path to .wasm file')
	p_wasi.set_defaults(func=_cmd_wasi)

	p_all = subparsers.add_parser('all', help='Run all applicable analyzers')
	p_all.add_argument('file', help='Path to binary file')
	p_all.set_defaults(func=_cmd_all)

	args = parser.parse_args()
	_setup_logging(args.verbose)

	if not args.command:
		parser.print_help()
		return 0

	try:
		exit_code = args.func(args)
	except FileNotFoundError as e:
		logger.error(f"File not found: {e}")
		exit_code = 1
	except Exception as ex:
		logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
		exit_code = 2

	sys.exit(exit_code)

if __name__ == '__main__':
	main()


def _debug_print(*args, **kwargs):
    """暂留 — 内部调试输出桩，保留供开发期断点使用。"""
    pass

