#!/usr/bin/env python3
"""crypto 命令行入口"""
import argparse, sys, logging, os

def main():
	p = argparse.ArgumentParser(prog=f"binmind-crypto", description=f"BinMind crypto CLI")
	p.add_argument("--config", default=None, help="YAML config path")
	p.add_argument("--verbose", "-v", action="store_true")
	p.add_argument("--debug", action="store_true")
	p.add_argument("--output", "-o", default=None)
	sp = p.add_subparsers(dest="command", help="sub-commands")
	sp.add_parser("detect", help="detect — crypto 子命令")
	sp.add_parser("misuse", help="misuse — crypto 子命令")
	sp.add_parser("traffic", help="traffic — crypto 子命令")
	sp.add_parser("hash", help="hash — crypto 子命令")
	sp.add_parser("pqc", help="pqc — crypto 子命令")
	sp.add_parser("stegano", help="stegano — crypto 子命令")
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
	rc = _dispatch(a, _log)
	return rc

def _dispatch(args, log):
	handlers = {
		"detect": _run_detect,
		"misuse": _run_misuse,
		"traffic": _run_traffic,
		"hash": _run_hash,
		"pqc": _run_pqc,
		"stegano": _run_stegano,
	}
	fn = handlers.get(args.command)
	if fn is None:
		log.error("未知子命令: %s", args.command)
		return 2
	return fn(args, log)

def _run_detect(args, log):
	from .crypto_detector import detect_by_magic_constants
	log.info("detect: 扫描魔数常量")
	if not args.output:
		log.error("缺少 --output")
		return 1
	detect_by_magic_constants(args.output)
	return 0

def _run_misuse(args, log):
	from .crypto_misuse import detect_crypto_misuse
	log.info("misuse: 扫描密码学误用")
	if not args.output:
		log.error("缺少 --output")
		return 1
	detect_crypto_misuse(args.output)
	return 0

def _run_traffic(args, log):
	from .crypto_traffic_decrypt import analyze_traffic
	log.info("traffic: 分析加密流量")
	if not args.output:
		log.error("缺少 --output")
		return 1
	analyze_traffic(args.output)
	return 0

def _run_hash(args, log):
	from .hardware_hash import compute_file_hash
	log.info("hash: 计算文件哈希")
	if not args.output:
		log.error("缺少 --output")
		return 1
	h = compute_file_hash(args.output)
	print(h)
	return 0

def _run_pqc(args, log):
	from .pqc_detector import detect_pqc_bytes
	log.info("pqc: 后量子密码检测")
	if not args.output:
		log.error("缺少 --output")
		return 1
	with open(args.output, "rb") as f:
		detect_pqc_bytes(f.read())
	return 0

def _run_stegano(args, log):
	from .steganography_detector import detect_steganography_bytes
	log.info("stegano: 隐写检测")
	if not args.output:
		log.error("缺少 --output")
		return 1
	with open(args.output, "rb") as f:
		detect_steganography_bytes(f.read())
	return 0

if __name__ == "__main__":
	sys.exit(main())
