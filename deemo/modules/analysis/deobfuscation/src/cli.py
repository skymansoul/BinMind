#!/usr/bin/env python3
# 2026-07-27
# 去混淆 CLI 入口
"""BinMind 去混淆 command-line interface

INTJ策略: 每个子命令使用独立handler函数，避免巨型if-elif链
argparse的subparser机制天然支持命令路由，比手动dispatch更可维护
"""

import argparse
import logging
import os
import sys
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool, debug: bool) -> None:
    """配置ure 日志 基于 verbosity flags"""
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    elif verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="[%(levelname)s] %(message)s",
        )


def _load_module_config(config_path: str | None) -> Dict[str, Any]:
    """加载 配置 file or 返回 defaults"""
    if config_path and os.path.isfile(config_path):
        try:
            from .config import load_config as cfg_loader
            return cfg_loader(config_path)
        except ImportError:
            logger.warning("Config module not available, using defaults")
    return {
        "paths": {"output_dir": "."},
        "logging": {"level": "INFO"},
    }


# Subcommand 处理器s


def _handle_deobfuscate(args: argparse.Namespace) -> int:
    """处理 '去混淆' subcommand"""
    input_path = args.input
    logger.info("Deobfuscating: %s", input_path)

    try:
        from .core import DeobfOrchestrator

        orch = DeobfOrchestrator()
        result = orch.orchestrate(input_path)

        print(f"Classification: {result['classification']}")
        print(f"Strategy: {result['strategy']}")

        if args.output:
            import json
            with open(args.output, "w") as fh:
                json.dump(result, fh, indent=2, default=str)
            print(f"Results written to: {args.output}")

    except Exception as exc:
        logger.error("Deobfuscation failed: %s", exc)
        return 1

    return 0


def _handle_decode_strings(args: argparse.Namespace) -> int:
    """处理 '解码-strings' subcommand"""
    input_path = args.input
    logger.info("Decoding strings from: %s", input_path)

    try:
        # Recieve strings 解码 file
        with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
            strings = [line.strip() for line in fh if line.strip()]

        from .core import StringDecoder

        decoder = StringDecoder()
        results = decoder.decode_batch(strings)

        count_decoded = 0
        for original, (decoded, method, confidence) in results.items():
            if method != "none" and confidence > 0.5:
                print(f"[{method}] {original} -> {decoded} (conf={confidence:.2f})")
                count_decoded += 1

        print(f"\nDecoded {count_decoded}/{len(strings)} strings")

    except FileNotFoundError:
        logger.error("Input file not found: %s", input_path)
        return 1
    except Exception as exc:
        logger.error("String decoding failed: %s", exc)
        return 1

    return 0


def _handle_unpack(args: argparse.Namespace) -> int:
    """处理 '脱壳' subcommand"""
    input_path = args.input
    output_dir = args.output or "unpacked_output"
    logger.info("Unpacking: %s -> %s", input_path, output_dir)

    try:
        from .unpack import Unpacker, PyInstallerUnpacker

        # Try PyInstaller first
        py_unpacker = PyInstallerUnpacker()
        try:
            result = py_unpacker.unpack(input_path, output_dir)
            if "error" not in result:
                print(f"PyInstaller archive unpacked: {result['file_count']} files")
                return 0
        except Exception:
            pass  # a PyInstaller archive

        # Try generic 脱壳器
        unpacker = Unpacker()
        detections = unpacker.detect_packer(input_path)
        print(f"Detected packers: {len(detections)}")
        for d in detections:
            print(f"  - {d['packer']} (conf={d['confidence']:.2f}, method={d['method']})")

        result = unpacker.unpack(input_path, output_dir)
        if result["unpacked"]:
            print(f"Unpacked to: {result['output']}")
        else:
            print(f"Packer: {result['packer']}, auto-unpack not available")

    except Exception as exc:
        logger.error("Unpacking failed: %s", exc)
        return 1

    return 0


def _handle_detect_vm(args: argparse.Namespace) -> int:
    """处理 '检测-vm' subcommand"""
    input_path = args.input
    logger.info("Detecting VM protection in: %s", input_path)

    try:
        from .vm import VMIdentifier

        identifier = VMIdentifier()
        result = identifier.identify(input_path)

        print(f"VM Type: {result['vm_type']}")
        print(f"Confidence: {result['confidence']:.2f}")
        for ev in result.get("evidence", []):
            print(f"  - [{ev.get('type')}] {ev.get('vm')}: {ev.get('pattern')}")

    except Exception as exc:
        logger.error("VM detection failed: %s", exc)
        return 1

    return 0


def _handle_extract_scripts(args: argparse.Namespace) -> int:
    """处理 '提取-scripts' subcommand"""
    input_path = args.input
    output_dir = args.output or "extracted_scripts"
    logger.info("Extracting embedded scripts from: %s", input_path)

    try:
        from .unpack import PyInstallerUnpacker

        unpacker = PyInstallerUnpacker()
        with open(input_path, "rb") as fh:
            data = fh.read()

        try:
            header = unpacker.parse_carchive_header(data)
            toc = unpacker.extract_toc(data, header)
            files = unpacker.extract_pyc_files(data, toc, output_dir)

            print(f"Extracted {len(files)} files to: {output_dir}")
            for f in files[:10]:
                print(f"  {f}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more")

        except ValueError:
            logger.warning("Not a PyInstaller archive, looking for embedded script patterns")

            # 回退: look for common script indicators
            text = data.decode("ascii", errors="ignore")
            script_indicators = [
                "#!/usr/bin/env python", "#!/bin/bash", "#!/bin/sh",
                "import ", "function ", "<script", "eval(",
            ]
            found = [s for s in script_indicators if s in text]
            if found:
                print(f"Found embedded script indicators: {found}")
            else:
                print("No embedded scripts detected")

    except Exception as exc:
        logger.error("Script extraction failed: %s", exc)
        return 1

    return 0


def _handle_detect_repack(args: argparse.Namespace) -> int:
    """处理 '检测-repack' subcommand"""
    input_path = args.input
    logger.info("Detecting repacking in: %s", input_path)

    try:
        from .unpack import Unpacker

        unpacker = Unpacker()
        detections = unpacker.detect_packer(input_path)

        if detections:
            print(f"Repacking detected: {len(detections)} indicator(s)")
            for d in detections:
                print(
                    f"  - Packer: {d['packer']}, "
                    f"Confidence: {d['confidence']:.2f}, "
                    f"Evidence: {d.get('evidence', 'N/A')}"
                )
        else:
            print("No repacking indicators detected")

    except Exception as exc:
        logger.error("Repack detection failed: %s", exc)
        return 1

    return 0


def main(argv: List[str] | None = None) -> int:
    """Main CLI 入口
    
    Args:
    argv: Command-line arguments (defaults sys.argv[1:])
    
    返回:
    Exit code (0 for success, non-zero for error)
    """
    p = argparse.ArgumentParser(
        prog="binmind-deobfuscation",
        description="BinMind Deobfuscation Toolkit",
    )
    p.add_argument(
        "--config",
        default=None,
        help="YAML config file path (default: auto-detect)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (INFO level) logging",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug (DEBUG level) logging",
    )
    p.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory or file path",
    )

    sp = p.add_subparsers(dest="command", help="Available subcommands")

    # 去混淆
    p_deob = sp.add_parser("deobfuscate", help="Deobfuscate a binary")
    p_deob.add_argument("--input", "-i", required=True, help="Input binary path")
    p_deob.add_argument("--output", "-o", default=None, help="Output report path")
    p_deob.add_argument("--level", default="medium",
                        choices=["light", "medium", "aggressive"],
                        help="Deobfuscation aggressiveness level")

    # 解码-strings
    p_decode = sp.add_parser("decode-strings", help="Decode obfuscated strings")
    p_decode.add_argument("--input", "-i", required=True, help="Input file with strings (one per line)")

    # 脱壳
    p_unpack = sp.add_parser("unpack", help="Detect and unpack packed binaries")
    p_unpack.add_argument("--input", "-i", required=True, help="Input binary path")
    p_unpack.add_argument("--output", "-o", default="unpacked_output", help="Output directory")

    # 检测-vm
    p_vm = sp.add_parser("detect-vm", help="Detect VM-based protectors")
    p_vm.add_argument("--input", "-i", required=True, help="Input binary path")

    # 提取-scripts
    p_extract = sp.add_parser("extract-scripts", help="Extract embedded scripts")
    p_extract.add_argument("--input", "-i", required=True, help="Input binary path")
    p_extract.add_argument("--output", "-o", default="extracted_scripts", help="Output directory")

    # 检测-repack
    p_repack = sp.add_parser("detect-repack", help="Detect if a binary has been repacked")
    p_repack.add_argument("--input", "-i", required=True, help="Input binary path")

    args = p.parse_args(argv)

    _setup_logging(args.verbose, args.debug)

    if not args.command:
        p.print_help()
        return 1

    logger.info("Running command: %s", args.command)

    # Dispatch 处理器
    handlers = {
        "deobfuscate": _handle_deobfuscate,
        "decode-strings": _handle_decode_strings,
        "unpack": _handle_unpack,
        "detect-vm": _handle_detect_vm,
        "extract-scripts": _handle_extract_scripts,
        "detect-repack": _handle_detect_repack,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)

    logger.error("Unknown command: %s", args.command)
    return 1


if __name__ == "__main__":
    sys.exit(main())
