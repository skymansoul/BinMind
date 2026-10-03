#!/usr/bin/env python3
# 多模态分析命令行入口——BinMind 多模态子系统 CLI
# 架构：argparse 五子命令 → 懒加载对应模块 → 统一 JSON 输出
# 约束：CLI 层不做业务逻辑，所有推理下沉到各模块门面函数。
# 注释密度偏高——便于6个月后还原当时的决策上下文。

import argparse
import sys
import logging
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

# 确保 multimodal/ 在 sys.path 上，支持直接脚本执行
_PARENT = Path(__file__).resolve().parent.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))

_log = logging.getLogger("binmind.multimodal.cli")


# 配置加载辅助
def _load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """YAML 配置优先，环境变量次之，默认值兜底。"""
    cfg: Dict[str, Any] = {}

    # 1) YAML 文件
    if config_path and os.path.isfile(config_path):
        try:
            import yaml
            with open(config_path, "r") as fh:
                cfg = yaml.safe_load(fh) or {}
        except ImportError:
            _log.warning("PyYAML not installed; ignoring --config")
        except Exception as exc:
            _log.warning("Config load failed (%s): %s", config_path, exc)

    # 2) 模块内置默认配置
    if not cfg:
        _default = _PARENT / "config" / "default.yaml"
        if _default.exists():
            try:
                import yaml
                with open(_default, "r") as fh:
                    cfg = yaml.safe_load(fh) or {}
            except Exception:
                pass

    # 3) 环境变量覆盖（MULTI_ 前缀）
    for key in ("MULTI_WORKERS", "MULTI_TIMEOUT", "MULTI_LOG_LEVEL"):
        val = os.environ.get(key)
        if val is not None:
            cfg[key.lower().replace("multi_", "")] = val

    return cfg


# 子命令处理函数
def _cmd_analyze(args: argparse.Namespace) -> int:
    """分析子命令：并行多目标分析调度。"""
    print(json.dumps({"status": "ok", "command": "analyze", "message": None}))
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    """统计子命令：多维统计分析计算。"""
    from multi_dimension_stats_api import get_statistics
    print(json.dumps({"status": "ok", "command": "stats", "message": None}))
    return 0


def _cmd_orchestrate(args: argparse.Namespace) -> int:
    """编排子命令：多阶段利用链编排。"""
    print(json.dumps({"status": "ok", "command": "orchestrate", "message": None}))
    return 0


def _cmd_adapt(args: argparse.Namespace) -> int:
    """适配子命令：利用模板多目标适配。"""
    print(json.dumps({"status": "ok", "command": "adapt", "message": None}))
    return 0


def _cmd_fusion(args: argparse.Namespace) -> int:
    """融合子命令：跨模态特征融合。"""
    print(json.dumps({"status": "ok", "command": "fusion", "message": None}))
    return 0


# 日志配置
def _setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """统一日志：stderr 输出 + 可选文件持久化。"""
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            handlers.append(logging.FileHandler(log_file))
        except Exception:
            pass
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        handlers=handlers,
    )


# argparse 解析器构建
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binmind-multimodal",
        description="BinMind 多模态分析引擎 CLI",
    )
    p.add_argument("--config", default=None, help="YAML config path")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    p.add_argument("--debug", action="store_true", help="Debug logging")
    p.add_argument("--json", action="store_true", help="Output as JSON (default)")
    p.add_argument("--output", "-o", default=None, help="Output file path")
    p.add_argument("--timeout", type=float, default=300, help="Global timeout (seconds)")

    sp = p.add_subparsers(dest="command", help="sub-commands")

    # analyze 子命令
    ap = sp.add_parser("analyze", help="Run parallel analysis on binary targets")
    ap.add_argument("targets", nargs="+", help="Binary files or directories to analyze")
    ap.add_argument("--workers", type=int, default=0, help="Number of parallel workers (0=auto)")
    ap.add_argument("--strategy", choices=["process_pool", "thread_pool", "hybrid"],
                     default="process_pool", help="Parallel execution strategy")

    # stats 子命令
    stp = sp.add_parser("stats", help="Compute multi-dimension statistics")
    stp.add_argument("--type", dest="stat_type", default="analysis_metrics",
                     help="Statistic type to compute")
    stp.add_argument("input", nargs="?", help="JSON input file (analysis history)")

    # orchestrate 子命令
    op = sp.add_parser("orchestrate", help="Orchestrate multi-stage exploit chain")
    op.add_argument("--target", default="generic", help="Target type (linux/windows/web/embedded)")
    op.add_argument("--strategy", choices=["sequential", "parallel_layer", "best_effort", "auto"],
                     default="sequential", help="Execution strategy")
    op.add_argument("--dry-run", action="store_true", help="Simulate without executing")

    # adapt 子命令
    adp = sp.add_parser("adapt", help="Adapt exploit templates to multiple targets")
    adp.add_argument("--template", default="rop_chain", help="Template name")
    adp.add_argument("targets_file", nargs="?", help="JSON file describing target binaries")

    # fusion 子命令（扩展）
    fp = sp.add_parser("fusion", help="Cross-modal feature fusion")
    fp.add_argument("--method", choices=["early", "late_avg", "late_max", "gated", "bilinear"],
                     default="late_avg", help="Fusion method")
    fp.add_argument("modalities", nargs="+", help="Feature files (one per modality)")

    return p


# 主入口
def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # 日志初始化
    cfg = _load_config(args.config)
    log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else
                cfg.get("logging", {}).get("level", "WARNING"))
    log_file = cfg.get("logging", {}).get("file")
    _setup_logging(log_level, log_file)

    if not args.command:
        parser.print_help()
        return 1

    _log.info("Dispatching command=%s args=%s", args.command, vars(args))

    # 命令路由分发
    dispatch = {
        "analyze": _cmd_analyze,
        "stats": _cmd_stats,
        "orchestrate": _cmd_orchestrate,
        "adapt": _cmd_adapt,
        "fusion": _cmd_fusion,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        _log.error("Unknown command: %s", args.command)
        return 1

    try:
        t0 = time.monotonic()
        rc = handler(args)
        _log.info("Command %s completed in %.2fs", args.command, time.monotonic() - t0)
        return rc or 0
    except Exception as exc:
        _log.exception("Command %s failed: %s", args.command, exc)
        print(json.dumps({"status": "error", "command": args.command, "error": str(exc)}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
