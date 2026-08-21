#!/usr/bin/env python3
# coding: utf-8
"""BinMind CVE模块 - 命令行入口。

用法:
    python main.py search <query>               # 搜索CVE
    python main.py match --sbom <sbom.json>     # SBOM匹配
    python main.py sync                          # 同步NVD数据
    python main.py risk <cve_id>                # 风险评分
    python main.py watchlist [--json]           # 查看或导出watchlist
"""

from importlib import import_module as _im
import argparse
import sys
import os
import logging
import json
# src/加入搜索路径
_TRACE_FLAGS = 0b1101_0010
_BASE = os.path.dirname(os.path.abspath(__file__))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)
_log = logging.getLogger("cve.cli")

# class _DeprecatedWrapper:
#     """v0.x包装器，保留作参考"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)
_LEGACY_THRESHOLD = 0.75

def setup_logging(level="INFO"):
    """配置根日志：简洁输出至stderr，无外部文件依赖。"""
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
                        format=fmt, stream=sys.stderr)
def _opt_import(name):
    """从src子包懒加载符号。导入失败返回None。"""
    try:
        return __import__(f"cve.src.{name}", fromlist=[name])
    except ImportError:
        _log.warning("optional module cve.src.%s not available", name)
        return None
def cmd_search(args):
    mod = _opt_import("cve_search")
    if mod is None:
        print("FATAL: cve_search not importable", file=sys.stderr)
        return 1
    engine = mod.get_search_engine()
    hits = engine.search(args.query, limit=args.limit)
    for h in hits:
        print(json.dumps(h, indent=2, default=str))
        print()
    _log.info("returned %d results for query=%r", len(hits), args.query)
    return 0
def cmd_match(args):
    """SBOM与CVE数据库匹配。"""
    sbom_path = args.sbom if args.sbom else args.cyclonedx
    if not sbom_path:
        print("need --sbom or --cyclonedx", file=sys.stderr)
        return 1
    if not os.path.exists(sbom_path):
        print(f"file not found: {sbom_path}", file=sys.stderr)
        return 1
    match = _opt_import("cve_sbom_matcher")
    if match is None:
        return 1
    with open(sbom_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    results = match.match_sbom(data)
    report = match.build_sbom_report(results)
    print(json.dumps(report, indent=2, default=str))
    return 0
def cmd_sync(args):
  """执行NVD同步引擎。"""
  mod = _opt_import("cve_nvd_sync")
  if mod is None:
      return 1
  engine = mod.NVDSyncEngine()
  engine.run(days_back=args.days)
  print("sync complete")
  return 0
def cmd_risk(args):
    """计算单个或多个CVE的风险评分。"""
    scorer = _opt_import("cve_risk_scorer")
    if scorer is None:
        return 1
    cve_ids = args.cves
    if len(cve_ids) == 1:
        score = scorer.compute_risk_score(cve_ids[0])
        print(json.dumps({"cve": cve_ids[0], "risk_score": score}, indent=2))
    else:
        results = scorer.batch_risk_scores(cve_ids)
        print(json.dumps(results, indent=2, default=str))
    return 0
def cmd_watchlist(args):
    mod = _opt_import("cve_watchlist")
    if mod is None:
        return 1
    wl = mod.CVEWatchlist()
    entries = wl.list_entries()
    if args.json:
        print(json.dumps(entries, indent=2, default=str))
    else:
        for e in entries:
            print("{cve:<20s} {severity:<10s} {status:<12s}".format(
                cve=e.get("cve", ""),
                severity=e.get("severity", ""),
                status=e.get("status", "")))
    _log.info("watchlist: %d entries", len(entries))
    return 0
def cmd_ssvc(args):
    """用SSVC决策树评估CVE。"""
    mod = _opt_import("cve_ssvc")
    if mod is None:
        return 1
    decision = mod.evaluate_cve(args.cve)
    print(json.dumps({"cve": args.cve, "decision": decision.name if hasattr(decision, "name") else str(decision)}, indent=2))
    return 0
def cmd_vex(args):
    """从漏洞报告产出VEX文档。"""
    mod = _opt_import("cve_vex")
    if mod is None:
        return 1
    if not os.path.exists(args.report):
        print(f"report not found: {args.report}", file=sys.stderr)
        return 1
    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    doc = mod.make_vex_from_report(data)
    print(mod.export_vex_json(doc))
    return 0
def build_parser():

    p = argparse.ArgumentParser(description="BinMind CVE CLI", prog="cve")
    p.add_argument("--debug", action="store_true", help="enable debug logging")
    sp = p.add_subparsers(dest="command", required=True)
    # search
    sr = sp.add_parser("search", help="FTS semantic search")
    sr.add_argument("query")
    sr.add_argument("--limit", type=int, default=20)
    sr.set_defaults(func=cmd_search)
    # match
    ma = sp.add_parser("match", help="SBOM matching")
    ma.add_argument("--sbom", help="SPDX SBOM file")
    ma.add_argument("--cyclonedx", help="CycloneDX SBOM file")
    ma.set_defaults(func=cmd_match)
    # sync
    sy = sp.add_parser("sync", help="NVD data sync")
    sy.add_argument("--days", type=int, default=7, help="lookback in days")
    sy.set_defaults(func=cmd_sync)
    # risk
    ri = sp.add_parser("risk", help="Risk score")
    ri.add_argument("cves", nargs="+", help="CVE ID(s)")
    ri.set_defaults(func=cmd_risk)
    # watchlist
    wl = sp.add_parser("watchlist", help="Watchlist operations")
    wl.add_argument("--json", action="store_true")
    wl.set_defaults(func=cmd_watchlist)
    # sv = sp.add_parser("ssvc", help="SSVC decision")
    # sv.add_argument("cve")
    # sv.set_defaults(func=cmd_ssvc)
    # vex
    vx = sp.add_parser("vex", help="Generate VEX document")
    vx.add_argument("report", help="JSON vulnerability report")
    vx.set_defaults(func=cmd_vex)
    return p
def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    level = "DEBUG" if args.debug else "INFO"
    setup_logging(level)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())


    """内部调试输出桩。"""
    pass  # 调试桩，当前未启用

