# 2026-08-01 — vuln_detection CLI入口
# argparse驱动: scan/export/stats/dedup/lifecycle/plugins/config 子命令

import argparse
import sys
import os
import json as _json

json = _json


def _cmd_scan(args):
    """扫描二进制或目录"""
    from vuln_detection import CodeLocator, CVEFootprint
    locator = CodeLocator()
    target = args.target
    if os.path.isfile(target):
        results = []
        fp = locator.find_affected_code(target, args.cve) if args.cve else None
        if fp and fp.confidence > 0:
            results.append(fp)
        else:
            impacts = locator.assess_impact(target)
            results = impacts
    elif os.path.isdir(target):
        results = []
        for root, _, files in os.walk(target):
            for f in files:
                fpath = os.path.join(root, f)
                if os.path.isfile(fpath):
                    impacts = locator.assess_impact(fpath)
                    results.extend(impacts)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(1)

    if args.json:
        out = [{"cve_id": r.cve_id, "confidence": r.confidence,
                "functions": [f"0x{a:x}" for a in r.matched_functions],
                "strings": r.matched_strings} for r in results]
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            print(f"{r.cve_id}: confidence={r.confidence:.0%}"
                  f" funcs={len(r.matched_functions)} strs={len(r.matched_strings)}")
    return 0


def _cmd_export(args):
    """导出SBOM"""
    from vuln_detection import SBOMGenerator
    gen = SBOMGenerator()
    if args.components:
        for c in json.loads(args.components):
            gen.add_component(**c)
    out_path = args.output or f"sbom.{args.format}"
    fmt = args.format or "spdx"
    version = args.version or ""
    gen.write(out_path, format=fmt, version=version)
    print(f"SBOM written to {out_path}")
    return 0


def _cmd_stats(args):
    """统计概览"""
    from vuln_detection import VulnLifecycleAPI
    api = VulnLifecycleAPI(args.db)
    st = api.stats()
    print(f"Total records: {st['total']}")
    print(f"By status: {st['by_status']}")
    print(f"By severity: {st['by_severity']}")
    return 0


def _cmd_dedup(args):
    """去重合并多源漏洞"""
    from vuln_detection import VulnDedupMerger
    merger = VulnDedupMerger()
    sources = {}
    if args.ghidra:
        with open(args.ghidra) as f:
            sources["ghidra"] = json.load(f)
    if args.ida:
        with open(args.ida) as f:
            sources["ida"] = json.load(f)
    if args.r2:
        with open(args.r2) as f:
            sources["r2"] = json.load(f)
    result = merger.merge_from_sources(**sources)
    print(f"Input: {result.total_input}, Merged: {result.stats['merged']}"
          f", Conflicts: {result.stats['conflicts']}")
    for mf in result.merged:
        print(f"  {mf.cve_id or 'NO_CVE'}: {mf.function_name} (sources={mf.sources})")
    if args.output:
        with open(args.output, "w") as f:
            out_data = {
                "merged": [{"cve_id": m.cve_id, "function_name": m.function_name,
                            "severity": m.severity, "sources": m.sources}
                           for m in result.merged],
                "stats": result.stats,
            }
            json.dump(out_data, f, indent=2)
    return 0


def _cmd_lifecycle(args):
    """漏洞生命周期管理"""
    from vuln_detection import VulnLifecycleAPI, VulnStatus, VulnSeverity
    api = VulnLifecycleAPI(args.db)
    if args.action == "list":
        status = VulnStatus(args.status) if args.status else None
        severity = VulnSeverity(args.severity) if args.severity else None
        recs = api.list_all(status=status, severity=severity)
        for r in recs:
            print(f"[{r.status.value}] {r.cve_id or r.vuln_id}: {r.title} ({r.severity.value})")
    elif args.action == "transition":
        ok = api.transition(args.vuln_id, VulnStatus(args.status_to), reason=args.reason or "")
        print(f"Transition {'OK' if ok else 'FAILED'}")
    elif args.action == "history":
        hist = api.get_history(args.vuln_id)
        for h in hist:
            print(f"  {h.timestamp}: {h.from_status.value} -> {h.to_status.value} ({h.reason})")
    elif args.action == "create":
        rec = api.create(cve_id=args.cve_id or "", title=args.title or "",
                         description=args.desc or "", severity=VulnSeverity(args.severity or "info"))
        print(f"Created {rec.vuln_id}")
    if args.db:
        api.save()
    return 0


def _cmd_plugins(args):
    """插件管理"""
    from vuln_detection.src.core.plugin import discover_plugins, PluginManager
    mgr = PluginManager()
    discovered = discover_plugins(args.dir or "")
    for p in discovered:
        mgr.register(p)
    print(f"Loaded {len(discovered)} plugins:")
    for p in mgr.list_all():
        print(f"  {p.name} v{p.version}: {p.description}")
    return 0


def _cmd_config(args):
    """配置管理"""
    from vuln_detection.src.config import load_config, save_config, config_to_dict
    cfg_path = args.file or ""
    if args.action == "show":
        cfg = load_config(cfg_path)
        print(json.dumps(config_to_dict(cfg), indent=2))
    elif args.action == "init":
        from vuln_detection.src.config import Config
        cfg = Config()
        out_path = args.output or "vuln_detection_config.json"
        save_config(cfg, out_path)
        print(f"Config written to {out_path}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vuln_detect",
                                     description="BinMind Vulnerability Detection CLI")
    sub = parser.add_subparsers(dest="command", help="sub-command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan binary for vulnerabilities")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--cve", help="Specific CVE to check for")
    p_scan.add_argument("--json", action="store_true", help="JSON output")

    # export
    p_exp = sub.add_parser("export", help="Export SBOM")
    p_exp.add_argument("--format", default="spdx", choices=["spdx", "cyclonedx"])
    p_exp.add_argument("--version", default="")
    p_exp.add_argument("--components", help="JSON list of components")
    p_exp.add_argument("--output", "-o", help="Output file path")

    # stats
    p_stats = sub.add_parser("stats", help="Vulnerability statistics")
    p_stats.add_argument("--db", help="Lifecycle DB path")

    # dedup
    p_dedup = sub.add_parser("dedup", help="Deduplicate/merge findings")
    p_dedup.add_argument("--ghidra", help="Ghidra findings JSON")
    p_dedup.add_argument("--ida", help="IDA findings JSON")
    p_dedup.add_argument("--r2", help="Radare2 findings JSON")
    p_dedup.add_argument("--output", "-o", help="Output merged JSON")

    # lifecycle
    p_life = sub.add_parser("lifecycle", help="Vulnerability lifecycle management")
    p_life.add_argument("action", choices=["list", "create", "transition", "history"])
    p_life.add_argument("--db", help="Lifecycle DB path")
    p_life.add_argument("--vuln-id", help="Vulnerability ID")
    p_life.add_argument("--status", help="Filter by status")
    p_life.add_argument("--severity", help="Filter by severity")
    p_life.add_argument("--status-to", help="Target status for transition")
    p_life.add_argument("--reason", help="Transition reason")
    p_life.add_argument("--cve-id", help="CVE ID for creation")
    p_life.add_argument("--title", help="Title for creation")
    p_life.add_argument("--desc", help="Description for creation")

    # plugins
    p_plug = sub.add_parser("plugins", help="Plugin management")
    p_plug.add_argument("--dir", help="Plugin directory")

    # config
    p_cfg = sub.add_parser("config", help="Configuration management")
    p_cfg.add_argument("action", choices=["show", "init"])
    p_cfg.add_argument("--file", "-f", help="Config file path")
    p_cfg.add_argument("--output", "-o", help="Output path for init")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    cmd_map = {
        "scan": _cmd_scan, "export": _cmd_export, "stats": _cmd_stats,
        "dedup": _cmd_dedup, "lifecycle": _cmd_lifecycle,
        "plugins": _cmd_plugins, "config": _cmd_config,
    }
    handler = cmd_map.get(args.command)
    if handler:
        return handler(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
