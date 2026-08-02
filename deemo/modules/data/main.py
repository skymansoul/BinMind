#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BinMind Data Module — CLI entry point.

用法:
    python main.py init                     # 初始化数据库
    python main.py import <path> [--stage raw]  # 导入文件/目录
    python main.py search <query>           # FTS 搜索
    python main.py export [--fmt json] [--stage raw] [--out results.json]
    python main.py dedup                    # 运行去重
    python main.py stats                    # 数据库统计
    python main.py health                   # 数据库健康检查
    python main.py lifecycle run            # 运行生命周期维护
    python main.py lifecycle log <sig_id>   # 查看某签名的生命周期日志
"""

import argparse
import json
import os
import sys
import time
import logging

# 确保 src/ 在 path 里
_BASE = os.path.dirname(os.path.abspath(__file__))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from src.config import get_config, reset_config
from src.db import get_db

_log = logging.getLogger("data.cli")

# tqdm 可选 —— 有则显示进度条，无则静默
try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


def _progress(iterable, desc="", total=None, disable=False):
    """可选的进度条包装器。"""
    if _HAS_TQDM and not disable:
        return _tqdm(iterable, desc=desc, total=total, unit="items",
                     ncols=100, smoothing=0.1)
    return iterable


def setup_logging(level="INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _emit_json(data: dict, exit_code: int = 0):
    """以 JSON 格式输出结果并退出 —— 用于脚本化调用。"""
    print(json.dumps(data, ensure_ascii=False, default=str))
    sys.exit(exit_code)


def cmd_init(args):
    """Initialize the database schema."""
    db = get_db()
    stats = db.db_stats()
    if args.json_output:
        _emit_json({"status": "ok", **stats})
    print(f"DB initialized: {stats['total_signatures']} signatures, "
          f"{stats['total_chunks']} chunks")
    print("Stages:", stats.get("by_stage", {}))
    db.close()


def cmd_import(args):
    """Import files into the signature database."""
    from src.streaming import StreamProcessor
    from src.pipeline import Pipeline, make_hash_stage

    db = get_db()
    cfg = get_config()
    path = args.path

    if not os.path.exists(path):
        if args.json_output:
            _emit_json({"status": "error", "error": f"path '{path}' does not exist"}, 1)
        print(f"Error: path '{path}' does not exist.")
        sys.exit(1)

    if args.dry_run:
        _do_dry_import(path, args)
        return

    t0 = time.time()
    sp = StreamProcessor(config=cfg.streaming)

    pipeline = Pipeline("import", cfg.pipeline)
    pipeline.add_stage("compute_sha256", make_hash_stage("sha256"))

    count = 0
    if os.path.isfile(path):
        import hashlib
        sha = hashlib.sha256()
        fsize = 0
        mtime = 0.0
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
                    fsize += len(chunk)
            mtime = os.path.getmtime(path)
        except (OSError, PermissionError) as exc:
            if args.json_output:
                _emit_json({"status": "error", "error": str(exc)}, 1)
            print(f"Error reading '{path}': {exc}")
            sys.exit(1)
        sha256_hex = sha.hexdigest()
        db.add_signature(
            file_path=os.path.abspath(path),
            sha256=sha256_hex,
            file_size=fsize,
            mtime=mtime,
            metadata={"imported_from": args.path, "stage": args.stage},
        )
        count = 1
    else:
        seen = set()
        batch = []
        file_list = []
        for root, _dirs, files in os.walk(path):
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.isfile(fp) and not fp.endswith(('.gz', '.zip', '.7z', '.xz')):
                    file_list.append(fp)

        with _progress(file_list, desc="Importing", disable=args.no_progress) as pbar:
            for fp in pbar:
                abspath = os.path.abspath(fp)
                if abspath in seen:
                    continue
                seen.add(abspath)
                try:
                    fsize = os.path.getsize(fp)
                except OSError:
                    continue
                batch.append({
                    "file_path": abspath,
                    "data": b"",
                    "file_size": fsize,
                    "stage": args.stage,
                })
                if len(batch) >= 100:
                    _import_batch(db, batch)
                    count += len(batch)
                    batch = []
        if batch:
            _import_batch(db, batch)
            count += len(batch)

    elapsed = time.time() - t0
    if args.json_output:
        _emit_json({"status": "ok", "imported": count, "elapsed_s": round(elapsed, 1)})
    print(f"Imported {count} signatures in {elapsed:.1f}s")
    db.close()


def _do_dry_import(path, args):
    """预览导入：扫描文件但不写入数据库。"""
    file_list = []
    if os.path.isfile(path):
        file_list = [path]
    else:
        for root, _dirs, files in os.walk(path):
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.isfile(fp):
                    file_list.append(fp)

    total_size = 0
    for fp in file_list:
        try:
            total_size += os.path.getsize(fp)
        except OSError:
            pass

    print(f"Dry run: would import {len(file_list)} files ({total_size / (1024*1024):.1f} MB)")
    if file_list:
        for fp in file_list[:10]:
            print(f"  {fp}")
        if len(file_list) > 10:
            print(f"  ... and {len(file_list) - 10} more")


def _import_batch(db, batch):
    """Helper: import a batch of file records."""
    import hashlib
    records = []
    for item in batch:
        fp = item["file_path"]
        sha = hashlib.sha256()
        fsize = 0
        mtime = 0.0
        try:
            with open(fp, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
                    fsize += len(chunk)
            mtime = os.path.getmtime(fp)
        except (OSError, PermissionError) as e:
            _log.warning("Skip %s: %s", fp, e)
            continue
        records.append({
            "file_path": fp,
            "sha256": sha.hexdigest(),
            "file_size": fsize,
            "mtime": mtime,
            "stage": item.get("stage", "raw"),
        })
    if records:
        db.add_signatures_batch(records)


def cmd_search(args):
    """FTS search."""
    db = get_db()
    results = db.search(args.query, limit=args.limit)

    if args.json_output:
        _emit_json({"status": "ok", "query": args.query, "count": len(results), "results": results})

    for r in results:
        fp = r.get("file_path", "?")
        sha = r.get("sha256", "")[:16]
        stage = r.get("stage", "?")
        print(f"  [{stage}] {fp}  ({sha}...)")
    print(f"\n{len(results)} result(s) for '{args.query}'")
    db.close()


def cmd_export(args):
    """Export signatures."""
    from src.export import DataExporter

    db = get_db()
    exporter = DataExporter(db)
    out_path = args.out or f"export_{args.stage or 'all'}.{args.fmt}"
    since = args.since or ""

    t0 = time.time()
    count = exporter.export_signatures(
        out_path, fmt=args.fmt, stage=args.stage,
        limit=args.limit, since=since
    )
    elapsed = time.time() - t0

    if args.json_output:
        _emit_json({"status": "ok", "exported": count, "file": out_path,
                    "elapsed_s": round(elapsed, 1)})
    print(f"Exported {count} records to {out_path} ({elapsed:.1f}s)")
    db.close()


def cmd_dedup(args):
    """Run deduplication."""
    from src.dedup import dedup_from_config

    db = get_db()
    engine = dedup_from_config(db)
    sigs = db.list_signatures(limit=args.limit if args.limit else 10000)

    found = 0
    for sig in _progress(sigs, desc="Dedup scan", disable=args.no_progress):
        sha = sig.get("sha256", "")
        if not sha:
            continue
        canonical = engine.dedup_by_hash(sha)
        if canonical and canonical != sha:
            found += 1
            if args.verbose:
                print(f"  DUP: {sha[:16]}... -> {canonical[:16]}...")

    bstats = engine.bloom_stats
    cstats = engine.cardinality_stats

    if args.json_output:
        _emit_json({"status": "ok", "scanned": len(sigs), "duplicates_found": found,
                    "bloom": bstats, "cardinality": cstats})

    print(f"Dedup scan complete: {found} duplicates found in {len(sigs)} signatures.")
    print(f"Bloom filter: {bstats['bloom_skips']} DB lookups avoided "
          f"({bstats['skip_rate']*100:.0f}% skip rate)")
    print(f"Estimated uniques (HLL): {cstats['hll_estimated_uniques']}")
    db.close()


def cmd_stats(args):
    """Print DB statistics."""
    db = get_db()
    stats = db.db_stats()
    if args.json_output:
        _emit_json({"status": "ok", **stats})
    print(json.dumps(stats, indent=2, default=str))
    db.close()


def cmd_restore(args):
    """Restore signatures from binary export file."""
    from src.export import import_bin_to_db
    db = get_db()
    t0 = time.time()
    count = import_bin_to_db(args.path, db)
    elapsed = time.time() - t0
    if args.json_output:
        _emit_json({"status": "ok", "restored": count, "elapsed_s": round(elapsed, 1)})
    print(f"Restored {count} signatures from {args.path} ({elapsed:.1f}s)")
    db.close()


def cmd_health(args):
    """Database health check."""
    db = get_db()
    errors = db.integrity_check()
    stats = db.db_stats()

    result = {
        "integrity_ok": len(errors) == 0,
        "integrity_errors": errors,
        "db_size_mb": stats.get("db_size_mb", 0),
        "wal_size_mb": stats.get("wal_size_mb", 0),
        "total_signatures": stats.get("total_signatures", 0),
    }

    if args.json_output:
        _emit_json({"status": "ok", **result})

    status = "OK" if result["integrity_ok"] else "FAILED"
    print(f"Health check: {status}")
    print(f"  DB: {result['db_size_mb']} MB  WAL: {result['wal_size_mb']} MB")
    print(f"  Signatures: {result['total_signatures']}")
    if errors:
        for e in errors:
            print(f"  ERROR: {e}")
    db.close()


def cmd_lifecycle(args):
    """Lifecycle management subcommands."""
    from src.lifecycle import LifecycleManager

    db = get_db()
    lm = LifecycleManager(db)

    if args.lc_cmd == "run":
        summary = lm.run_maintenance(dry_run=args.dry_run)
        if args.dry_run:
            print(lm.dry_run_report())
        if args.json_output:
            _emit_json({"status": "ok", "dry_run": args.dry_run, **summary})
        print(json.dumps(summary, indent=2))
    elif args.lc_cmd == "log":
        if not args.sig_id:
            print("Error: --sig-id required for lifecycle log")
        else:
            entries = lm.get_lifecycle_log(args.sig_id)
            for e in entries:
                print(f"  {e['transition_at']}: {e['from_stage']} -> {e['to_stage']} ({e['reason']})")
    elif args.lc_cmd == "transition":
        if not args.sig_id or not args.to_stage:
            print("Error: --sig-id and --to-stage required for transition")
        else:
            ok = lm.transition(args.sig_id, args.to_stage, args.reason or "manual")
            print(f"Transition {'OK' if ok else 'FAILED'}")

    db.close()


def main():
    parser = argparse.ArgumentParser(
        prog="binmind-data",
        description="BinMind Data Module — signature DB, ETL, dedup, export",
    )
    parser.add_argument("--config", "-c", default=None, help="Config file path")
    parser.add_argument("--profile", "-p", default=None, help="Config profile name (e.g. ci, prod)")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--json-output", action="store_true",
                        help="Output machine-readable JSON instead of text")
    parser.add_argument("--no-progress", action="store_true",
                        help="Disable progress bars")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview actions without making changes (import/lifecycle)")

    sub = parser.add_subparsers(dest="cmd", help="Commands")

    sub.add_parser("init", help="Initialize database schema")

    p_import = sub.add_parser("import", help="Import files/directory into DB")
    p_import.add_argument("path", help="File or directory path")
    p_import.add_argument("--stage", default="raw", help="Lifecycle stage (default: raw)")

    p_search = sub.add_parser("search", help="FTS search in signatures")
    p_search.add_argument("query", help="Search query (FTS5 syntax)")
    p_search.add_argument("--limit", "-n", type=int, default=50, help="Max results")

    p_export = sub.add_parser("export", help="Export signatures to file")
    p_export.add_argument("--fmt", default="json", choices=["json", "csv", "yaml", "msgpack", "jsonl", "bin"])
    p_export.add_argument("--stage", default="", help="Filter by stage")
    p_export.add_argument("--out", "-o", default="", help="Output file path")
    p_export.add_argument("--limit", type=int, default=0, help="Max rows (0=all)")
    p_export.add_argument("--since", default="", help="ISO timestamp for incremental export")

    # --- restore ---
    p_restore = sub.add_parser("restore", help="Restore signatures from binary export")
    p_restore.add_argument("path", help="Path to .bin export file")

    p_dedup = sub.add_parser("dedup", help="Run deduplication scan")
    p_dedup.add_argument("--limit", type=int, default=0, help="Max signatures to scan")
    p_dedup.add_argument("--verbose", "-v", action="store_true")

    sub.add_parser("stats", help="Print database statistics")
    sub.add_parser("health", help="Run database integrity check")

    p_lc = sub.add_parser("lifecycle", help="Lifecycle management")
    p_lc_sub = p_lc.add_subparsers(dest="lc_cmd")
    p_lc_sub.add_parser("run", help="Run lifecycle maintenance (TTL, compression)")
    p_lc_log = p_lc_sub.add_parser("log", help="Show lifecycle transition log")
    p_lc_log.add_argument("--sig-id", type=int, required=True)
    p_lc_trans = p_lc_sub.add_parser("transition", help="Manual stage transition")
    p_lc_trans.add_argument("--sig-id", type=int, required=True)
    p_lc_trans.add_argument("--to-stage", required=True, choices=["raw", "analysis", "report", "archive"])
    p_lc_trans.add_argument("--reason", default="manual")

    args = parser.parse_args()
    setup_logging(args.log_level)

    if args.config:
        from src.config import DataConfig
        import src.config as _cfg
        _cfg._GLOBAL_CONFIG = DataConfig.from_file(args.config)
    elif args.profile:
        from src.config import get_config_by_profile
        get_config_by_profile(args.profile)

    commands = {
        "init": cmd_init,
        "import": cmd_import,
        "search": cmd_search,
        "export": cmd_export,
        "dedup": cmd_dedup,
        "stats": cmd_stats,
        "restore": cmd_restore,
        "health": cmd_health,
        "lifecycle": cmd_lifecycle,
    }

    if args.cmd in commands:
        commands[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
