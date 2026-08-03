#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BinMind Data 模块 — CLI 入口。

用法:
    python main.py init                     # 初始化数据库
    python main.py import <path> [--stage raw]  # 导入文件/目录
    python main.py search <query>           # FTS 全文检索
    python main.py export [--fmt json] [--stage raw] [--out results.json]
    python main.py dedup                    # 执行去重扫描
    python main.py stats                    # 数据库统计摘要
    python main.py health                   # 完整性校验
    python main.py lifecycle run            # 生命周期维护作业
    python main.py lifecycle log <sig_id>   # 查询签名生命周期日志
"""

import argparse
import json
import os
import sys
import time
import logging

# 将 src/ 注入 sys.path
_BASE = os.path.dirname(os.path.abspath(__file__))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from src.config import get_config, reset_config
from src.db import get_db

_log = logging.getLogger("data.cli")

# tqdm 可选依赖：存在则渲染进度条，缺失则静默降级
try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False


def _progress(iterable, desc="", total=None, disable=False):
    """可选进度条包装器：tqdm 可用时启用，否则原样透传迭代器。"""
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
    """JSON 序列化输出并退出 — 面向脚本化调用链路。"""
    print(json.dumps(data, ensure_ascii=False, default=str))
    sys.exit(exit_code)


def cmd_init(args):
    """初始化数据库 schema。"""
    db = get_db()
    stats = db.db_stats()
    if args.json_output:
        _emit_json({"status": "ok", **stats})
    print(f"DB initialized: {stats['total_signatures']} signatures, "
          f"{stats['total_chunks']} chunks")
    print("Stages:", stats.get("by_stage", {}))
    db.close()


def cmd_import(args):
    """将文件批量导入签名数据库。"""
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
    """预演模式：遍历文件系统计算规模，不写入数据库。"""
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
    """批处理辅助：逐文件计算 SHA-256 后批量写入。"""
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
    """FTS5 全文检索签名。"""
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
    """导出签名到外部格式。"""
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
    """执行去重扫描：Bloom 预过滤 + 哈希比对。"""
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
    """打印数据库统计指标。"""
    db = get_db()
    stats = db.db_stats()
    if args.json_output:
        _emit_json({"status": "ok", **stats})
    print(json.dumps(stats, indent=2, default=str))
    db.close()


def cmd_restore(args):
    """从二进制导出文件还原签名记录。"""
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
    """数据库完整性诊断。"""
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
    """生命周期管理子命令分发。"""
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


# ---------------------------------------------------------------------------
# 2025 扩展命令处理
# ---------------------------------------------------------------------------

def cmd_delta(args):
    from src.delta import delta_encode, delta_decode, delta_stats
    if args.delta_cmd == "encode":
        with open(args.old_file, "rb") as f:
            old = f.read()
        with open(args.new_file, "rb") as f:
            new = f.read()
        patch = delta_encode(old, new)
        with open(args.out, "wb") as f:
            f.write(patch)
        print(f"Patch written: {len(patch)} bytes -> {args.out}")
        if args.json_output:
            _emit_json({"status": "ok", "patch_size": len(patch),
                        "old_size": len(old), "new_size": len(new)})
    elif args.delta_cmd == "decode":
        with open(args.old_file, "rb") as f:
            old = f.read()
        with open(args.patch_file, "rb") as f:
            patch = f.read()
        new = delta_decode(old, patch)
        with open(args.out, "wb") as f:
            f.write(new)
        print(f"Restored: {len(new)} bytes -> {args.out}")
    elif args.delta_cmd == "stats":
        with open(args.files[0], "rb") as f:
            old = f.read()
        with open(args.files[1], "rb") as f:
            new = f.read()
        s = delta_stats(old, new)
        if args.json_output:
            _emit_json({"status": "ok", **s})
        for k, v in s.items():
            print(f"  {k}: {v}")


def cmd_provenance(args):
    db = get_db()
    from src.provenance import ProvenanceTracker
    tracker = ProvenanceTracker(db)
    if args.prov_cmd == "chain":
        g = tracker.get_chain(args.sig_id)
        if args.json_output:
            _emit_json({"status": "ok", "nodes": g.node_count, "edges": g.edge_count,
                        "prov_json": g.to_prov_json()})
        for n in g._nodes.values():
            print(f"  [{n.node_type}] {n.node_id}: {n.name}")
    elif args.prov_cmd == "recent":
        acts = tracker.recent_activities()
        for a in acts:
            print(f"  {a['node_id']}: {a['name']}")
    elif args.prov_cmd == "export":
        g = tracker.export_graph(args.sig_ids if hasattr(args, 'sig_ids') else None)
        with open(args.out, "w") as f:
            import json
            json.dump(g.to_prov_json(), f, indent=2, default=str)
        print(f"Provenance graph exported: {args.out}")
    db.close()


def cmd_cold_storage(args):
    db = get_db()
    from src.cold_storage import TierManager, StoragePolicy
    tm = TierManager(db)
    if args.cs_cmd == "classify":
        dist = tm.classify()
        if args.json_output:
            _emit_json({"status": "ok", "distribution": dist})
        for tier, info in dist.items():
            print(f"  {tier}: {info['count']} sigs, ~{info['est_bytes']/1024:.0f} KB")
    elif args.cs_cmd == "demote":
        r = tm.demote(dry_run=args.dry_run)
        if args.json_output:
            _emit_json({"status": "ok", **r})
        for k, v in r.items():
            print(f"  {k}: {v}")
    elif args.cs_cmd == "rebalance":
        cnt = tm.rebalance(args.tier, dry_run=args.dry_run)
        print(f"Rebalanced tier '{args.tier}': {cnt} sigs")
    elif args.cs_cmd == "cost":
        est = tm.cost_estimate()
        if args.json_output:
            _emit_json({"status": "ok", **est})
        print(f"Total: {est['total_gb']} GB, ${est['total_cost_monthly']}/mo")
    db.close()


def cmd_vector_search(args):
    db = get_db()
    from src.vector_search import VectorIndex
    vx = VectorIndex()
    if args.vs_cmd == "build":
        vx.build_from_db(db)
        st = vx.stats()
        if args.json_output:
            _emit_json({"status": "ok", **st})
        print(f"Index built: {st['total_vectors']} vectors, dim={st['dim']}")
    elif args.vs_cmd == "query":
        vx.build_from_db(db)
        results = vx.find_similar_to(args.sig_id, k=args.k)
        sig = db.get_signature_by_id(args.sig_id)
        print(f"Similar to sig#{args.sig_id} ({sig.get('file_path','?') if sig else '?'}):")
        for sid, sim in results:
            s = db.get_signature_by_id(sid)
            fp = s.get("file_path", "?") if s else "?"
            print(f"  sig#{sid} ({fp[:60]}): {sim:.4f}")
    db.close()


def cmd_signature_miner(args):
    db = get_db()
    from src.signature_miner import IOCExtractor, SignaturePatternMiner
    if args.sm_cmd == "ioc":
        extractor = IOCExtractor()
        analyses = db.get_analyses(args.sig_id)
        from src.gnn_scorer import _flatten_findings
        findings = _flatten_findings(analyses)
        iocs = extractor.extract_from_findings(findings, sig_id=args.sig_id)
        if args.fmt == "yara":
            rule = extractor.to_yara_rule(f"sig_{args.sig_id}_rule")
            if args.out:
                with open(args.out, "w") as f:
                    f.write(rule)
                print(f"YARA rule -> {args.out}")
            else:
                print(rule)
        elif args.fmt == "stix":
            bundle = extractor.to_stix_bundle()
            if args.out:
                import json as _json
                with open(args.out, "w") as f:
                    _json.dump(bundle, f, indent=2)
            else:
                import json as _json
                print(_json.dumps(bundle, indent=2, default=str))
        else:
            if args.json_output:
                _emit_json({"status": "ok", "iocs": len(iocs), "items": iocs})
            for ioc in iocs:
                print(f"  [{ioc['type']}] {ioc['value'][:80]} ({ioc['confidence']:.0%})")
    elif args.sm_cmd == "patterns":
        miner = SignaturePatternMiner(min_support=args.min_support)
        analyses = db.get_analyses(args.sig_id)
        from src.gnn_scorer import _flatten_findings
        findings = _flatten_findings(analyses)
        patterns = miner.mine_from_findings(findings, sig_id=args.sig_id)
        freq = miner.frequent_api_patterns(top_k=10)
        for seq, cnt in freq:
            print(f"  [support={cnt}] {' -> '.join(seq)}")
    db.close()


def cmd_dataset(args):
    db = get_db()
    from src.dataset_builder import DatasetBuild, DatasetSplit, ContaminationCheck, LabelAnnotator
    if args.ds_cmd == "create":
        ds = DatasetBuild(args.name, db)
        print(f"Dataset '{args.name}' created")
    elif args.ds_cmd == "import":
        ds = DatasetBuild(args.name, db)
        n = ds.add_from_query(stage=args.stage)
        print(f"Added {n} signatures to '{args.name}'")
    elif args.ds_cmd == "stats":
        ds = DatasetBuild(args.name, db)
        s = ds.stats()
        if args.json_output:
            _emit_json({"status": "ok", **s})
        for k, v in s.items():
            print(f"  {k}: {v}")
    elif args.ds_cmd == "snapshot":
        ds = DatasetBuild(args.name, db)
        snap = ds.snapshot()
        print(f"Snapshot '{snap['snapshot']}': {snap['sig_count']} sigs")
    elif args.ds_cmd == "split":
        ds = DatasetBuild(args.name, db)
        ds.add_from_query(limit=10000)
        splits = DatasetSplit.random_split(ds)
        for k, v in splits.items():
            print(f"  {k}: {len(v)} sigs")
    elif args.ds_cmd == "check-contam":
        ds_a = DatasetBuild(args.dataset_a, db)
        ds_b = DatasetBuild(args.dataset_b, db)
        checker = ContaminationCheck(db)
        report = checker.full_report(ds_a._sig_ids, ds_b._sig_ids)
        print(f"Verdict: {report['verdict']}")
        print(f"  Exact overlap: {report['exact']['overlap_count']}")
        print(f"  Near-dups: {report['near_duplicate']['near_duplicate_pairs']}")
    elif args.ds_cmd == "auto-label":
        ds = DatasetBuild(args.name, db)
        annotator = LabelAnnotator()
        n = annotator.annotate_batch(ds, db, limit=500)
        print(f"Auto-labeled {n} signatures in '{args.name}'")
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

    # --- delta diff ---
    p_delta = sub.add_parser("delta", help="Binary delta encoding between two files")
    p_delta_sub = p_delta.add_subparsers(dest="delta_cmd")
    p_delta_enc = p_delta_sub.add_parser("encode", help="Generate patch old -> new")
    p_delta_enc.add_argument("old_file", help="Old (reference) file")
    p_delta_enc.add_argument("new_file", help="New (target) file")
    p_delta_enc.add_argument("--out", "-o", default="patch.bin", help="Patch output path")
    p_delta_dec = p_delta_sub.add_parser("decode", help="Apply patch to old -> new")
    p_delta_dec.add_argument("old_file", help="Old file")
    p_delta_dec.add_argument("patch_file", help="Patch file (.bin)")
    p_delta_dec.add_argument("--out", "-o", default="restored.bin", help="Output file")
    p_delta_stats_sub = p_delta_sub.add_parser("stats", help="Estimate delta size between two files")
    p_delta_stats_sub.add_argument("files", nargs=2, help="old_file new_file")

    # --- provenance ---
    p_prov = sub.add_parser("provenance", help="Provenance chain tracking")
    p_prov_sub = p_prov.add_subparsers(dest="prov_cmd")
    p_prov_chain = p_prov_sub.add_parser("chain", help="Show provenance chain for sig_id")
    p_prov_chain.add_argument("--sig-id", type=int, required=True)
    p_prov_sub.add_parser("recent", help="Recent provenance activities")
    p_prov_exp = p_prov_sub.add_parser("export", help="Export provenance graph as PROV-JSON")
    p_prov_exp.add_argument("--out", "-o", default="prov.json")
    p_prov_exp.add_argument("--sig-ids", nargs="*", type=int)

    # --- cold-storage ---
    p_cs = sub.add_parser("cold-storage", help="Cold storage tier management")
    p_cs_sub = p_cs.add_subparsers(dest="cs_cmd")
    p_cs_sub.add_parser("classify", help="Classify data by temperature tier")
    p_cs_sub.add_parser("demote", help="Demote expired data to colder tiers")
    p_cs_sub.add_parser("cost", help="Estimate storage cost by tier")
    p_cs_rb = p_cs_sub.add_parser("rebalance", help="Rebalance compression in a tier")
    p_cs_rb.add_argument("--tier", default="cold", choices=["hot","warm","cold","frozen"])

    # --- vector-search ---
    p_vs = sub.add_parser("vector-search", help="Vector similarity search")
    p_vs_sub = p_vs.add_subparsers(dest="vs_cmd")
    p_vs_build = p_vs_sub.add_parser("build", help="Build LSH index from DB")
    p_vs_build.add_argument("--dim", type=int, default=32)
    p_vs_query = p_vs_sub.add_parser("query", help="Find similar sigs by id")
    p_vs_query.add_argument("--sig-id", type=int, required=True)
    p_vs_query.add_argument("--k", type=int, default=10)

    # --- signature-miner ---
    p_sm = sub.add_parser("signature-miner", help="IOC & detect-pattern extraction")
    p_sm_sub = p_sm.add_subparsers(dest="sm_cmd")
    p_sm_ioc = p_sm_sub.add_parser("ioc", help="Extract IOCs from analysis findings")
    p_sm_ioc.add_argument("--sig-id", type=int, required=True)
    p_sm_ioc.add_argument("--out", "-o", default="", help="Output path (YARA/STIX)")
    p_sm_ioc.add_argument("--fmt", default="yara", choices=["yara", "stix", "json"])
    p_sm_pat = p_sm_sub.add_parser("patterns", help="Mine detection patterns")
    p_sm_pat.add_argument("--sig-id", type=int, required=True)
    p_sm_pat.add_argument("--min-support", type=int, default=3)

    # --- dataset-builder ---
    p_ds = sub.add_parser("dataset", help="Dataset building and management")
    p_ds_sub = p_ds.add_subparsers(dest="ds_cmd")
    p_ds_create = p_ds_sub.add_parser("create", help="Create a new dataset")
    p_ds_create.add_argument("name", help="Dataset name")
    p_ds_import = p_ds_sub.add_parser("import", help="Import sigs into dataset")
    p_ds_import.add_argument("name", help="Dataset name")
    p_ds_import.add_argument("--stage", default="", help="Filter by stage")
    p_ds_sub.add_parser("stats", help="Show dataset statistics").add_argument("name")
    p_ds_snap = p_ds_sub.add_parser("snapshot", help="Create dataset snapshot")
    p_ds_snap.add_argument("name", help="Dataset name")
    p_ds_split = p_ds_sub.add_parser("split", help="Split dataset into train/val/test")
    p_ds_split.add_argument("name", help="Dataset name")
    p_ds_contam = p_ds_sub.add_parser("check-contam", help="Check contamination between two datasets")
    p_ds_contam.add_argument("dataset_a", help="First dataset name")
    p_ds_contam.add_argument("dataset_b", help="Second dataset name")
    p_ds_label = p_ds_sub.add_parser("auto-label", help="Auto-label unlabeled sigs via rules")
    p_ds_label.add_argument("name", help="Dataset name")

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
        "delta": cmd_delta,
        "provenance": cmd_provenance,
        "cold-storage": cmd_cold_storage,
        "vector-search": cmd_vector_search,
        "signature-miner": cmd_signature_miner,
        "dataset": cmd_dataset,
    }

    if args.cmd in commands:
        commands[args.cmd](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
