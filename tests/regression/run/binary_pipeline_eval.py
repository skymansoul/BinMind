# coding: utf-8
"""真实二进制链路全量评测 — 可复现生成 binary_pipeline_full.json。

口径(2026-09-16 审计确立):
- 检测核心: detectors_binary.run_binary_pipeline_detector (core.pipeline.run_pipeline)
- 样本-类型-标签映射: ground_truth.SAMPLE_ROOTS / CAT_TYPE / GOLD (gold.jsonl)
- 指标口径: tools/audit/compute_metrics (Wilson/Clopper-Pearson/bootstrap/饱和判定)
- 数据缺口: 无 exe / 超时 / pipeline 报错的样本列 data_gaps, 不进指标分母

本脚本与历史临时脚本 .temp/binary_eval_patch.py 等价, 但为正式可复现工具:
  python tests/regression/run/binary_pipeline_eval.py --mode safe   # 只跑 safe 样本(修复验证)
  python tests/regression/run/binary_pipeline_eval.py              # 全量 121+ 样本
  --out 指定输出路径(默认覆盖 deemo/test_reports/binary_pipeline_full.json)
"""

import argparse
import concurrent.futures
import json
import multiprocessing
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]  # deemo
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT.parent / "tools" / "audit"))

from tests.regression.run.detectors_binary import locate_binary, run_binary_pipeline_detector
from tests.regression.run.ground_truth import CAT_TYPE, GOLD, SAMPLE_ROOTS
from compute_metrics import (Confusion, bootstrap_f1_ci, clopper_pearson_ci,
                             is_saturated, prf, wilson_ci)

DEFAULT_TIMEOUT = 150  # 单样本超时, 与 caliber 记录的 per_sample_timeout 一致
OUT_DEFAULT = _ROOT / "test_reports" / "binary_pipeline_full.json"


def build_sample_list() -> list:
    """按 SAMPLE_ROOTS 枚举样本: sample_id(目录名)/type/label/binary 路径.

    只收录 gold.jsonl 有标签的样本; 无 exe 或平台不可编译样本列 data_gaps.
    """
    samples = []
    for root_rel, cat in SAMPLE_ROOTS:
        root = _ROOT / root_rel
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if not entry.is_dir():
                continue
            sid = entry.name
            if sid not in GOLD:
                continue  # 无正式标签, 不进评测
            samples.append({
                "sample_id": sid,
                "type": CAT_TYPE.get(cat, "unknown"),
                "label": int(GOLD[sid]),
                "binary": locate_binary(str(entry)),
            })
    return samples


def _detect_worker(q, binary_path: str):
    """子进程入口: 执行检测并把 (detected, detail) 放入队列.

    Windows spawn 启动会重新 import 本模块, 模块级仅做路径设置与
    轻量数据加载, 不触发 pipeline 重量级初始化.
    """
    try:
        result = run_binary_pipeline_detector(binary_path)
    except Exception as e:  # 子进程内异常也要回传, 否则主进程误判 error
        result = (False, f"worker error: {e}")
    q.put(result)


def run_one(sample: dict, timeout: int) -> dict:
    """执行单个样本的 pipeline 检测, 返回 per_sample 记录.

    进程隔离执行: 线程无法强杀 (早期 ThreadPoolExecutor 方案在
    cve_2023_23001_custom 反编译死循环上卡死全量评测 17 分钟,
    泄漏线程持 GIL 又把后续样本拖慢约 10 倍), 子进程超时可直接
    terminate, 死循环样本被干净回收不影响后续样本.
    """
    t0 = time.time()
    rec = {
        "sample_id": sample["sample_id"],
        "type": sample["type"],
        "binary": sample["binary"],
        "label": sample["label"],
    }
    if not sample["binary"]:
        rec["status"] = "no_binary"
        rec["detail"] = "no exe found (platform not compilable?)"
        rec["elapsed_s"] = round(time.time() - t0, 1)
        return rec
    q = multiprocessing.Queue()
    proc = multiprocessing.Process(target=_detect_worker,
                                   args=(q, sample["binary"]))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(10)
        rec["status"] = "timeout"
        rec["detail"] = f"timeout > {timeout}s (process killed)"
    else:
        try:
            detected, detail = q.get(timeout=15)
            rec["predicted"] = 1 if detected else 0
            rec["detail"] = detail
        except Exception:
            rec["status"] = "error"
            rec["detail"] = f"worker died, exitcode={proc.exitcode}"
    q.close()
    rec["elapsed_s"] = round(time.time() - t0, 1)
    return rec


def _confusion_of(rows: list) -> Confusion:
    c = Confusion()
    for r in rows:
        t, p = r["label"], r.get("predicted")
        if p is None:
            continue
        if t == 1 and p == 1:
            c.tp += 1
        elif t == 0 and p == 1:
            c.fp += 1
        elif t == 1 and p == 0:
            c.fn += 1
        else:
            c.tn += 1
    return c


def by_type_metrics(per_sample: list) -> dict:
    """按类型聚合混淆矩阵与指标, 附带独立口径 FP rate / Specificity."""
    grouped = {}
    for s in per_sample:
        grouped.setdefault(s["type"], []).append(s)
    result = {}
    for vtype, rows in sorted(grouped.items()):
        c = _confusion_of(rows)
        m = prf(c)
        fp_tn = c.fp + c.tn
        result[vtype] = {
            "confusion": {"tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn, "n": c.n},
            "metrics": m,
            "recall_ci_wilson_95": wilson_ci(c.tp, c.tp + c.fn),
            "precision_ci_wilson_95": wilson_ci(c.tp, c.tp + c.fp),
            "fp_rate": (c.fp / fp_tn) if fp_tn else 0.0,
            "specificity": (c.tn / fp_tn) if fp_tn else 0.0,
        }
    return result


def aggregate(per_sample: list, min_n: int, f1_threshold: float) -> dict:
    """全量混淆矩阵 + 指标 + FP 过滤能力独立口径."""
    c = _confusion_of(per_sample)
    m = prf(c)
    y_true = [s["label"] for s in per_sample if s.get("predicted") is not None]
    y_pred = [s["predicted"] for s in per_sample if s.get("predicted") is not None]
    blo, bhi, degen = bootstrap_f1_ci(y_true, y_pred)
    status, reason = is_saturated(c, m["f1"], min_n, f1_threshold)
    err = c.fp + c.fn
    wl, wu = wilson_ci(err, c.n)
    fp_tn = c.fp + c.tn
    fp_rate = (c.fp / fp_tn) if fp_tn else 0.0
    specificity = (c.tn / fp_tn) if fp_tn else 0.0
    if fp_tn > 0:
        claim = (f"F1={m['f1']:.3f} (n={c.n}, TP={c.tp}, FP={c.fp}, FN={c.fn}, TN={c.tn}); "
                 f"错误率 {err}/{c.n} 的 95% Wilson CI [{wl:.3f}, {wu:.3f}]; "
                 f"FP rate={fp_rate:.3f}, Specificity={specificity:.3f}")
    else:
        claim = (f"F1={m['f1']:.3f} (n={c.n}, TP={c.tp}, FP={c.fp}, FN={c.fn}, TN={c.tn}); "
                 f"错误率 {err}/{c.n} 的 95% Wilson CI [{wl:.3f}, {wu:.3f}]")
    return {
        "confusion": {"tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn, "n": c.n},
        "metrics": m,
        "error_rate_ci_95": {
            "wilson": [wl, wu],
            "clopper_pearson": clopper_pearson_ci(err, c.n),
        },
        "recall_ci_wilson_95": wilson_ci(c.tp, c.tp + c.fn),
        "precision_ci_wilson_95": wilson_ci(c.tp, c.tp + c.fp),
        "f1_bootstrap": {"low": blo, "high": bhi, "degenerate": degen},
        "saturation": {"status": status, "reason": reason},
        "fp_rate": fp_rate,
        "specificity": specificity,
        "claim": claim,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="真实二进制链路全量评测(可复现)")
    p.add_argument("--mode", choices=["full", "safe", "sample"],
                   default="full", help="full=全量 / safe=仅 safe 样本 / sample=指定样本")
    p.add_argument("--ids", nargs="*", default=[], help="sample 模式下指定的样本 id 列表")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单样本超时秒数")
    p.add_argument("--min-n", type=int, default=100, help="饱和判定最小样本量")
    p.add_argument("--f1-threshold", type=float, default=0.95, help="饱和判定 F1 门槛")
    p.add_argument("--out", default=str(OUT_DEFAULT), help="输出 JSON 路径")
    p.add_argument("--workers", type=int, default=1,
                   help="并行 worker 数(默认 1; 并行不改变指标)")
    args = p.parse_args(argv)

    samples = build_sample_list()
    if args.mode == "safe":
        samples = [s for s in samples if s["label"] == 0]
    elif args.mode == "sample":
        wanted = set(args.ids)
        samples = [s for s in samples if s["sample_id"] in wanted]
    if not samples:
        print("未匹配到任何样本, 退出", file=sys.stderr)
        return 2

    print(f"评测样本数: {len(samples)} (mode={args.mode})")
    results = []
    if args.workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(run_one, s, args.timeout): s["sample_id"] for s in samples}
            for fut in concurrent.futures.as_completed(futs):
                rec = fut.result()
                results.append(rec)
                print(f"  [{rec['sample_id']}] predicted={rec.get('predicted')} "
                      f"{rec.get('detail', '')} {rec.get('elapsed_s', 0):.1f}s")
    else:
        for s in samples:
            rec = run_one(s, args.timeout)
            results.append(rec)
            print(f"  [{rec['sample_id']}] label={rec['label']} "
                  f"predicted={rec.get('predicted')} {rec.get('detail', '')} "
                  f"{rec.get('elapsed_s', 0):.1f}s", flush=True)
    results.sort(key=lambda r: r["sample_id"])

    evaluated = [r for r in results if r.get("predicted") is not None]
    gaps = [r for r in results if r.get("predicted") is None]

    report = {
        "benchmark": "binary_pipeline_full",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "caliber": {
            "detector": "binary pipeline (core.pipeline.run_pipeline)",
            "run_config": (f"max_funcs=8, ai_analysis=False, symbolic=False, fuzz=False, "
                           f"r2=auto, per_sample_timeout={args.timeout}s"),
            "labels": "deemo/labels/gold.jsonl (legacy 手写标签迁移; 可信度见 labels/gold_audit.md)",
            "eligible": f"{len(evaluated)} 正常完成; "
                        f"{sum(1 for r in gaps if r.get('status') == 'timeout')} 超时; "
                        f"{sum(1 for r in gaps if r.get('status') in ('no_binary', 'error'))} "
                        f"缺口(POSIX 不可编译或错误)",
        },
        "aggregate": aggregate(evaluated, args.min_n, args.f1_threshold),
        "by_type": by_type_metrics(evaluated),
        "per_sample": results,
        "data_gaps": [{"sample_id": g["sample_id"], "type": g["type"],
                       "status": g.get("status", "no_prediction"),
                       "detail": g.get("detail", "")} for g in gaps],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n指标汇总: {report['aggregate']['claim']}")
    print(f"FP rate={report['aggregate']['fp_rate']:.4f} "
          f"Specificity={report['aggregate']['specificity']:.4f}")
    print(f"已写入: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())