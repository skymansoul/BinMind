#!/usr/bin/env python3
# LLM 对照消融评测: 对同一批样本分别以规则检测(AI关闭)和规则+LLM辅助(AI开启)
# 两种模式运行 core.pipeline.run_pipeline, 记录检出漏洞数/类型/耗时/simulation标记.
# 样本从 samples/teaching 目录选取前3个, 结果输出到 eval/llm_ablation_result.json.
# pipeline 不可用时如实记录错误, 不伪造数据.

import json
import os
import sys
import time
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

_TEACHING_DIR = _BASE / "samples" / "teaching"
_RESULT_PATH = Path(__file__).resolve().parent / "llm_ablation_result.json"
_MAX_SAMPLES = 3


def _pick_teaching_samples():
    """从 samples/teaching 选取含 .exe 的样本目录, 限 _MAX_SAMPLES 个."""
    if not _TEACHING_DIR.is_dir():
        return []
    out = []
    for entry in sorted(_TEACHING_DIR.iterdir()):
        if not entry.is_dir():
            continue
        exes = list(entry.glob("*.exe"))
        if exes:
            out.append({
                "name": entry.name,
                "binary_path": str(exes[0]),
            })
        if len(out) >= _MAX_SAMPLES:
            break
    return out


def _extract_vuln_types(result):
    """从 pipeline 返回结果提取漏洞类型列表."""
    types = []
    for r in (result.get("decomp_analysis") or []):
        analysis = r.get("analysis", r) if isinstance(r, dict) else {}
        if not isinstance(analysis, dict):
            continue
        for v in analysis.get("vulnerabilities", []):
            if isinstance(v, dict):
                t = v.get("type", v.get("vuln_type", "unknown"))
                types.append(t)
    return types


def _run_one_mode(binary_path, use_ai):
    """单样本单模式执行, 返回结果字典."""
    rec = {
        "mode": "ai_enabled" if use_ai else "rules_only",
        "binary_path": binary_path,
        "vuln_count": 0,
        "vuln_types": [],
        "elapsed_sec": 0.0,
        "simulation": None,
        "error": None,
    }
    try:
        from core.pipeline import run_pipeline
    except Exception as exc:
        rec["error"] = f"import failed: {exc}"
        return rec

    t0 = time.time()
    try:
        result = run_pipeline(
            binary_path,
            ai_analysis=use_ai,
            symbolic=False,
            fuzz=False,
            max_funcs=10,
        )
    except Exception as exc:
        rec["error"] = f"pipeline error: {exc}"
        rec["elapsed_sec"] = round(time.time() - t0, 3)
        return rec

    rec["elapsed_sec"] = round(time.time() - t0, 3)

    if isinstance(result, dict) and result.get("error"):
        rec["error"] = result["error"]
        return rec

    rec["vuln_count"] = result.get("total_vulns", 0) if isinstance(result, dict) else 0
    rec["vuln_types"] = _extract_vuln_types(result if isinstance(result, dict) else {})

    ai_info = result.get("ai_analysis") if isinstance(result, dict) else None
    if isinstance(ai_info, dict):
        rec["simulation"] = ai_info.get("simulation", None)
    else:
        rec["simulation"] = None

    return rec


def main():
    samples = _pick_teaching_samples()
    output = {
        "tool": "eval/llm_ablation.py",
        "description": "LLM 对照消融评测: 规则检测 vs 规则+LLM辅助",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "max_samples": _MAX_SAMPLES,
        "teaching_dir": str(_TEACHING_DIR),
        "sample_count": len(samples),
        "results": [],
    }

    if not samples:
        output["error"] = (
            f"未在 {_TEACHING_DIR} 找到含 .exe 的教学样本目录"
        )
    else:
        for s in samples:
            for use_ai in (False, True):
                rec = _run_one_mode(s["binary_path"], use_ai)
                rec["sample_name"] = s["name"]
                output["results"].append(rec)

    # 汇总两种模式的检出数与耗时, 便于横向对比 LLM 增益
    summary = {}
    for mode_label in ("rules_only", "ai_enabled"):
        recs = [r for r in output["results"] if r["mode"] == mode_label]
        if not recs:
            continue
        total = len(recs)
        ok = [r for r in recs if not r.get("error")]
        summary[mode_label] = {
            "samples_run": total,
            "samples_ok": len(ok),
            "samples_error": total - len(ok),
            "total_vulns": sum(r["vuln_count"] for r in ok),
            "avg_vulns_per_sample": round(
                sum(r["vuln_count"] for r in ok) / len(ok), 2
            ) if ok else 0,
            "total_elapsed_sec": round(
                sum(r["elapsed_sec"] for r in ok), 3
            ),
            "avg_elapsed_sec": round(
                sum(r["elapsed_sec"] for r in ok) / len(ok), 3
            ) if ok else 0,
            "all_simulation": all(
                r.get("simulation") is True for r in ok
            ) if ok else False,
        }
    if summary:
        output["summary"] = summary

    _RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_RESULT_PATH, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print(f"评测结果已写入: {_RESULT_PATH}")
    if output.get("error"):
        print(f"错误: {output['error']}")
    else:
        for r in output["results"]:
            mode_label = "AI" if r["mode"] == "ai_enabled" else "NO-AI"
            err = r.get("error") or ""
            print(
                f"[{mode_label}] {r['sample_name']}: "
                f"{r['vuln_count']} vulns, "
                f"{r['elapsed_sec']}s, sim={r['simulation']} {err}"
            )
        if summary:
            for mode_label, s in summary.items():
                print(
                    f"[SUMMARY-{mode_label}] "
                    f"avg={s['avg_vulns_per_sample']} vulns/sample, "
                    f"avg_time={s['avg_elapsed_sec']}s, "
                    f"sim_all={s['all_simulation']}"
                )


if __name__ == "__main__":
    main()
