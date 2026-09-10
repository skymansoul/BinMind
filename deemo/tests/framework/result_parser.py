"""
结果解析模块 — 从扫描 JSON 输出中统计检出率、误报率、漏报率。

输入: JSON 格式的扫描结果（scan_scheduler 产出）。
输出: 按漏洞类型分组的统计摘要和 CSV 表格。

误报/漏报计算需要 ground truth —— 从 CVE 样本目录中的
vuln.c 注释提取预期的漏洞标签（CWE 或类型名）。
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List


CVE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cve_samples",
)


@dataclass
class SampleGroundTruth:
    sample_name: str
    cve_id: str
    vuln_type: str           # 'stack-overflow' | 'format-string' | 'heap-corruption' | 'command-injection'
    cwe: str = ""


@dataclass
class EvalResult:
    sample_name: str
    vuln_type: str
    detected: bool
    true_positive: bool
    false_positive: bool
    false_negative: bool
    extra_findings: int = 0


def load_ground_truth() -> List[SampleGroundTruth]:
    """从 CVE 样本源码注释中提取 expected vulnerabilities。"""
    truths: List[SampleGroundTruth] = []
    if not os.path.isdir(CVE_DIR):
        return truths

    for sample_dir in sorted(os.listdir(CVE_DIR)):
        sample_path = os.path.join(CVE_DIR, sample_dir)
        if not os.path.isdir(sample_path):
            continue

        vuln_c = os.path.join(sample_path, "vuln.c")
        if not os.path.isfile(vuln_c):
            continue

        with open(vuln_c, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        cve_id = sample_dir.replace("cve_", "CVE-").replace("_", "-")
        # 从注释提取漏洞类型
        vuln_type = "unknown"
        for line in source.split("\n")[:10]:
            lower = line.lower()
            if "类型:" in line or "type:" in lower:
                if "堆" in line or "heap" in lower:
                    vuln_type = "heap-corruption"
                elif "栈" in line or "stack" in lower:
                    vuln_type = "stack-overflow"
                elif "格式" in line or "format" in lower:
                    vuln_type = "format-string"
                elif "命令" in line or "command" in lower:
                    vuln_type = "command-injection"
                elif "double-free" in lower:
                    vuln_type = "heap-corruption"
                elif "uaf" in lower:
                    vuln_type = "heap-corruption"

        truths.append(SampleGroundTruth(
            sample_name=sample_dir,
            cve_id=cve_id, vuln_type=vuln_type,
            cwe="CWE-" + ("120" if vuln_type == "stack-overflow"
                          else "134" if vuln_type == "format-string"
                          else "416" if vuln_type == "heap-corruption"
                          else "78"),  # command injection
        ))
    return truths


def evaluate(scan_results_path: str) -> Dict[str, Any]:
    """从扫描结果 JSON 计算检出率/误报率/漏报率。

    返回字典: {vuln_type: {tp, fp, fn, detection_rate, false_positive_rate}}
    """
    with open(scan_results_path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    truths = load_ground_truth()
    truth_map: Dict[str, SampleGroundTruth] = {t.sample_name: t for t in truths}

    # 按漏洞类型统计
    stats: Dict[str, Dict[str, int]] = {}
    for t in truths:
        stats.setdefault(t.vuln_type, {"tp": 0, "fp": 0, "fn": 0, "total": 0})
        stats[t.vuln_type]["total"] += 1

    for entry in scan_data:
        name = entry.get("sample_name", "")
        findings = entry.get("findings_count", 0)
        truth = truth_map.get(name)
        if truth is None:
            continue

        detected = findings > 0
        if detected:
            stats[truth.vuln_type]["tp"] += 1
        else:
            stats[truth.vuln_type]["fn"] += 1
        # FP: extra findings beyond expected = max(0, findings - 1) per sample
        if findings > 1:
            stats[truth.vuln_type]["fp"] += (findings - 1)

    result = {}
    for vtype, s in stats.items():
        tp, fp, fn, total = s["tp"], s["fp"], s["fn"], s["total"]
        detection_rate = tp / total if total > 0 else 0.0
        fp_rate = fp / (fp + tp) if (fp + tp) > 0 else 0.0
        result[vtype] = {
            "tp": tp, "fp": fp, "fn": fn, "total_samples": total,
            "detection_rate": round(detection_rate, 3),
            "false_positive_rate": round(fp_rate, 3),
        }

    return result


def to_csv(eval_result: Dict[str, Any], output_path: str) -> None:
    """将评估结果输出为 CSV 文件。"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("vuln_type,samples,TP,FP,FN,detection_rate,FPR\n")
        for vtype, s in eval_result.items():
            f.write(f"{vtype},{s['total_samples']},{s['tp']},{s['fp']},"
                    f"{s['fn']},{s['detection_rate']},{s['false_positive_rate']}\n")


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/scan_results.json"
    if os.path.isfile(path):
        result = evaluate(path)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        to_csv(result, path.replace(".json", ".csv"))
        print(f"CSV saved to: {path.replace('.json', '.csv')}")
    else:
        print(f"No scan results found at {path}")
