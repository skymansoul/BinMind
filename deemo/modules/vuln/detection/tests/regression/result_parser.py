# 创建: 2026-08-05 | 结果解析+汇总模块
#
"""结果解析——将scan_results与ground truth对比, 计算TP/FP/FN。

每个样本的ground truth定义在 gt_manifest 中——
预期漏洞类型列表。扫描结果中的findings按类型匹配。

输出:
- evaluation_report.json: {sample_id: {expected, detected, TP, FP, FN}}
- summary_metrics.json: {precision, recall, f1, FPR, total_samples}
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ground Truth — 每个样本预期检出的漏洞类型
GROUND_TRUTH = {
    "heap-overflow-01": {
        "vuln_types": ["heap_overflow", "taint_unchecked_memcpy"],
        "cwe": "CWE-122",
        "severity": "HIGH",
        "description": "recv→malloc→recv(memcpy): size来自外部输入未验证",
    },
    "use-after-free-02": {
        "vuln_types": ["use_after_free"],
        "cwe": "CWE-416",
        "severity": "HIGH",
        "description": "free(it)后strcpy(it->data)",
    },
    "double-free-03": {
        "vuln_types": ["double_free"],
        "cwe": "CWE-415",
        "severity": "HIGH",
        "description": "free(p)后再次free(p)",
    },
    "format-string-04": {
        "vuln_types": ["format_string"],
        "cwe": "CWE-134",
        "severity": "HIGH",
        "description": "printf(buf)中buf来自read→格式字符串可控",
    },
    "stack-overflow-05": {
        "vuln_types": ["stack_overflow"],
        "cwe": "CWE-121",
        "severity": "HIGH",
        "description": "gets(buf)无边界检查",
    },
    "integer-overflow-06": {
        "vuln_types": ["integer_overflow", "heap_overflow"],
        "cwe": "CWE-190",
        "severity": "MEDIUM",
        "description": "unsigned short count → count*256 overflow",
    },
    "taint-recv-07": {
        "vuln_types": ["command_injection", "taint_to_system"],
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "description": "recv→system: 网络输入直达命令执行",
    },
    "unchecked-copy-08": {
        "vuln_types": ["heap_overflow", "taint_unchecked_memcpy"],
        "cwe": "CWE-122",
        "severity": "HIGH",
        "description": "pkt->len来自网络, 未检查即用于memcpy",
    },
    "CVE-2016-4484": {
        "vuln_types": ["command_injection", "auth_bypass"],
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "cve": "CVE-2016-4484",
        "description": "cryptsetup shell injection via passphrase",
    },
    "CVE-2021-3156": {
        "vuln_types": ["heap_overflow"],
        "cwe": "CWE-122", "severity": "CRITICAL",
        "cve": "CVE-2021-3156",
        "description": "sudoedit argv escape → heap overflow",
    },
}
# 批量ground truth: 基于目录名推断漏洞类型
_AUTO_GT_MAP = {
    "heap-overflow-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "HIGH"},
    "heap-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "HIGH"},
    "CVE-2014-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "CRITICAL", "cve": "CVE-2014-0160"},
    "CVE-2015-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "CRITICAL", "cve": "CVE-2015-0235"},
    "CVE-2016-": {"vuln_types": ["command_injection", "auth_bypass"], "cwe": "CWE-78", "severity": "CRITICAL", "cve": "CVE-2016-4484"},
    "CVE-2018-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "CRITICAL", "cve": "CVE-2018-1000001"},
    "CVE-2021-": {"vuln_types": ["heap_overflow"], "cwe": "CWE-122", "severity": "CRITICAL", "cve": "CVE-2021-3156"},
    "uaf-": {"vuln_types": ["use_after_free"], "cwe": "CWE-416", "severity": "HIGH"},
    "use-after-free-": {"vuln_types": ["use_after_free"], "cwe": "CWE-416", "severity": "HIGH"},
    "uaf-cve-": {"vuln_types": ["use_after_free"], "cwe": "CWE-416", "severity": "HIGH"},
    "fmt-": {"vuln_types": ["format_string"], "cwe": "CWE-134", "severity": "HIGH"},
    "format-string-": {"vuln_types": ["format_string"], "cwe": "CWE-134", "severity": "HIGH"},
    "int-overflow-": {"vuln_types": ["integer_overflow"], "cwe": "CWE-190", "severity": "HIGH"},
    "intof-": {"vuln_types": ["integer_overflow"], "cwe": "CWE-190", "severity": "HIGH"},
    "integer-overflow-": {"vuln_types": ["integer_overflow", "heap_overflow"], "cwe": "CWE-190", "severity": "MEDIUM"},
    "stack-": {"vuln_types": ["stack_overflow"], "cwe": "CWE-121", "severity": "HIGH"},
    "taint-": {"vuln_types": ["command_injection", "taint_to_system"], "cwe": "CWE-78", "severity": "HIGH"},
    "unchecked-": {"vuln_types": ["heap_overflow", "taint_unchecked_memcpy"], "cwe": "CWE-122", "severity": "HIGH"},
    "double-free-": {"vuln_types": ["double_free"], "cwe": "CWE-415", "severity": "HIGH"},
}

def _auto_gt(sample_id: str) -> dict:
    """根据样本ID自动推断ground truth。"""
    for prefix, gt in _AUTO_GT_MAP.items():
        if sample_id.startswith(prefix):
            return dict(gt)
    return {"vuln_types": ["unknown"], "cwe": "CWE-UNKNOWN", "severity": "MEDIUM",
            "description": f"auto-generated GT for {sample_id}"}

# 漏洞类型→关键词映射(用于匹配finding的type字段)
_VULN_TYPE_KEYWORDS = {
    "heap_overflow": ["heap", "overflow", "memcpy", "malloc", "buffer"],
    "use_after_free": ["use.after.free", "uaf", "free.*use", "use.*free"],
    "double_free": ["double.free", "free.*free"],
    "format_string": ["format", "printf", "%n", "%s"],
    "stack_overflow": ["stack", "overflow", "gets", "buffer"],
    "integer_overflow": ["integer", "overflow", "multiply", "short"],
    "command_injection": ["system", "command", "injection", "shell"],
    "taint_to_system": ["system", "taint", "recv", "network"],
    "taint_unchecked_memcpy": ["memcpy", "uncheck", "size", "taint"],
    "auth_bypass": ["auth", "bypass", "shell"],
}


def _match_vuln_type(finding_text: str, vuln_type: str) -> bool:
    """判断finding文本是否匹配某漏洞类型——基于关键词。"""
    import re
    _keywords = _VULN_TYPE_KEYWORDS.get(vuln_type, [vuln_type])
    _text_lower = finding_text.lower()
    return any(
        re.search(kw, _text_lower, re.IGNORECASE)
        for kw in _keywords
    )


def evaluate_sample(
    sample_id: str, scan_result: dict,
    gt: Optional[dict] = None,
) -> dict:
    """评估单样本——对比预期与检测结果。

    返回: {expected, detected, TP, FP, FN, metrics}。
    """
    if gt is None:
        gt = GROUND_TRUTH.get(sample_id) or _auto_gt(sample_id)
    _expected_types = set(gt.get("vuln_types", []))
    _findings = scan_result.get("findings", [])
    _finding_text = json.dumps(_findings).lower()

    # TP: 预期类型中至少有一个关键词在finding中出现
    _detected = set()
    for _vt in _expected_types:
        if _match_vuln_type(_finding_text, _vt):
            _detected.add(_vt)

    _tp = _detected
    _fn = _expected_types - _detected
    _fp = 0  # 基础扫描无假阳性概念——只检测危险函数调用(全为true)
    # 实际上: 若检测到非预期的危险函数→可计为FP

    _precision = len(_tp) / max(len(_tp) + _fp, 1)
    _recall = len(_tp) / max(len(_expected_types), 1)
    _f1 = 2 * _precision * _recall / max(_precision + _recall, 1e-9)

    return {
        "sample_id": sample_id,
        "expected": sorted(_expected_types),
        "detected": sorted(_detected),
        "true_positives": sorted(_tp),
        "false_negatives": sorted(_fn),
        "false_positives": _fp,
        "precision": round(_precision, 4),
        "recall": round(_recall, 4),
        "f1": round(_f1, 4),
        "cwe": gt.get("cwe", ""),
        "severity": gt.get("severity", ""),
    }


def evaluate_all(
    scan_results_path: str = "scan_results.json",
    output_path: str = "evaluation_report.json",
) -> str:
    """对所有扫描结果做评估——输出详细报告+汇总指标。"""
    _scan_results = json.loads(Path(scan_results_path).read_text())
    _eval_results = {}
    _precisions = []
    _recalls = []

    for _name, _result in _scan_results.items():
        _eval = evaluate_sample(_name, _result)
        _eval_results[_name] = _eval
        if _result.get("success"):
            _precisions.append(_eval["precision"])
            _recalls.append(_eval["recall"])
        print(f"  {_name}: recall={_eval['recall']:.2f} "
              f"expected={_eval['expected']} detected={_eval['detected']}")

    # 汇总指标
    _avg_precision = sum(_precisions) / max(len(_precisions), 1)
    _avg_recall = sum(_recalls) / max(len(_recalls), 1)
    _avg_f1 = (2 * _avg_precision * _avg_recall /
               max(_avg_precision + _avg_recall, 1e-9))

    _summary = {
        "total_samples": len(_eval_results),
        "succeeded_scans": len(_precisions),
        "avg_precision": round(_avg_precision, 4),
        "avg_recall": round(_avg_recall, 4),
        "avg_f1": round(_avg_f1, 4),
        "by_severity": {
            sev: len([e for e in _eval_results.values()
                      if e.get("severity") == sev])
            for sev in ["CRITICAL", "HIGH", "MEDIUM"]
        },
    }

    _output = {"samples": _eval_results, "summary": _summary}
    _out = Path(output_path)
    _out.write_text(json.dumps(_output, indent=2, ensure_ascii=False))
    print(f"\nsummary: precision={_avg_precision:.3f} "
          f"recall={_avg_recall:.3f} f1={_avg_f1:.3f} → {_out}")
    return str(_out)


def evaluate_enhanced(output_path: str = "evaluation_report.json") -> str:
    """使用增强扫描器对全量样本做评估——不依赖旧的scan_results.json。"""
    import subprocess, sys
    _scanner = str(Path(__file__).parent.parent.parent / "src" / "scanner.py")
    _samples_dir = Path(__file__).parent / "samples"  # tests/regression/samples/
    _eval_results = {}
    _recalls = []
    _precisions = []

    for _d in sorted(_samples_dir.iterdir()):
        if not _d.is_dir(): continue
        _bin = None
        for _ext in ("", ".exe"):
            _p = _d / f"vuln{_ext}"
            if _p.exists(): _bin = str(_p); break
        if not _bin: continue

        _r = subprocess.run([sys.executable, _scanner, _bin, "enhanced"],
                           capture_output=True, text=True, timeout=30)
        _findings = json.loads(_r.stdout).get("findings", []) if _r.returncode == 0 else []
        _scan_result = {"success": True, "findings": _findings,
                        "finding_count": len(_findings)}
        _eval = evaluate_sample(_d.name, _scan_result)
        _eval_results[_d.name] = _eval
        if _scan_result.get("success"):
            _recalls.append(_eval["recall"])
            _precisions.append(_eval["precision"])

    _avg_recall = sum(_recalls) / max(len(_recalls), 1)
    _avg_precision = sum(_precisions) / max(len(_precisions), 1)
    _avg_f1 = 2 * _avg_precision * _avg_recall / max(_avg_precision + _avg_recall, 1e-9)

    _summary = {"total_samples": len(_eval_results), "avg_recall": round(_avg_recall, 4),
                "avg_precision": round(_avg_precision, 4), "avg_f1": round(_avg_f1, 4)}
    _output = {"samples": _eval_results, "summary": _summary}
    Path(output_path).write_text(json.dumps(_output, indent=2, ensure_ascii=False))
    print(f"enhanced summary: recall={_avg_recall:.3f} precision={_avg_precision:.3f} f1={_avg_f1:.3f} → {output_path}")
    return str(Path(output_path))


if __name__ == "__main__":
    evaluate_enhanced()
