"""
堆溢出回归测试扫描调度模块 — 对编译后的样本运行检测器并收集原始结果.

职责单一: 调用各检测器, 输出原始检测数据, 不做结果判定.
"""

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def read_c_source(source_path: str) -> str:
    """读取C源码文本."""
    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def extract_ground_truth(source_path: str) -> Dict[str, Any]:
    """从源码注释中提取ground truth标签.

    支持的注释标记 (按优先级):
      // VULN: heap_overflow — 标记为真阳性
      // SAFE: guarded — 标记为真阴性
      // CVE: CVE-XXXX-XXXX — CVE编号
      // EXPECTED: overflow at offset X — 期望检出
      Also handles block comments:
        /* heap_overflow_01: ... TRUE POSITIVE ... */
        /* heap_safe_01: ... FALSE POSITIVE ... */
    """
    truth = {
        "is_vulnerable": False,
        "vuln_type": "",
        "expected_offset": -1,
        "description": "",
        "cve_ref": "",
    }

    try:
        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return truth

    # 检查块注释中是否有漏洞/安全标记
    # TRUE POSITIVE / FALSE POSITIVE 在块注释中
    if "TRUE POSITIVE" in content:
        truth["is_vulnerable"] = True
    if "FALSE POSITIVE" in content:
        truth["is_vulnerable"] = False

    # 提取第一个块注释作为描述
    block_match = re.search(r'/\*\s*(.+?)\s*\*/', content, re.DOTALL)
    if block_match:
        truth["description"] = block_match.group(1).strip().replace('\n', ' ')[:200]

    # 提取CVE编号
    cve_match = re.search(r'CVE-\d{4}-\d{4,}', content)
    if cve_match:
        truth["cve_ref"] = cve_match.group(0)

    # 行注释覆盖块注释 (行注释更精确)
    for line in content.splitlines():
        line = line.strip()

        m = re.match(r'//\s*VULN:\s*(.+)', line, re.IGNORECASE)
        if m:
            truth["is_vulnerable"] = True
            truth["vuln_type"] = m.group(1).strip()
            continue

        m = re.match(r'//\s*SAFE:\s*(.+)', line, re.IGNORECASE)
        if m:
            truth["is_vulnerable"] = False
            truth["description"] = m.group(1).strip()
            continue

        m = re.match(r'//\s*CVE:\s*(\S+)', line, re.IGNORECASE)
        if m:
            truth["cve_ref"] = m.group(1)
            continue

        m = re.match(r'//\s*EXPECTED:\s*(.+)', line, re.IGNORECASE)
        if m:
            truth["description"] = m.group(1).strip()
            m2 = re.search(r'offset\s+(\d+)', truth["description"])
            if m2:
                truth["expected_offset"] = int(m2.group(1))
            continue

    return truth


def run_heap_overflow_detector(source_code: str) -> List[Dict]:
    """运行堆溢出检测器, 返回告警列表."""
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        findings = detect_heap_overflow(source_code)
        return findings if isinstance(findings, list) else []
    except ImportError:
        return []


def run_enhanced_filter(findings: List[Dict],
                        source_code: str) -> Dict[str, Any]:
    """运行增强过滤管线."""
    result = {
        "filtered_count": 0,
        "kept_count": 0,
        "decisions": [],
    }

    try:
        from analysis.heap_overflow_integrator import HeapOverflowIntegrator
        integrator = HeapOverflowIntegrator()

        for f in findings:
            alloc_sz = f.get("allocation_size", f.get("alloc_size", 0))
            write_sz = f.get("write_size", f.get("store_size", 0))
            verdict = integrator.analyze(
                pseudocode=source_code,
                alloc_size=alloc_sz,
                write_size=write_sz,
            )
            if verdict.is_false_positive:
                result["filtered_count"] += 1
            else:
                result["kept_count"] += 1
            result["decisions"].append({
                "is_overflow": verdict.is_overflow,
                "is_fp": verdict.is_false_positive,
                "confidence": verdict.confidence,
                "fp_likelihood": verdict.fp_likelihood,
            })
    except ImportError:
        # 回退: 简单的分配器语义过滤
        for f in findings:
            alloc_sz = f.get("allocation_size", f.get("alloc_size", 0))
            write_sz = f.get("write_size", f.get("store_size", 0))
            effective = _simple_effective_size(alloc_sz)
            if write_sz <= effective:
                result["filtered_count"] += 1
                result["decisions"].append({
                    "is_overflow": False, "is_fp": True,
                    "confidence": 0.7, "fp_likelihood": 0.7,
                })
            else:
                result["kept_count"] += 1
                result["decisions"].append({
                    "is_overflow": True, "is_fp": False,
                    "confidence": 0.6, "fp_likelihood": 0.4,
                })

    return result


def _simple_effective_size(requested: int) -> int:
    """简单的分配器有效大小."""
    if requested <= 0:
        return 0
    align = 16
    min_chunk = 32
    header = 16
    aligned = ((requested + header + align - 1) // align) * align
    return max(min_chunk, aligned) - header


def scan_sample(source_path: str, output_dir: str = "") -> Dict[str, Any]:
    """对单个样本运行完整扫描管线.

    Returns:
        {
            "sample_name": str,
            "source_path": str,
            "ground_truth": {...},
            "detector_findings": [...],
            "filter_result": {...},
            "scan_time_ms": float,
        }
    """
    t0 = time.time()
    sample_name = Path(source_path).parent.name

    source_code = read_c_source(source_path)
    ground_truth = extract_ground_truth(source_path)

    findings = run_heap_overflow_detector(source_code)
    filter_result = run_enhanced_filter(findings, source_code)

    dt = (time.time() - t0) * 1000

    return {
        "sample_name": sample_name,
        "source_path": source_path,
        "ground_truth": ground_truth,
        "detector_findings": findings,
        "filter_result": filter_result,
        "scan_time_ms": round(dt, 1),
    }


def scan_all_samples(sample_dir: str) -> List[Dict[str, Any]]:
    """扫描目录下所有样本."""
    results = []
    root = Path(sample_dir)
    for vuln_path in sorted(root.rglob("vuln.c")):
        r = scan_sample(str(vuln_path))
        results.append(r)
    for c_path in sorted(root.rglob("*.c")):
        if c_path.name == "vuln.c":
            continue
        r = scan_sample(str(c_path))
        results.append(r)
    return results


if __name__ == "__main__":
    base = Path(__file__).parent.parent.parent
    sample_dir = str(base / "samples" / "cve")
    results = scan_all_samples(sample_dir)
    print(f"Scanned {len(results)} samples:")
    for r in results:
        print(f"  {r['sample_name']}: {len(r['detector_findings'])} findings, "
              f"{r['scan_time_ms']:.0f}ms")
