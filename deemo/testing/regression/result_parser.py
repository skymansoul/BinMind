# 结果解析模块 —— 从扫描输出中提取发现项, 匹配已知漏洞位置, 统计检出/漏报。
# 创建: 2026-08-14

import json, re, os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MatchResult:
    sample_name: str
    expected_cve: str
    expected_type: str          # "stack_overflow"/"heap_overflow"/"uaf"/"format_string"
    detected: bool
    detection_confidence: float  # 扫描器报告的置信度
    matched_keyword: str = ""   # 匹配到的关键词
    false_positives: int = 0    # 扫描器报告的其他(非目标)发现数


# 每个样本的预期漏洞信息 —— 用于结果比对
_EXPECTED_VULNS = {
    "CVE-2014-0160": {"type": "heap_overflow", "keywords": ["heartbleed", "Heartbleed", "heartbeat", "heap", "overflow", "DTLS"]},
    "CVE-2016-4971": {"type": "format_string", "keywords": ["format", "printf", "wget"]},
    "CVE-2018-1000001": {"type": "heap_overflow", "keywords": ["realpath", "heap", "buffer", "overflow"]},
    "CVE-2019-14287": {"type": "uaf", "keywords": ["sudo", "use.after.free", "UAF"]},
    "CVE-2021-3156": {"type": "heap_overflow", "keywords": ["sudo", "heap", "overflow", "baron", "samedit"]},
    "CVE-2021-4034": {"type": "stack_overflow", "keywords": ["pkexec", "stack", "overflow", "argv"]},
    "CVE-2022-0847": {"type": "uaf", "keywords": ["dirty", "pipe", "splice"]},
    "CVE-2022-23222": {"type": "uaf", "keywords": ["bpf", "verifier", "uaf"]},
    "CVE-2023-4911": {"type": "heap_overflow", "keywords": ["looney", "tunables", "glibc", "ld.so", "heap"]},
    "CVE-2021-4002": {"type": "uaf", "keywords": ["hugetlb", "uaf", "memory"]},
}


def parse_scan_output(scan_result) -> dict:
    """解析扫描器输出: 优先JSON结构化解析, 回退关键词匹配。"""
    findings = []
    output = (scan_result.stdout or "") + "\n" + (scan_result.stderr or "")

    # 尝试JSON解析(scan_runner.py输出格式)
    try:
        import json
        data = json.loads(scan_result.stdout or "{}")
        for category, result in data.items():
            if isinstance(result, dict):
                if category == 'stack' and result.get('overflowable'):
                    findings.append({"type": "stack_overflow",
                        "matched_text": f"overflowable={result.get('overflowable')}",
                        "context": str(result.get('padding', ''))[:80],
                        "confidence": 0.85})
                if category == 'fmt' and isinstance(result, list):
                    for f in result:
                        if isinstance(f, dict) and f.get('confidence', 0) > 0.3:
                            findings.append({"type": "format_string",
                                "matched_text": f.get('format_func', ''),
                                "context": f.get('description', '')[:80],
                                "confidence": f.get('confidence', 0.5)})
                if category == 'heap' and isinstance(result, dict):
                    for c in result.get('uaf_candidates', []):
                        findings.append({"type": "uaf",
                            "matched_text": "UAF candidate",
                            "context": c.get('evidence', '')[:80],
                            "confidence": c.get('confidence', 0.5)})
        if findings:
            return {"findings": findings, "finding_count": len(findings),
                    "raw_output_length": len(output), "parsed_json": True}
    except (json.JSONDecodeError, AttributeError):
        pass

    # 回退: 关键词正则匹配
    vuln_patterns = [
        (r'(stack.overflow|栈溢出)', 'stack_overflow'),
        (r'(heap.overflow|堆溢出)', 'heap_overflow'),
        (r'(use.after.free|UAF|uaf)', 'uaf'),
        (r'(format.string|格式化字符串|printf.*format)', 'format_string'),
        (r'(double.free|double_free)', 'double_free'),
    ]

    for pattern, vtype in vuln_patterns:
        for m in re.finditer(pattern, output, re.IGNORECASE):
            ctx_start = max(0, m.start() - 40)
            ctx_end = min(len(output), m.end() + 40)
            findings.append({
                "type": vtype,
                "matched_text": m.group(0),
                "context": output[ctx_start:ctx_end].strip(),
                "confidence": 0.6,
            })

    # 提取置信度数值
    conf_matches = re.findall(r'confidence[:=]\s*([\d.]+)', output, re.IGNORECASE)
    if conf_matches and findings:
        for i, f in enumerate(findings[:len(conf_matches)]):
            try:
                f["confidence"] = float(conf_matches[i])
            except ValueError:
                pass

    return {
        "findings": findings,
        "finding_count": len(findings),
        "raw_output_length": len(output),
    }


def match_against_expected(sample_name: str,
                            parsed: dict) -> MatchResult:
    """将解析结果与预期漏洞比对。"""
    expected = _EXPECTED_VULNS.get(sample_name, {})
    if not expected:
        return MatchResult(sample_name, "", "", False, 0.0)

    expected_type = expected.get("type", "")
    keywords = expected.get("keywords", [])
    findings = parsed.get("findings", [])

    # 匹配: 任何finding的类型匹配或关键词命中
    detected = False
    best_conf = 0.0
    matched_kw = ""

    for f in findings:
        if f.get("type") == expected_type:
            detected = True
            best_conf = max(best_conf, f.get("confidence", 0.5))
            matched_kw = f.get("matched_text", "")
            break
        # 回退: 关键词匹配
        for kw in keywords:
            if kw.lower() in (f.get("matched_text", "") + f.get("context", "")).lower():
                detected = True
                best_conf = max(best_conf, f.get("confidence", 0.5))
                matched_kw = kw
                break

    # 误报: 非预期类型的finding数
    fp_count = sum(1 for f in findings
                   if f.get("type") != expected_type)

    return MatchResult(
        sample_name=sample_name,
        expected_cve=sample_name,
        expected_type=expected_type,
        detected=detected,
        detection_confidence=round(best_conf, 3),
        matched_keyword=matched_kw,
        false_positives=fp_count,
    )


def compute_statistics(matches: List[MatchResult]) -> dict:
    """从匹配结果计算检出率/误报率等统计指标。"""
    total = len(matches)
    if total == 0:
        return {"error": "无样本"}

    detected = sum(1 for m in matches if m.detected)
    total_fp = sum(m.false_positives for m in matches)
    avg_conf = (sum(m.detection_confidence for m in matches) /
                max(total, 1))

    by_type = {}
    for m in matches:
        t = m.expected_type
        if t not in by_type:
            by_type[t] = {"total": 0, "detected": 0}
        by_type[t]["total"] += 1
        if m.detected:
            by_type[t]["detected"] += 1

    return {
        "total_samples": total,
        "detected": detected,
        "missed": total - detected,
        "detection_rate": round(detected / total, 3),
        "total_false_positives": total_fp,
        "avg_fp_per_sample": round(total_fp / total, 2),
        "avg_confidence": round(avg_conf, 3),
        "by_type": {t: {
            "detection_rate": round(v["detected"] / v["total"], 3)
        } for t, v in by_type.items()},
    }


if __name__ == "__main__":
    # 独立测试: 解析示例输出
    sample_output = """
    [FINDING] stack_overflow in function vuln_func: buffer of 64 bytes, write of 128 bytes (confidence=0.85)
    [FINDING] format_string in function log_msg: printf(user_input) (confidence=0.72)
    """
    parsed = parse_scan_output(type('R', (), {
        'stdout': sample_output, 'stderr': '',
        'sample_name': 'test_sample', 'binary_path': '/tmp/test',
        'success': True, 'exit_code': 0, 'duration_sec': 1.5, 'error': ''})())
    print(json.dumps(parsed, indent=2, ensure_ascii=False))
