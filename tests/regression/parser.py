# coding: utf-8
"""结果解析模块 — 将扫描原始输出解析为结构化测试报告, 做误报/漏报统计."""
import json, os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 每个样本的预期漏洞信息: {sample_name: {vuln_type, cwe_id, expected}}
_GROUND_TRUTH = {
    'cve_2014_0160_heartbleed':    {'type': 'heap_overflow',    'cwe': 'CWE-126'},
    'cve_2016_6301_uaf':           {'type': 'uaf',             'cwe': 'CWE-416'},
    'cve_2017_1000253_format':     {'type': 'format_string',  'cwe': 'CWE-134'},
    'cve_2018_16864_stack':        {'type': 'stack_overflow', 'cwe': 'CWE-121'},
    'cve_2019_11477_tcp_sack':     {'type': 'heap_overflow',  'cwe': 'CWE-122'},
    'cve_2021_3156_sudo_heap':     {'type': 'heap_overflow',  'cwe': 'CWE-122'},
    'cve_2022_0185_kernel_uaf':    {'type': 'uaf',             'cwe': 'CWE-416'},
    'cve_2022_23222_linux_bpf':    {'type': 'heap_overflow',  'cwe': 'CWE-823'},
    'cve_2023_3269_heap_overflow': {'type': 'heap_overflow',  'cwe': 'CWE-122'},
    'cve_2024_21817_format_string':{'type': 'format_string',  'cwe': 'CWE-134'},
}

@dataclass
class TestReport:
    sample_name: str; variant: str
    expected_type: str; detected_type: str = ''
    true_positive: bool = False   # 预期有漏洞, 检出
    false_negative: bool = False  # 预期有漏洞, 未检出
    false_positive: bool = False  # 预期无漏洞, 检出 (N/A 于单样本)
    confidence: float = 0.0

def parse_results(scan_results: List, ground_truth: Optional[Dict] = None) -> List[TestReport]:
    gt = ground_truth or _GROUND_TRUTH
    reports = []
    for sr in scan_results:
        expected = gt.get(sr.sample_name, {})
        exp_type = expected.get('type', 'unknown')
        detected = ''
        # 从 raw_output 中提取检测到的漏洞类型
        raw = getattr(sr, 'raw_output', {})
        findings = raw.get('findings', raw.get('vulns', []))
        if isinstance(findings, list) and findings:
            detected = findings[0].get('vuln_type', findings[0].get('type', ''))
        elif sr.findings_count > 0:
            detected = exp_type  # 有发现但无细化类型, 假定匹配

        tp = bool(detected and exp_type in detected)
        fn = bool(not detected and exp_type != 'unknown')
        reports.append(TestReport(
            sample_name=sr.sample_name, variant=sr.variant,
            expected_type=exp_type, detected_type=detected,
            true_positive=tp, false_negative=fn,
            confidence=sr.raw_output.get('confidence', 0.0) if isinstance(raw, dict) else 0.0,
        ))
    return reports

def compute_metrics(reports: List[TestReport]) -> Dict[str, Any]:
    tp = sum(1 for r in reports if r.true_positive)
    fn = sum(1 for r in reports if r.false_negative)
    fp = sum(1 for r in reports if r.false_positive)
    total_expected = tp + fn
    return {
        'samples_tested': len(reports),
        'true_positives': tp,
        'false_negatives': fn,
        'false_positives': fp,
        'detection_rate': round(tp / max(1, total_expected), 3),
        'false_negative_rate': round(fn / max(1, total_expected), 3),
    }

def save_report(reports: List[TestReport], metrics: Dict, path: str):
    data = {
        'metrics': metrics,
        'details': [{'sample': r.sample_name, 'variant': r.variant,
                     'expected': r.expected_type, 'detected': r.detected_type,
                     'tp': r.true_positive, 'fn': r.false_negative,
                     'confidence': r.confidence} for r in reports],
    }
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
