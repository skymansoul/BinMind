from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time as _time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FunctionSummary:
    name: str
    address: int = 0
    purpose: str = ""
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    security_relevant: bool = False
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    data_flow_summary: str = ""
    raw_summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': self.address,
            'purpose': self.purpose,
            'inputs': self.inputs,
            'outputs': self.outputs,
            'security_relevant': self.security_relevant,
            'risk_score': self.risk_score,
            'risk_factors': self.risk_factors,
            'api_calls': self.api_calls,
            'data_flow_summary': self.data_flow_summary,
            'raw_summary': self.raw_summary,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FunctionSummary:
        return cls(
            name=data.get('name', ''),
            address=data.get('address', 0),
            purpose=data.get('purpose', ''),
            inputs=data.get('inputs', []),
            outputs=data.get('outputs', []),
            security_relevant=data.get('security_relevant', False),
            risk_score=data.get('risk_score', 0.0),
            risk_factors=data.get('risk_factors', []),
            api_calls=data.get('api_calls', []),
            data_flow_summary=data.get('data_flow_summary', ''),
            raw_summary=data.get('raw_summary', ''),
            metadata=data.get('metadata', {}),
        )


DANGEROUS_APIS: Dict[str, float] = {
    'strcpy': 0.9, 'strcat': 0.9, 'sprintf': 0.8, 'gets': 1.0,
    'scanf': 0.5, 'memcpy': 0.4, 'memmove': 0.3, 'strncpy': 0.2,
    'strncat': 0.2, 'snprintf': 0.1, 'system': 0.95, 'popen': 0.95,
    'exec': 0.95, 'execl': 0.95, 'execle': 0.95, 'execlp': 0.95,
    'execv': 0.95, 'execve': 0.95, 'execvp': 0.95, 'WinExec': 0.85,
    'ShellExecute': 0.85, 'CreateProcess': 0.7, 'LoadLibrary': 0.3,
    'dlopen': 0.3, 'VirtualAlloc': 0.5, 'VirtualProtect': 0.7,
    'malloc': 0.1, 'calloc': 0.1, 'realloc': 0.15, 'free': 0.1,
    'alloca': 0.3, 'CreateFile': 0.2, 'ReadFile': 0.2, 'WriteFile': 0.2,
    'RegOpenKey': 0.2, 'RegQueryValue': 0.3, 'RegSetValue': 0.6,
    'send': 0.3, 'recv': 0.5, 'connect': 0.3, 'bind': 0.2,
    'CryptEncrypt': 0.4, 'CryptDecrypt': 0.4, 'atoi': 0.1,
    'strtol': 0.05, 'base64_encode': 0.1, 'base64_decode': 0.1,
}


class SummaryBasedAnalyzer:
    def __init__(self) -> None:
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self._risk_cache: Dict[str, float] = {}
        self._pattern_db: List[Tuple[str, float, str]] = []
        # 初始化历史记录——决策需要数据支撑，不能凭感觉
        self._analysis_history: List[Dict[str, Any]] = []
        self._bin_marker: str = self._derive_binary_marker()

    @staticmethod
    def _derive_binary_marker() -> str:
        return hashlib.sha1(str(_time.time()).encode()).hexdigest()[:12]

    # 风险趋势追踪与模式学习
    # 记录每次分析的分数变化，识别坏模式自动加权。
    def _record_risk_snapshot(self, name: str, score: float) -> None:
        """记录风险分数快照并追加历史条目，供趋势回放"""
        previous = self._risk_cache.get(name)
        self._risk_cache[name] = score
        entry = {
            'ts': _time.time(),
            'function': name,
            'score': score,
            'previous_score': previous,
            'bin_marker': self._bin_marker,
        }
        self._analysis_history.append(entry)

    def get_risk_trend(self, name: str) -> Optional[List[float]]:
        """返回某个函数历次分析的风险分数序列，供可视化趋势图"""
        scores = [
            e['score'] for e in self._analysis_history
            if e['function'] == name
        ]
        return scores if scores else None

    def learn_pattern(
        self, pattern_regex: str, weight_boost: float, label: str
    ) -> None:
        """人工或启发式注入已知恶意模式"""
        self._pattern_db.append((pattern_regex, weight_boost, label))

    def _apply_learned_patterns(self, pseudocode: str) -> Tuple[float, List[str]]:
        """遍历模式库，对匹配到的危险模式叠加额外风险分"""
        boost = 0.0
        matched: List[str] = []
        for pat, w, lbl in self._pattern_db:
            if re.search(pat, pseudocode, re.IGNORECASE):
                boost += w
                matched.append(lbl)
        return boost, matched

    # SBOM/漏洞报告兼容导出
    # 面向 Syft/Grype/Trivy 生态，把函数级风险摘要导出为下游
    # 漏洞扫描器可消费的条目（minimal CycloneDX-style vulnerability item）。
    def export_vulnerability_items(self) -> List[Dict[str, Any]]:
        """高危函数映射为漏洞条目，供聚合引擎消费。"""
        items: List[Dict[str, Any]] = []
        for summ in self.function_summaries.values():
            if not summ.security_relevant or summ.risk_score < 0.25:
                continue  # 低风险跳过，不脏输出
            severity = self._risk_to_severity(summ.risk_score)
            vuln_id = f"FUNC-RISK-{hashlib.md5(summ.name.encode()).hexdigest()[:8]}"
            items.append({
                'bom-ref': vuln_id,
                'id': vuln_id,
                'name': f"Dangerous function pattern: {summ.name}",
                'description': summ.raw_summary,
                'recommendation': self._build_recommendation(summ),
                'severity': severity,
                'cvss_score': round(summ.risk_score * 10.0, 1),
                'affected_api_calls': summ.api_calls[:20],
                'risk_factors': summ.risk_factors,
                'source': 'summary_based_analyzer',
                'address': f"0x{summ.address:x}" if summ.address else None,
            })
        return items

    @staticmethod
    def _risk_to_severity(score: float) -> str:
        if score >= 0.85:
            return 'critical'
        if score >= 0.6:
            return 'high'
        if score >= 0.3:
            return 'medium'
        return 'low'

    @staticmethod
    def _build_recommendation(summ: FunctionSummary) -> str:
        tips: List[str] = []
        code_lower = summ.raw_summary.lower()
        if 'strcpy' in code_lower:
            tips.append("Replace strcpy with strncpy or strlcpy")
        if 'sprintf' in code_lower:
            tips.append("Replace sprintf with snprintf")
        if any(api in code_lower for api in ('system', 'popen', 'exec')):
            tips.append("Avoid shell execution; use direct API calls or sanitize input")
        if 'memcpy' in code_lower:
            tips.append("Validate buffer sizes with sizeof before memcpy")
        if not tips:
            tips.append("Manual code review recommended for this function")
        return '; '.join(tips)

    # 统计仪表盘与聚合分析
    # 除单函数视角外提供全局鸟瞰：哪些 API 是最大地雷、
    # 风险分布是否符合长尾，帮助 triage 时间分配。
    def aggregate_statistics(self) -> Dict[str, Any]:
        """返回可直接序列化的字典，供前端或报告消费。"""
        if not self.function_summaries:
            return {'error': 'No summaries available', 'count': 0}

        scores = [s.risk_score for s in self.function_summaries.values()]
        n = len(scores)
        mean_score = sum(scores) / n
        variance = sum((x - mean_score) ** 2 for x in scores) / n
        stddev = math.sqrt(variance)

        # 分位数 -- 了解风险分布形状
        sorted_scores = sorted(scores)
        p50 = sorted_scores[int(n * 0.50)] if n > 0 else 0.0
        p75 = sorted_scores[int(n * 0.75)] if n > 1 else 0.0
        p90 = sorted_scores[int(n * 0.90)] if n > 2 else 0.0
        p95 = sorted_scores[int(n * 0.95)] if n > 3 else 0.0
        p99 = sorted_scores[int(n * 0.99)] if n > 10 else 0.0

        # API 热点排行 -- 哪些危险API出现最频繁
        api_counter: Counter = Counter()
        for s in self.function_summaries.values():
            dangerous = [a for a in s.api_calls if a in DANGEROUS_APIS]
            api_counter.update(dangerous)
        api_hotspots = api_counter.most_common(20)

        # 目的类别分布
        purpose_dist: Counter = Counter()
        for s in self.function_summaries.values():
            purpose_dist[s.purpose] += 1

        # 风险段计数
        risk_buckets = {
            'critical (>=0.85)': sum(1 for x in scores if x >= 0.85),
            'high (0.6-0.84)': sum(1 for x in scores if 0.6 <= x < 0.85),
            'medium (0.3-0.59)': sum(1 for x in scores if 0.3 <= x < 0.6),
            'low (<0.3)': sum(1 for x in scores if x < 0.3),
        }

        # 全局最高风险摘要
        top5 = sorted(
            self.function_summaries.values(),
            key=lambda s: s.risk_score,
            reverse=True,
        )[:5]

        return {
            'total_functions': n,
            'security_relevant_count': sum(
                1 for s in self.function_summaries.values() if s.security_relevant
            ),
            'mean_risk_score': round(mean_score, 4),
            'stddev_risk_score': round(stddev, 4),
            'percentiles': {
                'p50': round(p50, 4),
                'p75': round(p75, 4),
                'p90': round(p90, 4),
                'p95': round(p95, 4),
                'p99': round(p99, 4),
            },
            'risk_distribution': risk_buckets,
            'api_hotspots': [
                {'api': api, 'count': cnt, 'base_risk': DANGEROUS_APIS.get(api, 0.0)}
                for api, cnt in api_hotspots
            ],
            'purpose_distribution': dict(purpose_dist.most_common()),
            'top5_riskiest': [
                {'name': s.name, 'score': s.risk_score, 'purpose': s.purpose}
                for s in top5
            ],
            'bin_marker': self._bin_marker,
            'generated_at': _time.time(),
        }

    def analyze_function(
        self,
        name: str,
        pseudocode: str,
        address: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FunctionSummary:
        summary = FunctionSummary(
            name=name,
            address=address,
            metadata=metadata or {},
        )

        summary.api_calls = self._extract_api_calls(pseudocode)
        summary.purpose = self._infer_purpose(pseudocode, summary.api_calls)
        summary.inputs, summary.outputs = self._extract_io(pseudocode)
        summary.risk_score = self._assess_risk(pseudocode, summary.api_calls)
        summary.security_relevant = summary.risk_score > 0.3
        summary.risk_factors = self._identify_risk_factors(pseudocode, summary.api_calls)
        summary.data_flow_summary = self._summarize_data_flow(pseudocode)
        summary.raw_summary = self._generate_raw_summary(summary)

        # 集成风险快照: 记录趋势并应用学习到的模式
        learned_boost, learned_labels = self._apply_learned_patterns(pseudocode)
        if learned_boost > 0:
            summary.risk_score = min(summary.risk_score + learned_boost, 1.0)
            if learned_labels:
                summary.risk_factors.append(
                    f"Matched learned patterns: {', '.join(learned_labels)}"
                )
                summary.security_relevant = True
        self._record_risk_snapshot(name, summary.risk_score)

        self.function_summaries[name] = summary
        return summary

    @staticmethod
    def _extract_api_calls(pseudocode: str) -> List[str]:
        calls = re.findall(r'\b([A-Za-z_]\w*)\s*\(', pseudocode)
        return list(set(calls))

    @staticmethod
    def _infer_purpose(pseudocode: str, api_calls: List[str]) -> str:
        code_lower = pseudocode.lower()

        if any(s in code_lower for s in ('encrypt', 'decrypt', 'hash', 'sha', 'md5', 'aes', 'rsa')):
            return "Cryptographic operation"
        if any(s in code_lower for s in ('socket', 'send', 'recv', 'connect', 'http', 'url')):
            return "Network communication"
        if any(s in code_lower for s in ('file', 'fopen', 'fread', 'fwrite', 'createfile', 'readfile')):
            return "File I/O operation"
        if any(s in code_lower for s in ('registry', 'regopen', 'regquery', 'regset')):
            return "Registry manipulation"
        if any(s in code_lower for s in ('process', 'createprocess', 'exec', 'shell')):
            return "Process execution"
        if any(s in code_lower for s in ('thread', 'mutex', 'semaphore', 'createthread')):
            return "Threading/synchronization"
        if any(s in code_lower for s in ('malloc', 'free', 'alloc', 'heap', 'virtualalloc')):
            return "Memory management"
        if any(s in code_lower for s in ('parse', 'decode', 'encode', 'serialize', 'deserialize')):
            return "Data parsing/transformation"
        if any(s in code_lower for s in ('gui', 'window', 'dialog', 'messagebox')):
            return "UI/GUI operation"
        if any(s in code_lower for s in ('loadlibrary', 'getprocaddress', 'dll')):
            return "Dynamic library loading"
        if any(s in code_lower for s in ('strcmp', 'strlen', 'strcpy', 'strcat', 'memcpy', 'memset')):
            return "String/memory utility"

        return "General computation"

    @staticmethod
    def _extract_io(pseudocode: str) -> Tuple[List[str], List[str]]:
        inputs: List[str] = []
        outputs: List[str] = []

        sig_match = re.search(r'\w+\s*\(([^)]*)\)', pseudocode.split('\n')[0] if pseudocode else '')
        if sig_match:
            params = [p.strip().split()[-1].lstrip('*') for p in sig_match.group(1).split(',') if p.strip()]
            for p in params:
                if p and not p.startswith('*'):
                    inputs.append(p)

        if 'return' in pseudocode.lower():
            outputs.append('return_value')
        if re.search(r'\*\s*\w+\s*=', pseudocode):
            outputs.append('output_pointer')

        return inputs, outputs

    @staticmethod
    def _assess_risk(pseudocode: str, api_calls: List[str]) -> float:
        risk_score = 0.0
        matched_apis = 0
        max_api_score = 0.0

        for call in api_calls:
            if call in DANGEROUS_APIS:
                function_risk = DANGEROUS_APIS[call]
                risk_score += function_risk
                matched_apis += 1
                max_api_score = max(max_api_score, function_risk)

        code_lower = pseudocode.lower()

        additional_risks = 0.0
        if 'memcpy' in code_lower and 'sizeof' not in code_lower:
            additional_risks += 0.2
        if 'strcpy' in code_lower and 'strlen' not in code_lower:
            additional_risks += 0.2
        if 'sprintf' in code_lower and 'snprintf' not in code_lower:
            additional_risks += 0.15
        if 'system(' in code_lower or 'popen(' in code_lower:
            if 'sanitize' not in code_lower and 'check' not in code_lower:
                additional_risks += 0.3

        if matched_apis == 0:
            return min(additional_risks, 1.0)

        combined = (risk_score / max(matched_apis, 1)) * 0.7 + max_api_score * 0.3 + additional_risks * 0.1
        return min(combined, 1.0)

    @staticmethod
    def _identify_risk_factors(pseudocode: str, api_calls: List[str]) -> List[str]:
        factors: List[str] = []
        code_lower = pseudocode.lower()

        dangerous_found = [api for api in api_calls if api in DANGEROUS_APIS and DANGEROUS_APIS[api] > 0.5]
        if dangerous_found:
            factors.append(f"Uses dangerous APIs: {', '.join(dangerous_found)}")

        if 'memcpy' in code_lower and 'sizeof' not in code_lower and 'len' not in code_lower:
            factors.append("Memory copy without visible bounds check")
        if 'strcpy' in code_lower:
            factors.append("Unbounded string copy (strcpy)")
        if 'strcat' in code_lower:
            factors.append("Unbounded string concatenation (strcat)")
        if 'sprintf' in code_lower and 'snprintf' not in code_lower:
            factors.append("Potentially unsafe format string (sprintf vs snprintf)")
        if 'system(' in code_lower or 'popen(' in code_lower:
            factors.append("Command execution - injection risk")
        if 'recv' in code_lower and 'sizeof' not in code_lower:
            factors.append("Network receive without visible bounds check")
        if re.search(r'malloc\s*\(\s*\w+\s*\*', pseudocode):
            factors.append("Integer overflow risk in allocation size")

        return factors

    @staticmethod
    def _summarize_data_flow(pseudocode: str) -> str:
        parts: List[str] = []
        code_lower = pseudocode.lower()

        if any(kw in code_lower for kw in ('recv', 'fread', 'read', 'recvfrom')):
            parts.append("reads external data")
        if any(kw in code_lower for kw in ('send', 'fwrite', 'write', 'sendto')):
            parts.append("writes external data")
        if any(kw in code_lower for kw in ('malloc', 'calloc', 'realloc', 'new', 'alloc')):
            parts.append("allocates memory")
        if any(kw in code_lower for kw in ('memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf')):
            parts.append("copies/formats data")
        if 'return' in code_lower:
            parts.append("returns result")

        if not parts:
            return "Internal computation"
        return "Function " + ", ".join(parts)

    @staticmethod
    def _generate_raw_summary(summary: FunctionSummary) -> str:
        lines = [
            f"Function: {summary.name}",
            f"Purpose: {summary.purpose}",
            f"Risk Score: {summary.risk_score:.2f}",
        ]
        if summary.risk_factors:
            lines.append("Risk Factors:")
            for f in summary.risk_factors:
                lines.append(f"  - {f}")
        if summary.api_calls:
            lines.append(f"API Calls: {', '.join(summary.api_calls[:10])}")
        return '\n'.join(lines)

    def batch_analyze(
        self,
        functions: Dict[str, str],
        addresses: Optional[Dict[str, int]] = None,
    ) -> Dict[str, FunctionSummary]:
        addresses = addresses or {}
        results: Dict[str, FunctionSummary] = {}
        for name, code in functions.items():
            addr = addresses.get(name, 0)
            results[name] = self.analyze_function(name, code, addr)
        return results

    def get_high_risk_functions(self, threshold: float = 0.5) -> List[FunctionSummary]:
        high_risk = [
            s for s in self.function_summaries.values()
            if s.risk_score >= threshold
        ]
        return sorted(high_risk, key=lambda s: s.risk_score, reverse=True)

    def compare_functions(
        self,
        name_a: str,
        name_b: str,
    ) -> Dict[str, Any]:
        if name_a not in self.function_summaries or name_b not in self.function_summaries:
            return {'error': 'Function not found', 'similarity': 0.0}

        a = self.function_summaries[name_a]
        b = self.function_summaries[name_b]

        common_calls = set(a.api_calls) & set(b.api_calls)
        all_calls = set(a.api_calls) | set(b.api_calls)

        api_similarity = len(common_calls) / max(len(all_calls), 1)
        risk_diff = abs(a.risk_score - b.risk_score)
        same_purpose = a.purpose == b.purpose

        return {
            'functions': (name_a, name_b),
            'api_similarity': api_similarity,
            'common_apis': list(common_calls),
            'risk_diff': risk_diff,
            'same_purpose': same_purpose,
            'purpose_a': a.purpose,
            'purpose_b': b.purpose,
        }

    def save(self, filepath: str) -> None:
        data = {
            name: summary.to_dict()
            for name, summary in self.function_summaries.items()
        }
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(data)} summaries to {filepath}")

    def load(self, filepath: str) -> None:
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.function_summaries = {
            name: FunctionSummary.from_dict(d)
            for name, d in data.items()
        }
        logger.info(f"Loaded {len(self.function_summaries)} summaries from {filepath}")

    def generate_report(self, top_n: int = 50) -> str:
        sorted_funcs = sorted(
            self.function_summaries.values(),
            key=lambda s: s.risk_score,
            reverse=True,
        )

        lines = [
            "=" * 60,
            "FUNCTION SUMMARY ANALYSIS REPORT",
            "=" * 60,
            f"Total functions analyzed: {len(self.function_summaries)}",
            f"Security-relevant functions: {sum(1 for s in sorted_funcs if s.security_relevant)}",
            f"High risk (>0.7): {sum(1 for s in sorted_funcs if s.risk_score > 0.7)}",
            "",
        ]

        if sorted_funcs:
            lines.append("TOP RISK FUNCTIONS:")
            lines.append("-" * 40)
            for i, summary in enumerate(sorted_funcs[:top_n]):
                if summary.risk_score > 0:
                    lines.append(f"{i + 1}. {summary.name} (risk: {summary.risk_score:.2f})")
                    lines.append(f"   Purpose: {summary.purpose}")
                    if summary.risk_factors:
                        lines.append(f"   Factors: {'; '.join(summary.risk_factors[:3])}")
                    lines.append("")

        lines.append("=" * 60)
        return '\n'.join(lines)

    # 统计报告生成器
    def generate_stats_report(self) -> str:
        stats = self.aggregate_statistics()
        if 'error' in stats:
            return f"[Stats] {stats['error']}"

        lines = [
            "─" * 50,
            "AGGREGATE RISK DASHBOARD",
            "─" * 50,
            f"Analyzed: {stats['total_functions']} functions  |  "
            f"Security-relevant: {stats['security_relevant_count']}",
            f"Mean risk: {stats['mean_risk_score']}  |  StdDev: {stats['stddev_risk_score']}",
            f"Percentiles → P50={stats['percentiles']['p50']}  "
            f"P75={stats['percentiles']['p75']}  P90={stats['percentiles']['p90']}  "
            f"P95={stats['percentiles']['p95']}  P99={stats['percentiles']['p99']}",
            "",
            "Risk Buckets:",
        ]
        for bucket, count in stats['risk_distribution'].items():
            bar = '█' * min(count, 60)
            lines.append(f"  {bucket:25s} : {count:4d}  {bar}")

        lines.append("")
        lines.append("API Hotspots (most frequent dangerous calls):")
        for item in stats['api_hotspots'][:10]:
            lines.append(
                f"  {item['api']:20s} x{item['count']:3d}  "
                f"(base_risk={item['base_risk']:.2f})"
            )

        lines.append("")
        lines.append("Top-5 Riskiest Functions:")
        for i, f_ in enumerate(stats['top5_riskiest'], 1):
            lines.append(
                f"  {i}. {f_['name']:30s}  score={f_['score']:.2f}  "
                f"({f_['purpose']})"
            )

        lines.append("─" * 50)
        return '\n'.join(lines)


def build_function_summaries(
    functions: Dict[str, str],
    addresses: Optional[Dict[str, int]] = None,
) -> Dict[str, FunctionSummary]:
    analyzer = SummaryBasedAnalyzer()
    return analyzer.batch_analyze(functions, addresses)
