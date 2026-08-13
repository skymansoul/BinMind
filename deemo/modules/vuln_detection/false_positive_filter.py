import logging as _logging
import re
from collections import Counter

logger = _logging.getLogger(__name__)


class BenignPatternLearner:
    """基于正则模式匹配，将汇编片段分类为良性或恶意。"""

    _BENIGN_PATTERNS = (
        (r'\b(?:assert|BUG_ON|WARN_ON)\s*\(',           'assertion_check'),
        (r'\b(?:if\s*\(.*==\s*NULL\))',                  'null_check'),
        (r'\b(?:if\s*\(.*<\s*(?:sizeof|length|size)\))', 'bounds_check'),
        (r'\b(?:goto\s+(?:out|err|fail|cleanup))',       'error_cleanup_goto'),
        (r'\b(?:return\s+-?(?:EINVAL|ENOMEM|ENOSPC|EIO))', 'error_return'),
        (r'\b(?:printk|dev_err|pr_err)\s*\(',            'error_logging'),
    )

    _MALICIOUS_PATTERNS = (
        (r'\b(?:strcpy|strcat|gets|sprintf)\s*\([^)]*\)', 'dangerous_api_no_check'),
        (r'\b(?:system|popen|execve)\s*\(\s*"(?!.*[/])',   'command_injection_risk'),
        (r'\bmemcpy\s*\([^)]*\)\s*;(?!.*\bif\b)',           'unchecked_memcpy'),
    )

    def __init__(self):
        self._benign = Counter()
        self._malicious = Counter()
        self._weights = {}

    def learn_benign(self, asm_code):
        """从已知干净二进制摄入汇编代码，填充良性模式计数。"""
        if asm_code is None:
            return
        for pat, name in self._BENIGN_PATTERNS:
            cnt = len(re.findall(pat, asm_code, re.IGNORECASE))
            self._benign[name] += cnt

    def learn_malicious(self, asm_code):
        """从已知恶意二进制摄入汇编代码，填充威胁模式计数。"""
        if asm_code is None:
            return
        for pat, name in self._MALICIOUS_PATTERNS:
            cnt = len(re.findall(pat, asm_code, re.IGNORECASE))
            self._malicious[name] += cnt

    def score(self, desc, ctx=''):
        """产出连续分值——0.0明确误报，1.0确认正报。"""
        benign_s = 0.0
        malicious_s = 0.0
        for pat, _name in self._BENIGN_PATTERNS:
            if re.search(pat, ctx, re.IGNORECASE):
                benign_s += 0.15
        for pat, _name in self._MALICIOUS_PATTERNS:
            if re.search(pat, ctx, re.IGNORECASE):
                malicious_s += 0.25
        total = benign_s + malicious_s
        if total == 0:
            return 0.5
        return malicious_s / total


class FalsePositiveFilter:
    """阈值门控过滤器——评分委托BenignPatternLearner，finding未达阈值即丢弃。"""

    def __init__(self, threshold=0.3):
        self._learner = BenignPatternLearner()
        self._threshold = float(threshold) if threshold is not None else 0.3
        self._stats = {'total': 0, 'filtered': 0, 'passed': 0}

    def filter(self, findings):
        """对每条finding应用learner评分，标注分数，仅返回达阈值条目。"""
        if findings is None:
            return []
        out = []
        for finding in findings:
            self._stats['total'] += 1
            desc = str(finding.get('description', ''))
            ctx = desc + ' ' + str(finding.get('context', ''))
            score = self._learner.score(desc, ctx)
            finding['false_positive_score'] = round(score, 2)
            finding['likely_false_positive'] = (score < self._threshold)
            if score >= self._threshold:
                out.append(finding)
                self._stats['passed'] += 1
            else:
                self._stats['filtered'] += 1
                logger.info(
                    f"FP filtered: {desc[:80]} (score={score:.2f})")
        return out

    def filter_rate(self):
        """被过滤finding与总处理量之比。分母钳位至≥1。"""
        denom = self._stats['total']
        if denom < 1:
            denom = 1
        return self._stats['filtered'] / denom


def create_false_positive_filter(threshold=0.3):
    """构造FalsePositiveFilter实例，绑定指定分数阈值。"""
    return FalsePositiveFilter(threshold)
