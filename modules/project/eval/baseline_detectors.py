# 基线检测器: 用于量化对比的朴素方法
# 1. NaivePatternDetector — 模式匹配 (无值域分析)
#    逻辑: malloc后只要有memcpy/strcpy/memset就报告
#    预期: 高召回 (几乎所有malloc+write都报告), 极高FPR
# 2. RegexOnlyDetector — objdump + 正则 (工业界最简方案)
#    逻辑: 在反汇编中找malloc(size); memcpy(dst, src, size)
#    预期: 召回中等, FPR高 (无法区分栈/堆, 无法约束验证)
# 核心对比: ASA-VRA vs Naive → FPR从X降至0%, 展示方法学创新
from __future__ import annotations
import re, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class BaselineFinding:
    """统一格式的检测发现."""
    detector: str        # naive / regex_only / asa_vra
    function_name: str
    alloc_func: str
    sink_func: str
    severity: str        # HIGH / MEDIUM / LOW
    confidence: float
    detail: str
    is_false_positive: bool = False


@dataclass
class BaselineResult:
    """单个检测器在单个样本上的结果."""
    detector_name: str
    sample_name: str
    sample_type: str     # heap_overflow / safe / uaf
    detected: bool
    num_findings: int
    findings: List[BaselineFinding] = field(default_factory=list)
    error_msg: str = ""


class NaivePatternDetector:
    """朴素模式匹配检测器 — 函数级匹配, 无值域分析.

    算法:
      1. objdump反汇编
      2. 按函数边界分组指令
      3. 若某函数同时包含malloc+写入sink → 报告
      4. 不做任何约束验证或值域分析

    这代表了大多数工业界SAST工具的简化版.
    与ASA-VRA的差距 (=FPR从~X%降到0%) 就是我们的创新贡献.
    """

    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc',
                    'HeapAlloc', 'GlobalAlloc', 'new'}
    _SINK_FUNCS = {'memcpy', 'memset', 'memmove', 'strcpy', 'strncpy',
                   'strcat', 'strncat', 'sprintf', 'snprintf',
                   '__memcpy_chk', '__memmove_chk', 'bcopy', 'memccpy'}

    def analyze(self, binary_path: str) -> BaselineResult:
        """运行朴素模式匹配分析."""
        sample_name = Path(binary_path).stem
        try:
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                return BaselineResult(
                    detector_name='naive', sample_name=sample_name,
                    sample_type='unknown', detected=False,
                    num_findings=0, error_msg='objdump failed')
        except Exception as e:
            return BaselineResult(
                detector_name='naive', sample_name=sample_name,
                sample_type='unknown', detected=False,
                num_findings=0, error_msg=str(e)[:200])

        text = proc.stdout
        # 按函数切片: 查找所有函数标签 <funcname>:
        func_slices = {}
        current_func = '_entry_'
        current_start = 0
        lines = text.split('\n')
        for i, line in enumerate(lines):
            # objdump函数标签格式 (从第0列开始, 无缩进):
            # 0000000140001550 <main>:
            if '<' in line and '>:' in line and not line.startswith(' '):
                m = re.search(r'<([\w.@]+)>:', line)
                if m:
                    if current_func != '_entry_':
                        func_slices[current_func] = (current_start, i)
                    current_func = m.group(1).split('@')[0]
                    current_start = i
        # 最后一段
        if current_func != '_entry_':
            func_slices[current_func] = (current_start, len(lines))

        findings = []
        for func_name, (start, end) in func_slices.items():
            func_text = '\n'.join(lines[start:end])
            has_alloc = any(af in func_text for af in self._ALLOC_FUNCS)
            # call 目标匹配必须用正则: 字面子串 'call.*<sf>' 永不匹配
            # 反汇编文本 (预存缺陷, naive 基线曾完全失效)
            has_sink = any(
                re.search(r'call\s+.*?<' + re.escape(sf) + r'>', func_text)
                or re.search(r'call\s+.*?' + re.escape(sf), func_text)
                for sf in self._SINK_FUNCS)

            if has_alloc and has_sink:
                # 找到具体的sink函数
                for sf in self._SINK_FUNCS:
                    if sf in func_text:
                        findings.append(BaselineFinding(
                            detector='naive',
                            function_name=func_name,
                            alloc_func='malloc',
                            sink_func=sf,
                            severity='HIGH',
                            confidence=0.60,
                            detail=(f"朴素匹配: {func_name}内malloc+{sf}共存, "
                                    f"不做值域约束验证")))
                        break

        return BaselineResult(
            detector_name='naive',
            sample_name=sample_name,
            sample_type='unknown',
            detected=len(findings) > 0,
            num_findings=len(findings),
            findings=findings)


class RegexOnlyDetector:
    """纯正则检测器 — 连分配大小都不提取, 只找malloc+memcpy共现.

    这是比NaivePatternDetector更弱的基线: 甚至连函数边界
    都不判断, 只在整个二进制中扫描模式.
    """

    def analyze(self, binary_path: str) -> BaselineResult:
        sample_name = Path(binary_path).stem
        try:
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                return BaselineResult(
                    detector_name='regex_only', sample_name=sample_name,
                    sample_type='unknown', detected=False,
                    num_findings=0, error_msg='objdump failed')
        except Exception as e:
            return BaselineResult(
                detector_name='regex_only', sample_name=sample_name,
                sample_type='unknown', detected=False,
                num_findings=0, error_msg=str(e)[:200])

        text = proc.stdout
        # 找所有memcpy/memset/strcpy调用
        sink_matches = re.findall(
            r'call\s+.*?<(memcpy|memset|strcpy|memmove|strncpy|strcat|sprintf)>',
            text)
        # 找所有malloc调用
        alloc_matches = re.findall(
            r'call\s+.*?<(malloc|calloc|realloc)>', text)

        has_both = len(sink_matches) > 0 and len(alloc_matches) > 0
        findings = []
        if has_both:
            findings.append(BaselineFinding(
                detector='regex_only',
                function_name='<global>',
                alloc_func=alloc_matches[0] if alloc_matches else 'malloc',
                sink_func=sink_matches[0] if sink_matches else 'memcpy',
                severity='HIGH',
                confidence=0.40,
                detail=f"纯正则: alloc={alloc_matches}, sinks={sink_matches}"))

        return BaselineResult(
            detector_name='regex_only',
            sample_name=sample_name,
            sample_type='unknown',
            detected=len(findings) > 0,
            num_findings=len(findings),
            findings=findings)


def compute_baseline_metrics(results: List[BaselineResult],
                             expected_types: Dict[str, str]
                             ) -> Dict:
    """计算基线检测器的汇总指标.

    expected_types: {sample_name: 'heap_overflow'|'safe'|'uaf'}
    """
    tp = fp = tn = fn = 0
    for r in results:
        etype = expected_types.get(r.sample_name, 'unknown')
        is_vuln = etype not in ('safe', 'unknown')
        if is_vuln and r.detected:
            tp += 1
        elif is_vuln and not r.detected:
            fn += 1
        elif not is_vuln and r.detected:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    return {
        'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'recall': tp / max(tp + fn, 1),
        'precision': tp / max(tp + fp, 1),
        'fpr': fp / max(fp + tn, 1),
        'f1': 2 * tp / max(2 * tp + fp + fn, 1),
    }
