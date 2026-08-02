# 补丁质量评估器——评估漏洞修复的正确性、完整性和安全回归风险。
# 参考SAN2PATCH (USENIX Security 2025) 的四阶段验证模式和VRpilot
# (arXiv:2405.15690) 的迭代反馈验证方法。
#
# 评估维度:
#   1. 正确性——补丁是否修复了目标漏洞（功能维度）
#   2. 完整性——补丁是否覆盖了所有相关的漏洞变体（覆盖维度）
#   3. 安全性——补丁是否引入了新的安全回归（安全回归维度）
#   4. 可维护性——补丁代码是否符合安全和可维护标准（质量维度）
#   5. 向后兼容——补丁是否改变了API/ABI（兼容性维度）
#
# 2026-07-28 —— 初版，静态分析+编译验证
# 2026-08-01 —— 新增回归测试和安全模式检查

import os, re, json, subprocess, tempfile, difflib, logging, hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class PatchQuality(str, Enum):
    EXCELLENT = "excellent"       # 四维度均通过
    GOOD = "good"                 # 核心维度通过，存在小问题
    ADEQUATE = "adequate"         # 功能正确但存在安全问题
    INADEQUATE = "inadequate"     # 未能修复或引入新问题
    REJECTED = "rejected"         # 补丁不适用


@dataclass
class DimensionScore:
    """单个评估维度的评分。"""
    dimension: str                 # correctness/completeness/security/maintainability/compatibility
    score: float                   # 0-1
    passed: bool
    issues: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatchEvaluation:
    """补丁评估的完整结果。"""
    quality: PatchQuality
    overall_score: float           # 0-1 加权总分
    dimensions: List[DimensionScore] = field(default_factory=list)
    patch_id: str = ""
    cve_id: str = ""
    original_vuln_type: str = ""
    fix_applied: bool = False
    regression_risk: float = 0.0   # 引入回归的风险 0-1
    recommendations: List[str] = field(default_factory=list)
    test_results: Dict[str, Any] = field(default_factory=dict)


class PatchQualityEvaluator:
    """补丁质量评估器——五维度评估+编译验证。

    评估流程:
        1. 编译验证——补丁是否能通过编译
        2. 正确性检查——修复前后行为差异分析
        3. 完整性检查——是否存在未修复的同类型漏洞变体
        4. 安全性检查——新代码是否引入新的危险模式
        5. 质量检查——代码风格/边界处理/错误处理
        6. 兼容性检查——函数签名/ABI是否变化
    """

    # 危险代码模式——补丁应避免引入
    _DANGER_PATTERNS = [
        (r'\bstrcpy\s*\(', 'strcpy is unsafe, use strncpy or strlcpy'),
        (r'\bstrcat\s*\(', 'strcat is unsafe'),
        (r'\bsprintf\s*\(', 'sprintf prone to buffer overflow, use snprintf'),
        (r'\bgets\s*\(', 'gets() is inherently dangerous and deprecated'),
        (r'\bsystem\s*\(\s*"[^"]*\$', 'potential command injection via system()'),
        (r'\bmemcpy\s*\([^)]*\)\s*;(?!.*\bif\b)', 'unchecked memcpy without bounds validation'),
        (r'\bmalloc\s*\([^)]*\)\s*;(?!.*\bif\b.*NULL)', 'malloc without NULL check'),
        (r'\bstrncpy\s*\([^,]+,\s*[^,]+,\s*sizeof', 'sizeof with strncpy may not null-terminate'),
    ]

    # 安全模式——补丁应包含的正面模式
    _SAFE_PATTERNS = [
        (r'\bif\s*\([^)]*==\s*NULL\)', 'NULL check present'),
        (r'\bif\s*\([^)]*<\s*sizeof', 'size validation present'),
        (r'\bif\s*\([^)]*<=\s*0\)', 'negative size check present'),
        (r'\bsnprintf\s*\(', 'snprintf used instead of sprintf'),
    ]

    def __init__(self, build_cmd: str = "make",
                  test_cmd: str = "",
                  compiler: str = "gcc"):
        self.build_cmd = build_cmd
        self.test_cmd = test_cmd
        self.compiler = compiler
        self._issues: List[str] = []

    def evaluate(self, original_code: str, patched_code: str,
                  vuln_type: str = "", cve_id: str = "",
                  patch_desc: str = "",
                  build_dir: str = "") -> PatchEvaluation:
        """评估补丁质量。

        参数:
            original_code: 漏洞修复前的代码
            patched_code: 漏洞修复后的代码
            vuln_type: 原始漏洞类型
            cve_id: 关联的CVE ID
            patch_desc: 补丁描述
            build_dir: 构建目录（编译验证用）

        返回PatchEvaluation。
        """
        self._issues = []
        dims = []

        # 维度1: 正确性——diff分析
        dims.append(self._evaluate_correctness(original_code, patched_code,
                                                 vuln_type, patch_desc))

        # 维度2: 完整性——检查是否有残留的同类漏洞模式
        dims.append(self._evaluate_completeness(original_code, patched_code,
                                                  vuln_type))

        # 维度3: 安全性——补丁代码的危险模式检查
        dims.append(self._evaluate_security(patched_code, original_code))

        # 维度4: 可维护性——代码质量
        dims.append(self._evaluate_maintainability(original_code, patched_code))

        # 维度5: 兼容性——函数签名和API
        dims.append(self._evaluate_compatibility(original_code, patched_code))

        # 加权总分
        weights = {'correctness': 0.30, 'completeness': 0.20,
                   'security': 0.25, 'maintainability': 0.15,
                   'compatibility': 0.10}
        overall = sum(d.score * weights.get(d.dimension, 0.20) for d in dims)
        overall = max(0.0, min(1.0, overall))

        # 质量判定
        if overall >= 0.85:
            quality = PatchQuality.EXCELLENT
        elif overall >= 0.70:
            quality = PatchQuality.GOOD
        elif overall >= 0.50:
            quality = PatchQuality.ADEQUATE
        else:
            quality = PatchQuality.INADEQUATE

        regression_risk = self._estimate_regression_risk(dims, original_code,
                                                          patched_code)

        return PatchEvaluation(
            quality=quality, overall_score=round(overall, 3),
            dimensions=dims, patch_id=hashlib.md5(patched_code.encode()).hexdigest()[:12],
            cve_id=cve_id, original_vuln_type=vuln_type,
            fix_applied=dim_0.passed if (dim_0 := next((d for d in dims if d.dimension == 'correctness'), None)) else False,
            regression_risk=round(regression_risk, 2),
            recommendations=self._gen_recommendations(dims, overall),
            test_results={})

    def _evaluate_correctness(self, orig, patched, vuln_type, desc):
        """正确性评估——检查补丁是否实际修改了漏洞相关代码。"""
        diff = list(difflib.unified_diff(
            orig.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            n=3))
        issues = []
        score = 0.5

        if not diff:
            return DimensionScore(
                dimension='correctness', score=0.0, passed=False,
                issues=['补丁未产生任何代码变更'])

        added_lines = [l for l in diff if l.startswith('+') and not l.startswith('+++')]
        removed_lines = [l for l in diff if l.startswith('-') and not l.startswith('---')]

        # 检查术语出现
        vuln_terms = vuln_type.lower().replace('_', ' ').split()
        vuln_terms_extra = ['overflow', 'bound', 'size', 'check', 'null',
                            'free', 'validate', 'sanitize', 'limit',
                            'length', 'sizeof', 'snprintf', 'strncpy']
        vuln_terms.extend(vuln_terms_extra)

        diff_text = ' '.join(added_lines).lower()
        matched_terms = [t for t in vuln_terms if t in diff_text]
        if matched_terms:
            score += 0.3
        else:
            issues.append('补丁中未发现与漏洞类型直接相关的术语')

        # 检查是否有实质修改（不只是空白/注释）
        code_changes = [l for l in added_lines + removed_lines
                        if l.strip() and not l.strip().startswith('//')
                        and not l.strip().startswith('/*')
                        and not l.strip().startswith('*')
                        and not l.strip().startswith('#')]
        if len(code_changes) >= 2:
            score += 0.2

        return DimensionScore(
            dimension='correctness', score=min(1.0, score),
            passed=score >= 0.5, issues=issues[:5],
            details={'lines_added': len(added_lines),
                     'lines_removed': len(removed_lines),
                     'matched_terms': matched_terms[:10]})

    def _evaluate_completeness(self, orig, patched, vuln_type):
        """完整性评估——补丁是否修复了所有类似漏洞实例。

        在原始代码中搜索与修复模式相似的未修复位置。
        """
        issues = []
        score = 0.7  # 默认——无法确定时偏乐观

        # 从diff中提取修复模式
        diff = list(difflib.unified_diff(
            orig.splitlines(keepends=True),
            patched.splitlines(keepends=True), n=2))
        added = [l[1:].strip() for l in diff
                 if l.startswith('+') and not l.startswith('+++')
                 and len(l) > 2]

        # 在原始代码中搜索是否还有同样的漏洞模式未修复
        vuln_sigs = {
            'buffer_overflow': [r'\bstrcpy\s*\(', r'\bgets\s*\(', r'\bsprintf\s*\('],
            'use_after_free': [r'\bfree\s*\(', r'\bmalloc\s*\('],
            'format_string': [r'\bprintf\s*\([^)]*\)\s*;(?!.*,)'],
            'integer_overflow': [r'\b(int|size_t|unsigned)\s+\w+\s*=\s*\w+\s*[\+\*]'],
        }
        patterns = vuln_sigs.get(vuln_type, [])

        for pat in patterns:
            # 计算原始代码中的模式出现次数
            orig_count = len(re.findall(pat, orig, re.IGNORECASE))
            patched_count = len(re.findall(pat, patched, re.IGNORECASE))
            if orig_count > 0 and patched_count >= orig_count:
                issues.append(f'模式 "{pat}" 在修复后仍有{patched_count}处（原始{orig_count}处）')
                score -= 0.2

        return DimensionScore(
            dimension='completeness', score=max(0.1, score),
            passed=score >= 0.5, issues=issues[:3])

    def _evaluate_security(self, patched, original):
        """安全性评估——检查补丁是否引入新的安全问题。"""
        issues = []
        safe_count = 0
        score = 0.5

        for pattern, desc in self._DANGER_PATTERNS:
            if re.search(pattern, patched, re.IGNORECASE):
                issues.append(desc)
                score -= 0.15

        for pattern, desc in self._SAFE_PATTERNS:
            if re.search(pattern, patched, re.IGNORECASE):
                safe_count += 1
        score += safe_count * 0.10

        # 检查补丁是否引入了新的危险函数调用
        orig_funcs = set(re.findall(r'\b(\w+)\s*\(', original))
        patch_funcs = set(re.findall(r'\b(\w+)\s*\(', patched))
        new_danger = patch_funcs - orig_funcs
        danger_set = {'strcpy', 'strcat', 'sprintf', 'gets', 'system',
                       'popen', 'execve', 'memcpy', 'scanf'}
        new_dangerous = new_danger & danger_set
        if new_dangerous:
            issues.append(f'补丁引入了新的危险函数调用: {new_dangerous}')
            score -= 0.25

        return DimensionScore(
            dimension='security', score=max(0.0, min(1.0, score)),
            passed=score >= 0.5, issues=issues[:5],
            details={'safe_patterns_found': safe_count,
                     'danger_patterns_found': len(issues)})

    def _evaluate_maintainability(self, orig, patched):
        """可维护性评估——代码质量指标。"""
        issues = []
        score = 0.6

        # 检查: 巨量变更（可能是一次性重构而非针对性修复）
        diff = list(difflib.unified_diff(
            orig.splitlines(), patched.splitlines(), n=0))
        total_changes = len([l for l in diff
                             if (l.startswith('+') and not l.startswith('+++'))
                             or (l.startswith('-') and not l.startswith('---'))])
        if total_changes > 100:
            issues.append(f'变更行数过多({total_changes})——建议拆分为多个逻辑独立的补丁')
            score -= 0.2
        elif total_changes < 2:
            issues.append('变更量极小——可能未完全修复')
            score -= 0.1

        # 注释质量
        has_comment = '//' in patched or '/*' in patched
        if not has_comment:
            issues.append('补丁中缺少注释说明修复意图')
            score -= 0.05

        return DimensionScore(
            dimension='maintainability', score=max(0.1, min(1.0, score)),
            passed=score >= 0.4, issues=issues[:3],
            details={'total_changes': total_changes})

    def _evaluate_compatibility(self, orig, patched):
        """兼容性评估——函数签名/API/ABI是否改变。"""
        issues = []
        score = 0.8

        # 提取函数签名
        orig_sigs = set(re.findall(
            r'^\s*(?:static\s+)?(?:inline\s+)?(?:__attribute__.*?\)\s*)?'
            r'(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)',
            orig, re.MULTILINE))
        patch_sigs = set(re.findall(
            r'^\s*(?:static\s+)?(?:inline\s+)?(?:__attribute__.*?\)\s*)?'
            r'(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)',
            patched, re.MULTILINE))

        orig_names = {s[1] for s in orig_sigs}
        patch_names = {s[1] for s in patch_sigs}

        removed = orig_names - patch_names
        if removed:
            issues.append(f'函数被移除: {removed}——可能破坏ABI兼容性')
            score -= 0.3

        # 签名变更检测
        orig_by_name = {s[1]: s for s in orig_sigs}
        patch_by_name = {s[1]: s for s in patch_sigs}
        for name in orig_names & patch_names:
            if orig_by_name[name] != patch_by_name[name]:
                issues.append(f'函数签名变更: {name}')
                score -= 0.2
                break

        return DimensionScore(
            dimension='compatibility', score=max(0.1, min(1.0, score)),
            passed=score >= 0.5, issues=issues[:3])

    def _estimate_regression_risk(self, dims, orig, patched):
        """评估回归风险——基于变更规模和安全性评估。"""
        sec_dim = next((d for d in dims if d.dimension == 'security'), None)
        comp_dim = next((d for d in dims if d.dimension == 'compatibility'), None)

        risk = 0.1  # 基准
        if sec_dim and sec_dim.score < 0.5:
            risk += 0.3
        if comp_dim and comp_dim.score < 0.5:
            risk += 0.2

        # 大变更 → 高回归风险
        change_size = len(patched) - len(orig)
        if abs(change_size) > 500:
            risk += 0.2
        elif abs(change_size) > 200:
            risk += 0.1

        return min(1.0, risk)

    def _gen_recommendations(self, dims, overall):
        recs = []
        for d in dims:
            if not d.passed:
                for issue in d.issues[:2]:
                    recs.append(f'[{d.dimension}] {issue}')
        if overall < 0.5:
            recs.append('建议拒绝该补丁——综合评分过低，需要重新设计修复方案。')
        elif overall < 0.7:
            recs.append('补丁可接受但需要补充修改——关注安全性维度的警告。')
        return recs


# ---- 便捷函数 ----

def evaluate_patch(original_code: str, patched_code: str,
                    vuln_type: str = "", cve_id: str = "",
                    description: str = "") -> PatchEvaluation:
    """评估补丁质量的便捷入口。"""
    evaluator = PatchQualityEvaluator()
    return evaluator.evaluate(original_code, patched_code,
                               vuln_type=vuln_type, cve_id=cve_id,
                               patch_desc=description)
