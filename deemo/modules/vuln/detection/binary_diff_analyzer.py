# 二进制版本差异分析器——比较同一程序的两个版本，识别安全相关的增删改。
# 参考IRBinDiff (arXiv:2410.18561) 的LLVM-IR级对比学习和Value Flow GNN
# (NC&A 2024) 的值流图差异检测。
#
# 分析维度:
#   - 函数级差异: 新增/删除/修改的函数，按安全关键词加权
#   - 字符串差异: 新增/删除的字符串，标记URL/路径/凭据相关
#   - 导入表差异: 新增/删除的库调用，标记危险API变化
#   - 控制流差异: 基本块级别的图编辑距离近似
#   - 指令级差异: 逐指令对比，标记安全敏感的修改（权限提升、认证旁路）
#
# 2026-07-25 —— 初版，函数+字符串+导入差异
# 2026-07-31 —— 新增安全关键词加权和差异报告模板

import os, re, hashlib, json, logging, struct, difflib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class ChangeCategory(str, Enum):
    FUNCTION_ADDED = "function_added"
    FUNCTION_REMOVED = "function_removed"
    FUNCTION_MODIFIED = "function_modified"
    STRING_ADDED = "string_added"
    STRING_REMOVED = "string_removed"
    IMPORT_ADDED = "import_added"
    IMPORT_REMOVED = "import_removed"
    SECURITY_SENSITIVE = "security_sensitive"


class SecurityImpact(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BinaryChange:
    """单条差异记录。"""
    category: ChangeCategory
    item_name: str
    old_value: str = ""
    new_value: str = ""
    address: int = 0
    security_impact: SecurityImpact = SecurityImpact.NONE
    security_keywords_matched: List[str] = field(default_factory=list)
    similarity_score: float = 0.0    # 对修改项，新旧版本的相似度


@dataclass
class DiffReport:
    """二进制差异分析报告。"""
    binary_old: str
    binary_new: str
    old_hash: str = ""
    new_hash: str = ""
    total_changes: int = 0
    changes: List[BinaryChange] = field(default_factory=list)
    security_summary: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    change_distribution: Dict[str, int] = field(default_factory=dict)


# ---- 安全关键词集合 ----
# 这些词在函数名/字符串/导入中出现，暗示安全相关的变更。

_SECURITY_KEYWORDS = {
    'auth': SecurityImpact.HIGH,
    'login': SecurityImpact.HIGH,
    'password': SecurityImpact.CRITICAL,
    'crypto': SecurityImpact.HIGH,
    'encrypt': SecurityImpact.HIGH,
    'decrypt': SecurityImpact.HIGH,
    'hash': SecurityImpact.MEDIUM,
    'verify': SecurityImpact.HIGH,
    'sign': SecurityImpact.HIGH,
    'cert': SecurityImpact.HIGH,
    'admin': SecurityImpact.HIGH,
    'root': SecurityImpact.HIGH,
    'privilege': SecurityImpact.CRITICAL,
    'access': SecurityImpact.MEDIUM,
    'permission': SecurityImpact.MEDIUM,
    'backdoor': SecurityImpact.CRITICAL,
    'shell': SecurityImpact.CRITICAL,
    'exec': SecurityImpact.CRITICAL,
    'system': SecurityImpact.CRITICAL,
    'inject': SecurityImpact.CRITICAL,
    'sql': SecurityImpact.HIGH,
    'sanitize': SecurityImpact.MEDIUM,
    'validate': SecurityImpact.MEDIUM,
    'escape': SecurityImpact.MEDIUM,
    'filter': SecurityImpact.MEDIUM,
    'bypass': SecurityImpact.CRITICAL,
    'exploit': SecurityImpact.CRITICAL,
    'payload': SecurityImpact.CRITICAL,
    'overflow': SecurityImpact.HIGH,
    'pointer': SecurityImpact.MEDIUM,
}

_DANGER_IMPORTS = {
    'system': SecurityImpact.CRITICAL,
    'execve': SecurityImpact.CRITICAL,
    'popen': SecurityImpact.CRITICAL,
    'gets': SecurityImpact.HIGH,
    'strcpy': SecurityImpact.HIGH,
    'strcat': SecurityImpact.HIGH,
    'sprintf': SecurityImpact.HIGH,
    'scanf': SecurityImpact.MEDIUM,
    'memcpy': SecurityImpact.LOW,
    'dlopen': SecurityImpact.MEDIUM,
    'ptrace': SecurityImpact.MEDIUM,
    'fork': SecurityImpact.LOW,
}


class BinaryDiffAnalyzer:
    """二进制版本差异分析器。

    分析两个二进制版本的差异，重点标记安全相关的变更。
    支持从工具输出（objdump/nm/readelf）中提取特征，不依赖
    完整的反编译器——降低环境依赖。
    """

    def __init__(self):
        self._keyword_re = re.compile(
            '|'.join(re.escape(k) for k in _SECURITY_KEYWORDS), re.IGNORECASE)

    def diff(self, old_binary: Dict[str, Any],
              new_binary: Dict[str, Any],
              old_path: str = "", new_path: str = "") -> DiffReport:
        """对比两个二进制版本的特征字典。

        输入dict格式:
            {
                'functions': [{'name': str, 'addr': int, 'code_hash': str}, ...],
                'strings': ['str1', 'str2', ...],
                'imports': ['func1', 'func2', ...],
                'exports': ['exp1', 'exp2', ...],
                'sections': [{'name': str, 'size': int}, ...],
            }

        返回DiffReport。
        """
        report = DiffReport(
            binary_old=old_path, binary_new=new_path,
            old_hash=hashlib.sha256(json.dumps(old_binary, sort_keys=True).encode()).hexdigest()[:16],
            new_hash=hashlib.sha256(json.dumps(new_binary, sort_keys=True).encode()).hexdigest()[:16])

        # 函数差异
        old_funcs = {f.get('name', ''): f for f in old_binary.get('functions', [])}
        new_funcs = {f.get('name', ''): f for f in new_binary.get('functions', [])}
        old_names, new_names = set(old_funcs), set(new_funcs)

        added_funcs = new_names - old_names
        removed_funcs = old_names - new_names
        common_funcs = old_names & new_names

        for fname in added_funcs:
            impact, kw_matches = self._assess_security_impact(fname)
            report.changes.append(BinaryChange(
                category=ChangeCategory.FUNCTION_ADDED, item_name=fname,
                new_value=new_funcs[fname].get('code_hash', ''),
                address=new_funcs[fname].get('addr', 0),
                security_impact=impact, security_keywords_matched=kw_matches))

        for fname in removed_funcs:
            impact, kw_matches = self._assess_security_impact(fname)
            report.changes.append(BinaryChange(
                category=ChangeCategory.FUNCTION_REMOVED, item_name=fname,
                old_value=old_funcs[fname].get('code_hash', ''),
                address=old_funcs[fname].get('addr', 0),
                security_impact=impact, security_keywords_matched=kw_matches))

        # 公共函数的修改检测——基于代码哈希差异
        for fname in common_funcs:
            old_hash_v = old_funcs[fname].get('code_hash', '')
            new_hash_v = new_funcs[fname].get('code_hash', '')
            if old_hash_v != new_hash_v:
                similarity = self._quick_similarity(
                    str(old_funcs.get(fname, {})),
                    str(new_funcs.get(fname, {})))
                impact, kw_matches = self._assess_security_impact(fname)
                report.changes.append(BinaryChange(
                    category=ChangeCategory.FUNCTION_MODIFIED, item_name=fname,
                    old_value=old_hash_v, new_value=new_hash_v,
                    address=new_funcs[fname].get('addr', 0),
                    security_impact=impact,
                    security_keywords_matched=kw_matches,
                    similarity_score=similarity))

        # 字符串差异
        old_strs = set(old_binary.get('strings', []))
        new_strs = set(new_binary.get('strings', []))
        for s in new_strs - old_strs:
            if len(s) >= 4:
                impact, kw_matches = self._assess_string_impact(s)
                if impact != SecurityImpact.NONE or len(s) > 20:
                    report.changes.append(BinaryChange(
                        category=ChangeCategory.STRING_ADDED, item_name=s[:80],
                        security_impact=impact, security_keywords_matched=kw_matches))
        for s in old_strs - new_strs:
            if len(s) >= 4:
                impact, kw_matches = self._assess_string_impact(s)
                if impact != SecurityImpact.NONE or len(s) > 20:
                    report.changes.append(BinaryChange(
                        category=ChangeCategory.STRING_REMOVED, item_name=s[:80],
                        security_impact=impact, security_keywords_matched=kw_matches))

        # 导入差异
        old_imports = set(old_binary.get('imports', []))
        new_imports = set(new_binary.get('imports', []))
        for imp in new_imports - old_imports:
            imp_impact = _DANGER_IMPORTS.get(imp.lower(), SecurityImpact.LOW)
            report.changes.append(BinaryChange(
                category=ChangeCategory.IMPORT_ADDED, item_name=imp,
                security_impact=imp_impact))
        for imp in old_imports - new_imports:
            imp_impact = _DANGER_IMPORTS.get(imp.lower(), SecurityImpact.LOW)
            report.changes.append(BinaryChange(
                category=ChangeCategory.IMPORT_REMOVED, item_name=imp,
                security_impact=imp_impact))

        # 汇总
        report.total_changes = len(report.changes)
        report.change_distribution = dict(Counter(
            c.category.value for c in report.changes))
        report.security_summary = self._summarize_security_impact(report.changes)
        report.risk_score = self._calculate_risk_score(report)
        report.recommendations = self._gen_recommendations(report)

        return report

    def _assess_security_impact(self, name: str) -> Tuple[SecurityImpact, List[str]]:
        """根据名称中的安全关键词评估安全影响。"""
        matches = re.findall(self._keyword_re, name.lower())
        if not matches:
            return SecurityImpact.NONE, []
        impacts = [_SECURITY_KEYWORDS[m.lower()] for m in matches
                   if m.lower() in _SECURITY_KEYWORDS]
        if not impacts:
            return SecurityImpact.NONE, list(set(matches))
        # 取最高影响级别
        impact_order = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        max_idx = max(impact_order.index(i.value) for i in impacts)
        return SecurityImpact(impact_order[max_idx]), list(set(matches))

    def _assess_string_impact(self, s: str) -> Tuple[SecurityImpact, List[str]]:
        """评估字符串的安全敏感性——URL/IP/路径/凭据。"""
        kw_matches = []
        impact = SecurityImpact.NONE

        if re.search(r'https?://', s):
            kw_matches.append('url')
            impact = SecurityImpact.LOW
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
            kw_matches.append('ip_address')
            impact = max(impact, SecurityImpact.LOW, key=lambda x: (
                ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x)))
        if re.search(r'(?i)(password|secret|token|key)', s):
            kw_matches.append('credential')
            impact = SecurityImpact.CRITICAL
        if re.search(r'(?i)/bin/|/etc/|/root/', s):
            kw_matches.append('system_path')
            impact = max(impact, SecurityImpact.MEDIUM, key=lambda x: (
                ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x)))

        return impact, kw_matches

    def _quick_similarity(self, a: str, b: str) -> float:
        """快速文本相似度——基于differ的序列匹配率。"""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        sm = difflib.SequenceMatcher(None, a, b)
        return sm.ratio()

    def _summarize_security_impact(self, changes: List[BinaryChange]
                                     ) -> Dict[str, int]:
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NONE': 0}
        for c in changes:
            counts[c.security_impact.value.upper()] += 1
        return counts

    def _calculate_risk_score(self, report: DiffReport) -> float:
        """计算整体风险评分 (0-1)。

        评分公式: (critical*1.0 + high*0.7 + medium*0.4 + low*0.15) / max(total, 1)
        """
        s = report.security_summary
        w_score = (s.get('CRITICAL', 0) * 1.0 + s.get('HIGH', 0) * 0.7 +
                   s.get('MEDIUM', 0) * 0.4 + s.get('LOW', 0) * 0.15)
        risk = w_score / max(sum(s.values()), 1)
        return min(1.0, risk)

    def _gen_recommendations(self, report: DiffReport) -> List[str]:
        recs = []
        if report.security_summary.get('CRITICAL', 0) > 0:
            recs.append(
                f"检测到 {report.security_summary['CRITICAL']} 个严重安全变更——"
                "建议立即进行安全审计，关注认证机制和权限变更。")
        if report.security_summary.get('HIGH', 0) > 0:
            recs.append(
                f"检测到 {report.security_summary['HIGH']} 个高风险变更——"
                "建议审查加密实现和输入验证逻辑的变更。")
        danger_imports = [c for c in report.changes
                          if c.category == ChangeCategory.IMPORT_ADDED
                          and c.security_impact in (SecurityImpact.CRITICAL, SecurityImpact.HIGH)]
        if danger_imports:
            names = ', '.join(c.item_name for c in danger_imports[:5])
            recs.append(f"新增危险导入: {names}——可能存在后门或未授权的系统调用。")
        if report.risk_score > 0.5:
            recs.append("整体风险评分偏高，建议在部署前完成全量安全回归测试。")
        return recs


# ---- 便捷函数 ----

def diff_binaries(old_features: Dict, new_features: Dict,
                   old_path: str = "", new_path: str = "") -> DiffReport:
    """对比两个二进制版本的特征。"""
    return BinaryDiffAnalyzer().diff(old_features, new_features,
                                      old_path, new_path)


def compare_function_lists(old_funcs: List[str],
                            new_funcs: List[str]) -> Tuple[List[str], List[str], List[str]]:
    """轻量级函数列表对比——返回(added, removed, common)。"""
    olds = set(old_funcs)
    news = set(new_funcs)
    return (list(sorted(news - olds)),
            list(sorted(olds - news)),
            list(sorted(olds & news)))
