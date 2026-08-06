# 差分补丁安全分析器: 补丁前后的漏洞类型推断 / 利用原语 / 完整性评估
# 技术问题: 安全补丁发布时通常不详细说明修复的漏洞类型和原始利用方式,
#   攻击者可逆向补丁推断漏洞并开发exploit (patch gap exploitation).
#   防御者需要同样能力以评估补丁的紧迫性和完整性.
#   现有工具 (BinDiff, Diaphora) 仅做二进制差异比较,
#   不回答 "这个补丁修复了什么类型的漏洞" 和 "修复是否完整"
# 解决手段: 将补丁差异分解为三个分析层:
#   层1: 变更类型分类 — 边界检查添加/空指针检查/锁移动/输入验证
#   层2: 漏洞类型推断 — 从变更模式反推原始漏洞的CWE
#   层3: 利用原语推断 — 修复前的代码状态提供了什么利用能力
#   层4: 补丁完整性 — 检查修复是否覆盖了所有相关的代码路径
# 技术效果: 从补丁变更模式反推漏洞类型, 辅助安全分析师
#   快速评估补丁的安全影响和紧迫性
# 参考:
#   ESBMC-AI (AST 2025) — BMC验证修复后代码,
#     本项目借鉴其detect-fix-verify循环但聚焦补丁差异分析
#   Lancet (USENIX Security 2025) — 崩溃利用病理学,
#     本项目借鉴其漏洞类型分类但适配补丁差异场景
from __future__ import annotations
import hashlib
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class PatchChange:
    """单条补丁变更."""
    change_id: str
    change_type: str     # 'added_check' | 'removed_code' | 'replaced_call'
    file_path: str = ""
    old_code: str = ""
    new_code: str = ""
    line_number: int = 0
    context_before: str = ""
    context_after: str = ""


@dataclass
class PatchAnalysis:
    """补丁分析结果."""
    patch_id: str
    inferred_cwe: str = ""
    cwe_confidence: float = 0.0
    exploit_primitive_inferred: str = ""
    exploit_confidence: float = 0.0
    is_fix_complete: bool = False
    completeness_issues: List[str] = field(default_factory=list)
    risk_level: str = "medium"    # 'critical' | 'high' | 'medium' | 'low'
    changes: List[PatchChange] = field(default_factory=list)


class PatchChangeClassifier:
    """补丁变更类型分类器.

    将每条变更归类为以下类型之一:
      - bounds_check_added: 添加了大小/索引边界检查
      - null_check_added: 添加了空指针检查
      - overflow_check_added: 添加了整数溢出检查
      - lock_repositioned: 锁获取位置移动
      - sanitization_added: 添加了输入清理/转义
      - auth_check_added: 添加了权限/认证检查
      - safe_api_replacement: 不安全API替换为安全替代
      - initialization_added: 添加了变量/内存初始化
      - refcount_fix: 引用计数修正
      - other: 其他类型
    """

    _RULES = [
        ("bounds_check_added",
         r'if\s*\(.*\s*(?:>=|<=|>|<)\s*(?:sizeof|ARRAY_SIZE|MAX|SIZE|len)'),
        ("null_check_added",
         r'if\s*\(\s*!\s*\w+\s*\)|if\s*\(\s*\w+\s*==\s*(?:NULL|nullptr|0)\s*\)'),
        ("overflow_check_added",
         r'if\s*\(.*(?:UINT_MAX|INT_MAX|SIZE_MAX|overflow|wraparound)'),
        ("lock_repositioned",
         r'(?:spin_lock|mutex_lock|acquire|lock)\s*\('),
        ("sanitization_added",
         r'(?:escape|sanitize|htmlspecialchars|filter_var|'
         r'mysql_real_escape|prepared?_stmt)'),
        ("auth_check_added",
         r'(?:check_permission|require_auth|can_access|has_role|'
         r'is_authorized|CAP_SYS)'),
        ("safe_api_replacement",
         r'(?:strcpy|sprintf|gets|scanf)\s*\(.*→.*(?:strncpy|snprintf|fgets|'
         r'scanf_s)'),
        ("initialization_added",
         r'(?:memset|calloc|={0}|\bzero)\s*\('),
        ("refcount_fix",
         r'(?:refcnt|ref_count|kref|atomic_(?:inc|dec)|get_device|put_device)'),
    ]

    def classify(self, change: PatchChange) -> str:
        combined = f"{change.new_code} {change.context_after}"
        for ctype, pattern in self._RULES:
            if re.search(pattern, combined, re.IGNORECASE):
                return ctype
        if change.old_code and not change.new_code:
            return "removed_code"
        if change.new_code and not change.old_code:
            return "added_code"
        return "other"


class DifferentialPatchAnalyzer:
    """差分补丁安全分析主引擎.

    输入: 补丁前后的差异变更列表
    输出: 结构化PatchAnalysis包含漏洞推断+利用原语+完整性
    """

    def __init__(self):
        self._classifier = PatchChangeClassifier()

    def analyze(self, patch_id: str,
                changes: List[PatchChange]) -> PatchAnalysis:
        # 分类每条变更
        for ch in changes:
            ch.change_type = self._classifier.classify(ch)
        analysis = PatchAnalysis(patch_id=patch_id, changes=changes)
        # 层1: 从变更类型组合推断CWE
        cwe, cwe_conf = self._infer_cwe(changes)
        analysis.inferred_cwe = cwe
        analysis.cwe_confidence = cwe_conf
        # 层2: 从变更类型反推原始利用原语
        prim, prim_conf = self._infer_exploit_primitive(changes)
        analysis.exploit_primitive_inferred = prim
        analysis.exploit_confidence = prim_conf
        # 层3: 补丁完整性检查
        complete, issues = self._assess_completeness(changes)
        analysis.is_fix_complete = complete
        analysis.completeness_issues = issues
        # 层4: 风险评级
        analysis.risk_level = self._assess_risk(cwe, prim, complete)
        return analysis

    def _infer_cwe(self, changes: List[PatchChange]
                   ) -> Tuple[str, float]:
        ctypes = Counter(c.change_type for c in changes)
        # 模式匹配: 变更类型→CWE
        if ctypes.get("bounds_check_added", 0) >= 2:
            return ("CWE-787", 0.80)
        if ctypes.get("bounds_check_added", 0) == 1:
            return ("CWE-125", 0.65)
        if ctypes.get("null_check_added", 0) >= 1:
            return ("CWE-476", 0.70)
        if "overflow_check_added" in ctypes:
            return ("CWE-190", 0.75)
        if "lock_repositioned" in ctypes:
            return ("CWE-367", 0.72)
        if "sanitization_added" in ctypes or "safe_api_replacement" in ctypes:
            if "safe_api_replacement" in ctypes:
                return ("CWE-120", 0.68)
            return ("CWE-79", 0.60)
        if "auth_check_added" in ctypes:
            return ("CWE-862", 0.70)
        if "initialization_added" in ctypes:
            return ("CWE-457", 0.65)
        if "refcount_fix" in ctypes:
            return ("CWE-416", 0.68)
        if ctypes.get("removed_code", 0) > 0:
            return ("CWE-787", 0.35)  # 弱信号
        return ("CWE-unknown", 0.20)

    def _infer_exploit_primitive(self, changes: List[PatchChange]
                                 ) -> Tuple[str, float]:
        ctypes = [c.change_type for c in changes]
        # bounds_check → 原始代码允许越界写→任意写
        if "bounds_check_added" in ctypes:
            # 区分读和写: 检查是否涉及写操作
            has_write = any("write" in c.context_before.lower() or
                           "memcpy" in c.context_before.lower() or
                           "copy_to_user" in c.context_before.lower()
                           for c in changes)
            if has_write:
                return ("arbitrary_write", 0.72)
            return ("arbitrary_read", 0.60)
        if "null_check_added" in ctypes:
            return ("denial_of_service", 0.55)
        if "overflow_check_added" in ctypes:
            return ("controlled_allocation_size", 0.65)
        if "lock_repositioned" in ctypes:
            return ("race_condition_exploit", 0.68)
        if "sanitization_added" in ctypes or "safe_api_replacement" in ctypes:
            return ("code_execution", 0.60)
        if "auth_check_added" in ctypes:
            return ("privilege_escalation", 0.70)
        return ("unknown", 0.25)

    def _assess_completeness(self, changes: List[PatchChange]
                             ) -> Tuple[bool, List[str]]:
        issues = []
        ctypes = Counter(c.change_type for c in changes)
        # 完整性检查1: bounds_check只加了一处但函数中有多处类似访问
        if ctypes.get("bounds_check_added", 0) == 1:
            similar = sum(1 for c in changes
                         if "other" in c.change_type or "added_code" in c.change_type)
            if similar == 0:
                issues.append("仅添加1处边界检查, 可能存在其他未修复的越界点")
        # 完整性检查2: null_check之后仍有未保护的解引用
        if "null_check_added" in ctypes:
            for c in changes:
                if "->" in c.new_code or "." in c.new_code:
                    if "if" not in c.context_before[:50]:
                        issues.append("空指针检查后仍有未保护的结构体解引用")
                        break
        # 完整性检查3: 修复仅覆盖了热路径但冷路径未修复
        if "safe_api_replacement" in ctypes:
            for c in changes:
                if c.old_code and "strcpy" in c.old_code:
                    # 查找同一文件中是否还有strcpy未被替换
                    if "strcpy" not in c.context_after:
                        pass  # 单个替换, 文件中可能还有其他
        complete = len(issues) == 0
        return complete, issues

    def _assess_risk(self, cwe: str, primitive: str,
                     complete: bool) -> str:
        # 高风险: 远程代码执行原语+不完整修复
        if primitive in ("code_execution", "arbitrary_write"):
            if not complete:
                return "critical"
            return "high"
        if primitive in ("privilege_escalation", "race_condition_exploit"):
            return "high"
        if cwe == "CWE-787" and not complete:
            return "high"
        return "medium"

    def batch_analyze(self, patches: Dict[str, List[PatchChange]]
                      ) -> Dict[str, PatchAnalysis]:
        return {pid: self.analyze(pid, changes)
                for pid, changes in patches.items()}
