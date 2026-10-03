# 初始实现：补丁修复模式的抽象+跨二进制匹配
# 增加 CWE 映射 + 修复模板生成

"""Cross-Patch Fix Pattern Distiller — 补丁修复模式的跨二进制移植。

问题：已知 binary A 上的补丁 P_A 修复了漏洞 V（如 CWE-120 缓冲区溢出）。
binary B 上有类似的代码模式但尚未修补。能否从 P_A 中提取"修复本质"，
自动生成针对 B 的修复建议？

方法：
  1. Fix Essence 提取：从补丁中抽象修复模式（不是具体指令，而是语义操作）
  2. 修复模式表示：
     - 前置条件（什么条件下需要此修复）
     - 修复操作（添加了什么检查/替换了什么函数）
     - 后置条件（修复后的安全属性）
  3. 跨二进制匹配：在目标 binary 中搜索匹配前置条件的代码位置
  4. 修复建议生成：输出针对每个匹配位置的修复建议

Fix Essence 的形式：
  一组 (pattern, replacement, constraint) 三元组，
  其中 pattern 匹配漏洞代码，replacement 是修复后的代码。

与 CVE "superseded by" 的差异：
  superseded by 是同一 binary 上的补丁替代关系。
  本模块是跨 binary 的修复知识迁移——首次实现此概念。
"""

import re
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class FixCategory(str, Enum):
    BOUNDS_CHECK = "bounds_check"
    NULL_CHECK = "null_check"
    FUNCTION_REPLACE = "function_replace"
    INPUT_SANITIZE = "input_sanitize"
    CANARY_INSERT = "canary_insert"
    FORMAT_STRING_FIX = "format_string_fix"
    INTEGER_OVERFLOW_CHECK = "integer_overflow_check"


@dataclass
class FixEssence:
    """从补丁中提取的修复本质——跨 binary 可移植的修复描述。"""
    essence_id: str = ""
    category: FixCategory = FixCategory.BOUNDS_CHECK
    # 前置条件：目标 binary 中需要此修复的代码特征
    precondition: str = ""
    # 漏洞代码模式（正则）
    vulnerable_pattern: str = ""
    # 修复后的代码模式
    fixed_pattern: str = ""
    # CWE 编号
    cwe_id: str = ""
    # 来源补丁
    source_patch_id: str = ""
    # 可靠性评分（基于来源补丁的验证结果）
    reliability: float = 0.5

    def to_dict(self) -> Dict:
        return {
            'essence_id': self.essence_id,
            'category': self.category.value,
            'precondition': self.precondition,
            'vuln_pattern': self.vulnerable_pattern,
            'fixed_pattern': self.fixed_pattern,
            'cwe': self.cwe_id,
            'source': self.source_patch_id,
            'reliability': self.reliability,
        }


@dataclass
class FixCandidate:
    """在目标 binary 中匹配到的候选修复位置。"""
    target_function: str = ""
    target_address: int = 0
    matched_pattern: str = ""
    essence: Optional[FixEssence] = None
    match_confidence: float = 0.0
    suggested_fix: str = ""


@dataclass
class DistillationReport:
    """修复模式蒸馏报告。"""
    source_patch_id: str = ""
    target_binary_id: str = ""
    essence: Optional[FixEssence] = None
    candidates: List[FixCandidate] = field(default_factory=list)
    # 统计
    high_confidence_matches: int = 0
    total_matches: int = 0
    # 建议
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'source': self.source_patch_id,
            'target': self.target_binary_id,
            'category': self.essence.category.value if self.essence else 'unknown',
            'matches': self.total_matches,
            'high_conf': self.high_confidence_matches,
            'recommendations': self.recommended_actions[:5],
        }


# Fix Essence 提取器

class FixEssenceExtractor:
    """从已知补丁中提取跨二进制可移植的修复本质。

    分析补丁前后汇编变化，抽象出：
      - 漏洞模式（什么样的代码需要修复）
      - 修复模式（修复成什么样）
    """

    # 已知漏洞→修复映射
    _VULN_FIX_TEMPLATES = {
        FixCategory.BOUNDS_CHECK: FixEssence(
            category=FixCategory.BOUNDS_CHECK,
            precondition="函数接受外部输入的长度参数",
            vulnerable_pattern=r'\bcall\s+.*\b(memcpy|strcpy|strcat|read)\b',
            fixed_pattern="call前插入: cmp <len_reg>, <bound>; jbe .ok; call abort",
            cwe_id="CWE-120",
            reliability=0.85,
        ),
        FixCategory.NULL_CHECK: FixEssence(
            category=FixCategory.NULL_CHECK,
            precondition="函数接收指针参数且直接解引用",
            vulnerable_pattern=r'\bmov\s+\w+,\s*\[(rdi|rsi|rdx)\b',
            fixed_pattern="解引用前插入: test <ptr_reg>, <ptr_reg>; jz .error",
            cwe_id="CWE-476",
            reliability=0.90,
        ),
        FixCategory.FUNCTION_REPLACE: FixEssence(
            category=FixCategory.FUNCTION_REPLACE,
            precondition="使用了危险 C 库函数",
            vulnerable_pattern=r'\bcall\s+.*\b(strcpy|strcat|gets|sprintf)\b',
            fixed_pattern="替换为: strncpy/strncat/fgets/snprintf + 长度参数",
            cwe_id="CWE-676",
            reliability=0.95,
        ),
        FixCategory.INPUT_SANITIZE: FixEssence(
            category=FixCategory.INPUT_SANITIZE,
            precondition="用户输入用于系统调用或命令执行",
            vulnerable_pattern=r'\bcall\s+.*\b(system|popen|execve)\b',
            fixed_pattern="调用前插入输入过滤: and/compare 移除特殊字符",
            cwe_id="CWE-78",
            reliability=0.80,
        ),
        FixCategory.FORMAT_STRING_FIX: FixEssence(
            category=FixCategory.FORMAT_STRING_FIX,
            precondition="printf 族函数使用了用户控制的格式字符串",
            vulnerable_pattern=r'\bcall\s+printf\b(?!.*"%")',
            fixed_pattern="替换 printf(user_str) → printf(\"%s\", user_str)",
            cwe_id="CWE-134",
            reliability=0.88,
        ),
        FixCategory.INTEGER_OVERFLOW_CHECK: FixEssence(
            category=FixCategory.INTEGER_OVERFLOW_CHECK,
            precondition="涉及大小计算且用于内存分配",
            vulnerable_pattern=r'\b(add|mul|imul)\s+.*\bcall\s+malloc\b',
            fixed_pattern="计算后插入溢出检查: jo .overflow_handler",
            cwe_id="CWE-190",
            reliability=0.70,
        ),
    }

    def extract(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "") -> Optional[FixEssence]:
        """从补丁汇编中提取修复本质。"""
        orig_text = '\n'.join(original_asm)
        patch_text = '\n'.join(patched_asm)

        # 对每个已知模板检查是否匹配
        for category, template in self._VULN_FIX_TEMPLATES.items():
            if re.search(template.vulnerable_pattern, orig_text, re.I):
                essence = FixEssence(
                    essence_id=hashlib.sha256(
                        (category.value + patch_id).encode()
                    ).hexdigest()[:16],
                    category=category,
                    precondition=template.precondition,
                    vulnerable_pattern=template.vulnerable_pattern,
                    fixed_pattern=template.fixed_pattern,
                    cwe_id=template.cwe_id,
                    source_patch_id=patch_id,
                    reliability=template.reliability,
                )
                return essence
        return None


# 跨 Binary 匹配器

class CrossBinaryFixMatcher:
    """在目标 binary 中搜索匹配 Fix Essence 的代码位置。

    对每个 target function 的汇编，用 essence 的 vulnerable_pattern
    做正则匹配。匹配到的位置即为候选修复点。
    """

    def match(self, essence: FixEssence,
              target_functions: Dict[str, List[str]]
              # {function_name: [asm_lines]}
              ) -> List[FixCandidate]:
        """在目标 binary 的所有函数中搜索匹配。"""
        candidates = []
        pattern = re.compile(essence.vulnerable_pattern, re.I)

        for func_name, asm_lines in target_functions.items():
            for i, line in enumerate(asm_lines):
                stripped = line.strip()
                m = pattern.search(stripped)
                if not m:
                    continue
                # 提取上下文（前后 3 行）
                context_start = max(i - 3, 0)
                context_end = min(i + 4, len(asm_lines))
                context = '\n'.join(asm_lines[context_start:context_end])

                confidence = self._compute_confidence(stripped, essence)
                candidate = FixCandidate(
                    target_function=func_name,
                    target_address=0,  # 需要反汇编提供地址
                    matched_pattern=stripped,
                    essence=essence,
                    match_confidence=confidence,
                    suggested_fix=self._generate_fix_suggestion(
                        context, essence),
                )
                candidates.append(candidate)

        # 按置信度排序
        candidates.sort(key=lambda c: c.match_confidence, reverse=True)
        return candidates

    def _compute_confidence(self, matched_line: str,
                            essence: FixEssence) -> float:
        """计算匹配置信度。"""
        conf = essence.reliability * 0.7  # 基础：模板可靠性
        # 模式匹配质量
        if essence.category == FixCategory.FUNCTION_REPLACE:
            # 检查是否确实是危险函数调用（非注释/非间接调用）
            if 'call' in matched_line.lower() and ';' not in matched_line:
                conf += 0.15
        elif essence.category == FixCategory.BOUNDS_CHECK:
            # memcpy 的第三个参数是 size → 高置信
            if 'memcpy' in matched_line.lower():
                conf += 0.10
        return min(conf, 1.0)

    def _generate_fix_suggestion(self, context: str,
                                 essence: FixEssence) -> str:
        """基于修复本质生成针对性的修复建议。"""
        if essence.category == FixCategory.BOUNDS_CHECK:
            return ("在此位置之前插入边界检查:\n"
                    "  cmp <len>, <max_allowed>\n"
                    "  jbe .safe\n"
                    "  mov eax, -ERANGE\n"
                    "  jmp .error_return")
        elif essence.category == FixCategory.NULL_CHECK:
            return ("在此位置之前插入空指针检查:\n"
                    "  test <ptr>, <ptr>\n"
                    "  jz .null_error")
        elif essence.category == FixCategory.FUNCTION_REPLACE:
            return "将调用替换为带长度限制的安全版本 (strncpy/strncat/snprintf)"
        elif essence.category == FixCategory.FORMAT_STRING_FIX:
            return "将 printf(user_str) 改为 printf(\"%s\", user_str)"
        else:
            return "参考模板: %s" % essence.fixed_pattern


# 蒸馏引擎

class FixDistiller:
    """修复模式蒸馏引擎。

    用法:
        distiller = FixDistiller()
        report = distiller.distill(
            source_original_asm, source_patched_asm,
            target_functions, source_patch_id='CVE-2024-0001')
    """

    def __init__(self):
        self._extractor = FixEssenceExtractor()
        self._matcher = CrossBinaryFixMatcher()

    def distill(self, source_original_asm: List[str],
                source_patched_asm: List[str],
                target_functions: Dict[str, List[str]],
                source_patch_id: str = "",
                target_binary_id: str = "") -> DistillationReport:
        """修复知识蒸馏主流程。"""
        report = DistillationReport(
            source_patch_id=source_patch_id,
            target_binary_id=target_binary_id)

        # 提取修复本质
        essence = self._extractor.extract(
            source_original_asm, source_patched_asm, source_patch_id)
        if not essence:
            report.recommended_actions.append(
                "无法从源补丁中提取修复本质——补丁可能属于未知模式")
            return report
        report.essence = essence

        # 在目标 binary 中匹配
        candidates = self._matcher.match(essence, target_functions)
        report.candidates = candidates
        report.total_matches = len(candidates)
        report.high_confidence_matches = sum(
            1 for c in candidates if c.match_confidence >= 0.75)

        # 生成建议
        if report.high_confidence_matches > 0:
            report.recommended_actions.append(
                "发现 %d 个高置信度匹配——建议优先审查并按模板应用修复" % (
                    report.high_confidence_matches))
        elif report.total_matches > 0:
            report.recommended_actions.append(
                "发现 %d 个候选位置——置信度不足以自动修复，需人工确认" % (
                    report.total_matches))
        else:
            report.recommended_actions.append(
                "目标 binary 中未找到匹配——可能不需要此修复或代码差异过大")

        return report
