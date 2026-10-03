# coding: utf-8
#
"""
语义补丁完整性验证-调用点契约推断器。

技术问题:
  现有补丁质量评估（patch_quality_evaluator）仅做静态模式匹配，
  无法判断补丁是否在语义层面完整修复了漏洞。
  攻击者可通过仅修补常见变体而保留等价利用路径来绕过检测。

解决方案:
  从函数的调用点（call sites）推断隐式契约（前置条件/后置条件/不变量），
  构建函数应有的行为边界。补丁必须使修复后代码满足此边界。

创新点:
  1. 调用点契约挖掘-从参数约束与实际使用模式反推前置条件
  2. 边界值合成-基于类型信息与调用上下文生成契约边界测试用例
  3. 与patch_quality_evaluator互补-后者检查代码模式，前者检查语义完备性

与现有工作差异:
  - COBRA/SRIF推断函数签名（非契约），用于漏洞检测而非补丁验证
  - Daikon推断运行时不变式（需执行轨迹），本模块仅需静态源码
  - 本方法: 纯静态 + 调用点模式挖掘 + 补丁完备性专用
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

_log = logging.getLogger(__name__)


# 契约表示


@dataclass
class FunctionContract:
    """函数的隐式契约-从调用点推断的行为边界"""
    function_name: str
    # 前置条件: 调用者必须保证的条件
    preconditions: List[str] = field(default_factory=list)
    # 后置条件: 函数执行后必须满足的条件
    postconditions: List[str] = field(default_factory=list)
    # 边界约束: 参数取值范围的推断
    param_bounds: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    # 非空约束: 哪些指针参数不允许NULL
    nonnull_params: Set[str] = field(default_factory=set)
    # 返回码约束: 返回值检查模式
    return_check_pattern: str = ""        # always_checked | sometimes_checked | unchecked
    # 调用点统计-契约推断的证据基础
    call_site_count: int = 0
    evidence_lines: List[int] = field(default_factory=list)


@dataclass
class ContractViolation:
    """补丁违反的契约条目"""
    contract_entry: str
    violation_type: str     # precondition_violated | postcondition_broken | bound_exceeded
    original_behavior: str
    patched_behavior: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    fix_location: str = ""


# 契约推断引擎


class ContractInferrer:
    """从调用点推断函数隐式契约。

    方法:
      扫描所有对目标函数的调用，提取:
        1. 前置条件: 调用前的if检查/断言/参数验证模式
        2. 后置条件: 调用后的返回值检查/errno检查/状态断言
        3. 参数边界: 数组索引范围、缓冲区大小与数据长度的关系

    推断可靠性分级:
      strong: ≥3个独立调用点展示相同模式
      moderate: 2个独立调用点
      weak: 仅1个调用点（提示性，不作为强制约束）
    """

    # 调用点前置检查模式
    _PRECONDITION_PATTERNS = [
        # if (ptr != NULL) - nonnull约束
        (r'if\s*\(\s*(\w+)\s*!=\s*(?:NULL|0|nullptr)\s*\)', 'nonnull'),
        # if (len <= size) - 缓冲区大小约束
        (r'if\s*\(\s*(\w+)\s*<=\s*(\w+)\s*\)', 'bound'),
        # assert(ptr != NULL) - 断言前置条件
        (r'assert\s*\(\s*(\w+)\s*!=\s*(?:NULL|0|nullptr)\s*\)', 'assert_nonnull'),
        # if (index < max) - 索引边界
        (r'if\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)', 'index_bound'),
        # if (size > 0) - 正数约束
        (r'if\s*\(\s*(\w+)\s*>\s*0\s*\)', 'positive'),
    ]

    # 调用后检查模式-推断后置条件
    _POSTCONDITION_PATTERNS = [
        # if (ret < 0) - 错误处理期望
        (r'if\s*\(\s*(\w+)\s*<\s*0\s*\)', 'error_check'),
        # if (ret == -1) - 精确错误码检查
        (r'if\s*\(\s*(\w+)\s*==\s*-1\s*\)', 'exact_error'),
        # if (!ptr) after call - 空返回值检查
        (r'if\s*\(\s*!\s*(\w+)\s*\)', 'null_return_check'),
        # errno check
        (r'if\s*\(\s*errno\s*==', 'errno_check'),
    ]

    def __init__(self):
        self._contract_cache: Dict[str, FunctionContract] = {}

    def infer_from_source(self, source_lines: List[str],
                           function_name: str) -> FunctionContract:
        """从源码行列表推断目标函数的契约。

        参数:
          source_lines: 源码文件的行列表
          function_name: 目标函数名

        返回FunctionContract。
        """
        contract = FunctionContract(function_name=function_name)
        calls = self._find_call_sites(source_lines, function_name)
        contract.call_site_count = len(calls)

        if not calls:
            _log.debug("函数%s无调用点-契约为空", function_name)
            return contract

        # 对每个调用点提取前后3行的上下文
        for line_no in calls:
            contract.evidence_lines.append(line_no + 1)
            context_before = source_lines[max(0, line_no - 3):line_no]
            context_after = source_lines[line_no + 1:min(len(source_lines), line_no + 4)]

            # 前置条件挖掘
            for ctx_line in context_before:
                for pattern, ptype in self._PRECONDITION_PATTERNS:
                    m = re.search(pattern, ctx_line, re.IGNORECASE)
                    if m:
                        if ptype == 'nonnull' or ptype == 'assert_nonnull':
                            contract.nonnull_params.add(m.group(1))
                            contract.preconditions.append(
                                f"{m.group(1)} != NULL (line {line_no + 1})")
                        elif ptype == 'bound':
                            contract.preconditions.append(
                                f"{m.group(1)} <= {m.group(2)} (line {line_no + 1})")
                        elif ptype == 'positive':
                            contract.preconditions.append(
                                f"{m.group(1)} > 0 (line {line_no + 1})")

            # 后置条件挖掘
            for ctx_line in context_after:
                for pattern, ptype in self._POSTCONDITION_PATTERNS:
                    if re.search(pattern, ctx_line, re.IGNORECASE):
                        contract.postconditions.append(
                            f"{ptype} (line {line_no + 1})")

        # 推断返回值检查模式
        ret_checks = sum(1 for pc in contract.postconditions
                         if 'error_check' in pc or 'null_return_check' in pc)
        if ret_checks >= len(calls) * 0.8:
            contract.return_check_pattern = "always_checked"
        elif ret_checks > 0:
            contract.return_check_pattern = "sometimes_checked"
        else:
            contract.return_check_pattern = "unchecked"

        self._contract_cache[function_name] = contract
        return contract

    def _find_call_sites(self, lines: List[str],
                          func_name: str) -> List[int]:
        """在源码中定位函数调用点-返回行号列表(0-based)。

        使用词边界匹配避免子串误匹配（如'free'误匹配'freeze'）。
        """
        call_sites = []
        pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            if pattern.search(line) and not stripped.startswith('#'):
                # 排除函数定义行（行首出现返回类型+函数名）
                if not re.match(r'^\s*(?:static\s+|inline\s+|virtual\s+|extern\s+)*'
                                r'(?:void|int|char|float|double|long|short|unsigned|'
                                r'struct\s+\w+|size_t|ssize_t|bool|uint\w+_t|int\w+_t'
                                r')\s*(?:\*\s*)*' + re.escape(func_name) + r'\s*\(', line):
                    call_sites.append(i)
        return call_sites


# 边界值推断


def infer_param_bounds(source_lines: List[str],
                        function_name: str,
                        param_names: List[str]) -> Dict[str, Tuple[float, float]]:
    """从调用点推断参数边界-用于合成测试值。

    对每个参数:
      - 扫描所有调用点中作为该参数传入的表达式
      - 统计传入值的范围（常量、sizeof表达式、数组长度等）
      - 返回[min, max]边界估计

    返回{param_name: (min_val, max_val)}-用于补丁完备性的边界测试。
    """
    bounds = {}
    pattern = re.compile(r'\b' + re.escape(function_name) + r'\s*\((.*?)\)')
    for line in source_lines:
        m = pattern.search(line)
        if not m:
            continue
        args_str = m.group(1)
        # 简单分割-不处理嵌套括号
        args = [a.strip() for a in args_str.split(',')]
        for i, arg_expr in enumerate(args):
            if i >= len(param_names):
                break
            pname = param_names[i]
            val = _extract_numeric_hint(arg_expr)
            if val is not None:
                if pname not in bounds:
                    bounds[pname] = (val, val)
                else:
                    lo, hi = bounds[pname]
                    bounds[pname] = (min(lo, val), max(hi, val))
    return bounds


def _extract_numeric_hint(expr: str) -> Optional[float]:
    """从参数表达式中提取数值提示-常量/sizeof/strlen返回值"""
    expr = expr.strip()
    # 直接常量
    try:
        return float(expr)
    except ValueError:
        pass
    # sizeof表达式 - 提示为大缓冲区
    if 'sizeof' in expr:
        return 256.0  # 典型缓冲区大小下限
    # strlen - 提示为字符串长度
    if 'strlen' in expr:
        return 64.0
    # 十六进制常量
    if expr.startswith('0x'):
        try:
            return float(int(expr, 16))
        except ValueError:
            pass
    return None


__all__ = [
    "FunctionContract",
    "ContractViolation",
    "ContractInferrer",
    "infer_param_bounds",
]
