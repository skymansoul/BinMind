# coding: utf-8
"""
格式字符串约束系统 — 判定用户可控格式串是否可导致任意写.

核心洞察: 格式串漏洞的本质不是"格式串来自用户",
而是"格式串中 %n 写入的地址对应的参数来自用户".
将格式串利用条件编码为约束:
  C1: fmt_arg ∈ TaintedSources (格式串参数可被用户控制)
  C2: %n_count > 0 (格式串中存在 %n 写原语)
  C3: 对应 %n 的参数地址可被用户控制 (指向 attacker 选择的位置)
  C4: 参数在栈/寄存器中的偏移在合法范围内

若 C1∧C2∧C3∧C4 可满足 → 可被利用 → 保留
若 C1 不满足 (fmt 是常量) 或 C2 不满足 (无 %n) → 安全 → 过滤

  - "FormatShield: A Binary Rewriting Defense"
  - "Precise and Scalable Format String Bug Detection"
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

class FmtArgSource(Enum):
    CONSTANT = auto()       # 编译时常量 "hello" — 安全
    STACK_VAR = auto()      # 栈上变量 — 可能被覆写
    HEAP_VAR = auto()       # 堆上变量 — 可能被用户输入填充
    EXTERNAL_INPUT = auto() # 直接外部输入 (recv/read/argv) — 高危
    INTERNAL_DATA = auto()  # 内部数据 — 低风险

class FmtSpecType(Enum):
    REGULAR = auto()    # %s, %d, %x, %p, %c
    WRITE = auto()      # %n, %hn, %hhn, %ln (写原语)
    WIDTH_CTRL = auto() # %*d (宽度参数, 可用于信息泄露)
    POSITIONAL = auto() # %n$ (位置参数, 用于精确定位)

@dataclass
class FmtSpecifier:
    """单个格式说明符的解析结果."""
    spec_type: FmtSpecType
    position: int = 0        # %n$ 中的 n (0=顺序)
    width_arg: bool = False  # 是否有 * 宽度参数
    offset: int = 0          # 在格式串中的字节偏移
    write_width: int = 4     # %n=4, %hn=2, %hhn=1

@dataclass
class FmtStringAnalysis:
    """格式串分析结果."""
    fmt_string_addr: int
    fmt_source: FmtArgSource
    specifiers: List[FmtSpecifier]
    total_write_specs: int   # %n/%hn/%hhn 总数
    total_positional: int    # 位置参数数
    arg_count: int           # 需要的参数总数
    is_user_controlled: bool
    has_write_primitive: bool

class FmtParser:
    """格式串解析器 — 从字符串/字节中提取格式说明符.

    不完整解析 (non-exhaustive): 只提取安全相关的说明符.
    """

    # %[parameter][flags][width][.precision][length]type
    _FMT_SPEC_RE = __import__('re').compile(
        r'%'                           # 前缀
        r'((?P<pos>\d+)\$)?'          # 位置参数 n$
        r'(?P<flags>[#0\- +]*)?'      # flags
        r'(?P<width>\*|\d+)?'        # width
        r'(\.(?P<prec>\*|\d+))?'     # .precision
        r'(?P<len>hh|h|l|ll|z|t|j)?' # length modifier
        r'(?P<type>[diouxXeEfFgGaAcspn%])'  # conversion specifier
    )

    _WRITE_TYPES = {'n'}  # %n family — 写原语
    _WIDENED_WRITE = {'hn': 2, 'hhn': 1, 'n': 4, 'ln': 8, 'lln': 8}

    @classmethod
    def parse(cls, fmt_str: str,
              fmt_source: FmtArgSource = FmtArgSource.EXTERNAL_INPUT,
              ) -> FmtStringAnalysis:
        """解析格式串, 提取所有格式说明符."""
        specifiers = []
        total_writes = 0
        total_pos = 0
        max_pos = 0

        for m in cls._FMT_SPEC_RE.finditer(fmt_str):
            stype = m.group('type') or ''
            if stype == '%':
                continue

            pos = int(m.group('pos')) if m.group('pos') else 0
            if pos:
                total_pos += 1
                max_pos = max(max_pos, pos)

            is_write = stype in cls._WRITE_TYPES
            if is_write:
                total_writes += 1
                ww = cls._WIDENED_WRITE.get(
                    (m.group('len') or '') + stype, 4)
            else:
                ww = 0

            if is_write:
                ft = FmtSpecType.WRITE
            elif m.group('width') == '*' or m.group('prec') == '*n':
                ft = FmtSpecType.WIDTH_CTRL
            elif pos:
                ft = FmtSpecType.POSITIONAL
            else:
                ft = FmtSpecType.REGULAR

            specifiers.append(FmtSpecifier(
                spec_type=ft, position=pos,
                width_arg=(m.group('width') == '*'),
                offset=m.start(), write_width=ww,
            ))

        return FmtStringAnalysis(
            fmt_string_addr=0,
            fmt_source=fmt_source,
            specifiers=specifiers,
            total_write_specs=total_writes,
            total_positional=total_pos,
            arg_count=max_pos if total_pos else len(specifiers),
            is_user_controlled=(
                fmt_source in (FmtArgSource.EXTERNAL_INPUT,
                               FmtArgSource.HEAP_VAR)),
            has_write_primitive=(total_writes > 0),
        )

def classify_fmt_risk(analysis: FmtStringAnalysis) -> Tuple[str, float]:
    """根据格式串分析结果计算风险等级.

    返回: (risk_level, exploitability_score).
    """
    if not analysis.is_user_controlled:
        return 'SAFE', 0.01
    if not analysis.has_write_primitive:
        # 无 %n → 最多信息泄露, 不是任意写
        return 'INFO_LEAK', 0.15
    if analysis.total_write_specs >= 2:
        # 多个 %n → 可在一次调用中完成多次写
        return 'CRITICAL', 0.95
    if analysis.total_positional >= 2:
        # 位置参数 → 精确定位, 绕过栈随机化
        return 'HIGH', 0.85
    return 'MEDIUM', 0.65

def prove_fmt_safe(fmt_str: str, fmt_source: FmtArgSource
                   ) -> Tuple[bool, str]:
    """便捷判定: 证明该格式串不能用于任意写.

    返回: (可证明安全 → True, 理由).
    """
    analysis = FmtParser.parse(fmt_str, fmt_source)

    if not analysis.is_user_controlled:
        return True, '格式串非用户可控'
    if not analysis.has_write_primitive:
        return True, f'格式串不含写原语 (%n): {len(analysis.specifiers)} 个说明符'
    if analysis.total_write_specs > 0:
        return False, (
            f'格式串含 {analysis.total_write_specs} 个 %n, '
            f'{analysis.total_positional} 个位置参数 → 可能被利用')

    return False, '格式串可能被利用'

def check_arg_count_mismatch(fmt_str: str,
                              passed_args: int = 0) -> Tuple[bool, str]:
    """检测格式说明符数量与实际传入参数数量的不匹配.

    若格式串要求的参数数 > 传入参数数 → 栈越界读取 (信息泄露).
    这是格式串漏洞的独立维度 — 即使无 %n, 参数不足也可导致信息泄露.

    返回: (存在不匹配 → True, 原因).
    """
    analysis = FmtParser.parse(fmt_str)
    if not analysis.specifiers:
        return False, '无格式说明符'
    # 计算所需参数数 (排除 %% 等非消耗性说明符)
    expected = analysis.arg_count
    if passed_args > 0 and expected > passed_args:
        return True, (
            f'参数不足: 格式串要求 {expected} 个参数, '
            f'实际传入 {passed_args} 个 → 栈越界读取可能')
    # 即使 passed_args 未知, 高 arg_count 本身也是风险指标
    if expected > 8:
        return True, f'格式串参数需求异常 ({expected} 个) → 可能栈深度探测'
    return False, f'参数计数一致 (需要 {expected} 个)'

def classify_fmt_risk_enhanced(
    fmt_str: str, fmt_source: FmtArgSource,
    passed_args: int = 0,
) -> Tuple[str, float, List[str]]:
    """增强风险分类 — 结合写原语 + 参数不匹配 + 源可控性.

    返回: (risk_level, exploitability_score, evidence_reasons).
    """
    analysis = FmtParser.parse(fmt_str, fmt_source)
    reasons = []

    if not analysis.is_user_controlled:
        return 'SAFE', 0.01, ['格式串非用户可控']

    score = 0.0

    # 写原语检测
    if analysis.has_write_primitive:
        reasons.append(f'{analysis.total_write_specs} 个写原语 (%n/%hn)')
        score += 0.40
        if analysis.total_write_specs >= 2:
            score += 0.15

    # 参数不匹配
    mismatch, mreason = check_arg_count_mismatch(fmt_str, passed_args)
    if mismatch:
        reasons.append(mreason)
        score += 0.25

    # 位置参数 — 精确定位
    if analysis.total_positional >= 2:
        reasons.append(f'{analysis.total_positional} 个位置参数 (精确栈定位)')
        score += 0.15

    # 分级
    if score >= 0.80:
        return 'CRITICAL', min(score, 0.99), reasons
    elif score >= 0.50:
        return 'HIGH', score, reasons
    elif score >= 0.25:
        return 'MEDIUM', score, reasons
    elif score > 0:
        return 'INFO_LEAK', score, reasons
    return 'SAFE', 0.01, reasons

def batch_fmt_filter(candidates: List[Dict]) -> Tuple[List[Dict], Dict]:
    """批量格式串风险过滤."""
    retained = []
    stats = {'total': len(candidates), 'safe': 0, 'info_leak': 0, 'vulnerable': 0}

    for c in candidates:
        fmt = c.get('fmt_string', c.get('format_arg', ''))
        if not fmt:
            retained.append(c)
            continue

        source_str = c.get('fmt_source', 'external_input')
        try:
            source = FmtArgSource[source_str.upper()]
        except KeyError:
            source = FmtArgSource.EXTERNAL_INPUT

        safe, reason = prove_fmt_safe(fmt, source)
        if safe:
            stats['safe'] += 1
        else:
            retained.append(c)
            if 'CRITICAL' in reason or 'HIGH' in reason:
                stats['vulnerable'] += 1
            else:
                stats['info_leak'] += 1

    return retained, stats
