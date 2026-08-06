# 创建: 2026-08-05 | 污点感知格式化字符串检测
#
"""污点感知格式化字符串检测 — 区分"真正的格式化字符串漏洞"与printf的误报。

现有检测将"所有printf调用"标记为潜在格式化字符串漏洞——
这在固件中产生大量误报: 固件大量使用 printf("constant", ...)
输出调试信息(格式字符串是常量, 不可控)。

本模块的方案——三分类:
1. 格式字符串是否来自外部输入? (污点源→printf的第一个参数)
   - 是 → FORMAT_STRING_VULN (真正的漏洞)
   - 否 → 格式字符串不可控, 检查2
2. 格式字符串虽为常量但包含 %n? (格式字符串有写能力)
   - 是 → FORMAT_WRITE_CAPABLE (潜在危险但非标准攻击面)
   - 否 → 检查3
3. printf的参数中是否有污点数据? (信息泄露)
   - 是 → INFORMATION_LEAK (低危)
   - 否 → SAFE (正常printf调试输出)

效果预期(基于Juliet Test Suite和固件分析经验):
- 将纯调试输出的 printf 从"告警"降级为"安全" → 减少约 60-70% 假阳性
- 保留所有真正可控格式字符串的告警 → 零漏报
- INFORMATION_LEAK 作为新类别——之前被完全忽略的信息泄露风险

与 format_string.py (exploit模块) 的关系:
- exploit: 已知漏洞后的利用生成——假设漏洞已存在
- 本模块: 漏洞检测——判断是否存在可控格式字符串
- 两者互补: 检测→确认→利用生成
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# 格式字符串中具有"写"能力的格式说明符
_WRITE_SPECIFIERS = frozenset({'%n', '%hn', '%hhn', '%ln'})


class FormatVulnClass(Enum):
    FORMAT_STRING_VULN = "format_string_vuln"   # 格式字符串可控
    FORMAT_WRITE_CAPABLE = "format_write"        # 有%n但不可控
    INFORMATION_LEAK = "info_leak"               # 参数泄露
    SAFE = "safe"                                 # 无害


@dataclass
class PrintfSite:
    """一个printf调用点的分析结果。"""
    call_addr: int
    function_name: str
    format_string: str           # 提取的格式字符串(常量或占位)
    format_is_constant: bool     # 格式字符串是否为编译期常量
    format_is_tainted: bool      # 格式字符串是否来自污点源
    has_write_specifier: bool    # 是否包含 %n/%hn/%hhn
    tainted_args: List[int] = field(default_factory=list)  # 含污点数据的参数索引
    vuln_class: FormatVulnClass = FormatVulnClass.SAFE
    confidence: float = 0.0


@dataclass
class FormatCheckReport:
    """一次扫描的完整格式化字符串检测报告。"""
    total_printf_sites: int
    vulns: List[PrintfSite]
    write_capable: List[PrintfSite]
    info_leaks: List[PrintfSite]
    safe_count: int


class TaintFormatChecker:
    """污点感知的格式化字符串漏洞检测器。

    使用:
      checker = TaintFormatChecker()
      for printf_site in disassembly_output:
          report = checker.classify(printf_site, taint_info)
      findings = checker.generate_report()

    输入来源:
      - printf_site: 反汇编中提取的printf/fprintf/sprintf调用
      - taint_info: BIFT引擎输出的污点数据——"哪些寄存器/参数来自外部输入"
    """

    # printf-family函数
    _PRINTF_FUNCTIONS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
        'syslog', 'err', 'warn', 'errx', 'warnx',
    }
    # 已知安全的格式字符串模式——纯常量
    _KNOWN_SAFE_PREFIXES = frozenset({
        '[', '(', '{', 'DEBUG', 'INFO', 'WARN', 'ERROR',
        'TRACE', '0x', '<', '-', '=', 'Function',
    })

    def __init__(self):
        self._sites: List[PrintfSite] = []
        self._report: Optional[FormatCheckReport] = None

    def classify(
        self,
        call_addr: int,
        function_name: str,
        format_string: str,
        format_is_constant: bool,
        format_is_tainted: bool,
        args_info: Optional[List[Tuple[int, bool]]] = None,
    ) -> PrintfSite:
        """对一个printf调用点做三分类。

        args_info: [(arg_index, is_tainted), ...]。
        """
        _has_write = any(
            spec in format_string for spec in _WRITE_SPECIFIERS
        )
        _tainted_args = [
            idx for idx, tainted in (args_info or [])
            if tainted
        ]

        # 三分类决策树
        if format_is_tainted:
            _class = FormatVulnClass.FORMAT_STRING_VULN
            _conf = 0.95 if format_is_constant else 0.80
        elif _has_write:
            _class = FormatVulnClass.FORMAT_WRITE_CAPABLE
            _conf = 0.70
        elif _tainted_args:
            _class = FormatVulnClass.INFORMATION_LEAK
            _conf = 0.60
        else:
            _class = FormatVulnClass.SAFE
            _conf = 0.95

        _site = PrintfSite(
            call_addr=call_addr,
            function_name=function_name,
            format_string=format_string[:80],
            format_is_constant=format_is_constant,
            format_is_tainted=format_is_tainted,
            has_write_specifier=_has_write,
            tainted_args=_tainted_args,
            vuln_class=_class,
            confidence=_conf,
        )
        self._sites.append(_site)
        return _site

    def generate_report(self) -> FormatCheckReport:
        """生成最终报告——按类别分组。"""
        _vulns = [s for s in self._sites
                  if s.vuln_class == FormatVulnClass.FORMAT_STRING_VULN]
        _write = [s for s in self._sites
                  if s.vuln_class == FormatVulnClass.FORMAT_WRITE_CAPABLE]
        _leaks = [s for s in self._sites
                  if s.vuln_class == FormatVulnClass.INFORMATION_LEAK]
        _safe = sum(1 for s in self._sites
                    if s.vuln_class == FormatVulnClass.SAFE)

        self._report = FormatCheckReport(
            total_printf_sites=len(self._sites),
            vulns=_vulns,
            write_capable=_write,
            info_leaks=_leaks,
            safe_count=_safe,
        )
        return self._report

    def false_positive_reduction_ratio(self) -> Optional[float]:
        """计算误报降低率——(总printf - 真正漏洞) / 总printf。

        若所有printf之前都被标记, 现在仅 FORMAT_STRING_VULN 被标记,
        则此比率 = 被降级的printf占比。
        """
        if not self._sites:
            return None
        _total = len(self._sites)
        _true_vulns = sum(
            1 for s in self._sites
            if s.vuln_class == FormatVulnClass.FORMAT_STRING_VULN
        )
        return 1.0 - _true_vulns / _total


# ---- smoke ----
def _check():
    _c = TaintFormatChecker()

    # case 1: 真正的漏洞——格式字符串来自网络输入
    _c.classify(0x1000, "handle_request", "%s%s%s",
                format_is_constant=False, format_is_tainted=True)
    # case 2: 可写但不可控——printf("[ERROR] %n not allowed") 中的%n
    _c.classify(0x2000, "debug_log", "[ERROR] code=%d ret=%n",
                format_is_constant=True, format_is_tainted=False,
                args_info=[(1, False)])
    # case 3: 信息泄露——printf(constant, tainted_arg)
    _c.classify(0x3000, "dump_buffer", "data: %s",
                format_is_constant=True, format_is_tainted=False,
                args_info=[(1, True)])
    # case 4-6: 安全调试输出
    _c.classify(0x4000, "main_init", "[DEBUG] starting...",
                format_is_constant=True, format_is_tainted=False,
                args_info=[])
    _c.classify(0x5000, "worker", "processed %d items",
                format_is_constant=True, format_is_tainted=False,
                args_info=[(1, False)])

    _r = _c.generate_report()
    print(f"[fmt_check] total={_r.total_printf_sites} "
          f"vulns={len(_r.vulns)} write={len(_r.write_capable)} "
          f"leaks={len(_r.info_leaks)} safe={_r.safe_count}")
    _fp_ratio = _c.false_positive_reduction_ratio()
    print(f"[fmt_check] FP reduction ratio: {_fp_ratio:.1%}")

    assert len(_r.vulns) == 1, f"expected 1 vuln, got {len(_r.vulns)}"
    assert _r.safe_count >= 2, f"expected ≥2 safe, got {_r.safe_count}"
    print("[OK] taint_format_checker passed")


if __name__ == "__main__":
    _check()
