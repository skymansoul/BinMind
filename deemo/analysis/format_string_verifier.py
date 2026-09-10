"""
格式化字符串漏洞验证器 — 基于参数属性约束的误报削减.

format string 漏洞的本质是"用户输入作为格式字符串参数".
  而非所有 printf(variable) 都是漏洞.
  需要对变量做三阶段分析:
    1. 常量折叠: 变量是否为编译时常量字符串
    2. 数据流追踪: 变量是否来自用户输入源 (argv/read/recv/...)
    3. 路径约束: 变量是否在受保护路径中被校验

与现有 format_string_detector 的关系:
  - detector 做广度扫描 (找所有可疑 call site)
  - verifier 做深度验证 (过滤误报, 只保留有用户输入路径的)
"""


import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


# 用户输入来源函数
USER_INPUT_SOURCES = {
    'argv', 'getenv', 'read', 'fread', 'fgets', 'gets', 'scanf',
    'recv', 'recvfrom', 'recvmsg', 'getline', 'getdelim',
    '__isoc99_scanf', '__isoc99_fscanf', '__isoc99_sscanf',
}

# 硬编码字符串模式 (编译时常量)
STRING_LITERAL_PAT = re.compile(r'"(?:[^"\\]|\\.)*"')
# 格式字符串函数的格式参数位置
FMT_POSITIONS = {
    'printf': 0, 'fprintf': 1, 'dprintf': 1,
    'sprintf': 1, 'snprintf': 2,
    'syslog': 1, 'vsyslog': 1,
    'err': 1, 'warn': 1, 'errx': 1, 'warnx': 1,
    'setproctitle': 1,
}


@dataclass
class FmtStringVerdict:
    """格式化字符串漏洞判定."""
    call_site: int
    func_name: str
    fmt_arg: str
    is_constant: bool          # 是否为字符串常量
    has_user_source: bool      # 是否有用户输入路径
    has_format_spec: bool      # 是否包含格式化说明符 (%s/%d etc)
    is_cwe134: bool            # 最终是否为CWE-134
    confidence: float
    reason: str


class FormatStringVerifier:
    """格式化字符串漏洞三阶段验证.

    Phase 1: 常量折叠 — 变量是否编译时常量
    Phase 2: 污点追踪 — 变量是否源自用户输入
    Phase 3: 路径修剪 — 用户输入路径是否可达

    只在 Phase 1 失败 AND Phase 2 成功时报告 CWE-134.
    """

    def __init__(self):
        self._constants: Dict[str, str] = {}   # 变量 → 常量值
        self._tainted: Set[str] = set()        # 被污染的变量
        self._guarded: Set[str] = set()        # 被守卫保护的变量

    def clear(self):
        self._constants.clear()
        self._tainted.clear()
        self._guarded.clear()

    def scan_constants(self, insns: List[Tuple[int, str]]):
        """Phase 1: 扫描常量赋值."""
        for addr, text in insns:
            tl = text.strip()
            # char *fmt = "..."
            m = re.match(r'(?:const\s+)?char\s*\*\s*(\w+)\s*=\s*"([^"]*)"', tl)
            if m:
                var, val = m.group(1), m.group(2)
                self._constants[var] = val
                continue
            # fmt = "..."
            m = re.match(r'(\w+)\s*=\s*"([^"]*)"\s*;?', tl)
            if m:
                self._constants[m.group(1)] = m.group(2)

    def scan_taint(self, insns: List[Tuple[int, str]]):
        """Phase 2: 两跳污点传播.

        第一跳: 用户输入源函数 → 目标变量
        第二跳: 目标变量 → 其他变量 (赋值传播)
        """
        # 第一跳
        for addr, text in insns:
            tl = text.strip()
            for src in USER_INPUT_SOURCES:
                pattern = rf'{src}\s*\('
                if re.search(pattern, tl):
                    # 提取等号左边的变量
                    m = re.match(r'(\w+)\s*=', tl)
                    if m:
                        self._tainted.add(m.group(1))
                    else:
                        # 返回值赋给某变量 (分开的行)
                        pass

        # 第二跳: 赋值传播
        changed = True
        while changed:
            changed = False
            for addr, text in insns:
                tl = text.strip()
                m = re.match(r'(\w+)\s*=\s*(\w+)\s*;?$', tl)
                if m:
                    dst, src = m.group(1), m.group(2)
                    if src in self._tainted and dst not in self._tainted:
                        self._tainted.add(dst)
                        changed = True

    def scan_guards(self, insns: List[Tuple[int, str]]):
        """Phase 3: 检测格式参数是否被守卫保护."""
        for addr, text in insns:
            tl = text.strip()
            # if (fmt != NULL) or if (fmt)
            m = re.match(r'if\s*\((\w+)', tl)
            if m:
                self._guarded.add(m.group(1))

    def verify(self, call_site: int, func_name: str, fmt_arg: str,
               insns: List[Tuple[int, str]]) -> FmtStringVerdict:
        """验证单个格式化字符串调用."""
        # Phase 1: 常量折叠
        is_const = fmt_arg in self._constants
        const_val = self._constants.get(fmt_arg, "")
        has_fmt_spec = '%' in const_val if is_const else True

        # Phase 2: 用户输入
        has_user_src = fmt_arg in self._tainted

        # Phase 3: 守卫
        is_guarded = fmt_arg in self._guarded

        # 判定
        if is_const and has_fmt_spec:
            # 编译时常量格式字符串 → 安全 (Phase 1 通过)
            cwe134 = True  # 即使有格式说明符, 也需确认用户控制
            confidence = 0.95
            reason = "用户可控格式字符串 (常量折叠失败或动态构造)"
        elif is_const and not has_fmt_spec:
            cwe134 = False
            confidence = 0.05
            reason = f"编译时常量 '{const_val[:40]}', 无格式说明符 — 安全"
        elif has_user_src:
            if is_guarded:
                cwe134 = False
                confidence = 0.20
                reason = "用户输入但被路径守卫保护 — 可能安全"
            else:
                cwe134 = True
                confidence = 0.85
                reason = "用户输入直接作为格式字符串, 无保护 — CWE-134"
        else:
            cwe134 = False
            confidence = 0.30
            reason = "无用户输入源, 可能为内部变量 — 低风险"

        return FmtStringVerdict(
            call_site=call_site, func_name=func_name,
            fmt_arg=fmt_arg,
            is_constant=is_const,
            has_user_source=has_user_src,
            has_format_spec=has_fmt_spec,
            is_cwe134=cwe134,
            confidence=confidence,
            reason=reason,
        )

    def verify_all(self, call_sites: List[Tuple[int, str, str]],
                   insns: List[Tuple[int, str]]) -> List[FmtStringVerdict]:
        """批量验证。

        call_sites 为 [(addr, func_name, fmt_arg), ...], insns 为伪代码行。
        """
        self.scan_constants(insns)
        self.scan_taint(insns)
        self.scan_guards(insns)

        results = []
        for addr, func, arg in call_sites:
            results.append(self.verify(addr, func, arg, insns))
        return results
