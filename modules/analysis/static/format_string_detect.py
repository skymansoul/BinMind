# 格式化字符串漏洞检测器 (Format String Vulnerability Detector)
#
# 检测 printf 族函数中格式化字符串受用户控制的情况.
# 两个检测维度: 参数计数不匹配 和 pct_n 写入检测.
#
# 决策依据:
#   1. 参数计数: 解析格式说明符数量, 与调用点实参数量比较.
#      实参少于格式说明符时, 栈上的额外数据可能被攻击者控制.
#   2. pct_n 特殊处理: 唯一写入内存的格式说明符.
#      若格式字符串来自外部输入且包含pct_n, 直接标为critical.
#   3. 变参函数: x86-64下前6个参数走寄存器, 第7+走栈.
#      格式说明符超过6个 → 攻击面增大.
#   4. 误报抑制: 排除字面量格式字符串(编译时常量).
#

import re
from typing import Dict, List, Optional, Tuple


_PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "vdprintf", "syslog", "vsyslog",
    "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
    "__mingw_snprintf", "__mingw_vprintf", "__mingw_vfprintf",
    "__mingw_vsprintf", "__mingw_vsnprintf",
}

# 格式说明符正则
_FMT_RE = re.compile(r'%[+#0 -]*\d*\.?\d*[hljztL]?[diouxXeEfFgGaAcspn%]')

_FMT_ARG_MAP = {
    'd':1,'i':1,'o':1,'u':1,'x':1,'X':1,
    'e':1,'E':1,'f':1,'F':1,'g':1,'G':1,
    'a':1,'A':1,'c':1,'s':1,'p':1,'n':1,'%':0,
}


class FormatStringDetector:
    """格式化字符串漏洞检测器."""

    def __init__(self):
        self._findings: List[dict] = []

    def analyze_call(self, func_name: str, args: List[str],
                      fmt_source: str = "unknown",
                      address: int = 0) -> Optional[dict]:
        func = func_name.lower().split("@")[0]
        if func not in _PRINTF_FAMILY:
            return None

        # 格式字符串参数位置: printf=0, fprintf/dprintf=1, snprintf=2
        # (snprintf(buf, size, fmt, ...) 的 fmt 在第3实参)
        base = func.replace("__mingw_", "").replace("v", "", 1) \
            if func.startswith("__mingw") else func
        if base in ("fprintf", "dprintf"):
            fmt_idx = 1
        elif base in ("snprintf", "vsnprintf"):
            fmt_idx = 2
        else:
            fmt_idx = 0
        if fmt_idx >= len(args):
            return None

        if fmt_source == "literal":
            return None  # 编译时常量, 安全

        # 格式字符串来自寄存器 - 无法静态确定内容, 保守标记
        fmt_arg = args[fmt_idx].strip().lower().lstrip("%")
        # RIP 相对寻址 [rip+0x...] → 需区分目标节:
        #   .rdata/.rodata (只读字面量) → 安全
        #   .data/.bss (可写全局, 如全局格式字符串指针) → 攻击者可能可控
        is_rip_relative = ("rip" in fmt_arg and "[" in fmt_arg
                           and "]" in fmt_arg)
        if is_rip_relative:
            if any(k in fmt_arg for k in (".rdata", ".rodata")):
                return None  # 只读节字面量, 非攻击者可控
            # 可写节或未知: 保守告警
            f = {"type": "fmt_from_register", "function": func,
                 "address": address, "fmt_source": "global",
                 "severity": "medium",
                 "description": "format string from writable global, "
                                "content unknown"}
            self._findings.append(f)
            return f

        # 栈/堆内存操作数 ([rbp+0x10], [rax]) - 内容可能是运行时可控数据
        is_mem_operand = ("[" in fmt_arg and "]" in fmt_arg
                          and not is_rip_relative)
        is_literal = (fmt_arg.startswith("0x") or
                      (len(fmt_arg) > 2 and
                       (fmt_arg.startswith('"') or "ptr" not in fmt_arg
                        and "[" not in fmt_arg
                        and any(c in fmt_arg for c in ("%.", "%s", "%d", "%x", "%p")))))
        # 寄存器: 排除 RIP 相对 (已返回) 与纯地址常量
        is_register = (any(fmt_arg.startswith(p) for p in
                           ("r","e","rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
                            "r8","r9","r10","r11","r12","r13","r14","r15",
                            "eax","ebx","ecx","edx","esi","edi","ebp","esp"))
                       and not fmt_arg.startswith("rip"))
        if (is_register or is_mem_operand) and fmt_source != "literal":
            f = {"type":"fmt_from_register","function":func,"address":address,
                 "fmt_source":"register","severity":"medium",
                 "description": "format string from register/memory, content unknown"}
            self._findings.append(f)
            return f
        if is_literal:
            return None  # 编译时常量, 安全

        specs = self._parse_specs(args[fmt_idx])

        # pct_n 检测
        has_n = any(s[1] == 'n' for s in specs)
        if has_n:
            f = {"type":"fmt_pct_n","function":func,"address":address,
                 "fmt_source":fmt_source,"severity":"critical"}
            self._findings.append(f)
            return f

        # 参数计数
        expected = sum(_FMT_ARG_MAP.get(s[1],0) for s in specs)
        supplied = len(args) - fmt_idx - 1
        if supplied < expected:
            f = {"type":"fmt_arg_mismatch","function":func,"address":address,
                 "expected_args":expected,"supplied_args":supplied,
                 "fmt_source":fmt_source,
                 "severity":"high" if expected>6 else "medium"}
            self._findings.append(f)
            return f
        return None

    def analyze_batch(self, calls: List[dict]) -> List[dict]:
        results = []
        for c in calls:
            r = self.analyze_call(
                func_name=c.get("target",""),
                args=c.get("args",[]),
                fmt_source=c.get("fmt_source","unknown"),
                address=c.get("address",0))
            if r: results.append(r)
        return results

    @staticmethod
    def _parse_specs(fmt: str) -> List[Tuple[str,str]]:
        return [(m.group(0), m.group(0)[-1]) for m in _FMT_RE.finditer(fmt)]

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def reset(self):
        self._findings.clear()


__all__ = ["FormatStringDetector"]
