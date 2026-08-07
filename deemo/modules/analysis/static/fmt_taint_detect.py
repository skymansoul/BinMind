# 污点感知格式化字符串检测 (Taint-Aware Format String Detection)
#
# 在 format_string_detect.py 基础上增加污点源追踪.
# 核心区别: 不仅检测格式说明符数量不匹配, 更追踪格式字符串本身的来源.
#   格式字符串来自只读段(.rodata) → 安全 (编译时常量).
#   格式字符串来自栈/寄存器/外部输入 → 危险 (用户可控).
#
# 决策依据:
#   1. 字面量 vs 变量: 若格式字符串参数是立即数地址(指向.rodata) → 安全.
#      若格式字符串来自寄存器(运行时确定) → 需进一步追踪.
#   2. 追踪深度: 对来自寄存器的格式字符串, 反向追踪最多5条指令.
#      若5条内追溯到 read/recv/argv → 高危.
#      若5条内追溯到常量加载 → 安全.
#   3. 加固的误报抑制: 以下模式不应报告:
# printf("%s", user_str) → 安全的格式字符串使用
#      - fprintf(stderr, "error: %d", code) → 字面量格式字符串
#      - snprintf(buf, sizeof(buf), "%s", src) → 长度受限 + 字面量
#
# 创建: 2026-05-22

import re
from typing import Dict, List, Optional, Tuple

_PRINTF_FAMILY = {
    "printf","fprintf","sprintf","snprintf","dprintf",
    "vprintf","vfprintf","vsprintf","vsnprintf","vdprintf",
    "syslog","vsyslog","__printf_chk","__fprintf_chk",
}
_FMT_RE = re.compile(r'%[+#0 -]*\d*\.?\d*[hljztL]?[diouxXeEfFgGaAcspn%]')
_FMT_ARG_MAP = {'d':1,'i':1,'o':1,'u':1,'x':1,'X':1,'e':1,'E':1,'f':1,
                'F':1,'g':1,'G':1,'a':1,'A':1,'c':1,'s':1,'p':1,'n':1,'%':0}

# 产生格式字符串的安全函数
_SAFE_FMT_SOURCES = {"strerror","g_strerror","strsignal"}
# 外部输入源
_EXTERNAL_SOURCES = {"read","recv","recvfrom","fgets","scanf","getenv","argv"}


class TaintAwareFmtDetector:
    """污点感知格式化字符串检测器.

    扩展 format_string_detect.py 的检测维度:
      - fmt_source 追踪: 区分字面量/寄存器/外部输入
      - 5指令回溯窗口
      - 安全模式白名单过滤
    """

    def __init__(self, trace_depth: int = 5):
        self._trace_depth = trace_depth
        self._findings: List[dict] = []

    def analyze_call(self, func_name: str, args: List[str],
                      fmt_source: str = "unknown",
                      instructions: List[dict] = None,
                      address: int = 0) -> Optional[dict]:
        func = func_name.lower().split("@")[0].split(".")[-1]
        if func not in _PRINTF_FAMILY:
            return None

        fmt_idx = 1 if func in ("fprintf","dprintf") else 0
        if fmt_idx >= len(args):
            return None

        fmt_arg = args[fmt_idx]

        # 追踪格式字符串来源
        source_kind = self._trace_source(fmt_arg, instructions or [])
        if source_kind == "literal":
            return None  # 字面量, 安全
        if source_kind == "safe_function":
            return None

        # 解析格式说明符
        spec_count = len(_FMT_RE.findall(fmt_arg))

        # pct_n 检查
        has_n = any(m.group(0)[-1] == 'n' for m in _FMT_RE.finditer(fmt_arg))
        if has_n and source_kind in ("register","external_input","unknown"):
            self._findings.append({
                "type":"fmt_pct_n_tainted","function":func,
                "address":address,"fmt_source":source_kind,
                "severity":"critical"})

        # 参数计数
        expected = sum(_FMT_ARG_MAP.get(m.group(0)[-1],0)
                       for m in _FMT_RE.finditer(fmt_arg))
        supplied = len(args) - fmt_idx - 1

        if supplied < expected and source_kind != "literal":
            sev = "critical" if source_kind == "external_input" else (
                "high" if expected > 6 else "medium")
            f = {"type":"fmt_arg_mismatch","function":func,"address":address,
                 "expected":expected,"supplied":supplied,
                 "fmt_source":source_kind,"severity":sev}
            self._findings.append(f)
            return f
        return None

    def _trace_source(self, fmt_arg: str,
                       instructions: List[dict]) -> str:
        """回溯格式字符串的来源.

        立即数 → "literal"
        来自安全函数 → "safe_function"
        来自寄存器, 继续追踪 → "register" / "external_input"
        """
        # 立即数地址检测 (简化)
        if fmt_arg.startswith("0x") or (
            fmt_arg.startswith("$0x") or fmt_arg.startswith("$")):
            try:
                val = int(fmt_arg.replace("$","").replace("0x",""), 16)
                # 典型 .rodata 地址范围 (简化启发式)
                if val > 0x400000: return "literal"
            except ValueError: pass

        reg = fmt_arg.strip().lower().lstrip("%")
        if reg in ("rdi","rsi","rdx","rcx","r8","r9",
                    "edi","esi","edx","ecx"):
            return self._trace_reg(reg, instructions)

        if any(reg.startswith(f"[rbp") or reg.startswith(f"[rsp")
               for reg in [reg]):
            return "register"  # 栈变量, 保守

        return "unknown"

    def _trace_reg(self, reg: str, instructions: List[dict]) -> str:
        """在指令序列中反向追踪寄存器的值来源."""
        depth = 0
        for i in range(len(instructions)-1, -1, -1):
            if depth >= self._trace_depth: break
            ins = instructions[i]
            mnem = ins.get("mnemonic","").lower()
            ops = ins.get("operands",[])
            depth += 1

            dst = ops[0].strip().lower().lstrip("%") if ops else ""
            if dst == reg and len(ops) >= 2:
                src = ops[1].strip().lower().lstrip("%").replace("$","")
                if src.startswith("0x"): return "literal"
                if mnem == "lea" and "rip" in src: return "literal"
                if mnem == "call":
                    func = ops[0].split("@")[0].split(".")[-1].lower()
                    if func in _SAFE_FMT_SOURCES: return "safe_function"
                    if func in _EXTERNAL_SOURCES: return "external_input"
                reg = src  # 继续追踪新寄存器

        if reg in ("rdi","rsi"): return "external_input"  # 函数参数
        return "register"

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def reset(self):
        self._findings.clear()


__all__ = ["TaintAwareFmtDetector"]
