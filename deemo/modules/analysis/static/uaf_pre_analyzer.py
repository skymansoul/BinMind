# UAF 预分析器 — 函数识别与用户代码范围推导
#
# 职责: 识别用户函数地址范围, 排除CRT/库函数, 构建指令索引.
#
# 创建: 2024-04-07

import re
from typing import Dict, List, Set, Tuple

from .disasm_util import is_crt_func, parse_func_ranges


# libc/CRT/导入函数完整黑名单
_LIBC_NAMES = {
    "malloc", "free", "calloc", "realloc",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove", "memset", "memcmp", "memchr",
    "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar", "gets",
    "scanf", "fscanf", "sscanf", "fopen", "fclose", "fread", "fwrite",
    "fseek", "ftell", "fgetc", "fputc", "fgets", "fputs",
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtod",
    "abort", "exit", "_exit", "atexit",
    "qsort", "bsearch", "rand", "srand",
    "setjmp", "longjmp", "signal", "raise",
    "time", "clock", "gettimeofday",
    "_Znwm", "_Znam", "_ZdlPv", "_ZdaPv",
    "ExAllocatePoolWithTag", "ExFreePool",
    "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree",
    "LocalAlloc", "LocalFree", "GlobalAlloc", "GlobalFree",
    "fflush", "setvbuf", "vfprintf",
    "check_managed_app", "duplicate_ppstrings",
    "mark_section_writable", "do_pseudo_reloc", "restore_modified_sections",
}


class UAFPreAnalyzer:
    """函数识别与用户代码范围推导.

    两阶段:
      Phase 1 (analyze): 从 objdump 输出或指令列表识别用户函数
      Phase 2 (get_ranges): 返回合并后的用户函数地址范围列表
    """

    def __init__(self):
        self._ins_by_addr: Dict[int, dict] = {}
        self._user_func_addrs: Set[int] = set()
        self._all_func_starts: Set[int] = set()
        self._user_func_ranges: List[Tuple[int, int]] = []
        self._all_func_ranges: Dict[str, Tuple[int, int]] = {}

    def analyze_from_objdump(self, objdump_out: str):
        """从 objdump 原始输出分析函数范围."""
        all_ranges, user_ranges = parse_func_ranges(objdump_out)
        self._all_func_ranges = all_ranges
        self._user_func_ranges = user_ranges

    def analyze_from_instructions(self, instructions: List[dict]):
        """从结构化指令列表识别用户函数地址范围.

        两阶段:
          1. 扫描 call 目标排序得到所有函数起点
          2. 用户函数范围 = [func_start, next_func_start)
        """
        self._ins_by_addr = {ins.get("address", 0): ins for ins in instructions}
        self._user_func_addrs = set()
        all_starts: Set[int] = set()

        for ins in instructions:
            if ins.get("mnemonic") == "call" and ins.get("operands"):
                callee = ins["operands"][-1]
                name_match = re.search(r'<([^>]+)>', callee)
                if name_match:
                    name = name_match.group(1).split("@")[0]
                else:
                    name = callee.strip("<>").split("@")[0].split(".")[-1]

                if not name or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
                    continue

                target = None
                try:
                    addr_part = callee.split()[0]
                    target = int(addr_part, 16)
                    all_starts.add(target)
                except (ValueError, IndexError):
                    pass

                # 间接调用(call rax等)无法确定目标函数 → 跳过
                if target is None:
                    continue

                if is_crt_func(name) or name in _LIBC_NAMES:
                    continue
                if name.startswith("__") and not name.startswith("__user_"):
                    continue

                self._user_func_addrs.add(target)

        if instructions:
            first = instructions[0].get("address", 0)
            all_starts.add(first)
        self._all_func_starts = all_starts
        self._derive_ranges_from_addrs()

    def _derive_ranges_from_addrs(self):
        """从用户函数地址集合推导地址范围.

        每个用户函数范围 = [func_start, next_func_start),
        next_func_start 取所有已知函数起点中大于当前起点的最小值.
        """
        if not self._user_func_addrs:
            self._user_func_ranges = []
            return

        all_starts = sorted(self._all_func_starts | self._user_func_addrs)
        user_sorted = sorted(self._user_func_addrs)

        # 构建每个函数的 [start, end) — end = 下一个函数起点
        func_endpoints: Dict[int, int] = {}
        for i, s in enumerate(all_starts):
            if i + 1 < len(all_starts):
                func_endpoints[s] = all_starts[i + 1]
            else:
                func_endpoints[s] = s + 512

        # 用户函数范围
        ranges: List[Tuple[int, int]] = []
        for ua in user_sorted:
            end = func_endpoints.get(ua, ua + 512)
            # 合并相邻重叠的用户函数范围
            if ranges and ua <= ranges[-1][1] + 128:
                ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
            else:
                ranges.append((ua, end))
        self._user_func_ranges = sorted(ranges, key=lambda r: r[0])

    @property
    def user_func_ranges(self) -> List[Tuple[int, int]]:
        return self._user_func_ranges

    @property
    def all_func_ranges(self) -> Dict[str, Tuple[int, int]]:
        return self._all_func_ranges

    @property
    def ins_by_addr(self) -> Dict[int, dict]:
        return self._ins_by_addr

    def is_user_code(self, addr: int) -> bool:
        if not self._user_func_ranges:
            return True
        for lo, hi in self._user_func_ranges:
            if lo <= addr < hi:
                return True
        return False


__all__ = ["UAFPreAnalyzer"]
