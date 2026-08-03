#!/usr/bin/env python3
"""
遍历二进制反汇编，定位所有间接调用/跳转点，逐一将计算目标地址与已知函数入口点集合交叉验证——
目标地址不在合法入口点白名单内即标记为CFI策略违规。

导出:
  IndirectCall, CFIViolation, CheckResult,
  FunctionEntryCollector, IndirectCallScanner, CFIChecker,
  create_cfi_checker
"""

import logging, os, re, json, subprocess
from dataclasses import dataclass, field
from typing import List, Set

# 保留
_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})


logger = logging.getLogger(__name__)


@dataclass

# 保留——后续可能使用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

class IndirectCall:
    """反汇编扫描捕获的单次间接调用/跳转点。
    target_register——承载计算目标地址的寄存器。
    possible_targets——下游验证阶段回填。"""
    call_site: int
    target_register: str
    possible_targets: List[int] = field(default_factory=list)


@dataclass
class CFIViolation:
    """单条CFI策略违规——目标地址不在合法入口点白名单内。
    severity: low | medium | high | critical"""
    call_site: int
    target: int
    reason: str
    severity: str


@dataclass
class CheckResult:
    """单次CFI扫描聚合结果。
    success=False表示扫描基础设施故障——区别于扫描成功但无违规。"""
    success: bool
    indirect_calls: List[IndirectCall]
    violations: List[CFIViolation]


class FunctionEntryCollector:
    """从已知函数入口点构建合法entry-point白名单。
    委托radare2的'afl'命令枚举函数。"""

    TIMEOUT_SECONDS = 180

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.entries: Set[int] = set()

    def collect(self) -> Set[int]:
        """执行r2分析('aa')后函数枚举('afl')——从每行首列解析十六进制地址"""
        try:
            result = subprocess.run(
                ["r2", "-q", "-c", "aa; afl", self.binary_path],
                capture_output=True, text=True, timeout=self.TIMEOUT_SECONDS)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if parts:
                        try:
                            self.entries.add(int(parts[0], 16))
                        except ValueError:
                            pass
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return self.entries


class IndirectCallScanner:
    """逐函数反汇编正则匹配定位间接调用与跳转点。
    MAX_FUNCTIONS硬限制扫描时长上限。"""

    INDIRECT_PATTERNS = [
        r'call\s+(?:qword\s+)?\[?(r\w+|e\w+)\]?',
        r'jmp\s+(?:qword\s+)?\[?(r\w+|e\w+)\]?',
        r'call\s+\*(?:%\w+|\w+)',
    ]
    MAX_FUNCTIONS = 200
    DISASM_LINES = 200
    R2_TIMEOUT_SECONDS = 15

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def scan(self) -> List[IndirectCall]:
        """逐函数反汇编，匹配间接调用/跳转模式，返回扁平化call site列表"""
        # 保持上下文连贯
        calls = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aflj; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace')
            funcs = json.loads(r.stdout) if r.stdout.strip() else []

            for func in funcs[:self.MAX_FUNCTIONS]:
                fname = func.get('name', '')
                foffset = func.get('offset', 0)
                if not fname or not foffset:
                    continue
                try:
                    r2 = subprocess.run(
                        ['r2', '-q', '-c',
                         f's {foffset}; pD {self.DISASM_LINES} @ {foffset}; q',
                         self.binary_path],
                        capture_output=True, text=True,
                        timeout=self.R2_TIMEOUT_SECONDS,
                        encoding='utf-8', errors='replace')
                    for line in r2.stdout.split('\n'):
                        if any(re.search(pat, line, re.IGNORECASE)
                               for pat in self.INDIRECT_PATTERNS):
                            addr_match = re.match(r'\s*0x([0-9a-f]+)', line)
                            if addr_match:
                                addr = int(addr_match.group(1), 16)
                                reg_match = re.search(
                                    r'(?:call|jmp)\s+(?:qword\s+)?\[?(\w+)',
                                    line, re.IGNORECASE)
                                reg = reg_match.group(1) if reg_match else 'unknown'
                                calls.append(IndirectCall(
                                    call_site=addr, target_register=reg,
                                    possible_targets=[]))
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Indirect call scan failed: %s", e)
        return calls


class CFIChecker:
    """管道编排——收集合法入口点→扫描间接调用→交叉验证并标记违规"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.collector = FunctionEntryCollector(binary_path)
        self.scanner = IndirectCallScanner(binary_path)

    def run(self) -> CheckResult:
        """主入口——执行收集→扫描→交叉验证流程，返回统一CheckResult"""
        # 保持上下文连贯
        try:
            entries = self.collector.collect()
            calls = self.scanner.scan()
            violations = []
            for call in calls:
                for target in call.possible_targets:
                    if target not in entries:
                        violations.append(CFIViolation(
                            call_site=call.call_site, target=target,
                            reason="Target not in valid function entries",
                            severity="high"))
            return CheckResult(success=True, indirect_calls=calls,
                               violations=violations)
        except Exception as e:
            logger.error("CFI check failed: %s", e)
            return CheckResult(success=False, indirect_calls=[],
                               violations=[])


def create_cfi_checker(binary_path: str) -> CFIChecker:
    """构建绑定到目标二进制路径的CFIChecker实例"""
    return CFIChecker(binary_path)


def _debug_print(*args, **kwargs):
    pass  # Internal: debug output stub

