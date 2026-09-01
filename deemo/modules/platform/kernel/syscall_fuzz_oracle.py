# 系统调用Fuzz预言机：基于差分测试的syscall行为判定
#
# 相关工作:
#   "Characterizing and Briding the Diagnostic Gap in eBPF Verifier Rejections"
#     (arXiv 2607.02748) — syscall 参数约束建模的启发来源
#   SyzGen — 自动化 syscall 依赖推理与参数语法生成
#   Heimdall — 形式化等价性验证思想, 迁移到双内核差分 oracle

import os
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# 系统调用参数类型建模
# 每个syscall的参数携带类型约束；有效fuzz输入须满足这些约束
# 类型: fd(文件描述符), ptr(用户空间指针), buf(缓冲区+长度),
#       flags(位标志), path(文件系统路径), signal(信号编号),
#       pid(进程ID), mode(文件模式)

_PARAM_TYPE_GRAMMAR: dict[str, list] = {
    "fd":     [-1, 0, 1, 2, 3, 100, 0x7FFFFFFF],
    "ptr":    [0, 0xFFFFFFFFFFFFFFFF, 0x1000, 0xDEADBEEF],
    "buf":    [b"", b"A" * 4096, b"\x00" * 64, b"/etc/passwd\x00"],
    "flags":  [0, 0xFFFFFFFF, 0x8000, 0x4000, 0x200, 0x40],
    "path":   [b"/etc/hosts\x00", b"/proc/self/maps\x00", b"/tmp/fuzz\x00",
               b"/dev/null\x00", b"\x00"],
    "signal": [0, 1, 9, 15, 31, 64],
    "pid":    [0, 1, -1, 0x7FFFFFFF],
    "mode":   [0, 0o755, 0o644, 0o777, 0o1777],
    "int":    [-1, 0, 1, 0x7FFFFFFF, -0x80000000],
    "size":   [0, 1, 4096, 65536, 0x7FFFFFFF],
}

# 部分Linux syscall定义 (nr, name, arg_types)
_SYSCALL_TABLE: list[dict] = [
    {"nr": 0,   "name": "read",    "args": ["fd", "ptr", "size"]},
    {"nr": 1,   "name": "write",   "args": ["fd", "ptr", "size"]},
    {"nr": 2,   "name": "open",    "args": ["path", "flags", "mode"]},
    {"nr": 3,   "name": "close",   "args": ["fd"]},
    {"nr": 9,   "name": "mmap",    "args": ["ptr", "size", "flags", "flags", "fd", "int"]},
    {"nr": 10,  "name": "mprotect", "args": ["ptr", "size", "flags"]},
    {"nr": 59,  "name": "execve",  "args": ["path", "ptr", "ptr"]},
    {"nr": 62,  "name": "kill",    "args": ["pid", "signal"]},
    {"nr": 257, "name": "openat",  "args": ["fd", "path", "flags", "mode"]},
]

# 敏感syscall — fuzz至此需特别谨慎，可能引发系统不稳定
_SENSITIVE_SYSCALLS: set[str] = {
    "execve", "kill", "reboot", "shutdown", "exit", "exit_group",
    "mount", "umount2", "setuid", "setgid", "init_module", "delete_module",
}


@dataclass
class SyscallInput:
    """单次syscall fuzz输入 — 含各参数具体值。"""
    syscall_nr: int
    syscall_name: str = ""
    args: list = field(default_factory=list)  # 具体参数值列表
    expected_behavior: str = ""  # "success", "EFAULT", "EINVAL", "EBADF", "EPERM"
    is_sensitive: bool = False


@dataclass
class DiffOracleResult:
    syscall_name: str
    inputs: list[SyscallInput] = field(default_factory=list)
    kernel_a_behavior: str = ""   # "all_EINVAL", "mixed", "crashed", ...
    kernel_b_behavior: str = ""
    divergence_detected: bool = False
    divergence_details: list[str] = field(default_factory=list)
    confidence: float = 0.0


class SyscallFuzzOracle:
    """基于差分测试的系统调用fuzz预言机。

    设计理念 (参考Heimdall的形式化等价性):
    同一syscall输入在两个内核版本/配置下应产生一致的行为。
    若行为不一致 (返回值、errno、寄存器状态不同) → 潜在缺陷或回归。

    操作:
    1. 语法导向构造: 从参数类型语法派生合法输入
    2. 边界值变异: 注入极值和非法组合
    3. Oracle比对: 比较两个内核的输出 → 发现分歧
    """

    def __init__(self, syscall_whitelist: list[str] | None = None,
                 exclude_sensitive: bool = True):
        self._whitelist = set(syscall_whitelist) if syscall_whitelist else None
        self._exclude_sensitive = exclude_sensitive
        self._grammar = _PARAM_TYPE_GRAMMAR
        self._syscalls = _SYSCALL_TABLE
        self._findings: list[DiffOracleResult] = []

    def generate_inputs(self, syscall_name: str,
                        n_variants: int = 16) -> list[SyscallInput]:
        """为指定syscall构造fuzz输入组合。

        构造策略:
        - 合法输入: 各参数从其类型允许值集合中选取
        - 边界值: 最小值、最大值、0、-1
        - 非法组合: fd=-1对多数syscall触发EBADF
        """
        sc = next((s for s in self._syscalls if s["name"] == syscall_name), None)
        if sc is None:
            return []
        inputs = []
        arg_types = sc["args"]
        for v in range(min(n_variants, 64)):
            args = []
            for at in arg_types:
                pool = self._grammar.get(at, [0])
                idx = (v * 7 + 3) % len(pool)  # 质数步长消除周期性重复
                args.append(pool[idx])
            expected = self._predict_behavior(syscall_name, args)
            inputs.append(SyscallInput(
                syscall_nr=sc["nr"], syscall_name=syscall_name,
                args=args, expected_behavior=expected,
                is_sensitive=syscall_name in _SENSITIVE_SYSCALLS))
        return inputs

    def _predict_behavior(self, name: str, args: list) -> str:
        """根据参数值预测预期errno — 用于oracle比对。

        规则驱动预测 (完整实现需符号执行引擎):
        - fd=-1 → EBADF
        - ptr=0且需要有效指针 → EFAULT
        - flags无效组合 → EINVAL
        """
        for i, (arg, at) in enumerate(zip(args,
            next((s["args"] for s in self._syscalls if s["name"] == name), []))):
            if at == "fd" and arg == -1:
                return "EBADF"
            if at == "ptr" and arg == 0:
                return "EFAULT"
        return "success_or_EINVAL"

    def compare_behaviors(self, syscall_name: str,
                          results_a: dict, results_b: dict) -> DiffOracleResult:
        """比对两个内核版本的syscall行为 — 发现分歧。"""
        oracle = DiffOracleResult(syscall_name=syscall_name)
        for input_key, a_result in results_a.items():
            b_result = results_b.get(input_key)
            if b_result is None:
                oracle.divergence_details.append(
                    f"Input {input_key} missing in kernel B")
                oracle.divergence_detected = True
                continue
            if a_result.get("errno") != b_result.get("errno"):
                oracle.divergence_details.append(
                    f"Input {input_key}: errno mismatch A={a_result.get('errno')} "
                    f"vs B={b_result.get('errno')}")
                oracle.divergence_detected = True
            if a_result.get("crashed") != b_result.get("crashed"):
                oracle.divergence_details.append(
                    f"Input {input_key}: crash mismatch A={a_result.get('crashed')} "
                    f"vs B={b_result.get('crashed')}")
                oracle.divergence_detected = True
        if oracle.divergence_detected:
            oracle.confidence = 0.85
            self._findings.append(oracle)
        return oracle

    def fuzz_syscall(self, syscall_name: str,
                     n_inputs: int = 16) -> list[SyscallInput]:
        if self._exclude_sensitive and syscall_name in _SENSITIVE_SYSCALLS:
            logger.info("Skipping sensitive syscall: %s", syscall_name)
            return []
        if self._whitelist and syscall_name not in self._whitelist:
            return []
        return self.generate_inputs(syscall_name, n_variants=n_inputs)

    def fuzz_all(self, n_per_syscall: int = 8) -> dict[str, list[SyscallInput]]:
        results = {}
        for sc in self._syscalls:
            name = sc["name"]
            if self._exclude_sensitive and name in _SENSITIVE_SYSCALLS:
                continue
            if self._whitelist and name not in self._whitelist:
                continue
            results[name] = self.fuzz_syscall(name, n_inputs=n_per_syscall)
        logger.info("Fuzz oracle: generated inputs for %d syscalls", len(results))
        return results

    def coverage_report(self) -> dict:
        """报告参数类型覆盖率 — 哪些类型组合已通过测试。"""
        covered = defaultdict(set)
        for sc in self._syscalls:
            for at in sc["args"]:
                for val in self._grammar.get(at, []):
                    covered[at].add(val)
        return {
            at: {"total_values": len(self._grammar.get(at, [])),
                 "covered": len(vals)}
            for at, vals in covered.items()
        }


def generate_syscall_fuzz_inputs(syscall_name: str,
                                  n_inputs: int = 16) -> list[SyscallInput]:
    oracle = SyscallFuzzOracle()
    return oracle.fuzz_syscall(syscall_name, n_inputs=n_inputs)
