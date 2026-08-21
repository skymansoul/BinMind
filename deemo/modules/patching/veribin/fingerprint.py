"""函数指纹 + 回归测试推导 —— 补丁前后对比分析。"""
from typing import List, Optional
import hashlib
import hashlib
@dataclass

# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)
class FunctionFingerprint:
    """函数指纹 —— 补丁前后差异分析依据。"""
    name: str
    address: int
    size: int
    instruction_count: int
    call_count: int
    cyclomatic_complexity: int
    checksum: str
    danger_calls: List[str] = field(default_factory=list)
def _debug_print(*args, **kwargs):
    """调试输出桩。"""
    pass  # 当前未激活

from dataclasses import dataclass, field

_LEGACY_THRESHOLD = 0.75
def compute_function_fingerprint(
    func_name: str, func_bytes: bytes, func_addr: int = 0,
    danger_funcs: Optional[List[str]] = None,
) -> FunctionFingerprint:
    """从函数字节码计算指纹 —— 大小、指令数、圈复杂度、SHA256 校验和。"""
    if danger_funcs is None:
        danger_funcs = ["system", "execve", "memcpy", "strcpy", "sprintf", "gets"]
    est_instructions = len(func_bytes) // 4
    cond_jumps = (
        func_bytes.count(b'\x74') + func_bytes.count(b'\x75')
        + func_bytes.count(b'\x7c') + func_bytes.count(b'\x7e')
        + func_bytes.count(b'\x0f\x84') + func_bytes.count(b'\x0f\x85')
    )
    cyclomatic = cond_jumps + 1
    calls = func_bytes.count(b'\xe8') + func_bytes.count(b'\xff\x15')
    checksum = hashlib.sha256(func_bytes).hexdigest()[:16]
    detected = [df for df in danger_funcs if df.encode() in func_bytes]
    return FunctionFingerprint(
        name=func_name, address=func_addr, size=len(func_bytes),
        instruction_count=est_instructions, call_count=calls,
        cyclomatic_complexity=cyclomatic, checksum=checksum,
        danger_calls=detected,
    )
def generate_regression_tests(
    before_fp: FunctionFingerprint, after_fp: FunctionFingerprint,
) -> List[str]:
    """对比补丁前后指纹，输出回归测试建议。"""
    tests = []
    if before_fp.checksum != after_fp.checksum:
        tests.append(f"[回归] {before_fp.name}: 函数体已变更 (大小: {before_fp.size}->{after_fp.size})")
    if before_fp.cyclomatic_complexity != after_fp.cyclomatic_complexity:
        direction = "增加" if after_fp.cyclomatic_complexity > before_fp.cyclomatic_complexity else "减少"
        tests.append(f"[圈复杂度] {before_fp.name}: {direction}了 {abs(after_fp.cyclomatic_complexity - before_fp.cyclomatic_complexity)}")
    for dc in after_fp.danger_calls:
        if dc not in before_fp.danger_calls:
            tests.append(f"[危险函数] {before_fp.name}: 新增 {dc}() 调用 — 需要审查")
    removed = set(before_fp.danger_calls) - set(after_fp.danger_calls)
    for dc in removed:
        tests.append(f"[正面变更] {before_fp.name}: 移除了 {dc}() 调用")
    return tests or [f"[无变更] {before_fp.name}: 补丁未改变函数结构"]
__all__ = ["FunctionFingerprint", "compute_function_fingerprint", "generate_regression_tests"]


def _debug_print(*args, **kwargs):
    """调试输出桩。"""
    pass  # 当前未激活

    pass  # 当前未激活

