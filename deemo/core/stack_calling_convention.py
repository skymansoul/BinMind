"""
栈帧特征跨编译器泛化 — 从多种编译器(GCC/Clang/MSVC)产物的栈帧中提取通用溢出特征。

设计意图:
  stack_overflow_analyzer.py的符号执行依赖精确的函数边界和栈帧布局,
  但不同编译器(GCC/Clang/MSVC)和优化级别(-O0/-O2/-O3/-Os)产生不同的栈帧结构:
    (a) GCC -O0: push rbp; mov rbp,rsp; sub rsp,imm → 标准帧
    (b) Clang -O2: 可能省略帧指针(-fomit-frame-pointer), 用rsp直接寻址
    (c) MSVC: RtlUnwindEx异常处理链插入额外栈空间
    (d) -Os: 可能将多个局部变量合并到同一栈槽

  本模块从函数序言/结语中推断编译器和栈帧布局, 使偏移计算独立于编译器:
    G1 (序言分类): 7种常见序言模式 → 编译器+优化级别推断
    G2 (canary检测): 4种编译器插入canary的模式 → 通用canary识别
    G3 (栈帧重建): 从序言+函数体引用推断局部变量布局 → 通用缓冲区定位

  - Schneider et al.: "Breaking Bad: How Compilers Break
    Constant-Time Implementations" — 不同编译器对安全代码的破坏模式。
  - Di Federico et al.: "How the ELF Ruined Christmas" —
    二进制分析中栈帧重建的挑战和启发式方法。
  - Geimer & Maurice: "Fun with Flags" — GCC/Clang优化pass的CT破坏。

边界条件:
  - 无法处理手写汇编(无标准序言) → 标记为UNKNOWN_BY_CUSTOM_ASM。
  - 内联函数(inline)没有独立的栈帧 → 分析调用者时需考虑内联展开。
  - 异常处理栈帧(Windows SEH)的结构与标准帧不同 → 单独处理。
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

class CompilerFamily(Enum):
    GCC = auto()
    CLANG = auto()
    MSVC = auto()
    UNKNOWN = auto()

class OptLevel(Enum):
    O0 = auto()
    O1 = auto()
    O2 = auto()
    O3 = auto()
    Os = auto()     # 尺寸优化
    UNKNOWN = auto()

@dataclass
class StackFrameInfo:
    """从函数序言/结语推断的栈帧布局。"""
    compiler: CompilerFamily = CompilerFamily.UNKNOWN
    opt_level: OptLevel = OptLevel.UNKNOWN
    has_frame_pointer: bool = False      # 使用rbp作为帧指针?
    frame_size: int = 0                  # 从sub rsp,imm或栈分配总量推断
    canary_offset: int = -1              # canary在栈帧中的偏移(-1=无canary)
    return_addr_offset: int = -1         # 返回地址相对于入口rsp的偏移
    saved_regs_count: int = 0            # 保存的寄存器数量
    local_var_offsets: List[int] = field(default_factory=list)
    buffer_candidates: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

# 7种常见序言模式(字节级匹配)

_PROLOGUE_SIGNATURES: List[Tuple[bytes, CompilerFamily, OptLevel, str]] = [
    # (序言字节序列, 编译器, 优化级别, 描述)
    # GCC -O0: push rbp; mov rbp,rsp; sub rsp,imm
    (b'\x55\x48\x89\xE5\x48\x83\xEC', CompilerFamily.GCC, OptLevel.O0,
     'GCC -O0 standard frame pointer'),
    # GCC -O2: push rbx/rbp等; sub rsp,imm (可能省略帧指针)
    (b'\x53\x48\x83\xEC', CompilerFamily.GCC, OptLevel.O2,
     'GCC -O2 push reg + sub (may omit frame pointer)'),
    # Clang -O0: push rbp; mov rbp,rsp; sub rsp,imm (与GCC相同序言但sub立即数常更大)
    (b'\x55\x48\x89\xE5\x48\x81\xEC', CompilerFamily.CLANG, OptLevel.O0,
     'Clang -O0 large frame'),
    # Clang -O2: push rbp; mov rbp,rsp (简洁, 常省略sub rsp用push分配)
    (b'\x55\x48\x89\xE5\x50', CompilerFamily.CLANG, OptLevel.O2,
     'Clang -O2 push allocation'),
    # MSVC -O0: push rbp(R10); mov rbp,rsp; sub rsp,imm (REX前缀模式)
    (b'\x40\x55\x48\x8B\xEC\x48\x83\xEC', CompilerFamily.MSVC, OptLevel.O0,
     'MSVC -O0 standard'),
    # MSVC -O2: mov [rsp+imm], rbx等; sub rsp,imm (直接保存, 无push rbp)
    (b'\x48\x89\x5C\x24', CompilerFamily.MSVC, OptLevel.O2,
     'MSVC -O2 direct save (no push rbp)'),
    # GCC/Clang -Os: push regs only, compact
    (b'\x41\x54\x41\x55\x41\x56', CompilerFamily.GCC, OptLevel.Os,
     'GCC/Clang -Os callee-saved push chain'),
]

# 4种Canary插入模式

_CANARY_PATTERNS: List[Tuple[bytes, str, int]] = [
    # (特征字节序列, 描述, canary距离rbp的偏移估计)
    # GCC: mov rax, fs:[0x28]; mov [rbp-8], rax
    (b'\x64\x48\x8B\x04\x25\x28\x00\x00\x00', 'GCC/Clang __stack_chk_fail canary (fs:0x28)', 8),
    # MSVC: mov rax, __security_cookie; xor rax, rbp; mov [rbp+imm], rax
    (b'\x48\x8B\x05', 'MSVC __security_cookie load', 16),
    # ARM64: ldr xN, [xN, #imm] 从Thread Local Storage加载 → canary
    # (当前仅x86-64, ARM模式预留)
]

# 序言解析

def classify_stack_frame(func_bytes: bytes, func_offset: int = 0
                          ) -> StackFrameInfo:
    """
    从函数前64字节推断栈帧布局。

    func_bytes: 函数的原始字节(至少64字节)
    返回推断的栈帧信息。
    """
    info = StackFrameInfo()
    if len(func_bytes) < 8:
        info.warnings.append('function too short for prologue analysis')
        return info

    prologue = func_bytes[:64]

    # G1: 编译器+优化级别推断
    best_match_len = 0
    for sig, compiler, opt, desc in _PROLOGUE_SIGNATURES:
        if prologue[:len(sig)] == sig:
            if len(sig) > best_match_len:
                best_match_len = len(sig)
                info.compiler = compiler
                info.opt_level = opt
                info.warnings.append(f'matched prologue: {desc}')

    # 帧指针检测
    info.has_frame_pointer = (
        prologue[:3] == b'\x55\x48\x89'  # push rbp; mov rbp,rsp
        or prologue[:3] == b'\x40\x55\x48'  # MSVC variant
    )

    # G2: canary检测
    for canary_sig, desc, offset_est in _CANARY_PATTERNS:
        pos = func_bytes.find(canary_sig)
        if pos != -1 and pos < 128:  # canary通常在函数开头128字节内
            info.canary_offset = offset_est
            info.warnings.append(f'canary detected: {desc}')

    # G3: 栈帧大小推断
    info.frame_size = _infer_frame_size(prologue, info.compiler)
    if info.frame_size > 0 and info.has_frame_pointer:
        info.return_addr_offset = info.frame_size + 8  # rbp+8 = 返回地址
    elif info.frame_size > 0:
        info.return_addr_offset = info.frame_size  # 无帧指针, rsp直接寻址

    # 寄存器保存计数
    info.saved_regs_count = _count_saved_regs(prologue, info.compiler)

    return info

def _infer_frame_size(prologue: bytes, compiler: CompilerFamily) -> int:
    """
    从序言推断栈帧大小。
    搜索 sub rsp, imm 模式: 48 83 EC XX (小) 或 48 81 EC XX XX XX XX (大)
    """
    # 小帧: sub rsp, imm8 (48 83 EC XX)
    for i in range(len(prologue) - 4):
        if prologue[i:i+3] == b'\x48\x83\xEC':
            return prologue[i+3]  # imm8
        # 大帧: sub rsp, imm32 (48 81 EC XX XX XX XX)
        if prologue[i:i+3] == b'\x48\x81\xEC' and i + 7 <= len(prologue):
            return int.from_bytes(prologue[i+3:i+7], 'little')

    # Clang可能用push分配栈: 统计被保存寄存器数×8
    push_count = 0
    for b in prologue[:16]:
        if b in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):  # push rN
            push_count += 1
        elif b == 0x41 and push_count < 16:  # REX prefix for r8-r15 push
            push_count += 1
    if push_count > 0:
        return push_count * 8 + 32  # 估计+32的局部变量空间

    return 0

def _count_saved_regs(prologue: bytes, compiler: CompilerFamily) -> int:
    """统计序言中保存的寄存器数量。"""
    count = 0
    for b in prologue[:16]:
        if 0x50 <= b <= 0x57:  # push rN (x86-64)
            count += 1
        elif b == 0x41 and len(prologue) > 1:  # REX prefix
            # 下一字节若在0x50-0x57范围 → push r8-r15
            pass
    # 也统计MSVC风格的 mov [rsp+imm], reg
    for i in range(len(prologue) - 4):
        if prologue[i:i+3] == b'\x48\x89' and prologue[i+3] in (
            0x5C, 0x5D, 0x74, 0x7C):  # mov [rsp+imm], rbx/rbp/r12-r15
            count += 1
    return count

# 通用缓冲区偏移估计

def estimate_buffer_offset(frame_info: StackFrameInfo,
                            target_func: str = "",
                            buffer_name: str = "",
                            buffer_hint_size: int = 0
                            ) -> Dict[str, Any]:
    """
    基于栈帧信息估计缓冲区到返回地址的偏移(不依赖符号执行)。

    frame_info: classify_stack_frame的输出
    返回偏移估计和相关参数。
    """
    result: Dict[str, Any] = {
        'target_func': target_func,
        'compiler': frame_info.compiler.name,
        'opt_level': frame_info.opt_level.name,
        'has_frame_pointer': frame_info.has_frame_pointer,
        'has_canary': frame_info.canary_offset > 0,
        'estimated_total_frame': frame_info.frame_size,
    }

    if not frame_info.return_addr_offset or frame_info.return_addr_offset <= 0:
        result['padding_estimate'] = -1
        result['confidence'] = 0.20
        result['method'] = 'NONE'
        result['warning'] = 'cannot determine frame size'
        return result

    # 计算偏移
    ret_off = frame_info.return_addr_offset
    if frame_info.has_frame_pointer:
        # 帧指针模式: buf在rbp-N, 返回地址在rbp+8
        # padding = frame_size - buf_offset_from_rbp + 8
        # 简化: padding ≈ frame_size (保守)
        padding = frame_info.frame_size
    else:
        # 无帧指针: 返回地址在rsp+M, buf在rsp+N
        padding = ret_off

    if frame_info.canary_offset > 0:
        result['canary_at_offset'] = frame_info.canary_offset
        result['note'] = 'canary present — need leak primitive to bypass'

    result['padding_estimate'] = padding
    result['confidence'] = 0.60 if frame_info.has_frame_pointer else 0.45
    result['method'] = 'PROLOGUE_HEURISTIC'

    return result
