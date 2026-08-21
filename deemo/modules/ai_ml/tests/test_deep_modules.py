# 新模块单元测试: 参数等式/路径守卫/循环累积 三大误报压制模块
# 用合成的Intel/AT&T指令序列直接验证行为, 不依赖真实编译产物
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from analysis.param_size_equality import ParamSizeEquality, EqualityKind
from analysis.path_size_resolver import PathSizeResolver
from analysis.loop_cumulative_bound import LoopCumulativeBound


# 参数来源等式

def test_param_same_slot_intel():
    """alloc与copy的size同源于栈槽[rbp+0x18]→恒等"""
    instrs = [
        "mov QWORD PTR [rbp+0x18], rdx",   # 参数len暂存
        "mov rax, QWORD PTR [rbp+0x18]",   # len
        "mov rcx, rax",                    # → malloc size
        "call 0x1000 <malloc>",
        "mov r8, QWORD PTR [rbp+0x18]",    # len → copy size
        "mov rcx, rax",
        "mov rdx, rsi",
        "call 0x2000 <memcpy>",
    ]
    ai, ci = 3, 7
    r = ParamSizeEquality().check(instrs, ai, 'malloc', ci, 'memcpy')
    assert r.kind == EqualityKind.SAME_SLOT, r


def test_param_same_param_att():
    """AT&T下alloc/copy同参数→恒等"""
    instrs = [
        "mov %rdi,%rcx",           # len(rdi=param0) → malloc size
        "call malloc",
        "mov %rdi,%r8",            # len(rdi) → copy size
        "call memcpy",
    ]
    r = ParamSizeEquality().check(instrs, 1, 'malloc', 3, 'memcpy')
    assert r.kind == EqualityKind.SAME_PARAM, r


def test_param_arith_differs():
    """alloc=n*8 vs copy=n→算术变换→不判等"""
    instrs = [
        "mov rax, [rbp+0x18]",     # n
        "shl rax, 3",              # n*8
        "mov rcx, rax",
        "call 0x1000 <malloc>",    # malloc(n*8)
        "mov rax, [rbp+0x18]",     # n
        "mov r8, rax",
        "call 0x2000 <memcpy>",    # memcpy(..., n)
    ]
    ai, ci = 3, 6
    r = ParamSizeEquality().check(instrs, ai, 'malloc', ci, 'memcpy')
    assert r.kind == EqualityKind.DIFFERENT, r


def test_param_const_equal():
    """两处立即数相等→恒等"""
    instrs = [
        "mov ecx, 0x100",
        "call 0x1000 <malloc>",    # malloc(256)
        "mov r8d, 0x100",
        "call 0x2000 <memcpy>",    # memcpy(..., 256)
    ]
    r = ParamSizeEquality().check(instrs, 1, 'malloc', 3, 'memcpy')
    assert r.kind == EqualityKind.SAME_CONST, r


# 路径敏感逐路径大小解析

def test_path_guard_upper_bound():
    """支配守卫len≤256→copy上界256"""
    instrs = [
        "cmp edx, 0x100",          # bb0: 守卫 len(edx)≤256
        "jg 0x3000 <exit>",
        "mov rcx, rax",            # bb1: dst
        "mov r8d, edx",            # n = len
        "mov rdx, rsi",            # src
        "call 0x2000 <memcpy>",
        "ret",                     # bb2: exit
    ]
    bb = [(0, 2), (2, 6), (6, 7)]
    edges = [(0, 1), (0, 2), (1, 2)]
    r = PathSizeResolver().resolve_copy_upper_bound(
        instrs, 5, 'memcpy', bb, edges)
    assert r.upper_bound is not None and r.upper_bound == 0x100, r


def test_path_no_guard_none():
    """无守卫→无法证明→None"""
    instrs = [
        "mov rcx, rax",
        "mov rdx, rsi",
        "mov r8d, edx",
        "call 0x2000 <memcpy>",
    ]
    bb = [(0, 4)]
    r = PathSizeResolver().resolve_copy_upper_bound(
        instrs, 3, 'memcpy', bb, [])
    assert r.upper_bound is None


# 循环累积拷贝上界

_LOOP_HEAD = [
    # bb0: init i=0
    "mov DWORD PTR [rbp-0x4], 0x0",
    "jmp 0x4040",
]
_LOOP_BODY = [
    # bb1: memcpy(dst+i*16, src, 16); i++
    "mov eax, [rbp-0x4]",
    "shl eax, 0x4",
    "movsxd rdx, eax",
    "mov rax, [rbp-0x10]",
    "lea rcx, [rdx+rax]",
    "mov r8d, 0x10",
    "mov rdx, [rbp+0x10]",
    "call 0x2000 <memcpy>",
    "add DWORD PTR [rbp-0x4], 0x1",
]
_LOOP_TEST = lambda bound: [
    f"cmp DWORD PTR [rbp-0x4], {bound}",
    "jle 0x4040",
]


def _loop_cfg(bound):
    instrs = _LOOP_HEAD + _LOOP_BODY + _LOOP_TEST(bound)
    bb = [(0, 2), (2, 11), (11, 13)]
    edges = [(0, 2), (2, 1), (1, 2)]
    return instrs, bb, edges


def test_loop_cumulative_bounded_safe():
    """有界循环: 32×16=512 ≤ usable(512)=520→可证安全"""
    instrs, bb, edges = _loop_cfg("0x20")
    r = LoopCumulativeBound().compute(
        instrs, bb, edges, 9, 'memcpy', alloc_usable=520)
    assert r.in_loop, r
    assert r.iter_bound == 0x20, r
    assert r.provably_safe, r


def test_loop_cumulative_overflow():
    """有界循环但累积超出→不判安全(检测方处理)"""
    instrs, bb, edges = _loop_cfg("0x40")
    r = LoopCumulativeBound().compute(
        instrs, bb, edges, 9, 'memcpy', alloc_usable=520)
    assert r.in_loop and r.cumulative_hi is not None
    assert r.cumulative_hi > 520 and not r.provably_safe, r


def test_loop_advances_dst():
    """循环内dst由lea推进→offset式写"""
    instrs = [
        "mov eax, [rbp-0x4]",
        "lea rcx, [rdx+rax]",
        "call 0x2000 <memcpy>",
        "add DWORD PTR [rbp-0x4], 0x1",
    ]
    bb = [(0, 3), (3, 4)]
    edges = [(0, 1), (1, 0)]
    r = LoopCumulativeBound().loop_advances_dst(
        instrs, bb, edges, 2, 'memcpy')
    assert r is True
