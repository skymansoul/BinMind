# UAF重生追踪与格式串溯源模块单元测试
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from src.detect.analysis.uaf_rebirth_tracker import RebirthTracker
from src.detect.analysis.uaf_alias_tracker import AliasSet
from src.detect.analysis.fmt_provenance import FmtProvenance


def _aset(members, free_sites, use_sites):
    return AliasSet(canonical="x@0", members=set(members),
                    alloc_site=0, free_sites=free_sites, use_sites=use_sites,
                    is_freed=True, is_vulnerable=True)


def test_rebirth_realloc_writeback():
    """realloc写回→使用新指针安全: use被过滤"""
    instrs = [
        "mov rax, [rbp-0x8]",
        "mov rcx, rax",
        "call realloc",
        "mov [rbp-0x8], rax",      # 结果存槽
        "mov rax, [rbp-0x8]",
        "mov rcx, rax",
        "call memcpy",             # use@6 使用重生后的指针
        "mov rax, [rbp-0x8]",
        "call free",
    ]
    # free@2(realloc视为free), use@6
    a = _aset({"rax", "rcx"}, [2], [6])
    RebirthTracker().apply(instrs, [a])
    assert a.use_sites == [] and not a.is_vulnerable, a


def test_rebirth_keeps_real_uaf():
    """真实UAF: free后无重生→use保留"""
    instrs = [
        "mov rax, [rbp-0x8]",
        "mov rcx, rax",
        "call free",
        "mov rax, [rbp-0x8]",
        "mov rax, [rax]",          # 解引用悬垂指针 use@4
    ]
    a = _aset({"rax", "rcx"}, [2], [4])
    RebirthTracker().apply(instrs, [a])
    assert a.use_sites == [4] and a.is_vulnerable, a


def test_rebirth_null_after_free():
    """free后置空+NULL守卫→安全"""
    instrs = [
        "mov rcx, rax",
        "call free",
        "xor rax, rax",            # p=NULL
        "test rax, rax",
        "je 0x4040",
        "call memcpy",             # use@5 但前有置空
    ]
    a = _aset({"rax", "rcx"}, [1], [5])
    RebirthTracker().apply(instrs, [a])
    assert a.use_sites == [] and not a.is_vulnerable, a


def test_fmt_prov_const_rodata():
    """fmt直接指向.rodata→const"""
    instrs = [
        "mov ecx, 0x1",
        "lea rax, [rip+0x1234]",   # fmt
        "mov rcx, rax",
        "call printf",
    ]
    src, content = FmtProvenance().resolve(instrs, 3, "rcx", {0x1234: "hi %d"})
    assert src == "const_rodata", (src, content)


def test_fmt_prov_stack_const():
    """栈驻留常量fmt(movabs+lea+store)→const"""
    instrs = [
        "movabs rax, 0x64252065756c6176",   # "value %d"
        "lea rcx, [rsp+0x27]",
        "mov [rsp+0x27], rax",
        "mov byte [rsp+0x2f], 0x0",
        "call printf",
    ]
    src, content = FmtProvenance().resolve(instrs, 4, "rcx", {})
    assert src == "const_rodata", (src, content)


def test_fmt_prov_user_arg():
    """fmt来自函数参数→arg"""
    instrs = [
        "mov rcx, rdx",            # fmt=参数(rdx)
        "call printf",
    ]
    src, _ = FmtProvenance().resolve(instrs, 1, "rcx", {})
    assert src == "arg", src
