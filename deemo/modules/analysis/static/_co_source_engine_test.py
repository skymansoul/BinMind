# 分配-写关联 引擎自测 — 验证后向根来源追踪与同源判定
# 使用与 objdump 一致的真实指令格式
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
from modules.analysis.static.co_source_engine import (
    AWSCEngine, Root, ROOT_IMM, ROOT_STACK, ROOT_PARAM, ROOT_CALLRET)


def mk(addr, mnem, ops):
    return {"address": addr, "mnemonic": mnem, "operands": ops}


def build_same_stack_case():
    """分配与写入都从 [rbp-0x20] 取 size → 同源 SAFE."""
    ins = [
        mk(0x1000, "push", ["rbp"]),
        mk(0x1001, "mov", ["rbp", "rsp"]),
        mk(0x1004, "mov", ["QWORD PTR [rbp-0x20]", "rdi"]),   # size 参数入栈
        mk(0x1008, "mov", ["rax", "QWORD PTR [rbp-0x20]"]),
        mk(0x100c, "mov", ["rdi", "rax"]),
        mk(0x100f, "call", ["malloc"]),
        mk(0x1014, "mov", ["rbx", "rax"]),
        mk(0x1017, "mov", ["rax", "QWORD PTR [rbp-0x20]"]),
        mk(0x101b, "mov", ["rdx", "rax"]),                     # memcpy size
        mk(0x101e, "mov", ["rdi", "rbx"]),
        mk(0x1021, "mov", ["rsi", "0x400000"]),
        mk(0x1024, "call", ["memcpy"]),
    ]
    return ins


def build_param_case():
    """真实编译器模式: 参数rdx先入栈, 分配与写入都从 [rbp-0x20] 取 → 同源."""
    ins = [
        mk(0x2000, "push", ["rbp"]),
        mk(0x2001, "mov", ["rbp", "rsp"]),
        mk(0x2004, "mov", ["QWORD PTR [rbp-0x20]", "rdx"]),  # 参数保栈
        mk(0x2008, "mov", ["rax", "QWORD PTR [rbp-0x20]"]),
        mk(0x200c, "mov", ["rdi", "rax"]),
        mk(0x200f, "call", ["malloc"]),
        mk(0x2014, "mov", ["rbx", "rax"]),
        mk(0x2017, "mov", ["rax", "QWORD PTR [rbp-0x20]"]),   # 写入重新取回
        mk(0x201b, "mov", ["rdx", "rax"]),
        mk(0x201e, "mov", ["rdi", "rbx"]),
        mk(0x2021, "mov", ["rsi", "0x400000"]),
        mk(0x2024, "call", ["memcpy"]),
    ]
    return ins


def build_const_overflow_case():
    """分配 64, 写入 256 → 常量比较溢出."""
    ins = [
        mk(0x3000, "mov", ["rdi", "0x40"]),
        mk(0x3007, "call", ["malloc"]),
        mk(0x300c, "mov", ["rbx", "rax"]),
        mk(0x300f, "mov", ["rdx", "0x100"]),
        mk(0x3016, "mov", ["rdi", "rbx"]),
        mk(0x3019, "call", ["memcpy"]),
    ]
    return ins


def build_diff_source_case():
    """分配从 [rbp-0x20], 写入从 [rbp-0x28] → 不同源 unknown."""
    ins = [
        mk(0x4000, "mov", ["rax", "QWORD PTR [rbp-0x20]"]),
        mk(0x4004, "mov", ["rdi", "rax"]),
        mk(0x4007, "call", ["malloc"]),
        mk(0x400c, "mov", ["rbx", "rax"]),
        mk(0x400f, "mov", ["rax", "QWORD PTR [rbp-0x28]"]),
        mk(0x4013, "mov", ["rdx", "rax"]),
        mk(0x4016, "mov", ["rdi", "rbx"]),
        mk(0x4019, "call", ["memcpy"]),
    ]
    return ins


def build_taint_callret_case():
    """read 返回值作为写入 size → callret 根 (外部输入)."""
    ins = [
        mk(0x5000, "mov", ["rdi", "0x40"]),
        mk(0x5007, "call", ["malloc"]),
        mk(0x500c, "mov", ["rbx", "rax"]),
        mk(0x500f, "lea", ["rsi", "[rbp-0x40]"]),
        mk(0x5013, "mov", ["rdx", "0x400"]),
        mk(0x5016, "mov", ["rdi", "0x0"]),
        mk(0x5019, "call", ["read"]),       # rax = read(...)
        mk(0x501e, "mov", ["rdx", "rax"]),  # 写入 size = read 返回值
        mk(0x5021, "mov", ["rdi", "rbx"]),
        mk(0x5024, "call", ["memcpy"]),
    ]
    return ins


def main():
    eng = AWSCEngine(use_win64_abi=False)
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'OK' if cond else 'FAIL'}] {name}")
        ok += 1 if cond else 0

    # Case 1: 同栈槽同源
    ins = build_same_stack_case()
    ar = eng.trace_size_root(ins, 0x100f, "rdi")
    wr = eng.trace_size_root(ins, 0x1024, "rdx")
    print("alloc root:", ar, " write root:", wr)
    v, n, r = eng.correlate(ar, wr)
    print("  verdict:", v, n, r)
    check("same_stack co_source safe", v == "safe")

    # Case 2: 参数经栈槽传播 → 同源
    ins = build_param_case()
    ar = eng.trace_size_root(ins, 0x200f, "rdi")
    wr = eng.trace_size_root(ins, 0x2024, "rdx")
    print("alloc root:", ar, " write root:", wr)
    v, n, r = eng.correlate(ar, wr)
    print("  verdict:", v, n, r)
    check("param co_source safe", v == "safe")

    # Case 3: 常量溢出
    ins = build_const_overflow_case()
    ar = eng.trace_size_root(ins, 0x3007, "rdi")
    wr = eng.trace_size_root(ins, 0x3019, "rdx")
    print("alloc root:", ar, " write root:", wr)
    v, n, r = eng.correlate(ar, wr)
    print("  verdict:", v, n, r)
    check("const overflow detected", v == "overflow" and n == 192)

    # Case 4: 不同源 → unknown
    ins = build_diff_source_case()
    ar = eng.trace_size_root(ins, 0x4007, "rdi")
    wr = eng.trace_size_root(ins, 0x4019, "rdx")
    print("alloc root:", ar, " write root:", wr)
    v, n, r = eng.correlate(ar, wr)
    print("  verdict:", v, n, r)
    check("diff_source unknown", v == "unknown")

    # Case 5: 外部输入 callret
    ins = build_taint_callret_case()
    wr = eng.trace_size_root(ins, 0x5024, "rdx")
    print("write root:", wr)
    check("callret taint root", wr.kind == ROOT_CALLRET
          and wr.value == "read")

    print(f"\n{ok}/5 checks passed")
    sys.exit(0 if ok == 5 else 1)


if __name__ == "__main__":
    main()
