#!/usr/bin/env python3
# coding: utf-8
"""纯Python回归测试——无需objdump，内联测试数据验证全部4类检测器"""
import sys, os, json, time
# tests/regression_test_all.py → deemo/ (4 levels up from tests/)
_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, _PROJ)

# 内联测试用例: (名称, 漏洞类型, 指令列表, 期望检出)
TEST_CASES = [
# 堆溢出
    ("heap_tp_simple", "heap_overflow", [
        "mov edi, 64", "call malloc", "mov rdi, rax", "mov edx, 256", "call memcpy"
    ], True),
    ("heap_fp_disjoint", "heap_overflow", [
        "mov edi, 64", "call malloc", "mov rbx, rax",
        "mov edi, 128", "call malloc", "mov r12, rax",
        "mov rdi, rbx", "mov edx, 32", "call memcpy"
    ], False),  # 写入32 <= 分配64, 且指针关联到alloc#0
    ("heap_tp_two_allocs", "heap_overflow", [
        "mov edi, 64", "call malloc", "mov rbx, rax",
        "mov edi, 256", "call malloc", "mov r12, rax",
        "mov rdi, rbx", "mov edx, 80", "call memcpy"
    ], True),  # 写入80 > 分配64
    ("heap_tp_heartbleed", "heap_overflow", [
        "mov edi, 64", "call malloc", "mov rdi, rax",
        "mov rsi, r12", "mov edx, 65535", "call memcpy"
    ], True),  # 写入65535远超分配64

# UAF
    ("uaf_tp_basic", "uaf", [
        "call malloc", "mov rbx, rax", "mov rdi, rbx",
        "call free", "mov rax, [rbx]"
    ], True),
    ("uaf_fp_reassign", "uaf", [
        "call malloc", "mov rbx, rax", "mov rdi, rbx",
        "call free", "mov rbx, 0xDEAD", "mov rdi, rbx", "mov rax, [rbx]"
    ], False),  # rbx在free后重新赋值
    ("uaf_tp_double_free", "uaf", [
        "call malloc", "mov rbx, rax", "mov rdi, rbx",
        "call free", "mov rdi, rbx", "call free"
    ], True),

# 整数溢出
    ("int_tp_add_wrap", "integer_overflow", [
        "mov eax, 0x7FFFFFFF", "mov ecx, 100", "add eax, ecx",
        "mov edi, eax", "call malloc"
    ], True),
    ("int_tp_mul_wrap", "integer_overflow", [
        "mov eax, 0x1000000", "mov ecx, 0x100", "mul ecx",
        "mov edx, eax", "call memcpy"
    ], True),
    ("int_fp_safe_add", "integer_overflow", [
        "mov eax, 10", "mov ecx, 20", "add eax, ecx",
    ], False),  # 10+20=30, 无溢出

# 格式化字符串
    ("fmt_tp_tainted", "format_string", [
        "call recv", "mov rdi, rax", "call printf"
    ], True),
    ("fmt_fp_rodata", "format_string", [
        "lea rdi, [rip+0x2000]", "call printf"
    ], False),  # 格式串在.rodata, 安全
    ("fmt_fp_cleared", "format_string", [
        "call recv", "mov rdi, rax", "xor rdi, rdi", "call printf"
    ], False),  # rdi在printf前被清除
]

def run_test(name, vtype, insns, expected):
    t0 = time.time()
    try:
        if vtype == "heap_overflow":
            from modules.vuln.detection.ho_fp_filter import HoFpFilter
            s = HoFpFilter().filter(insns, name)
            detected = s.confirmed > 0
        elif vtype == "uaf":
            from modules.vuln.detection.uaf_detector import detect_uaf
            from modules.vuln.detection.uaf_lifecycle_filter import UafLifecycleFilter
            raw = detect_uaf(insns)
            detected = len(raw) > 0
            if detected:  # 应用时序过滤
                class F: pass
                wrapped = []
                for r in raw:
                    f = F(); f.free_insn_idx = r.free_insn_idx
                    f.use_insn_idx = r.use_insn_idx
                    f.dangling_pointer = r.dangling_pointer
                    wrapped.append(f)
                filt = UafLifecycleFilter().filter(insns, wrapped)
                detected = len(filt.confirmed) > 0
        elif vtype == "integer_overflow":
            from modules.vuln.detection.integer_overflow_detector import IntegerOverflowDetector
            from modules.vuln.detection.int_overflow_fp_filter import IntOverflowFpFilter
            raw = IntegerOverflowDetector().detect(insns, name)
            if raw:
                class F: pass
                wrapped = []
                for r in raw:
                    f = F(); f.location = r.location
                    f.operation = r.operation; f.confidence = r.confidence
                    f.dst_reg = getattr(r, 'dst_reg', ''); f.overflow_type = r.overflow_type
                    wrapped.append(f)
                filt = IntOverflowFpFilter().filter(insns, wrapped)
                detected = len(filt.confirmed) > 0
            else:
                detected = False
        elif vtype == "format_string":
            from modules.vuln.detection.path_taint_simplified import SimplifiedTaintTracker
            from modules.vuln.detection.fmt_fp_filter import FormatStringFpFilter
            tt = SimplifiedTaintTracker().track(insns, name)
            raw_detected = any(is_t for _,_,is_t in tt.format_calls)
            if raw_detected:
                class F: pass
                wrapped = []
                for idx, fn, is_t in tt.format_calls:
                    f = F(); f.call_idx = idx; f.call_address = 0
                    f.is_vulnerable = is_t; f.confidence = 0.8; f.fmt_arg = ''
                    wrapped.append(f)
                filt = FormatStringFpFilter().filter(insns, wrapped)
                detected = len(filt.confirmed) > 0
            else:
                detected = False
        else:
            detected = False
    except Exception as e:
        return {"name": name, "vuln_type": vtype, "detected": False, "expected": expected,
                "correct": False, "elapsed_ms": round((time.time()-t0)*1000,1), "error": str(e)[:80]}

    return {"name": name, "vuln_type": vtype, "detected": detected, "expected": expected,
            "correct": detected == expected, "elapsed_ms": round((time.time()-t0)*1000,1)}

print("=" * 60)
print("回归测试执行中...")
print("=" * 60)
results = [run_test(*tc) for tc in TEST_CASES]
correct = sum(1 for r in results if r["correct"])
print(f"\n结果: {correct}/{len(results)} 正确")
for r in results:
    status = "OK" if r["correct"] else "FAIL"
    exp = "TP" if r["expected"] else "FP"
    det = "FOUND" if r["detected"] else "MISS"
    print(f"  [{status}] {r['name']:30s} expect={exp:3s} got={det:5s} ({r['elapsed_ms']:.0f}ms)" +
          (f" ERR: {r.get('error','')}" if r.get('error') else ""))

with open(os.path.join(os.path.dirname(__file__) or '.', 'regression_results.json'), 'w') as f:
    json.dump(results, f, indent=2)
print(f"\n详细结果: regression_results.json")
