# -*- coding: utf-8 -*-
# SAWCE E2E verification script
# Verify Stage 9 symbolic correlation filter and Stage 10 loop accumulation detection

import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily


def test_same_source_safe():
    """malloc(arg0); memcpy(rax, rsi, arg0) -> alloc size == write size -> SAFE"""
    addr = 0x401000
    insns = [
        {"address": addr, "mnemonic": "mov", "operands": ["rdi", "rsi"]},
        {"address": addr+3, "mnemonic": "call", "operands": ["0x402000 <malloc>"]},
        {"address": addr+8, "mnemonic": "mov", "operands": ["rdi", "rax"]},
        {"address": addr+11, "mnemonic": "mov", "operands": ["rdx", "rsi"]},
        {"address": addr+14, "mnemonic": "call", "operands": ["0x403000 <memcpy>"]},
    ]
    det = HeapOverflowDetector(AllocatorFamily.GLIBC)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    findings = det.finalize(insns)
    stats = det.stats

    print("\n[Test 1] same_source_safe")
    print("  raw_findings: %d" % stats["raw_findings"])
    print("  filtered_findings: %d" % stats["filtered_findings"])
    print("  sawce_stats: %s" % stats.get("sawce_correlator", {}))
    for f in findings:
        print("  finding: alloc=%s write=%s" % (
            f.get("alloc_size"), f.get("write_size")))

    # SAWCE should filter: both alloc and write size come from rsi (arg1)
    return len(findings) == 0, "SAWCE should filter same-source alloc-write pair"


def test_different_source_overflow():
    """malloc(64); memcpy(p, src, 128) -> different source, write > alloc -> ALERT"""
    addr = 0x401000
    insns = [
        {"address": addr, "mnemonic": "mov", "operands": ["edi", "0x40"]},
        {"address": addr+5, "mnemonic": "call", "operands": ["0x402000 <malloc>"]},
        {"address": addr+10, "mnemonic": "mov", "operands": ["rdi", "rax"]},
        {"address": addr+13, "mnemonic": "lea", "operands": ["rsi", "[rip+0x4000]"]},
        {"address": addr+20, "mnemonic": "mov", "operands": ["edx", "0x80"]},
        {"address": addr+25, "mnemonic": "call", "operands": ["0x403000 <memcpy>"]},
    ]
    det = HeapOverflowDetector(AllocatorFamily.GLIBC)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    findings = det.finalize(insns)
    stats = det.stats

    print("\n[Test 2] different_source_overflow")
    print("  raw_findings: %d" % stats["raw_findings"])
    print("  filtered_findings: %d" % stats["filtered_findings"])
    print("  sawce_stats: %s" % stats.get("sawce_correlator", {}))
    for f in findings:
        print("  finding: alloc=%s write=%s" % (
            f.get("alloc_size"), f.get("write_size")))

    return len(findings) > 0, "Should retain overflow alert (different source)"


def test_const_safe():
    """malloc(128); memcpy(p, src, 64) -> alloc=128 >= write=64 -> SAFE"""
    addr = 0x401000
    insns = [
        {"address": addr, "mnemonic": "mov", "operands": ["edi", "0x80"]},
        {"address": addr+5, "mnemonic": "call", "operands": ["0x402000 <malloc>"]},
        {"address": addr+10, "mnemonic": "mov", "operands": ["rdi", "rax"]},
        {"address": addr+13, "mnemonic": "lea", "operands": ["rsi", "[rip+0x4000]"]},
        {"address": addr+20, "mnemonic": "mov", "operands": ["edx", "0x40"]},
        {"address": addr+25, "mnemonic": "call", "operands": ["0x403000 <memcpy>"]},
    ]
    det = HeapOverflowDetector(AllocatorFamily.GLIBC)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    findings = det.finalize(insns)
    stats = det.stats

    print("\n[Test 3] const_safe")
    print("  raw_findings: %d" % stats["raw_findings"])
    print("  filtered_findings: %d" % stats["filtered_findings"])

    return len(findings) == 0, "Constant comparison should be safe"


def test_loop_accumulate():
    """malloc(256); loop 5x { memcpy(p+offset, src, 64) } -> cumulative overflow"""
    addr = 0x401000
    insns = [
        {"address": addr, "mnemonic": "mov", "operands": ["edi", "0x100"]},
        {"address": addr+5, "mnemonic": "call", "operands": ["0x402000 <malloc>"]},
        {"address": addr+10, "mnemonic": "mov", "operands": ["rbx", "rax"]},
        {"address": addr+13, "mnemonic": "mov", "operands": ["ecx", "0x5"]},
        {"address": addr+18, "mnemonic": "lea", "operands": ["rsi", "[rip+0x4000]"]},
        # loop_start = addr+25 = 0x401019
        {"address": addr+25, "mnemonic": "mov", "operands": ["rdi", "rbx"]},
        {"address": addr+28, "mnemonic": "mov", "operands": ["edx", "0x40"]},
        {"address": addr+33, "mnemonic": "call", "operands": ["0x403000 <memcpy>"]},
        {"address": addr+38, "mnemonic": "add", "operands": ["rbx", "0x40"]},
        {"address": addr+43, "mnemonic": "dec", "operands": ["ecx"]},
        # back-edge: jnz to addr+25=0x401019
        {"address": addr+45, "mnemonic": "jnz", "operands": ["0x401019"]},
    ]
    det = HeapOverflowDetector(AllocatorFamily.GLIBC)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    findings = det.finalize(insns)
    stats = det.stats

    print("\n[Test 4] loop_accumulate")
    print("  raw_findings: %d" % stats["raw_findings"])
    print("  filtered_findings: %d" % stats["filtered_findings"])
    print("  loop_stats: %s" % stats.get("loop_accumulator", {}))
    for f in findings:
        print("  finding: method=%s alloc=%s write=%s" % (
            f.get("detection_method",""), f.get("alloc_size"),
            f.get("write_size")))

    has_loop = any(
        f.get("detection_method") == "loop_accumulation" for f in findings)
    return has_loop, "Stage 10 should report loop accumulation overflow"


def main():
    print("=" * 60)
    print("SAWCE Stage 9/10 E2E Verification")
    print("=" * 60)

    results = []
    for name, fn in [
        ("same_source_safe", test_same_source_safe),
        ("different_source_overflow", test_different_source_overflow),
        ("const_safe", test_const_safe),
        ("loop_accumulate", test_loop_accumulate),
    ]:
        try:
            ok, msg = fn()
            status = "PASS" if ok else "FAIL"
            results.append((name, status, msg))
            print("  -> %s: %s" % (status, msg))
        except Exception as e:
            results.append((name, "ERROR", str(e)))
            print("  -> ERROR: %s" % e)
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, status, msg in results:
        print("  [%s] %s: %s" % (status, name, msg))

    passed = sum(1 for _, s, _ in results if s == "PASS")
    total = len(results)
    print("\n  %d/%d passed" % (passed, total))


if __name__ == "__main__":
    main()
