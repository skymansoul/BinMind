# 来源约束写界推断冒烟测试.
#
# 覆盖四类核心场景:
#   1. 常量溢出: malloc(64) + memcpy(128)  → 确认溢出.
#   2. 同源安全: malloc(n) + memcpy(n)     → 符号相关, 不确认.
#   3. 守卫安全: malloc(64) + 有界写入     → 守卫约束, 不确认.
#   4. 同源越界: malloc(n) + memcpy(n+100) → 符号相关溢出, 确认.
#

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                '..', '..', '..', '..'))

from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector  # noqa: E402

_PASS = 0
_FAIL = 0


def _check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  [PASS] {name}")
    else:
        _FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def _ins(addr, mnem, ops):
    return {"address": addr, "mnemonic": mnem, "operands": ops}


def _run(stream, min_user=0x1000):
    det = HeapOverflowDetector(use_win64_abi=False)
    det.set_min_user_addr(min_user)
    det.pre_analyze(stream)
    for ins in stream:
        det.analyze_instruction(ins)
    confirmed = det.finalize(stream)
    return det, confirmed


def _find(confirmed):
    for f in confirmed:
        if "heap_overflow" in f.get("type", ""):
            return f
    return None


def test_const_overflow():
    """常量溢出: 分配64, 写入128."""
    stream = [
        _ins(0x1000, "mov", ["rdi", "64"]),
        _ins(0x1005, "call", ["<malloc>"]),
        _ins(0x100a, "mov", ["[rbp-0x8]", "rax"]),
        _ins(0x1010, "mov", ["rdx", "128"]),
        _ins(0x1015, "mov", ["rdi", "rax"]),
        _ins(0x101a, "mov", ["rsi", "rax"]),
        _ins(0x101f, "call", ["<memcpy>"]),
    ]
    det, confirmed = _run(stream)
    f = _find(confirmed)
    _check("const_overflow: memcpy confirmed",
           f is not None and f.get("wb_verdict") == "confirmed",
           f"confirmed={confirmed}")
    _check("const_overflow: reason mentions write bound",
           "write" in (f or {}).get("wb_reason", ""),
           (f or {}).get("wb_reason", ""))


def test_correlated_safe():
    """同源安全: malloc(n) + memcpy(n), n为函数参数."""
    stream = [
        _ins(0x2000, "mov", ["rdi", "rsi"]),
        _ins(0x2005, "call", ["<malloc>"]),
        _ins(0x200a, "mov", ["[rbp-0x8]", "rax"]),
        _ins(0x2010, "mov", ["rdx", "rsi"]),
        _ins(0x2015, "mov", ["rdi", "rax"]),
        _ins(0x201a, "mov", ["rsi", "rax"]),
        _ins(0x201f, "call", ["<memcpy>"]),
    ]
    det, confirmed = _run(stream)
    _check("correlated_safe: no confirmed finding", len(confirmed) == 0,
           f"confirmed={confirmed}")
    _check("correlated_safe: suspected list available",
           len(det.suspected_findings) >= 0)


def test_guarded_safe():
    """守卫安全: malloc(64), 写入经 cmp rdx,64 约束."""
    stream = [
        _ins(0x3000, "mov", ["rdi", "64"]),
        _ins(0x3005, "call", ["<malloc>"]),
        _ins(0x300a, "mov", ["[rbp-0x8]", "rax"]),
        _ins(0x3010, "mov", ["rdx", "rsi"]),
        _ins(0x3015, "cmp", ["rdx", "64"]),
        _ins(0x3018, "jbe", ["0x3020"]),
        _ins(0x301c, "mov", ["rdi", "rax"]),
        _ins(0x3020, "mov", ["rsi", "rax"]),
        _ins(0x3024, "call", ["<memcpy>"]),
    ]
    det, confirmed = _run(stream)
    _check("guarded_safe: no confirmed finding", len(confirmed) == 0,
           f"confirmed={confirmed}")


def test_correlated_overflow():
    """同源越界: malloc(n) + memcpy(n+100)."""
    stream = [
        _ins(0x4000, "mov", ["rdi", "rsi"]),
        _ins(0x4005, "call", ["<malloc>"]),
        _ins(0x400a, "mov", ["[rbp-0x8]", "rax"]),
        _ins(0x4010, "mov", ["rdx", "rsi"]),
        _ins(0x4015, "add", ["rdx", "100"]),
        _ins(0x4018, "mov", ["rdi", "rax"]),
        _ins(0x401c, "mov", ["rsi", "rax"]),
        _ins(0x4020, "call", ["<memcpy>"]),
    ]
    det, confirmed = _run(stream)
    f = _find(confirmed)
    _check("correlated_overflow: memcpy confirmed",
           f is not None and f.get("wb_verdict") == "confirmed",
           f"confirmed={confirmed}")


if __name__ == "__main__":
    test_const_overflow()
    test_correlated_safe()
    test_guarded_safe()
    test_correlated_overflow()
    print(f"\n来源约束写界推断 smoke: {_PASS} passed, {_FAIL} failed")
    sys.exit(1 if _FAIL else 0)
