#!/usr/bin/env python3
"""Debug import chain for detector."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

try:
    from sample_compiler import SAMPLE_ROOT
    print("OK: sample_compiler")
except Exception as e:
    print("FAIL: sample_compiler:", e)

try:
    from modules.analysis.static.disasm_util import disassemble_binary
    print("OK: disasm_util")
except Exception as e:
    print("FAIL: disasm_util:", e)

try:
    from modules.analysis.static.heap_overflow_detect import (
        HeapOverflowDetector, detect_heap_overflow)
    print("OK: heap_overflow_detect")
except Exception as e:
    print("FAIL: heap_overflow_detect:", e)

try:
    from modules.analysis.static.heap_alloc_model import AllocatorFamily
    print("OK: heap_alloc_model")
except Exception as e:
    print("FAIL: heap_alloc_model:", e)

try:
    from modules.analysis.static.import_resolver import resolve_call_targets
    print("OK: import_resolver")
except Exception as e:
    print("FAIL: import_resolver:", e)
