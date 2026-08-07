#!/usr/bin/env python3
"""CVE_06 单独测试脚本 — 验证calloc乘积语义修复."""
import sys, os
sys.path.insert(0, "C:\\Users\\Administrator\\Desktop\\BinMind")
sys.path.insert(0, "C:\\Users\\Administrator\\Desktop\\BinMind\\deemo")
sys.path.insert(0, "C:\\Users\\Administrator\\Desktop\\BinMind\\deemo\\modules\\vuln\\tests\\regression_heap")

from deemo.modules.vuln.tests.regression_heap.scan_scheduler import scan_binary

base = "C:\\Users\\Administrator\\Desktop\\BinMind\\deemo\\modules\\vuln\\sample_bins\\heap_overflow_cve\\CVE_06"

for name in ["vuln_CVE06", "vuln_CVE06.exe", "vuln_CVE_06", "vuln_CVE_06.exe"]:
    p = os.path.join(base, name)
    if os.path.isfile(p):
        result = scan_binary(p)
        print("Binary:", p)
        print("Findings:", len(result["findings"]))
        print("Time:", result["time_ms"], "ms")
        print("Error:", result["error"])
        for f in result["findings"]:
            print("  Finding:", f)
        print("Stats:", result["stats"])
        break
else:
    print("Files in CVE_06:", os.listdir(base))
    sys.exit(1)
