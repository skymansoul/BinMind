#!/usr/bin/env python3
"""调试ASIP失败样本的候选生成+求解器结果."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import extract_candidates_v2
from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict

def debug_sample(name, source, expected):
    lines = source.strip().split('\n')
    candidates = extract_candidates_v2(source)
    if not candidates:
        print(f"  {name}: NO candidates (expected {expected})")
        return
    for c in candidates:
        result, _ = solve_candidate(c, lines, source)
        print(f"  {name}: desc={c.description}, verdict={result.verdict}, reason={result.reason[:80] if result.reason else 'N/A'}")

# Test key failing samples
samples = [
    ("cve_01", "int main() {\n    char *buf = malloc(32);\n    memcpy(buf, src, 64);\n    return 0;\n}", "VULN"),
    ("cve_27", "int main() {\n    char *buf = malloc(1);\n    memcpy(buf, src, 16);\n    return 0;\n}", "VULN"),
    ("cve_03", 'int main() {\n    char *buf = malloc(16);\n    strcpy(buf, "long string");\n    return 0;\n}', "VULN"),
    ("cve_04", "int main() {\n    char *p = malloc(64);\n    p[64] = 0;\n    return 0;\n}", "VULN"),
    ("cve_05", "int main() {\n    char *buf = malloc(32);\n    memcpy(buf + 16, src, 32);\n    return 0;\n}", "VULN"),
    ("cve_10", "int main() {\n    char *buf = malloc(8);\n    *(int *)(buf + 4) = 0x41414141;\n    *(int *)(buf + 8) = 0x42424242;\n    return 0;\n}", "VULN"),
]

for name, src, exp in samples:
    debug_sample(name, src, exp)
