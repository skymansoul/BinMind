# Heap object lifecycle FSM: alloc→free→use path detection.
# Uses finite state machine instead of full pointer analysis. Alias analysis
# precision in the binary context is bounded by decompiler variable recovery.
# The FSM approach correctly tracks alloc/free/use triples as long as the
# decompiler assigns the same variable name.
import re
from collections import defaultdict

_HEAP_ALLOC = {"malloc","calloc","realloc","new","mmap","HeapAlloc","kalloc","kmalloc"}
_HEAP_FREE = {"free","delete","kfree","munmap","HeapFree","realloc"}


def detect_uaf_static(code: str, func_name: str = "") -> list[dict]:
    """静态检测UAF: 在归一化IR上构建对象生命周期FSM."""
    lines = [l.strip() for l in code.split('\n') if l.strip() and not l.strip().startswith('//')]
    objects: dict[str, dict] = {}  # var -> {alloc_line, free_line, use_lines}
    findings = []
    for lineno, line in enumerate(lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip().lower()
        if not lhs: continue
        # 检测分配
        if any(f in rhs for f in _HEAP_ALLOC):
            objects[lhs] = {"alloc_line": lineno, "free_line": -1, "use_lines": []}
        # 检测释放
        for free_func in _HEAP_FREE:
            if free_func in rhs and lhs in objects:
                # realloc既是free也是alloc
                if free_func == "realloc":
                    objects[lhs]["use_lines"].append(lineno)  # realloc之前的使用
                objects[lhs]["free_line"] = lineno
                break
        # 检测使用 (对已知对象检查引用)
        for var_name in list(objects.keys()):
            if var_name in rhs and var_name != lhs:
                objects[var_name]["use_lines"].append(lineno)
    # 分析生命周期违规
    for var, obj in objects.items():
        if obj["free_line"] < 0: continue
        for use_ln in obj["use_lines"]:
            if use_ln > obj["free_line"]:
                findings.append({
                    "rule_id": f"UAF-FSM-{var}",
                    "type": "heap-corruption",
                    "function": func_name,
                    "severity": "High",
                    "description": f"{var}: alloc@L{obj['alloc_line']} free@L{obj['free_line']} use@L{use_ln}",
                    "cwe": "CWE-416",
                    "confidence": 0.78,
                    "vuln_subtype": "uaf",
                })
    return findings


def detect_double_free(code: str, func_name: str = "") -> list[dict]:
    """检测同一变量多次free的模式."""
    findings = []
    lines = [l.strip() for l in code.split('\n') if l.strip()]
    free_counts: dict[str, list[int]] = defaultdict(list)
    for lineno, line in enumerate(lines):
        for free_func in _HEAP_FREE:
            if free_func not in line.lower(): continue
            m = re.search(rf'{free_func}\s*\(([^)]+)\)', line)
            if m:
                var = m.group(1).strip().strip('&').strip('*').strip()
                free_counts[var].append(lineno)
    for var, lines_list in free_counts.items():
        if len(lines_list) >= 2:
            findings.append({
                "rule_id": f"DF-{var}",
                "type": "heap-corruption", "function": func_name,
                "severity": "Critical",
                "description": f"{var}: 在L{lines_list[0]}和L{lines_list[1]}被两次释放",
                "cwe": "CWE-415", "confidence": 0.90,
                "vuln_subtype": "double_free",
            })
    return findings
