# Indirect format-string detection via def-use backtracking.
# Tracks two-hop variable propagation: char *p = user_input; ... printf(p).
# Longer chains are not tracked (>2 hops rare in real vulns, increase FPs).
_FORMAT_FUNCS = {"printf","fprintf","sprintf","snprintf","dprintf",
                 "syslog","vprintf","vfprintf","vsprintf","vsnprintf"}
_TAINT_SRC = {"read","recv","fgets","scanf","gets","argv","getenv",
              "fread","recvfrom","recvmsg","strcpy","strcat","memcpy"}


def detect_indirect_fmt(code: str, func_name: str = "") -> list[dict]:
    """检测间接传参的格式化字符串漏洞: user_input -> var -> printf(var)."""
    lines = [l.strip() for l in code.split('\n') if l.strip() and not l.strip().startswith('//')]
    findings = []; tainted_vars: set[str] = set()
    # 第一遍: 标记污点源
    for lineno, line in enumerate(lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs_l = line[eq+1:].strip().lower()
        if any(src in rhs_l for src in _TAINT_SRC):
            tainted_vars.add(lhs)
    # 第二遍: 传播一步 (var2 = var1)
    for lineno, line in enumerate(lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip()
        for tv in list(tainted_vars):
            if tv in rhs and lhs != tv:
                tainted_vars.add(lhs)
    # 第三遍: 检测格式化调用
    for lineno, line in enumerate(lines):
        line_l = line.lower()
        for func in _FORMAT_FUNCS:
            if func not in line_l: continue
            for tv in tainted_vars:
                if tv in line:
                    findings.append({
                        "rule_id": f"FS-IND-{tv}",
                        "type": "format-string", "function": func_name,
                        "severity": "High",
                        "description": f"间接格式串: {tv}来自用户输入后传入{func}@L{lineno}",
                        "cwe": "CWE-134", "confidence": 0.72,
                        "line": lineno,
                    })
                    break
    return findings
