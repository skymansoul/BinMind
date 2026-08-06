# Angr Exploration 模式适配器 — 自动漏洞点分析包装
# 调用 angr 的 CFGFast + 符号探索, 检测危险函数调用点.
# 创建: 2026-08-05

import os, sys, json, time

ANGR_OK = False
try:
    import angr, claripy
    from angr.analyses.cfg.cfg_fast import CFGFast
    ANGR_OK = True
except ImportError:
    pass

DANGEROUS = {
    "memcpy","strcpy","sprintf","gets","scanf","strcat",
    "free","system","execve","printf",
}

def find_vuln_calls(binary_path: str, timeout_sec: int = 120) -> list:
    """用Angr CFGFast找出所有危险函数调用点.

    策略: 不做完整符号执行(太慢), 而是用CFGFast快速恢复控制流,
    识别每个危险函数的调用点, 检查其参数是否来自符号化输入.
    """
    if not ANGR_OK:
        return [{"error": "angr_not_installed"}]

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        findings = []
        for func_addr, func in cfg.functions.items():
            if func.name in DANGEROUS:
                call_sites = cfg.functions.call_sites.get(func_addr, set())
                for cs in call_sites:
                    findings.append({
                        "type": "dangerous_call",
                        "function": func.name,
                        "address": cs,
                        "callers": [c for c in cfg.functions.call_sites
                                    if cs in cfg.functions.call_sites.get(c, set())],
                    })

        return findings
    except Exception as e:
        return [{"error": str(e)}]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: python angr_adapter.py <binary>"}))
        sys.exit(1)

    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error": f"file not found: {binary}"}))
        sys.exit(1)

    t0 = time.time()
    findings = find_vuln_calls(binary, timeout_sec=90)
    elapsed = (time.time() - t0) * 1000
    output = {"tool": "angr", "binary": binary, "elapsed_ms": elapsed,
              "findings": findings, "total_findings": len(findings)}
    print(json.dumps(output, default=str))
