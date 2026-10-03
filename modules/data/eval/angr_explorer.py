# Angr Exploration 漏洞点分析 - 利用符号执行找出可达危险函数调用

import os, sys, json, time

def analyze_with_angr(binary_path: str, timeout: int = 90) -> list:
    """用 Angr 的 exploration 引擎模拟执行, 找出危险函数调用点."""
    try:
        import angr
    except ImportError:
        return [{"error": "angr_not_installed"}]

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        dangerous = {"memcpy","strcpy","sprintf","gets","scanf","strcat",
                      "free","malloc","calloc","system","execve","printf"}
        findings = []

        for func_addr in cfg.functions:
            func = cfg.functions[func_addr]
            if func.name in dangerous:
                try:
                    state = proj.factory.call_state(func_addr)
                    simgr = proj.factory.simulation_manager(state)
                    simgr.run()
                    if len(simgr.active) > 0:
                        findings.append({
                            "type": "reachable_dangerous_call",
                            "function": func.name,
                            "address": func_addr,
                            "active_paths": len(simgr.active),
                        })
                except Exception:
                    findings.append({
                        "type": "dangerous_call_unreachable",
                        "function": func.name,
                        "address": func_addr,
                    })
        return findings

    except Exception as e:
        return [{"error": str(e)}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: angr_explorer.py <binary>"}))
        sys.exit(1)
    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error": f"not_found:{binary}"}))
        sys.exit(1)
    t0 = time.time()
    findings = analyze_with_angr(binary)
    elapsed = (time.time() - t0) * 1000
    result = {"tool": "angr", "binary": binary, "elapsed_ms": elapsed,
              "findings": findings, "total": len(findings)}
    print(json.dumps(result, default=str))
