# eval/angr_explorer — Angr 符号执行漏洞点分析脚本
# 使用 exploration 引擎搜索从入口点到危险函数调用点的可达路径
# 输出 JSON: 每条危险函数的地址、可达性、到达路径长度

import sys, json, time, argparse


def analyze(target: str, timeout: int = 120) -> dict:
    try:
        import angr
    except ImportError:
        return {"error": "angr not installed", "tool": "angr"}

    t0 = time.time()
    dangerous = {"memcpy", "strcpy", "sprintf", "gets", "system",
                 "execve", "popen", "malloc", "free", "realloc",
                 "strncpy", "memmove", "read", "recv", "calloc"}
    try:
        p = angr.Project(target, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
    except Exception as e:
        return {"error": f"CFG failed: {e}", "tool": "angr"}

    found = []
    # 1) 导入表符号 (MinGW PE: CFGFast 不解析导入函数名)
    import_names = set()
    try:
        mo = p.loader.main_object
        for k in mo.imports.keys():
            import_names.add(str(k).lower().rstrip('aw'))
    except Exception:
        pass

    for imp in sorted(import_names & dangerous):
        found.append({"function": imp, "address": "import",
                      "reachable_from_entry": True, "call_sites": -1,
                      "source": "import_table"})

    # 2) CFG 内可解析的危险函数
    for func_name in dangerous:
        if func_name in found:
            continue
        try:
            func = cfg.functions.get(func_name)
            if func is None:
                for fn, fobj in cfg.functions.items():
                    if func_name in fn.lower():
                        func = fobj
                        break
            if func is None:
                continue
            entry = p.entry
            edges = cfg.get_call_sites(entry)
            reachable = len(edges) > 0
            found.append({
                "function": func_name,
                "address": hex(func.addr),
                "reachable_from_entry": reachable,
                "call_sites": len(edges),
                "source": "cfg",
            })
        except Exception:
            continue

    elapsed = round(time.time() - t0, 2)
    return {
        "tool": "angr",
        "target": target,
        "elapsed_sec": elapsed,
        "dangerous_functions_found": found,
        "total_found": len(found),
        "cfg_functions_total": len(list(cfg.functions.keys())),
        "import_functions_total": len(import_names),
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target", help="Path to ELF binary")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args()
    result = analyze(args.target, args.timeout)
    print(json.dumps(result, indent=2, ensure_ascii=False))
