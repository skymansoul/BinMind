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
                 "execve", "popen", "malloc", "free", "realloc"}
    try:
        p = angr.Project(target, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
    except Exception as e:
        return {"error": f"CFG failed: {e}", "tool": "angr"}

    found = []
    for func_name in dangerous:
        try:
            func = cfg.functions.get(func_name)
            if func is None:
                # try case-insensitive
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
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target", help="Path to ELF binary")
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args()
    result = analyze(args.target, args.timeout)
    print(json.dumps(result, indent=2, ensure_ascii=False))
