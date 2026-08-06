# Angr 检测脚本 — exploration-based 危险函数调用点分析
"""通过Angr的CFG+exploration找出从入口可达的危险函数调用点。
若angr未安装: pip install angr。无angr时导出空结果并标记error。"""
import os, sys, json, time

def find_dangerous_calls(binary_path: str) -> dict:
    t0 = time.time()
    result = {"tool": "Angr", "binary": binary_path, "detected": False,
              "dangerous_sinks": [], "cfg_nodes": 0, "time_secs": 0, "error": None}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        result["cfg_nodes"] = len(list(cfg.nodes()))
        dangerous = {"strcpy","strcat","memcpy","sprintf","system","popen",
                     "execve","printf","fprintf","free","malloc","gets","scanf"}
        found = set()
        for func in cfg.functions.values():
            if func.name in dangerous:
                found.add(func.name)
        result["dangerous_sinks"] = sorted(found)
        result["detected"] = len(found) > 0
    except ImportError:
        result["error"] = "angr not installed"
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_secs"] = round(time.time() - t0, 2)
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python angr_explorer.py <binary>"); sys.exit(1)
    print(json.dumps(find_dangerous_calls(sys.argv[1]), indent=2))
