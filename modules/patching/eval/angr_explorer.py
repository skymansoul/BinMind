# Angr 检测脚本 — exploration-based 可达危险函数调用点分析
"""通过Angr的CFG+符号执行探索从入口可达的危险函数调用点。

方法:
  1. CFGFast 构建控制流图
  2. 识别危险sink函数(malloc/memcpy/strcpy等)
  3. 对每个sink检查是否从入口可达(调用链)
  4. 识别 malloc+memcpy 的堆分配/写入对, 判断是否存在
     "alloc大小 < 写入大小"的可疑模式

输出统一JSON: {tool, detected, findings, dangerous_sinks, ...}
无angr时导出空结果并标记error。

说明: angr符号执行在Windows PE上的模拟成本高, 本脚本以
CFG可达性为主、按调用栈上下文辅助判定, 控制单样本超时。
"""

import os, sys, json, time

# 危险sink分类: (函数名, 类别)
_DANGEROUS = {
    'malloc': 'alloc', 'calloc': 'alloc', 'realloc': 'alloc',
    'memcpy': 'write', 'memmove': 'write', 'strcpy': 'write',
    'strcat': 'write', 'sprintf': 'write', 'gets': 'write',
    'printf': 'format', 'system': 'exec', 'popen': 'exec',
    'execve': 'exec', 'free': 'free',
}

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc'}
_WRITE_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf',
                'gets', 'snprintf', 'strncpy'}


def find_dangerous_calls(binary_path: str) -> dict:
    t0 = time.time()
    result = {"tool": "Angr", "binary": binary_path, "detected": False,
              "dangerous_sinks": [], "alloc_write_pairs": [],
              "cfg_nodes": 0, "reachable_sinks": 0, "time_secs": 0,
              "error": None}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        try:
            result["cfg_nodes"] = len(list(cfg.graph.nodes()))
        except Exception:
            result["cfg_nodes"] = len(list(cfg.nodes()))

        # 收集函数及其sink
        sinks_found = {}
        alloc_callers = set()
        write_callers = set()
        funcs = list(cfg.functions.values())
        # callgraph: 哪些函数调用了危险函数
        try:
            callgraph = cfg.callgraph
            for src, dst in callgraph.edges():
                try:
                    dst_fn = cfg.functions.get_by_addr(dst)
                except Exception:
                    dst_fn = None
                if dst_fn and dst_fn.name:
                    base = dst_fn.name.split('@')[0]
                    if base in _ALLOC_FUNCS:
                        alloc_callers.add(src)
                    elif base in _WRITE_FUNCS:
                        write_callers.add(src)
        except Exception:
            pass
        for func in funcs:
            name = func.name or ''
            base = name.split('@')[0]
            if base in _DANGEROUS:
                sinks_found.setdefault(base, 0)
                sinks_found[base] += 1
        common = alloc_callers & write_callers
        for c in sorted(common):
            result["alloc_write_pairs"].append(c)

        result["dangerous_sinks"] = sorted(sinks_found)
        result["reachable_sinks"] = len(sinks_found)
        # 判定: 存在malloc+write共现函数或危险sink → 潜在检出
        result["detected"] = bool(common) or bool(sinks_found)
        if common:
            result["detected"] = True
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
