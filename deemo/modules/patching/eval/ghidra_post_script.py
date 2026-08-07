# Ghidra post-analysis script — called by analyzeHeadless -postScript
# 对binary做基础安全审计: 列出危险函数调用 + 导出函数列表
try:
    from ghidra.program.model.symbol import SymbolType
except ImportError:
    pass  # running inside Ghidra, imports auto-resolved

import json


def main():
    program = getCurrentProgram()
    listing = program.getListing()
    func_manager = program.getFunctionManager()
    dangerous = {"strcpy", "strcat", "memcpy", "memmove", "sprintf",
                 "snprintf", "system", "popen", "execve", "printf",
                 "fprintf", "free", "malloc", "calloc", "realloc",
                 "gets", "scanf", "strncpy", "read", "recv", "send"}
    found = []
    cfg_nodes = 0
    func_count = 0
    for func in func_manager.getFunctions(True):
        func_count += 1
        name = func.getName()
        for d in dangerous:
            if name.lower().find(d.lower()) >= 0:
                found.append({"name": name,
                              "addr": str(func.getEntryPoint())})
                break
    try:
        cfg_nodes = len(list(func_manager.getFunctions(True)))
    except Exception:
        pass
    result = {
        "functions": func_count,
        "cfg_nodes": cfg_nodes,
        "dangerous_sinks": sorted({f["name"] for f in found}),
        "sink_list": found,
    }
    print("BINMIND_GHIDRA_RESULT:")
    print(json.dumps(result))
    if found:
        print("DANGEROUS_FUNCTIONS_FOUND:")
        for f in found:
            print(f"  {f['name']} @ {f['addr']}")
    else:
        print("No dangerous functions found in import table.")


if __name__ == "__main__":
    main()
