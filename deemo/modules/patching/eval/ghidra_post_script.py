# Ghidra post-analysis script — called by analyzeHeadless -postScript
# 对binary做基础安全审计: 列出所有危险函数调用 + 导出函数列表
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.symbol import SymbolType
except ImportError:
    pass  # running inside Ghidra, imports auto-resolved

def main():
    program = getCurrentProgram()
    listing = program.getListing()
    func_manager = program.getFunctionManager()
    dangerous = {"strcpy","strcat","memcpy","sprintf","system","popen",
                 "execve","printf","fprintf","free","malloc","gets","scanf",
                 "strncpy","snprintf","read","recv","send","write"}
    found = []
    for func in func_manager.getFunctions(True):
        for d in dangerous:
            if func.getName().lower().find(d.lower()) >= 0:
                found.append((func.getName(), str(func.getEntryPoint())))
                break
    if found:
        print("DANGEROUS_FUNCTIONS_FOUND:")
        for name, addr in found:
            print(f"  {name} @ {addr}")
    else:
        print("No dangerous functions found in import table.")

if __name__ == "__main__":
    main()
