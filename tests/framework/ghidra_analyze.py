"""
Ghidra headless 分析脚本 — 反编译并搜索危险函数调用。
由 experiment_runner.py 通过 Ghidra headless 模式调用。
"""

DANGER_FUNCTIONS = {
    'printf', 'fprintf', 'sprintf', 'snprintf',
    'gets', 'strcpy', 'strcat', 'scanf',
    'system', 'popen', 'free',
}

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.listing import Function
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    prog = getCurrentProgram()
    decomp.openProgram(prog)

    fm = prog.getFunctionManager()
    for func in fm.getFunctions(True):
        result = decomp.decompileFunction(func, 30, monitor)
        if result is None or not result.decompileCompleted():
            continue
        code = result.getDecompiledFunction().getC()
        for line in code.split('\n'):
            for df in DANGER_FUNCTIONS:
                if df in line:
                    addr = func.getEntryPoint()
                    print("DANGER: {} found in {} at 0x{}".format(
                        df, func.getName(), addr))
                    break

    decomp.close()

except ImportError:
    # running outside Ghidra — fallback to file-based grep
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            data = f.read()
        for df in DANGER_FUNCTIONS:
            if df.encode() in data:
                print("DANGER: {} referenced in binary".format(df))
