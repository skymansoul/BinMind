# Ghidra无头分析脚本——自动审计二进制中的危险函数调用
# 通过Ghidra的Headless Analyzer运行: analyzeHeadless <proj> <dir> -scriptPath . -postScript ghidra_scanner.py
# 输出JSON到stdout，由run_comparison.py收集

import json
import sys

DANGEROUS_FUNCS = {
    'memcpy': 'buffer_overflow', 'strcpy': 'buffer_overflow',
    'strncpy': 'buffer_overflow', 'sprintf': 'buffer_overflow',
    'gets': 'buffer_overflow', 'memmove': 'buffer_overflow',
    'free': 'use_after_free', 'malloc': 'allocation',
    'calloc': 'allocation', 'realloc': 'allocation',
    'printf': 'format_string', 'fprintf': 'format_string',
    'system': 'command_injection', 'popen': 'command_injection',
}

try:
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SymbolType

    currentProgram = getCurrentProgram()
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()

    results = {'tool': 'ghidra', 'vulns': [], 'functions': 0}

    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(True)
    results['functions'] = len(list(funcs))

    for func in func_mgr.getFunctions(True):
        func_name = func.getName()
        func_addr = func.getEntryPoint().getOffset()

        if func_name in DANGEROUS_FUNCS:
            results['vulns'].append({
                'func_addr': hex(func_addr),
                'func_name': func_name,
                'type': DANGEROUS_FUNCS[func_name],
                'direct_use': True,
            })

        # 检查函数体内是否调用危险函数
        body = func.getBody()
        instrs = listing.getInstructions(body, True)
        for ins in instrs:
            if ins is None:
                continue
            mnemonic = ins.getMnemonicString()
            if mnemonic == 'CALL':
                for ref in ins.getReferencesFrom():
                    target = ref.getToAddress().getOffset()
                    sym = symtab.getPrimarySymbol(ref.getToAddress())
                    if sym:
                        tname = sym.getName()
                        if tname in DANGEROUS_FUNCS:
                            results['vulns'].append({
                                'func_addr': hex(func_addr),
                                'call_addr': hex(ins.getAddress().getOffset()),
                                'dangerous_func': tname,
                                'type': DANGEROUS_FUNCS[tname],
                            })

    print(json.dumps(results, indent=2))

except ImportError:
    # 未在Ghidra环境中运行时——输出占位结果
    print(json.dumps({
        'tool': 'ghidra', 'vulns': [], 'functions': 0,
        'error': 'Not running inside Ghidra headless environment',
        'usage': 'Run with: analyzeHeadless <project> <dir> -postScript ghidra_scanner.py'
    }))
    sys.exit(0)
