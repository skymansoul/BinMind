import angr
binary = 'C:/Users/Administrator/Desktop/BinMind/deemo/modules/vuln/test_samples/heap_overflow/sample01_direct_overflow/main.exe'
proj = angr.Project(binary, auto_load_libs=False)
cfg = proj.analyses.CFGFast()
DANGER = {'malloc','calloc','realloc','memcpy','memmove','strcpy','strcat','sprintf','gets','scanf','fgets','read','recv','strncpy'}
for name, func in cfg.functions.items():
    if func.name == 'main':
        print(f'main @ {hex(func.addr)}')
        for block in func.blocks:
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    target_addr = None
                    if insn.operands:
                        try:
                            target_addr = insn.operands[0].imm
                        except:
                            pass
                    target_fn = cfg.functions.get(target_addr) if target_addr else None
                    fname = target_fn.name if target_fn else 'unknown'
                    print(f'  call @ {hex(insn.address)} target={hex(target_addr) if target_addr else 0} fn={fname}')
                    if fname in DANGER:
                        print(f'    *** DANGER CALL: {fname}')
