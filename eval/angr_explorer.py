# Angr exploration模式漏洞点分析 —— 符号执行搜索危险函数可达路径。
import os, sys, time
try: import angr; ANGR_OK = True
except ImportError: ANGR_OK = False

DANGER = ['strcpy','strcat','sprintf','gets','scanf','memcpy','memmove','free','malloc','printf','system']

def angr_scan(binary_path, timeout_sec=180):
    if not ANGR_OK: return {'tool':'angr','sample':os.path.basename(binary_path),'success':False,'error':'angr not installed'}
    t0 = time.time()
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        findings = 0
        try:
            entry = proj.entry
            state = proj.factory.blank_state(addr=entry)
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=lambda s: any(getattr(proj.loader.find_symbol(fn),'rebased_addr',0)==s.addr for fn in DANGER if proj.loader.find_symbol(fn)), num_find=20)
            findings = len(simgr.found)
        except: pass
        if findings == 0:
            for func in cfg.functions.values():
                for b in func.blocks:
                    for insn in b.capstone.insns:
                        if insn.mnemonic == 'call':
                            try:
                                if cfg.functions.get(insn.operands[0].imm) and cfg.functions[insn.operands[0].imm].name in DANGER:
                                    findings += 1
                            except: pass
        dt = time.time() - t0
        return {'tool':'angr','sample':os.path.basename(binary_path),'success':True,'findings':findings,'duration_sec':round(dt,2)}
    except Exception as e:
        return {'tool':'angr','sample':os.path.basename(binary_path),'success':False,'error':str(e)[:200],'duration_sec':round(time.time()-t0,2)}
