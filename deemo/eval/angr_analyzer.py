# Angr-based heap vulnerability analyzer
# Uses CFG recovery + dangerous function call detection
import sys, os, json, time

def analyze(binary_path):
    t0 = time.time()
    result = {"tool": "Angr", "binary": binary_path, "findings": 0, "error": None}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        # Count dangerous heap function calls
        dangerous = {"malloc", "free", "realloc", "calloc", "memcpy", "strcpy"}
        count = 0
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                for insn in block.disassembly.insns:
                    if insn.mnemonic == "call":
                        for d in dangerous:
                            if d in (insn.op_str or ""):
                                count += 1
                                break
        result["findings"] = count
        result["functions"] = len(cfg.kb.functions)
    except Exception as e:
        result["error"] = str(e)[:100]
    result["time_s"] = round(time.time() - t0, 2)
    return result

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(json.dumps(analyze(sys.argv[1]), indent=2))
    else:
        print("Usage: python eval/angr_analyzer.py <binary>")
