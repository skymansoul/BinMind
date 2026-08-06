# -*- coding: utf-8 -*-
# Angr exploration-based vulnerability point analysis
import sys, os, time
def analyze(binary_path):
    try:
        import angr
        t0 = time.time()
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        dangerous = {"memcpy","strcpy","sprintf","system","malloc","free","gets","scanf"}
        found = [f.name for f in cfg.functions.values() if f.name in dangerous]
        return {"detected": len(found)>0, "elapsed_sec": round(time.time()-t0, 2), "functions_found": found}
    except ImportError: return {"detected": False, "error": "angr not installed"}
    except Exception as e: return {"detected": False, "error": str(e)[:80]}
if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv)>1 else "a.out"
    print(analyze(path))
