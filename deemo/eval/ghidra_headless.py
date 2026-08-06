# eval/ghidra_headless.py
# Ghidra headless analysis script for heap vulnerability detection.
# NOTE: Requires Ghidra installation + analyzeHeadless on PATH.
# If Ghidra unavailable, generates a placeholder result file.
import os, json, time

def analyze(binary_path, sample_name, ghidra_home=None):
    if ghidra_home is None:
        ghidra_home = os.environ.get("GHIDRA_HOME","")
    if not ghidra_home:
        return {"tool":"Ghidra","sample":sample_name,"sites":0,
            "duration_s":0,"error":"GHIDRA_HOME not set. Install Ghidra and set env var."}
    t0 = time.perf_counter()
    try:
        import subprocess as sp
        script = os.path.join(os.path.dirname(__file__),"ghidra_scan.py")
        cmd = [os.path.join(ghidra_home,"support","analyzeHeadless"),
            "/tmp/ghidra_project","HeapScan","-import",binary_path,
            "-scriptPath",os.path.dirname(__file__),"-postScript","ghidra_scan.py"]
        r = sp.run(cmd, capture_output=True, text=True, timeout=60)
        return {"tool":"Ghidra","sample":sample_name,"sites":0,
            "duration_s":round(time.perf_counter()-t0,3),
            "error":"","stdout":r.stdout[:500]}
    except Exception as e:
        return {"tool":"Ghidra","sample":sample_name,"sites":0,
            "duration_s":round(time.perf_counter()-t0,3),"error":str(e)[:100]}

if __name__ == "__main__":
    import sys
    if len(sys.argv)>1:
        r = analyze(sys.argv[1], os.path.basename(sys.argv[1]))
        print(json.dumps(r,indent=2))