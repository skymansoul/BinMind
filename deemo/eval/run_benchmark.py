# Benchmark runner - calls BinMind + Angr + QEMU on heap samples
import os, subprocess, json, time, sys

SD = "tests/regression/samples"

def run_binmind(binary):
    t0 = time.time()
    r = subprocess.run([sys.executable, "-m", "deemo", "--binary", binary,
        "--no-exec", "--format", "json"], capture_output=True, timeout=60)
    dt = time.time() - t0
    findings = []
    try: findings = json.loads(r.stdout or "[]")
    except: pass
    return {"tool":"BinMind","time_s":round(dt,1),"findings":len(findings)}

def run_angr(binary):
    t0 = time.time()
    try:
        import angr
        p = angr.Project(binary, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        return {"tool":"Angr","time_s":round(time.time()-t0,1),"functions":len(cfg.kb.functions)}
    except Exception as e:
        return {"tool":"Angr","time_s":round(time.time()-t0,1),"error":str(e)[:80]}

def run_qemu(binary):
    t0 = time.time()
    r = subprocess.run(["qemu-x86_64", "-d", "in_asm", binary], capture_output=True, timeout=30)
    return {"tool":"QEMU","time_s":round(time.time()-t0,1),"lines":len(r.stdout.splitlines()) if r.stdout else 0}

def main():
    results = []
    for d in sorted(os.listdir(SD)):
        dp = os.path.join(SD, d)
        if not os.path.isdir(dp): continue
        for f in os.listdir(dp):
            if f == "vuln" and os.access(os.path.join(dp,f), os.X_OK):
                binary = os.path.join(dp, f)
                entry = {"sample": d}
                for fn in [run_binmind, run_angr, run_qemu]:
                    try: entry.update(fn(binary))
                    except: pass
                results.append(entry)
                break
    with open("eval/bench_results.json","w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Benchmark: {len(results)} samples")

if __name__ == "__main__": main()
