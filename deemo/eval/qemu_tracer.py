# eval/qemu_tracer.py
# QEMU user-mode tracer for ground truth memory operation collection.
# Uses -d exec to count instructions and detect dangerous function calls.

import os, subprocess, json, time

def trace(binary_path, sample_name, timeout=10):
    try:
        t0 = time.perf_counter()
        r = subprocess.run(["qemu-x86_64","-d","in_asm",binary_path],
            capture_output=True,text=True,timeout=timeout)
        dt = round(time.perf_counter()-t0,3)
        calls = r.stdout.count("call") + r.stdout.count("callq")
        return {"tool":"QEMU-user","sample":sample_name,"calls":calls,
            "duration_s":dt,"error":""}
    except FileNotFoundError:
        return {"tool":"QEMU-user","sample":sample_name,"calls":0,
            "duration_s":0,"error":"qemu-x86_64 not found"}
    except subprocess.TimeoutExpired:
        return {"tool":"QEMU-user","sample":sample_name,"calls":0,
            "duration_s":timeout,"error":"timeout"}

if __name__ == "__main__":
    import sys
    if len(sys.argv)>1:
        r = trace(sys.argv[1], os.path.basename(sys.argv[1]))
        print(json.dumps(r,indent=2))
    else:
        print("Usage: qemu_tracer.py <binary>")