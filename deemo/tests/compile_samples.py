# 编译模块 —— 遍历样本目录执行make。
import os, subprocess, json
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "testing", "regression", "samples")
def compile_all(samples_dir=None):
    base = os.path.abspath(samples_dir or SAMPLES_DIR)
    if not os.path.isdir(base): return {"_error": "dir not found"}
    results = {}
    for entry in sorted(os.listdir(base)):
        sp = os.path.join(base, entry)
        if not os.path.isdir(sp) or not os.path.exists(os.path.join(sp, "Makefile")): continue
        try:
            subprocess.run(["make", "-C", sp, "clean"], capture_output=True, text=True, timeout=15)
            p = subprocess.run(["make", "-C", sp], capture_output=True, text=True, timeout=30)
            bins = [f for f in os.listdir(sp) if os.path.isfile(os.path.join(sp,f)) and not f.endswith(('.c','.h','.md'))]
            results[entry] = {"success": p.returncode==0, "binary_path": os.path.join(sp,bins[0]) if bins else "", "error": p.stderr[:200] if p.returncode!=0 else ""}
        except Exception as e: results[entry] = {"success": False, "error": str(e)[:200]}
    return results
if __name__ == "__main__": print(json.dumps(compile_all(), indent=2, ensure_ascii=False))
