# 创建: 2026-06-26 -- 扫描调度模块: 批量调用扫描器+收集结果
import subprocess, sys, os, json, time
from pathlib import Path
from build_samples import BUILD_DIR, compile_samples

def run_scan(binary_path, timeout_sec=60):
    """对单个二进制运行扫描, 返回(耗时, 发现列表, 峰值内存KB)."""
    start = time.time()
    findings = []
    mem_kb = 0
    try:
        cmd = [sys.executable, "-c", f"""
import sys; sys.path.insert(0, r'{Path(__file__).parent.parent.parent}')
from core.vuln_analyzer import analyze_all
from core.decompiler import decompile_function  # may fail gracefully
try:
    decompiled = {{}}
    findings = analyze_all(binary_path=r'{binary_path}', decompiled=decompiled,
                          vuln_types=['heap-corruption','format-string','stack-overflow'])
    import json
    print(json.dumps({{'findings': findings}}))
except Exception as e:
    print(json.dumps({{'error': str(e)}}))
"""]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if r.stdout:
            data = json.loads(r.stdout)
            findings = data.get("findings", [])
        elapsed = time.time() - start
    except subprocess.TimeoutExpired:
        elapsed = timeout_sec
        findings = [{"type": "timeout", "description": f"scan timeout at {timeout_sec}s"}]
    except Exception as e:
        elapsed = time.time() - start
        findings = [{"type": "error", "description": str(e)[:100]}]
    return elapsed, findings, mem_kb

def scan_all(compiler="gcc", opt="O0", timeout=60):
    """编译+扫描所有样本, 返回汇总结果."""
    # 确保已编译
    compile_results = compile_samples(compiler, opt)
    binaries = list(BUILD_DIR.glob(f"*_{compiler}_{opt}"))
    results = {}
    for b in binaries:
        cve_id = b.name.split("_")[0] + "_" + b.name.split("_")[1]
        elapsed, findings, mem = run_scan(str(b), timeout)
        results[cve_id] = {
            "binary": str(b),
            "elapsed_sec": round(elapsed, 2),
            "num_findings": len(findings),
            "findings": findings,
            "compile_status": compile_results.get(cve_id, "unknown"),
        }
    return results

if __name__ == "__main__":
    compiler = sys.argv[1] if len(sys.argv) > 1 else "gcc"
    opt = sys.argv[2] if len(sys.argv) > 2 else "O0"
    r = scan_all(compiler, opt)
    print(json.dumps(r, indent=2, ensure_ascii=False))
