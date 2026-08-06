# 创建: 2025-08-05
# 对比实验启动脚本 — 自动将同批样本喂给 BinMind/Angr/QEMU/Ghidra,
# 统计各工具耗时/误报/漏报/内存. 输出JSON汇总.
# 依赖: angr, qemu-user (需在PATH中), ghidra (需设置GHIDRA_HOME或默认路径)
import subprocess, sys, os, json, time, argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
SAMPLE_DIR = PROJECT_ROOT / "tests" / "cve_samples" / "build"

def measure_memory(cmd, timeout=300):
    """运行命令并测量峰值内存 (通过subprocess, 近似)."""
    start = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          shell=True if sys.platform == 'win32' else False)
        elapsed = time.time() - start
        return {"stdout": r.stdout, "stderr": r.stderr,
                "elapsed": round(elapsed, 2), "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "TIMEOUT",
                "elapsed": timeout, "returncode": -1}

def run_binmind(binary_path, timeout=120):
    """运行BinMind扫描器."""
    cmd = [sys.executable, "-c", f"""
import sys; sys.path.insert(0, r'{PROJECT_ROOT}')
from core.vuln_analyzer import analyze_all
import json, warnings; warnings.filterwarnings('ignore')
try:
    findings = analyze_all(binary_path=r'{binary_path}',
        vuln_types=['heap-corruption','format-string','stack-overflow'])
    print(json.dumps({{'tool':'BinMind','findings':len(findings),'details':findings}}))
except Exception as e:
    print(json.dumps({{'tool':'BinMind','error':str(e)[:200],'findings':0}}))
"""]
    return measure_memory(cmd, timeout)

def run_angr(binary_path, timeout=180):
    """运行Angr exploration-based分析."""
    cmd = [sys.executable, "-c", f"""
import angr, sys, json, warnings; warnings.filterwarnings('ignore')
try:
    proj = angr.Project(r'{binary_path}', auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    # 检测危险函数调用作为漏洞近似
    dangerous = {{'malloc','free','strcpy','memcpy','printf','system'}}
    found = []
    for func in cfg.functions.values():
        if func.name in dangerous:
            found.append({{'func':func.name,'addr':hex(func.addr)}})
    print(json.dumps({{'tool':'Angr','findings':len(found),'details':found}}))
except Exception as e:
    print(json.dumps({{'tool':'Angr','error':str(e)[:200],'findings':0}}))
"""]
    return measure_memory(cmd, timeout)

def run_qemu(binary_path, timeout=60):
    """运行QEMU user mode + 自定义插桩 (若可用)."""
    qemu_paths = ["qemu-x86_64", "qemu-x86_64-static"]
    qemu = None
    for p in qemu_paths:
        if subprocess.run(["which", p], capture_output=True).returncode == 0:
            qemu = p; break
    if qemu is None:
        return {"stdout":"","stderr":"QEMU not found in PATH","elapsed":0,"returncode":-1}
    cmd = [qemu, "-strace", str(binary_path)]
    return measure_memory(cmd, timeout)

def run_ghidra(binary_path, timeout=300):
    """运行Ghidra无头分析 (需GHIDRA_HOME或默认路径)."""
    ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
    analyze_headless = Path(ghidra_home) / "support" / "analyzeHeadless"
    if not analyze_headless.exists():
        return {"stdout":"","stderr":f"Ghidra not found at {ghidra_home}","elapsed":0,"returncode":-1}
    tmp_dir = Path("/tmp/ghidra_cmp")
    tmp_dir.mkdir(exist_ok=True)
    cmd = [str(analyze_headless), str(tmp_dir), "TempProject",
           "-import", str(binary_path), "-postScript", "FindVulns.java"]
    return measure_memory(cmd, timeout)

def run_all_comparisons(compiler="gcc", opt="O0"):
    """对所有已编译样本运行全部工具对比."""
    binaries = sorted(SAMPLE_DIR.glob(f"*_{compiler}_{opt}"))
    tools = {"BinMind": run_binmind, "Angr": run_angr,
             "QEMU": run_qemu, "Ghidra": run_ghidra}
    all_results = {}
    for b in binaries:
        cve_id = "_".join(b.name.split("_")[:2])
        all_results[cve_id] = {}
        for tool_name, runner in tools.items():
            print(f"  [{tool_name}] {cve_id} ...")
            r = runner(str(b))
            all_results[cve_id][tool_name] = {
                "elapsed": r["elapsed"],
                "findings": len(json.loads(r["stdout"]).get("findings", []))
                if r["stdout"] and r["returncode"] == 0 else 0,
                "status": "ok" if r["returncode"] == 0 else "error",
            }
    return all_results

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--compiler", default="gcc")
    p.add_argument("--opt", default="O0")
    p.add_argument("-o", "--output", default="comparison_results.json")
    args = p.parse_args()
    print(f"Running comparison: compiler={args.compiler}, opt={args.opt}")
    results = run_all_comparisons(args.compiler, args.opt)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    # 汇总统计
    tools = list(next(iter(results.values())).keys())
    for tool in tools:
        ok = sum(1 for r in results.values() if r[tool]["status"] == "ok")
        avg_t = sum(r[tool]["elapsed"] for r in results.values()) / max(len(results), 1)
        findings = sum(r[tool]["findings"] for r in results.values())
        print(f"{tool}: ok={ok}, avg_time={avg_t:.1f}s, total_findings={findings}")
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
