# 对比实验启动脚本 — BinMind vs Angr vs QEMU vs Ghidra
import os, subprocess, json, time, sys

TOOLS = ['binmind', 'angr', 'qemu', 'ghidra']
SAMPLE_DIR = '../tests/cve_samples'

def run_binmind(binary):
    r = subprocess.run([sys.executable, '-m', 'deemo', '--binary', binary,
        '--no-exec', '--format', 'json'], capture_output=True, timeout=120)
    return {'tool': 'binmind', 'findings': len(json.loads(r.stdout or '[]'))}

def run_angr(binary):
    try:
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        return {'tool': 'angr', 'functions': len(cfg.kb.functions)}
    except Exception as e:
        return {'tool': 'angr', 'error': str(e)[:100]}

def run_qemu(binary):
    t0 = time.time()
    r = subprocess.run(['qemu-x86_64', '-d', 'in_asm', binary],
                       capture_output=True, timeout=30)
    return {'tool': 'qemu', 'time': time.time()-t0, 'insns': len(r.stdout.splitlines())}

def run_ghidra(binary):
    t0 = time.time()
    r = subprocess.run(['ghidra_headless', os.path.dirname(binary),
        'TempProject', '-import', binary, '-postScript', 'AnalyzeHeadless'],
        capture_output=True, timeout=60)
    return {'tool': 'ghidra', 'time': time.time()-t0}

def run_all(sample_dir=SAMPLE_DIR):
    results = []
    for d in sorted(os.listdir(sample_dir)):
        dp = os.path.join(sample_dir, d)
        if not os.path.isdir(dp): continue
        for f in os.listdir(dp):
            if f.startswith('vuln') and '.' not in f[4:]:
                binary = os.path.join(dp, f)
                entry = {'sample': d, 'binary': f}
                for tool_func in [run_binmind, run_angr, run_qemu,
                                  run_ghidra]:
                    try:
                        entry.update(tool_func(binary))
                    except Exception:
                        pass
                results.append(entry)
                break
    return results

if __name__ == '__main__':
    r = run_all()
    with open('comparison_results.json', 'w') as f:
        json.dump(r, f, indent=2, default=str)
    print(f'Results saved ({len(r)} samples)')
