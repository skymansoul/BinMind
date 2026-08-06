# Ghidra 无头分析脚本 — 自动化静态审计危险函数调用点
# 依赖: GHIDRA_HOME 环境变量或 ghidra 在 PATH 中

import subprocess, sys, time, json, os, tempfile

_GHIDRA_SCRIPT = '''import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class FindDangerousCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] dangerous = {"malloc","calloc","realloc","memcpy","memmove",
            "strcpy","free","printf","sprintf","snprintf","fprintf"};
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            for (String d : dangerous) {
                if (f.getName().equals(d)) {
                    println("DANGER: " + d + " @ " + f.getEntryPoint());
                }
            }
        }
    }
}
'''

def analyze_binary(binary_path: str) -> dict:
    """Ghidra headless 分析binary, 标记危险函数调用

    返回: {detected, findings, time_ms, error}
    """
    t0 = time.perf_counter()
    result = {'tool': 'Ghidra', 'binary': binary_path, 'detected': False,
              'findings': [], 'time_ms': 0, 'error': ''}
    ghidra_home = os.environ.get('GHIDRA_HOME', '')
    ah = os.path.join(ghidra_home, 'support', 'analyzeHeadless') if ghidra_home else ''
    if not ah or not os.path.exists(ah):
        result['error'] = 'GHIDRA_HOME not set or analyzeHeadless not found'
        result['time_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        return result
    try:
        with tempfile.TemporaryDirectory() as td:
            script_path = os.path.join(td, 'FindDangerousCalls.java')
            with open(script_path, 'w') as f: f.write(_GHIDRA_SCRIPT)
            proj_dir = os.path.join(td, 'ghidra_proj')
            cmd = [ah, proj_dir, 'TempProj', '-import', binary_path,
                   '-scriptPath', td, '-postScript', 'FindDangerousCalls']
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            for line in r.stdout.split('\n'):
                if line.startswith('DANGER:'):
                    parts = line.split()
                    if len(parts) >= 4:
                        result['findings'].append({
                            'function': parts[1], 'address': parts[3],
                        })
            result['detected'] = len(result['findings']) > 0
    except subprocess.TimeoutExpired:
        result['error'] = 'timeout (120s)'
    except Exception as e:
        result['error'] = str(e)[:200]
    result['time_ms'] = round((time.perf_counter() - t0) * 1000, 1)
    return result

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('binary'); p.add_argument('--json', action='store_true')
    args = p.parse_args()
    r = analyze_binary(args.binary)
    if args.json: print(json.dumps(r, indent=2))
    else: print(f'Ghidra: {len(r.get("findings",[]))} findings, {r.get("time_ms",0)}ms {r.get("error","")}')
