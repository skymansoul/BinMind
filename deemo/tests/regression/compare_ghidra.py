"""
Ghidra 无头分析对比实验 —— 自动化静态审计脚本。

使用 Ghidra Headless Analyzer 对二进制做自动化反编译,
提取所有危险函数调用点 (strcpy/printf/free 等)。

依赖: Ghidra 安装路径需通过 GHIDRA_INSTALL_DIR 环境变量指定。
"""

import os, sys, subprocess, json, time, argparse, tempfile

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)


_GHIDRA_SCRIPT = '''
#@category BinMind.Compare
import ghidra.app.script.GhidraScript
from ghidra.program.model.symbol import SymbolType
import json, os

DANGEROUS = {'strcpy','strcat','sprintf','gets','memcpy','printf','fprintf','free','malloc','scanf','read','recv'}
findings = []
sym_table = currentProgram.getSymbolTable()
for sym in sym_table.getAllSymbols(True):
    if sym.getSymbolType() == SymbolType.FUNCTION:
        name = sym.getName()
        if name in DANGEROUS or any(d in name for d in DANGEROUS):
            refs = sym.getReferences(None)
            findings.append({'func': name, 'addr': str(sym.getAddress()),
                            'xrefs': len(list(refs))})

output_path = os.environ.get('GHIDRA_OUTPUT', '/tmp/ghidra_output.json')
with open(output_path, 'w') as f:
    json.dump({'findings': findings, 'total': len(findings)}, f, indent=2)
'''


def analyze_with_ghidra(binary_path: str, timeout: int = 120) -> dict:
    """使用 Ghidra Headless 分析二进制。"""
    result = {'binary': binary_path, 'tool': 'ghidra', 'findings': [],
              'error': '', 'elapsed_ms': 0, 'peak_memory_kb': 0}

    ghidra_home = os.environ.get('GHIDRA_INSTALL_DIR', '')
    if not ghidra_home:
        result['error'] = 'GHIDRA_INSTALL_DIR not set'
        return result

    t0 = time.perf_counter()
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as sf:
            sf.write(_GHIDRA_SCRIPT)
            script_path = sf.name

        output_json = os.path.join(tempfile.gettempdir(), 'ghidra_output.json')
        env = os.environ.copy()
        env['GHIDRA_OUTPUT'] = output_json

        analyzer = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
        if os.name == 'nt':
            analyzer += '.bat'

        proc = subprocess.run(
            [analyzer, tempfile.gettempdir(), 'BinMindProject',
             '-import', binary_path, '-postScript', script_path,
             '-deleteProject', '-noanalysis'],
            capture_output=True, text=True, timeout=timeout, env=env,
        )

        if os.path.exists(output_json):
            with open(output_json, 'r') as f:
                data = json.load(f)
                result['findings'] = data.get('findings', [])
        os.unlink(output_json)
        os.unlink(script_path)

    except FileNotFoundError:
        result['error'] = 'Ghidra analyzeHeadless not found'
    except subprocess.TimeoutExpired:
        result['error'] = f'timeout after {timeout}s'
    except Exception as e:
        result['error'] = str(e)[:200]
    finally:
        result['elapsed_ms'] = (time.perf_counter() - t0) * 1000

    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', help='Path to ELF binary')
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--output', default='')
    args = ap.parse_args()
    result = analyze_with_ghidra(args.binary, args.timeout)
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    print(f"Findings: {len(result['findings'])}")
    print(f"Errors: {result['error'] or 'none'}")
