"""Ghidra headless 对比实验脚本 — 自动化分析 + 危险函数检测.

设计决策:
  - 为什么用 analyzeHeadless 而非 Ghidra API:
    analyzeHeadless 是 Ghidra 官方推荐的批处理模式,
    不依赖 GUI, 适合 CI/实验环境。需要预先设置 GHIDRA_INSTALL_DIR 环境变量。
  - 超时 120s: Ghidra 对大型二进制反编译慢, 设置超时防止挂死。
"""

import json
import os
import subprocess
import sys
import time
import tempfile


def find_ghidra_headless() -> str:
    """查找 Ghidra headless 可执行文件路径."""
    ghidra_home = os.environ.get('GHIDRA_INSTALL_DIR', '')
    if not ghidra_home:
        for p in ['/opt/ghidra', '/usr/local/ghidra',
                  os.path.expanduser('~/ghidra')]:
            if os.path.isdir(p):
                ghidra_home = p
                break
    if not ghidra_home:
        return ''
    if sys.platform == 'win32':
        return os.path.join(ghidra_home, 'support', 'analyzeHeadless.bat')
    return os.path.join(ghidra_home, 'support', 'analyzeHeadless')


# Ghidra post-analysis script (会写入临时 .py 文件)
GHIDRA_SCRIPT = '''
import ghidra.app.script.GhidraScript
import ghidra.program.model.listing.Function
import json, os

class VulnScanner(GhidraScript):
    def run(self):
        dangerous = {'printf','sprintf','malloc','free','memcpy','strcpy','gets'}
        results = {'vulns_found': 0, 'vulns': []}
        func_mgr = self.currentProgram.getFunctionManager()
        listing = self.currentProgram.getListing()
        for func in func_mgr.getFunctions(True):
            for d in dangerous:
                if d in func.getName().lower():
                    results['vulns_found'] += 1
                    results['vulns'].append({
                        'func': func.getName(),
                        'addr': hex(func.getEntryPoint().getOffset()),
                    })
        output = os.environ.get('GHIDRA_OUTPUT','/tmp/ghidra_out.json')
        with open(output,'w') as f:
            json.dump(results, f, indent=2)
'''

def analyze_with_ghidra(binary_path: str) -> dict:
    """Ghidra headless 分析."""
    result = {
        'binary': os.path.basename(binary_path),
        'vulns_found': 0, 'vulns': [],
        'elapsed_sec': 0.0, 'error': '',
    }

    headless = find_ghidra_headless()
    if not headless or not os.path.isfile(headless):
        result['error'] = 'Ghidra headless not found. Set GHIDRA_INSTALL_DIR.'
        return result

    abs_binary = os.path.abspath(binary_path)
    if not os.path.isfile(abs_binary):
        result['error'] = f'Binary not found: {abs_binary}'
        return result

    start = time.time()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = os.path.join(tmpdir, 'project')
            script_path = os.path.join(tmpdir, 'VulnScanner.py')
            output_path = os.path.join(tmpdir, 'output.json')

            with open(script_path, 'w') as f:
                f.write(GHIDRA_SCRIPT)

            env = os.environ.copy()
            env['GHIDRA_OUTPUT'] = output_path

            cmd = [
                headless, project_dir, 'TempProject',
                '-import', abs_binary,
                '-postScript', script_path,
                '-deleteProject',
            ]

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=120, env=env)

            if os.path.isfile(output_path):
                with open(output_path, 'r') as f:
                    data = json.load(f)
                    result['vulns_found'] = data.get('vulns_found', 0)
                    result['vulns'] = data.get('vulns', [])

    except subprocess.TimeoutExpired:
        result['error'] = 'Ghidra analysis timeout (>120s)'
    except Exception as e:
        result['error'] = str(e)[:200]
    finally:
        result['elapsed_sec'] = round(time.time() - start, 2)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'usage: run_ghidra.py <binary>'}))
        sys.exit(1)
    result = analyze_with_ghidra(sys.argv[1])
    print(json.dumps(result, indent=2))
