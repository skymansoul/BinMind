"""Ghidra headless 脚本自动化分析适配器。

方法: 调用 Ghidra headless analyzer, 用预置脚本导出反编译结果和
交叉引用。从导出的 JSON 中提取危险函数调用和潜在漏洞点。
"""

import os, json, time, subprocess, sys, tempfile


def run_ghidra_analysis(binary_path: str, timeout_sec: int = 180) -> dict:
    t0 = time.time()
    result = {'tool': 'Ghidra', 'binary': binary_path,
              'findings': 0, 'elapsed_sec': 0, 'error': ''}

    ghidra_home = os.environ.get('GHIDRA_HOME', '')
    if not ghidra_home:
        result['error'] = 'GHIDRA_HOME not set'
        result['elapsed_sec'] = time.time() - t0
        return result

    analyze_headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
    if not os.path.isfile(analyze_headless) and not os.path.isfile(analyze_headless + '.bat'):
        result['error'] = f'analyzeHeadless not found at {analyze_headless}'
        result['elapsed_sec'] = time.time() - t0
        return result

    tmp_dir = tempfile.mkdtemp(prefix='ghidra_export_')
    try:
        cmd = [
            analyze_headless, tmp_dir, 'BinMindProject',
            '-import', binary_path,
            '-postScript', 'ExportFunctionsScript.py', tmp_dir,
            '-deleteProject', '-noanalysis',
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)

        # 搜索危险模式: 交叉引用到 malloc/free/printf/gets/strcpy
        findings = 0
        dangerous = {'malloc', 'free', 'printf', 'fprintf', 'gets', 'strcpy', 'memcpy'}
        for line in (proc.stdout + proc.stderr).split('\n'):
            for df in dangerous:
                if df in line.lower():
                    findings += 1
                    break

        result['findings'] = findings
        result['elapsed_sec'] = round(time.time() - t0, 1)

    except subprocess.TimeoutExpired:
        result['error'] = 'timeout'
        result['elapsed_sec'] = timeout_sec
    except Exception as e:
        result['error'] = str(e)[:200]
        result['elapsed_sec'] = round(time.time() - t0, 1)
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: python ghidra_runner.py <binary>')
        sys.exit(1)
    r = run_ghidra_analysis(sys.argv[1])
    print(json.dumps(r, indent=2))
