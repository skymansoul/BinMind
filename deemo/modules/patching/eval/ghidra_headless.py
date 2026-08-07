# Ghidra headless 自动化分析脚本
"""通过Ghidra的analyzeHeadless模式对binary做自动化静态审计。

依赖: GHIDRA_HOME环境变量指向Ghidra安装目录, 且Java可用。
无Ghidra时导出空结果并标记error(基准测试中该列显示不可用)。

分析内容:
  - 导入binary并分析 → 枚举函数
  - 识别危险函数调用(malloc/memcpy/strcpy等)
  - 记录cfg节点数与危险sink数

说明: Ghidra侧重反编译与人工审计, 不提供原生溢出可行性判定,
  其检出=危险sink存在(这与其"高误报"特性一致)。
"""

import os, sys, json, time, subprocess, tempfile

_DANGEROUS = ['malloc', 'calloc', 'realloc', 'memcpy', 'memmove',
              'strcpy', 'strcat', 'sprintf', 'printf', 'system',
              'popen', 'execve', 'free', 'gets', 'snprintf', 'strncpy']


def _find_ghidra_home() -> str:
    env = os.environ.get('GHIDRA_HOME', '').strip().strip('"')
    if env and os.path.isdir(env):
        return env
    candidates = [
        r'C:\ghidra', r'C:\Ghidra', r'D:\ghidra', r'D:\Ghidra',
        os.path.expanduser('~/ghidra'),
        os.path.expanduser('~/ghidra_*'),
    ]
    for c in candidates:
        import glob
        for p in glob.glob(c):
            if os.path.isdir(p):
                return p
    return ''


def analyze_binary(binary_path: str) -> dict:
    t0 = time.time()
    result = {"tool": "Ghidra", "binary": binary_path, "detected": False,
              "functions_analyzed": 0, "dangerous_sinks": [],
              "cfg_nodes": 0, "time_secs": 0, "error": None}

    ghidra_home = _find_ghidra_home()
    if not ghidra_home:
        result["error"] = "GHIDRA_HOME not set / Ghidra not found"
        result["time_secs"] = round(time.time() - t0, 2)
        return result

    headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
    if not os.path.isfile(headless):
        result["error"] = f"analyzeHeadless not found at {headless}"
        result["time_secs"] = round(time.time() - t0, 2)
        return result

    try:
        tmp = tempfile.mkdtemp(prefix='ghidra_binmind_')
        post_script = os.path.join(os.path.dirname(__file__),
                                   'ghidra_post_script.py')
        cmd = [headless, tmp, 'BinMind_Bench', '-import', binary_path,
               '-postScript', post_script,
               '-scriptPath', os.path.dirname(__file__),
               '-deleteProject']
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=180)
        out = proc.stdout + proc.stderr
        # 解析postScript输出的JSON
        marker = 'BINMIND_GHIDRA_RESULT:'
        if marker in out:
            payload = out.split(marker, 1)[1].strip()
            # 提取第一个完整JSON对象
            start, end = payload.find('{'), payload.rfind('}')
            if start >= 0 and end > start:
                data = json.loads(payload[start:end + 1])
                result['detected'] = bool(data.get('dangerous_sinks'))
                result['functions_analyzed'] = data.get('functions', 0)
                result['dangerous_sinks'] = data.get('dangerous_sinks', [])
                result['cfg_nodes'] = data.get('cfg_nodes', 0)
        elif 'dangerous' in out.lower():
            result['detected'] = True
    except FileNotFoundError:
        result["error"] = "analyzeHeadless not found"
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_secs"] = round(time.time() - t0, 2)
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python ghidra_headless.py <binary>"); sys.exit(1)
    print(json.dumps(analyze_binary(sys.argv[1]), indent=2))
