# Ghidra无头分析脚本: 模拟自动化静态审计
# 方法: 通过Ghidra的headless analyzer导入二进制→反汇编→扫描危险函数调用
# 输出: JSON格式的审计结果
#
# 依赖: Ghidra安装目录+analyzeHeadless批处理
# 用法: python ghidra_headless.py <binary> [--ghidra-path /path/to/ghidra]
#
# 若Ghidra不可用: 回退到objdump+增强模式匹配(模拟Ghidra反汇编精度)

import subprocess
import sys
import json
import time
import re
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# 危险函数签名: Ghirda的pcode分析关注点
DANGEROUS_CALLS = {
    'memcpy':  {'params': 3, 'danger': 'size > dst_alloc'},
    'strcpy':  {'params': 2, 'danger': 'implicit size'},
    'sprintf': {'params': 2, 'danger': 'implicit size'},
    'memmove': {'params': 3, 'danger': 'size > dst_alloc'},
    'strncpy': {'params': 3, 'danger': 'size > dst_alloc'},
    'gets':    {'params': 1, 'danger': 'unbounded input'},
    'read':    {'params': 3, 'danger': 'size > dst_alloc'},
    'recv':    {'params': 3, 'danger': 'size > dst_alloc'},
    'fread':   {'params': 4, 'danger': 'size*nmemb > dst_alloc'},
    'alloca':  {'params': 1, 'danger': 'user_controlled size'},
}


def find_ghidra_headless() -> Optional[str]:
    """查找Ghidra的analyzeHeadless可执行文件"""
    # Windows常见路径
    candidates = [
        r'C:\ghidra\support\analyzeHeadless.bat',
        r'C:\ghidra_11.0_PUBLIC\support\analyzeHeadless.bat',
        r'C:\ghidra_10.4_PUBLIC\support\analyzeHeadless.bat',
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    # 尝试从GHIDRA_HOME环境变量
    gh_home = os.environ.get('GHIDRA_HOME', '')
    if gh_home:
        bat = os.path.join(gh_home, 'support', 'analyzeHeadless.bat')
        if os.path.exists(bat):
            return bat
    return None


def analyze_with_objdump(binary_path: str) -> Dict:
    """objdump回退方案: 当Ghidra不可用时使用"""
    t0 = time.perf_counter()
    result = {
        "tool": "objdump_ghidra_fallback",
        "binary": binary_path,
        "vulns": [],
        "time_ms": 0,
        "error": "",
    }

    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary_path],
            capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        result["error"] = "objdump not found"
        result["time_ms"] = (time.perf_counter() - t0) * 1000
        return result

    if proc.returncode != 0:
        result["error"] = f"objdump failed: {proc.stderr[:200]}"
        result["time_ms"] = (time.perf_counter() - t0) * 1000
        return result

    output = proc.stdout

    # 解析objdump输出: 找call指令和对应函数名
    call_pattern = re.compile(r'call\s+[0-9a-f]+\s+<([^>]+)>', re.I)

    # 提取.dynsym和.plt中的符号: 用于解析call的目标
    sym_to_addr = {}
    addr_to_sym = {}
    try:
        syms = subprocess.run(
            ['objdump', '-t', binary_path],
            capture_output=True, text=True, timeout=10)
        for line in syms.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 6 and parts[2] in ('.text', '.plt', '*UND*'):
                addr = int(parts[0], 16)
                name = parts[-1].split('@')[0]
                addr_to_sym[addr] = name
    except Exception:
        pass

    current_func = ""
    for line in output.split('\n'):
        if '<' in line and '>:' in line:
            m = re.search(r'<([^>]+)>:', line)
            if m:
                current_func = m.group(1)

        m = call_pattern.search(line)
        if m:
            callee = m.group(1)
            # 解析动态符号
            if '@plt' in callee:
                callee_base = callee.replace('@plt', '')
            elif '+' in callee:
                callee_base = callee.split('+')[0]
            else:
                callee_base = callee

            callee_clean = callee_base.split('.')[-1]

            if callee_clean in DANGEROUS_CALLS:
                addr_match = re.match(r'\s*([0-9a-f]+):', line)
                addr = int(addr_match.group(1), 16) if addr_match else 0

                result["vulns"].append({
                    "func_name": current_func,
                    "callee": callee_clean,
                    "addr": hex(addr),
                    "danger": DANGEROUS_CALLS[callee_clean]['danger'],
                    "params": DANGEROUS_CALLS[callee_clean]['params'],
                })

    result["time_ms"] = (time.perf_counter() - t0) * 1000
    return result


def analyze_with_ghidra(binary_path: str, ghidra_path: str) -> Dict:
    """使用Ghidra无头模式分析二进制"""
    t0 = time.perf_counter()
    result = {
        "tool": "ghidra_headless",
        "binary": binary_path,
        "vulns": [],
        "time_ms": 0,
        "error": "",
    }

    binary = Path(binary_path).resolve()
    project_dir = binary.parent / "ghidra_project"
    project_dir.mkdir(exist_ok=True)

    # 构建Ghidra headless命令
    cmd = [
        ghidra_path,
        str(project_dir),
        "TempProject",
        "-import", str(binary),
        "-postScript", "FindDangerousCalls.java",
        "-scriptPath", str(Path(__file__).parent),
        "-noanalysis",  # 加速: 不做完整分析
        "-deleteProject",
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120)
        # Ghidra headless脚本通过文件输出结果
        output_file = binary.parent / "ghidra_vulns.json"
        if output_file.exists():
            with open(output_file) as f:
                ghidra_data = json.load(f)
            result["vulns"] = ghidra_data.get("vulns", [])
        else:
            result["error"] = "Ghidra script did not produce output"
    except subprocess.TimeoutExpired:
        result["error"] = "Ghidra analysis timeout (120s)"
    except FileNotFoundError:
        result["error"] = f"Ghidra not found at {ghidra_path}"
    except Exception as e:
        result["error"] = str(e)

    result["time_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: ghidra_headless.py <binary>", "vulns": []}))
        return 0

    binary = sys.argv[1]
    ghidra = None

    # 检查--ghidra-path参数
    for i, arg in enumerate(sys.argv):
        if arg == '--ghidra-path' and i + 1 < len(sys.argv):
            ghidra = sys.argv[i + 1]

    if ghidra:
        result = analyze_with_ghidra(binary, ghidra)
    else:
        ghidra = find_ghidra_headless()
        if ghidra:
            result = analyze_with_ghidra(binary, ghidra)
        else:
            # 回退到objdump
            result = analyze_with_objdump(binary)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
