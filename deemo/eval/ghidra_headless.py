#!/usr/bin/env python3
"""
Ghidra Headless分析器 — 堆漏洞检测 + objdump反汇编回退.

两种模式:
1. Ghidra headless: 通过analyzeHeadless运行自定义脚本, 检测堆溢出点
2. objdump回退: 无Ghidra时解析反汇编, 统计危险写入函数调用
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
from typing import Dict, List, Optional

DANGER_WRITES = frozenset([
    'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
    'memcpy', 'memmove', 'memset', 'read', 'fread',
])

# Ghidra Python脚本 — 在Ghidra JVM中执行
_GHIDRA_SCRIPT = r"""
# Ghidra heap overflow detection script
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.isExternal(): continue
    body = func.getBody()
    cu = body.getMinAddress()
    while cu and body.contains(cu):
        instruction = getInstructionAt(cu)
        if instruction:
            mnemonic = instruction.getMnemonicString()
            refs = instruction.getReferencesFrom()
            for ref in refs:
                ref_addr = ref.getToAddress()
                ref_type = ref.getReferenceType()
                if ref_type.isWrite():
                    print("HEAP_OVERFLOW_FOUND:" + str(cu))
                    break
        cu = cu.add(1)
"""


def analyze_ghidra(binary_path: str, sample_name: str,
                   ghidra_home: Optional[str] = None,
                   timeout: int = 120) -> Dict:
    """Ghidra headless分析: 运行自定义脚本检测堆溢出点."""
    if ghidra_home is None:
        ghidra_home = os.environ.get("GHIDRA_HOME", "")
    if not ghidra_home or not Path(ghidra_home).exists():
        return {"tool": "Ghidra", "sample": sample_name,
                "sites": 0, "duration_s": 0,
                "error": "GHIDRA_HOME not set or invalid"}
    # 写入临时脚本
    script_dir = Path(__file__).parent / ".cache"
    script_dir.mkdir(exist_ok=True)
    script_path = script_dir / "heap_detect.py"
    script_path.write_text(_GHIDRA_SCRIPT, encoding="utf-8")
    # 构造analyzeHeadless命令
    analyze = Path(ghidra_home) / "support" / "analyzeHeadless"
    if sys.platform == "win32":
        analyze = analyze.with_suffix(".bat")
    tmp_proj = script_dir / "ghidra_project"
    cmd = [
        str(analyze), str(tmp_proj), "HeapScan",
        "-import", binary_path,
        "-postScript", str(script_path),
        "-scriptPath", str(script_dir),
        "-deleteProject",
    ]
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        dt = round(time.perf_counter() - t0, 3)
        sites = _parse_ghidra_output(r.stdout)
        return {"tool": "Ghidra", "sample": sample_name,
                "sites": sites, "duration_s": dt,
                "error": "", "stdout": r.stdout[:500]}
    except FileNotFoundError:
        return {"tool": "Ghidra", "sample": sample_name,
                "sites": 0, "duration_s": 0,
                "error": "analyzeHeadless not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "Ghidra", "sample": sample_name,
                "sites": 0, "duration_s": timeout,
                "error": "timeout"}


def analyze_objdump(binary_path: str,
                    sample_name: str) -> Dict:
    """objdump回退: 解析反汇编统计危险写入函数调用频次."""
    t0 = time.perf_counter()
    try:
        r = subprocess.run(
            ["objdump", "-d", binary_path],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {"tool": "Ghidra-objdump", "sample": sample_name,
                    "sites": 0, "duration_s": 0,
                    "error": f"objdump exit {r.returncode}"}
    except FileNotFoundError:
        return {"tool": "Ghidra-objdump", "sample": sample_name,
                "sites": 0, "duration_s": 0,
                "error": "objdump not found"}
    except subprocess.TimeoutExpired:
        return {"tool": "Ghidra-objdump", "sample": sample_name,
                "sites": 0, "duration_s": 30, "error": "timeout"}
    # 统计危险写入函数调用
    sites = 0
    for line in r.stdout.splitlines():
        for fn in DANGER_WRITES:
            if fn in line and "call" in line:
                sites += 1
                break
    dt = round(time.perf_counter() - t0, 3)
    return {"tool": "Ghidra-objdump", "sample": sample_name,
            "sites": sites, "duration_s": dt, "error": ""}


def analyze_auto(binary_path: str, sample_name: str,
                 ghidra_home: Optional[str] = None,
                 timeout: int = 120) -> Dict:
    """自动选择: Ghidra → objdump回退."""
    r = analyze_ghidra(binary_path, sample_name, ghidra_home, timeout)
    if not r["error"]:
        return r
    return analyze_objdump(binary_path, sample_name)


def analyze_batch(binary_paths: List[str],
                  ghidra_home: Optional[str] = None,
                  timeout: int = 120) -> List[Dict]:
    """批量分析多个二进制文件."""
    results = []
    for bp in binary_paths:
        name = os.path.basename(bp)
        results.append(analyze_auto(bp, name, ghidra_home, timeout))
    return results


def _parse_ghidra_output(stdout: str) -> int:
    """从Ghidra脚本输出解析发现的溢出点数量."""
    count = 0
    for line in stdout.splitlines():
        if "HEAP_OVERFLOW_FOUND" in line:
            count += 1
    return count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ghidra_headless.py <binary> "
              "[--ghidra-home PATH] [--batch f1 f2 ...]")
        sys.exit(1)
    ghidra_home = None
    if "--ghidra-home" in sys.argv:
        idx = sys.argv.index("--ghidra-home")
        ghidra_home = sys.argv[idx + 1]
    if "--batch" in sys.argv:
        idx = sys.argv.index("--batch")
        paths = sys.argv[idx + 1:]
        out = analyze_batch(paths, ghidra_home)
    else:
        out = analyze_auto(sys.argv[1], os.path.basename(sys.argv[1]),
                           ghidra_home)
    print(json.dumps(out, indent=2))
