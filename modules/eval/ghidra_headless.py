"""
Ghidra 无头分析 — 模拟自动化静态审计.

合并说明 (BinMind/eval ↔ deemo/modules/eval 两个版本功能合并):
  - BinMind/eval 版: audit() — 优先 analyzeHeadless, 失败/缺失时
    objdump 反汇编危险调用面审计 (mode=objdump-fallback), 输出
    calls 明细 (call 指令行) + time_ms.
  - deemo/modules/eval 版: ghidra_headless_scan() — 内置
    HeapOverflowScan.java 脚本统计 ALLOC_CALLS/MEMCPY_CALLS/
    HEAP_REFS, 输出 success/findings/duration_sec, 供 run_benchmark
    消费; 无 Ghidra 时 _objdump_fallback 模式统计.
  - 两个查找器 (_find_ghidra 带 Windows 路径搜索 / _find_headless
    纯 which), 两个危险模式表 (_DANGEROUS / _DANGER) 与全部辅助
    函数均保留.
  - CLI 输出合并字典 (success/findings/calls/mode/time_ms/duration_sec
    全字段), 同时满足两个 run_benchmark 消费者的解析需求.

用 Ghidra headless analyzer (analyzeHeadless) 对目标二进制
运行内置脚本, 统计堆危险函数调用与对 malloc 缓冲的越界
引用. 无 Ghidra 环境时降级为 objdump + 模式统计, 保持输出
结构一致.

  输出: tool/sample/success/findings/duration_sec (+ calls/mode/time_ms).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

GHIDRA_SCRIPT = r"""
// HeapOverflowScan.java — 统计对 malloc 缓冲的危险写引用
// @category BinMind
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class HeapOverflowScan extends GhidraScript {
    @Override
    public void run() throws Exception {
        int allocCalls = 0, memcpyCalls = 0, heapRefs = 0;
        Listing listing = currentProgram.getListing();
        FunctionIterator fns = listing.getFunctions(true);
        while (fns.hasNext() && !monitor.isCancelled()) {
            Function fn = fns.next();
            InstructionIterator ins = listing.getInstructions(
                fn.getBody(), true);
            while (ins.hasNext() && !monitor.isCancelled()) {
                Instruction i = ins.next();
                String mnem = i.getMnemonicString().toLowerCase();
                if (mnem.equals("call")) {
                    Reference[] refs = i.getReferencesFrom();
                    for (Reference r : refs) {
                        String name = "";
                        Symbol s = getSymbolAt(r.getToAddress());
                        if (s != null) name = s.getName().toLowerCase();
                        if (name.contains("malloc") ||
                            name.contains("calloc") ||
                            name.contains("realloc")) allocCalls++;
                        if (name.contains("memcpy") ||
                            name.contains("memset") ||
                            name.contains("strcpy")) memcpyCalls++;
                    }
                }
                if (mnem.startsWith("mov")) {
                    if (i.toString().toLowerCase().contains("[") &&
                        i.toString().contains("+")) heapRefs++;
                }
            }
        }
        printf("ALLOC_CALLS=%d\n", allocCalls);
        printf("MEMCPY_CALLS=%d\n", memcpyCalls);
        printf("HEAP_REFS=%d\n", heapRefs);
    }
}
"""

_DANGEROUS = {"memcpy", "memmove", "strcpy", "strncpy", "strcat",
              "sprintf", "snprintf", "read", "fread", "recv",
              "malloc", "free", "memset"}

_DANGER = re.compile(
    r'(malloc|calloc|realloc|memcpy|memset|strcpy|strncpy)', re.IGNORECASE)


def _find_ghidra() -> str:
    """[BinMind/eval 版] 查找 analyzeHeadless (PATH + 常见安装路径)."""
    cands = shutil.which("analyzeHeadless")
    if cands:
        return cands
    for d in (Path(r"C:\Program Files\Ghidra"), Path("C:/ghidra")):
        if d.is_dir():
            for h in d.rglob("analyzeHeadless.bat"):
                return str(h)
    return ""


def _run_headless(binary: str) -> dict:
    """[BinMind/eval 版] analyzeHeadless 运行, 过滤危险行."""
    headless = _find_ghidra()
    if not headless:
        return {"tool": "ghidra", "findings": 0, "calls": [],
                "time_ms": 0, "mode": "objdump-fallback"}
    t0 = time.perf_counter()
    proj_dir = tempfile.mkdtemp(prefix="ghidra_")
    try:
        r = subprocess.run(
            [headless, proj_dir, "bench",
             "-import", binary, "-postScript", "None",
             "-analysisTimeoutPerFile", "60"],
            capture_output=True, timeout=180)
        out = r.stdout.decode("utf-8", errors="replace")
        calls = [{"line": ln.strip()[:200]}
                 for ln in out.splitlines()
                 if any(d in ln for d in _DANGEROUS)][:100]
        return {"tool": "ghidra", "findings": len(calls), "calls": calls,
                "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "mode": "headless", "returncode": r.returncode}
    except Exception as e:
        return {"tool": "ghidra", "findings": 0, "calls": [],
                "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "mode": "headless", "error": f"{type(e).__name__}: {e}"}


def _run_objdump_audit(binary: str) -> dict:
    """[BinMind/eval 版] objdump 危险调用面审计 — 统计调用危险函数的调用点."""
    t0 = time.perf_counter()
    calls = []
    try:
        out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                             capture_output=True, timeout=30
                             ).stdout.decode("utf-8", errors="replace")
        for line in out.splitlines():
            low = line.lower()
            m = re.search(r'call\s+[\w\s<>\d]+\s+<([^>]+)>', low)
            if m:
                name = m.group(1).split("@")[0].split(".")[-1].strip()
                if name in _DANGEROUS:
                    calls.append({"call": name, "line": line.strip()[:160]})
    except Exception as e:
        return {"tool": "ghidra", "findings": 0, "calls": [],
                "time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "mode": "objdump-fallback",
                "error": f"{type(e).__name__}: {e}"}
    return {"tool": "ghidra", "findings": len(calls), "calls": calls[:100],
            "time_ms": round((time.perf_counter() - t0) * 1000, 2),
            "mode": "objdump-fallback"}


def audit(binary: str) -> dict:
    """[BinMind/eval 版] 公开入口: headless 优先, objdump 降级."""
    r = _run_headless(binary)
    if r.get("mode") == "objdump-fallback" or r.get("error"):
        r = _run_objdump_audit(binary)
    return r


def _find_headless() -> Optional[str]:
    """[deemo/modules/eval 版] PATH 查找 analyzeHeadless."""
    for name in ('analyzeHeadless', 'analyzeHeadless.bat'):
        from shutil import which
        p = which(name)
        if p:
            return p
    return None


def _objdump_fallback(binary_path: str, name: str, t0: float) -> Dict:
    """[deemo/modules/eval 版] objdump 模式统计降级实现."""
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary_path],
            capture_output=True, text=True, timeout=60)
        text = proc.stdout
    except Exception as e:
        return {'tool': 'ghidra', 'sample': name, 'success': False,
                'error': str(e)[:200], 'findings': 0,
                'duration_sec': round(time.time() - t0, 2)}
    findings = len(_DANGER.findall(text))
    calls = len(re.findall(r'call\s+\S+', text))
    return {
        'tool': 'ghidra',
        'sample': name,
        'success': True,
        'findings': findings,
        'mode': 'objdump-fallback',
        'call_count': calls,
        'duration_sec': round(time.time() - t0, 2),
    }


def _grep_int(text: str, key: str) -> int:
    """[deemo/modules/eval 版] 从 Ghidra 输出解析计数."""
    m = re.search(rf'{key}=(\d+)', text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def ghidra_headless_scan(binary_path: str, timeout_sec: int = 300) -> Dict:
    """[deemo/modules/eval 版] Ghidra 无头分析目标二进制, 返回堆危险调用统计."""
    name = os.path.basename(binary_path)
    t0 = time.time()
    headless = _find_headless()
    if headless is None:
        # 降级: objdump 静态统计 (保持输出结构)
        return _objdump_fallback(binary_path, name, t0)
    with tempfile.TemporaryDirectory(prefix='ghidra_') as wd:
        proj_dir = os.path.join(wd, 'proj')
        script_dir = os.path.join(wd, 'scripts')
        Path(script_dir).mkdir()
        Path(script_dir, 'HeapOverflowScan.java').write_text(
            GHIDRA_SCRIPT, encoding='utf-8')
        try:
            proc = subprocess.run(
                [headless, proj_dir, 'scan_proj', '-import', binary_path,
                 '-postScript', 'HeapOverflowScan.java', '-scriptPath',
                 script_dir],
                capture_output=True, text=True, timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            return {'tool': 'ghidra', 'sample': name, 'success': False,
                    'error': 'timeout', 'findings': 0,
                    'duration_sec': round(time.time() - t0, 2)}
        except Exception as e:
            return {'tool': 'ghidra', 'sample': name, 'success': False,
                    'error': str(e)[:200], 'findings': 0,
                    'duration_sec': round(time.time() - t0, 2)}
        out = proc.stdout + proc.stderr
        alloc = _grep_int(out, 'ALLOC_CALLS')
        memcpy = _grep_int(out, 'MEMCPY_CALLS')
        refs = _grep_int(out, 'HEAP_REFS')
        return {
            'tool': 'ghidra',
            'sample': name,
            'success': True,
            'findings': alloc + memcpy,
            'alloc_calls': alloc,
            'memcpy_calls': memcpy,
            'heap_refs': refs,
            'duration_sec': round(time.time() - t0, 2),
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    args = ap.parse_args()
    r = ghidra_headless_scan(args.binary)
    detail = audit(args.binary)
    merged = dict(r)
    merged['calls'] = detail.get('calls', [])
    merged['mode'] = detail.get('mode', r.get('mode'))
    merged['time_ms'] = detail.get('time_ms', 0)
    print(json.dumps(merged, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()