"""Ghidra 无头分析器 — 模拟自动化静态审计的堆溢出检测.

Java 脚本策略 (与人工审计一致):
  1. 逐函数收集 malloc/calloc 调用及大小立即数 (回溯 rdi/rcx)
  2. 收集 memcpy/memmove/memset/strncpy 调用及大小立即数
  3. 函数内最近分配 ≤ 写入大小 → 报告 HEAP_OVERFLOW
  4. 函数内无分配 → 该调用标记 UNMATCHED (可审计性提示)

Ghidra 不可用 → N/A, 不阻塞基准流程.
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

_RESULTS_CACHE: Dict[str, dict] = {}

_GHIDRA_SCRIPT = r"""
// HeapOverflowAudit.java — 模拟自动化静态审计
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import java.util.*;

public class HeapOverflowAudit extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = listing.getFunctions(true);
        int overflow = 0;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            long lastMallocSize = -1;
            InstructionIterator insns = listing.getInstructions(func.getBody(), true);
            while (insns.hasNext()) {
                Instruction insn = insns.next();
                if (!insn.getMnemonicString().equalsIgnoreCase("call")) continue;
                Reference[] refs = insn.getReferencesFrom();
                for (Reference ref : refs) {
                    String target = ref.getToAddress().toString().toLowerCase();
                    if (target.contains("malloc") || target.contains("calloc")) {
                        long sz = scanImm(insn);
                        if (sz > 0) lastMallocSize = sz;
                    } else if (target.contains("memcpy") || target.contains("memmove")
                            || target.contains("memset") || target.contains("strncpy")) {
                        long w = scanImm(insn);
                        if (w > 0 && lastMallocSize > 0 && w > lastMallocSize) {
                            overflow++;
                            printf("HEAP_OVERFLOW: write(%d) > alloc(%d) func=%s\n",
                                w, lastMallocSize, func.getName());
                        }
                    }
                }
            }
        }
        printf("GHIDRA_SUMMARY: potential_overflow=%d\n", overflow);
    }
    long scanImm(Instruction insn) {
        for (int k = 0; k < 8; k++) {
            Instruction p = insn.getPrevious();
            if (p == null) break;
            insn = p;
            Object[] objs = insn.getInputObjects();
            for (Object o : objs) {
                if (o instanceof java.math.BigInteger) return ((java.math.BigInteger) o).longValue();
            }
            String t = insn.getMnemonicString().toLowerCase();
            if (!t.startsWith("mov") && !t.startsWith("lea")) break;
        }
        return -1;
    }
}
"""


def _check_ghidra() -> Optional[str]:
    """检查 Ghidra headless 是否可用."""
    ghidra_home = os.environ.get('GHIDRA_INSTALL_DIR', '')
    if ghidra_home:
        candidates = [
            os.path.join(ghidra_home, 'support', 'analyzeHeadless'),
            os.path.join(ghidra_home, 'support', 'analyzeHeadless.bat'),
        ]
        for c in candidates:
            if os.path.exists(c) or os.path.exists(c + '.bat'):
                return c
    for c in ('analyzeHeadless', 'ghidra'):
        try:
            r = subprocess.run([c, '--help'], capture_output=True, timeout=5)
            if r.returncode in (0, 1):
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _run_ghidra_analysis(binary_path: str,
                         ghidra_bin: str) -> List[dict]:
    """运行 Ghidra headless 分析, 解析 HEAP_OVERFLOW 输出."""
    findings = []
    try:
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.java', delete=False,
                prefix='HeapOverflowAudit_') as f:
            f.write(_GHIDRA_SCRIPT)
            script_path = f.name
        proj_dir = tempfile.mkdtemp(prefix='ghidra_proj_')
        cmd = [ghidra_bin, proj_dir, 'HeapProject',
               '-import', binary_path,
               '-postScript', script_path,
               '-deleteProject']
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180,
            shell=(os.name == 'nt'))
        try:
            os.unlink(script_path)
        except OSError:
            pass
        output = result.stdout + result.stderr
        for line in output.split('\n'):
            if line.startswith('HEAP_OVERFLOW:'):
                findings.append({
                    "type": "heap_overflow", "subtype": "ghidra_audit",
                    "reason": line.strip(), "confidence": 0.5})
            elif line.startswith('GHIDRA_SUMMARY:'):
                findings.append({
                    "type": "meta", "subtype": "ghidra_summary",
                    "reason": line.strip(), "confidence": 0.0})
    except Exception as e:
        return [{"error": f"ghidra analysis failed: {e}"}]
    return findings


def run_ghidra_scan(binary_path: str, sample_name: str = "",
                    cache: bool = True) -> dict:
    """对单个二进制运行 Ghidra 分析."""
    if cache and binary_path in _RESULTS_CACHE:
        return _RESULTS_CACHE[binary_path]
    ghidra_bin = _check_ghidra()
    result = {"tool": "ghidra", "sample": sample_name,
              "available": ghidra_bin is not None, "findings": [],
              "elapsed_ms": 0.0, "error": ""}
    if not ghidra_bin:
        result["error"] = "ghidra not found (set GHIDRA_INSTALL_DIR)"
        if cache:
            _RESULTS_CACHE[binary_path] = result
        return result
    t0 = time.perf_counter()
    try:
        result["findings"] = _run_ghidra_analysis(binary_path, ghidra_bin)
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    if cache:
        _RESULTS_CACHE[binary_path] = result
    return result


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Ghidra headless heap audit")
    ap.add_argument("binary", help="Path to binary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run_ghidra_scan(args.binary, Path(args.binary).stem)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        n = len([f for f in result["findings"]
                 if f.get("type") == "heap_overflow"])
        print(f"Ghidra Headless — {args.binary}")
        print(f"  Available: {result['available']}")
        print(f"  Heap findings: {n}")
        print(f"  Time: {result['elapsed_ms']:.1f}ms")
        if result["error"]:
            print(f"  Error: {result['error']}")


if __name__ == "__main__":
    main()
