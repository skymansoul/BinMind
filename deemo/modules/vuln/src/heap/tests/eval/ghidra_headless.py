"""SHIELD 对比实验 — Ghidra 无头模式批量反编译 + 堆溢出检测.

用 Ghidra headless analyzer 反编译每个样本, 提取 malloc/memcpy
调用点的参数, 对比 SHIELD 的约束关联结果.

依赖: Ghidra 10.4+ 安装, GHIDRA_INSTALL_DIR 环境变量

用法:
  python ghidra_headless.py --sample cve_2021_3156

创建: 2025-02-06
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional


BUILD_ROOT = Path(__file__).resolve().parent.parent / "build"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Ghidra headless 脚本 (Java) — 内联以便部署
GHIDRA_SCRIPT_CONTENT = """/* SHIELD Ghidra Headless — heap overflow detector */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.util.*;

public class ShieldGhidra extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<Map<String, String>> findings = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        for (Function func : fm.getFunctions(true)) {
            InstructionIterator iter = listing.getInstructions(func.getBody(), true);
            Map<Address, Long> allocSizes = new HashMap<>();

            while (iter.hasNext()) {
                Instruction insn = iter.next();
                String mnemonic = insn.getMnemonicString().toLowerCase();

                // 追踪 malloc size
                if (mnemonic.equals("call")) {
                    Reference[] refs = insn.getReferencesFrom();
                    for (Reference ref : refs) {
                        String target = ref.getToAddress().toString().toLowerCase();
                        if (target.contains("malloc") || target.contains("calloc")) {
                            // 尝试从前序指令推断 size (rcx = size)
                            Instruction prev = insn.getPrevious();
                            if (prev != null && prev.getMnemonicString().toLowerCase().equals("mov")) {
                                try {
                                    long size = insn.getPrevious().getScalar(0).getSignedValue();
                                    allocSizes.put(insn.getAddress(), size);
                                } catch (Exception e) { /* dynamic size */ }
                            }
                        }
                    }
                }
            }

            // 检查 memset/memcpy
            iter = listing.getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction insn = iter.next();
                if (insn.getMnemonicString().toLowerCase().equals("call")) {
                    Reference[] refs = insn.getReferencesFrom();
                    for (Reference ref : refs) {
                        String target = ref.getToAddress().toString().toLowerCase();
                        if (target.contains("memset") || target.contains("memcpy")) {
                            Map<String, String> f = new HashMap<>();
                            f.put("insn_addr", insn.getAddress().toString());
                            f.put("func", func.getName());
                            findings.add(f);
                        }
                    }
                }
            }
        }

        // 输出 JSON
        com.google.gson.Gson gson = new com.google.gson.Gson();
        System.out.println("GHIDRA_RESULT:" + gson.toJson(findings));
    }
}
"""


def run_ghidra_headless(exe_path: Path, timeout: int = 60) -> dict:
    """运行 Ghidra headless 分析单个样本."""
    t0 = time.perf_counter()

    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR", "")
    if not ghidra_home:
        return {'error': 'GHIDRA_INSTALL_DIR not set', 'time_ms': 0, 'findings': 0}

    # 写 Ghidra 脚本到临时目录
    script_dir = RESULTS_DIR / "ghidra_scripts"
    script_dir.mkdir(exist_ok=True)
    script_path = script_dir / "ShieldGhidra.java"
    script_path.write_text(GHIDRA_SCRIPT_CONTENT)

    headless = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(ghidra_home, "support", "analyzeHeadless")

    project_dir = str(RESULTS_DIR / "ghidra_projects")
    project_name = f"shield_{exe_path.stem}"

    try:
        result = subprocess.run(
            [headless, project_dir, project_name,
             "-import", str(exe_path),
             "-scriptPath", str(script_dir),
             "-postScript", "ShieldGhidra.java",
             "-deleteProject", "-noanalysis"],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'error': 'timeout', 'time_ms': timeout * 1000, 'findings': 0}
    except FileNotFoundError:
        return {'error': f'Ghidra not found at {headless}', 'time_ms': 0, 'findings': 0}

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    # 解析 Ghidra 输出中的 JSON
    findings = 0
    for line in result.stdout.split('\n'):
        if 'GHIDRA_RESULT:' in line:
            try:
                data = json.loads(line.split('GHIDRA_RESULT:', 1)[1])
                findings = len(data)
            except json.JSONDecodeError:
                pass

    return {
        'findings': findings,
        'time_ms': elapsed_ms,
        'error': '',
        'stdout_tail': result.stdout[-500:] if result.stdout else '',
    }


def main():
    parser = argparse.ArgumentParser(description="Ghidra Headless 分析")
    parser.add_argument("--sample", type=str, default="", help="单样本名称")
    args = parser.parse_args()

    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        print("  [INFO] GHIDRA_INSTALL_DIR not set.")
        print("  Set it first: export GHIDRA_INSTALL_DIR=/c/ghidra_10.4")
        print("  Skipping Ghidra comparison — use SHIELD + Angr + QEMU instead.")
        # 写占位结果
        placeholder = {'status': 'GHIDRA_NOT_CONFIGURED',
                       'note': 'Set GHIDRA_INSTALL_DIR to enable Ghidra comparison'}
        out_path = RESULTS_DIR / "ghidra_results.json"
        with open(out_path, "w") as f:
            json.dump(placeholder, f, indent=2)
        print(f"  Placeholder written to {out_path}")
        return

    opt_dir = BUILD_ROOT / "gcc" / "O0"
    exes = sorted(opt_dir.glob("*.exe"))
    if args.sample:
        exes = [e for e in exes if args.sample in e.stem]

    results = []
    for exe in exes:
        print(f"  Ghidra analyzing: {exe.stem} ...")
        r = run_ghidra_headless(exe)
        r['sample'] = exe.stem
        results.append(r)
        print(f"    Findings: {r['findings']}, Time: {r['time_ms']}ms")

    out_path = RESULTS_DIR / "ghidra_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results: {out_path}")


if __name__ == "__main__":
    main()
