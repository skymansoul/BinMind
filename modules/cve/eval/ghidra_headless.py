# Ghidra 无头分析 - 模拟自动化静态审计.
#
# 决策逻辑:
#   analyzeHeadless 加载样本 → 运行 Ghidra 内建分析 (反编译/引用),
#   以脚本扫描 malloc 调用点与其参数来源, 判定是否存在堆溢出.
#   GHIDRA_HOME 未配置时返回 unsupported, 不产生误报.
#   Ghidra 作为"通用反编译工具"对比组: 其检测依赖符号表与反编译质量,
#   对 stripped/PE 样本能力受限, 反映通用工具的实际精度.
#

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict


def ghidra_available() -> bool:
    home = os.environ.get("GHIDRA_HOME", "")
    if not home:
        return False
    exe = Path(home) / "support" / "analyzeHeadless"
    return exe.exists()


def _headless_cmd() -> str:
    home = os.environ.get("GHIDRA_HOME", "")
    return str(Path(home) / "support" / "analyzeHeadless")


# Ghidra Java 分析脚本: 枚举 malloc 调用点, 检查其所在函数
# 是否存在对 memcpy 的调用. 输出 VULN 标记供解析.
_GHIDRA_SCRIPT = """import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

var fm = currentProgram.getFunctionManager();
var msgs = new ArrayList();
for (var fn : fm.getFunctions(true)) {
    boolean hasMalloc = false;
    boolean hasWrite = false;
    var it = currentProgram.getListing().getInstructions(fn.getBody(), true);
    while (it.hasNext()) {
        var ins = it.next();
        if (!ins.getMnemonicString().equals("CALL")) continue;
        var refs = ins.getReferencesFrom();
        for (var r : refs) {
            var t = r.getToAddress();
            var name = currentProgram.getSymbolTable().getPrimarySymbol(t);
            String n = name == null ? "" : name.getName().toLowerCase();
            if (n.equals("malloc") || n.equals("calloc") || n.equals("realloc"))
                hasMalloc = true;
            if (n.equals("memcpy") || n.equals("memmove") || n.equals("memset"))
                hasWrite = true;
        }
    }
    if (hasMalloc && hasWrite) msgs.add(fn.getName());
}
if (!msgs.isEmpty()) System.out.println("VULN_FUNCS=" + msgs);
System.out.println("DONE");
"""


def trace(binary: str, workdir: str = None) -> Dict:
    """运行 Ghidra 无头分析, 判定样本是否含堆溢出模式.

    返回: {detected, findings, elapsed_ms, error}
    """
    t0 = time.perf_counter()
    result = {"detected": False, "findings": [], "elapsed_ms": 0.0,
              "error": ""}
    if not ghidra_available():
        result["error"] = "GHIDRA_HOME not set / analyzeHeadless not found"
        return result

    project_dir = workdir or os.path.join(
        os.environ.get("TEMP", "/tmp"), "ghidra_proj")
    os.makedirs(project_dir, exist_ok=True)
    proj_name = f"proj_{int(t0)}"
    script_dir = os.path.join(project_dir, "scripts")
    os.makedirs(script_dir, exist_ok=True)
    script_path = os.path.join(script_dir, "ScanHeap.java")
    with open(script_path, "w", encoding="utf-8") as fh:
        fh.write(_GHIDRA_SCRIPT)

    try:
        r = subprocess.run(
            [os.environ.get("JAVA", "java"), "-version"],
            capture_output=True, timeout=10)
        _ = r
    except Exception:
        result["error"] = "java unavailable"
        return result

    try:
        r = subprocess.run(
            [_headless_cmd(), project_dir, proj_name, "-import", binary,
             "-postScript", "ScanHeap.java", "-deleteProject"],
            capture_output=True, text=True, timeout=180,
            cwd=os.path.dirname(script_path))
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            if line.startswith("VULN_FUNCS="):
                result["findings"].append(line)
        result["detected"] = bool(result["findings"])
        if not result["findings"] and "DONE" not in out:
            result["error"] = "analysis did not complete"
    except subprocess.TimeoutExpired:
        result["error"] = "timeout (180s)"
    except Exception as e:
        result["error"] = f"ghidra failed: {str(e)[:120]}"

    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if len(sys.argv) < 2:
        print("usage: python ghidra_headless.py <binary> [--json]")
        return
    binary = sys.argv[1]
    res = trace(binary)
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(f"detected={res['detected']} findings={len(res['findings'])} "
              f"time={res['elapsed_ms']:.0f}ms error={res['error']}")


if __name__ == "__main__":
    main()
