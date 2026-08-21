#!/usr/bin/env python3
"""Ghidra Headless适配器 — 使用Ghidra脚本检测堆溢出.

需要Ghidra安装并设置GHIDRA_HOME环境变量.
通过headless analyzer运行内置/自定义脚本分析二进制.
"""
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from .run_benchmark import ToolAdapter

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "")
GHIDRA_AVAILABLE = bool(GHIDRA_HOME
                        and Path(GHIDRA_HOME).exists())


class GhidraAdapter(ToolAdapter):
    """Ghidra headless分析适配器."""

    name = "Ghidra"

    def run(self, binary_path: str) -> List[dict]:
        if not GHIDRA_AVAILABLE:
            raise RuntimeError("Ghidra not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "heap_detect.py"
            script_path.write_text(_GHIDRA_SCRIPT)

            analyze_headless = (Path(GHIDRA_HOME) / "support"
                                / "analyzeHeadless.bat")
            cmd = [
                str(analyze_headless),
                tmpdir, "TempProject",
                "-import", binary_path,
                "-postScript", str(script_path),
                "-scriptPath", tmpdir,
                "-deleteProject",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=120)
            findings = self._parse_output(result.stdout)
        return findings

    @staticmethod
    def _parse_output(stdout: str) -> List[dict]:
        """从Ghidra脚本输出解析findings."""
        findings = []
        for line in stdout.splitlines():
            if "HEAP_OVERFLOW_FOUND" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    addr = int(parts[1].strip(), 16)
                    findings.append({
                        "address": addr,
                        "type": "heap_overflow",
                    })
        return findings


# Ghidara Python脚本 — 在Ghidra中运行
_GHIDRA_SCRIPT = """\
# Ghidra heap overflow detection script
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType

fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.isExternal():
        continue
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


if __name__ == "__main__":
    if not GHIDRA_AVAILABLE:
        print("Ghidra not found. Set GHIDRA_HOME environment variable.")
        sys.exit(1)
    print("Ghidra adapter ready.")
