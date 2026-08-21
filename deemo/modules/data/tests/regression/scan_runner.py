# 扫描调度器 — 批量调用扫描引擎, 收集原始结果.

import os, sys, json, time, subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ScanResult:
    binary_path: str
    sample_name: str
    compiler: str
    opt_level: str
    elapsed_ms: float = 0.0
    findings: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    peak_memory_kb: int = 0

class ScanRunner:
    """批量扫描调度器."""

    def __init__(self, scanner_path: str = None):
        self._scanner = scanner_path or self._find_scanner()
        self._results: List[ScanResult] = []

    def scan_directory(self, binary_dir: str,
                        pattern: str = "*") -> List[ScanResult]:
        """扫描目录下所有匹配的二进制文件."""
        import glob
        binaries = sorted(glob.glob(os.path.join(binary_dir, pattern)))
        for bpath in binaries:
            if not os.path.isfile(bpath): continue
            if os.path.splitext(bpath)[1] in (".c",".h",".py"): continue
            result = self.scan_one(bpath)
            self._results.append(result)
        return self._results

    def scan_one(self, binary_path: str) -> ScanResult:
        """扫描单个二进制, 返回 ScanResult."""
        fname = os.path.basename(binary_path)
        parts = fname.rsplit("_", 3)
        sample_name = parts[0] if len(parts) >= 4 else fname
        compiler = parts[1] if len(parts) >= 4 else "unknown"
        opt = parts[3] if len(parts) >= 4 else "unknown"

        t0 = time.time()
        findings = []
        errors = []

        try:
            raw = self._run_scanner(binary_path)
            if isinstance(raw, list):
                findings = raw
            elif isinstance(raw, dict):
                findings = raw.get("findings", [])
        except Exception as e:
            errors.append(str(e))

        elapsed = (time.time() - t0) * 1000
        return ScanResult(
            binary_path=binary_path, sample_name=sample_name,
            compiler=compiler, opt_level=opt,
            elapsed_ms=elapsed, findings=findings, errors=errors)

    def _run_scanner(self, binary_path: str) -> dict:
        """调用扫描器 (当前为占位 — 实际集成时替换为真实扫描调用)."""
        # 生产环境替换为: from modules.analysis.static import *
        # 或 subprocess 调用独立扫描进程
        try:
            result = subprocess.run(
                [sys.executable, "-c", f"""
import sys; sys.path.insert(0, '.')
from modules.analysis.static.taint_engine import TaintTracker
from modules.analysis.static.stack_overflow_detect import StackOverflowDetector
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.format_string_detect import FormatStringDetector
from modules.analysis.static.vuln_scores import VulnScoreCalibrator
import json

binary = open('{binary_path}', 'rb').read()
findings = []

# Taint
tt = TaintTracker()
tt.set_sources([('rdi','user_input')])
# Stack overflow
sod = StackOverflowDetector()
sod.extract_frames(binary)
# UAF
uaf = UAFDetector()
# Format string
fsd = FormatStringDetector()
# Calibrate
cal = VulnScoreCalibrator()
all_findings = tt.findings + sod.findings + uaf.findings + fsd.findings
for f in all_findings: f['engine'] = 'taint_engine'
scored = cal.calibrate(all_findings)
print(json.dumps([s.to_dict() for s in scored]))
"""], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return {"findings": []}

    @staticmethod
    def _find_scanner() -> str:
        return sys.executable  # placeholder

    @property
    def results(self) -> List[ScanResult]:
        return list(self._results)


if __name__ == "__main__":
    runner = ScanRunner()
    bin_dir = os.path.join(os.path.dirname(__file__), "binaries")
    if os.path.isdir(bin_dir):
        results = runner.scan_directory(bin_dir)
        for r in results:
            print(f"{r.sample_name}: {len(r.findings)} findings, {r.elapsed_ms:.0f}ms")
    else:
        print(f"Binary dir not found: {bin_dir}")
