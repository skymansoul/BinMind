# created: 2026-07-22
# 扫描调度——对编译产物调用ai_ml检测管线, 收集原始输出
# 每个sample的O0/O3产物独立扫描, 输出保存到build/{sample}/{opt}/scan_result.json

import subprocess
import json
import sys
import time
import resource
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

BUILD_ROOT = Path(__file__).parent / "build"
AI_ML_ROOT = Path(__file__).parent.parent.parent  # ai_ml目录


@dataclass
class ScanResult:
    sample_name: str
    cve_id: str
    opt_level: str
    vuln_type: str
    binary_path: str
    scan_success: bool
    detected: bool              # 是否检出任何漏洞
    detected_type: str          # 检出的漏洞类型
    confidence: float
    scan_time_ms: float
    peak_memory_kb: int
    raw_output: str = ""
    error_msg: str = ""


def find_binaries() -> List[Path]:
    """扫描build/目录, 返回所有编译成功的ELF文件路径"""
    binaries = []
    if not BUILD_ROOT.exists():
        return binaries
    for elf in BUILD_ROOT.rglob("target"):
        if elf.is_file():
            binaries.append(elf)
    return sorted(binaries)


def run_scan(binary_path: Path) -> ScanResult:
    """对单个二进制文件运行ai_ml检测"""
    # 从路径中提取sample_name和opt_level
    parts = binary_path.parts
    opt_level = "O0"
    sample_name = "unknown"
    for i, p in enumerate(parts):
        if p in ("O0", "O3"):
            opt_level = p
            if i > 0:
                sample_name = parts[i - 1]
            break

    cve_id = sample_name.split("_")[0] if "_" in sample_name else sample_name
    vuln_type = infer_vuln_type(sample_name)

    t0 = time.perf_counter()
    try:
        # 通过main.py的vuln子命令执行检测
        proc = subprocess.run(
            [sys.executable, "-m", "main", "vuln",
             "--vuln-data", json.dumps({
                 "binary_path": str(binary_path),
                 "function_name": "main",
                 "vuln_type": vuln_type,
             })],
            capture_output=True, text=True, timeout=120,
            cwd=str(AI_ML_ROOT),
            env={**__import__('os').environ, "PYTHONPATH": str(AI_ML_ROOT)})

        success = proc.returncode == 0
        raw = proc.stdout[:5000]
        error = proc.stderr[:1000]

        # 解析输出
        detected = False
        detected_type = ""
        confidence = 0.0
        try:
            parsed = json.loads(raw) if raw.strip().startswith('{') else {}
            detected = parsed.get('is_vulnerable', False)
            detected_type = parsed.get('vuln_type', '')
            confidence = float(parsed.get('confidence', 0))
        except json.JSONDecodeError:
            pass

    except subprocess.TimeoutExpired:
        success = False
        raw = ""
        error = "scan timed out after 120s"
    except Exception as e:
        success = False
        raw = ""
        error = str(e)

    elapsed = (time.perf_counter() - t0) * 1000

    # 峰值内存(近似——Python进程的max RSS)
    peak_kb = 0
    try:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        peak_kb = usage.ru_maxrss
    except Exception:
        pass

    return ScanResult(
        sample_name=sample_name, cve_id=cve_id,
        opt_level=opt_level, vuln_type=vuln_type,
        binary_path=str(binary_path),
        scan_success=success, detected=detected,
        detected_type=detected_type, confidence=confidence,
        scan_time_ms=elapsed, peak_memory_kb=peak_kb,
        raw_output=raw[:3000], error_msg=error[:500])


def infer_vuln_type(dirname: str) -> str:
    lower = dirname.lower()
    if any(k in lower for k in ('uaf',)):
        return 'use_after_free'
    if any(k in lower for k in ('overflow', 'heap', 'heartbleed')):
        return 'buffer_overflow'
    return 'unknown'


def main():
    binaries = find_binaries()
    if not binaries:
        print("无编译产物——请先运行 compile_samples.py")
        sys.exit(1)

    results = []
    for binary in binaries:
        print(f"扫描 {binary.parent.name}/{binary.parent.parent.name} ...")
        result = run_scan(binary)
        status = "检出" if result.detected else "未检出"
        print(f"  [{result.opt_level}] {status} conf={result.confidence:.2f} time={result.scan_time_ms:.0f}ms")
        results.append(result)

        # 保存单样本结果
        out_dir = binary.parent
        out_path = out_dir / "scan_result.json"
        with open(out_path, 'w') as f:
            json.dump(asdict(result), f, indent=2)

    # 汇总
    detected = sum(1 for r in results if r.detected)
    print(f"\n扫描完成: {detected}/{len(results)} 检出漏洞")
    return 0


if __name__ == '__main__':
    sys.exit(main())
