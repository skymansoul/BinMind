"""扫描调度模块 - 将编译后的 ELF 送入检测器, 收集检测结果

读取 compile_samples.py 生成的 manifest.json,
对每个已编译的二进制调用检测器, 汇总结果。
"""

import json, os, sys, time, resource, shutil, subprocess, tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

BUILD_ROOT = Path(__file__).parent / 'build'
RESULTS_ROOT = Path(__file__).parent / 'results'

@dataclass
class ScanResult:
    binary: str
    cve_id: str
    vuln_type: str                 # ground truth
    compiler: str
    opt_level: str
    # 检测器输出
    detected: bool
    detection_type: str = ''       # 检测器判定的类型
    confidence: float = 0.0
    # 性能
    scan_time_ms: float = 0.0
    peak_memory_mb: float = 0.0
    # 误报/漏报判定
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False
    error: str = ''

def get_peak_memory_mb() -> float:
    try:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        return 0.0

def run_format_string_detector(binary_path: str) -> List[Dict]:
    """调用 format_string_detector"""
    try:
        r2 = shutil.which('r2') or shutil.which('radare2')
        if not r2:
            return []
        # 用r2反汇编, 提取函数列表
        cmd = [r2, '-q', '-c', 'aaa; afl', binary_path]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        # 简化: 对每个函数提取反汇编
        functions = {}
        for line in out.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 4:
                addr = int(parts[0], 16)
                name = parts[3]
                # 获取函数反汇编
                cmd2 = [r2, '-q', '-c', f's {addr}; pdf', binary_path]
                asm = subprocess.run(cmd2, capture_output=True, text=True, timeout=10).stdout
                functions[name] = [(addr, l) for l in asm.strip().split('\n') if l.strip()]
        from modules.analysis.static.tools.format_string_detector import FormatStringDetector
        detector = FormatStringDetector()
        findings = detector.detect(functions)
        return [{'type': 'format_string', 'verdict': f.verdict.value,
                 'confidence': f.confidence, 'address': f.call_address} for f in findings]
    except Exception as e:
        return [{'error': str(e)[:100]}]

def run_heap_overflow_detector(binary_path: str) -> List[Dict]:
    try:
        from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
        from modules.analysis.static.heap_alloc_model import AllocatorFamily
        from modules.analysis.static.disasm_util import disassemble_binary
        ins, fmt, main_addr, ranges = disassemble_binary(binary_path)
        det = HeapOverflowDetector(
            AllocatorFamily.GLIBC,
            use_win64_abi="pei" in fmt.lower())
        if main_addr:
            det.set_min_user_addr(main_addr)
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)
        return [{'type': 'heap_overflow', 'severity': f.get('severity', ''),
                 'write_addr': f.get('write_addr', 0)} for f in findings]
    except Exception as e:
        return [{'error': str(e)[:100]}]

def run_uaf_detector(binary_path: str) -> List[Dict]:
    try:
        from modules.analysis.static.uaf_detect import UAFDetector
        from modules.analysis.static.disasm_util import disassemble_binary
        ins, fmt, main_addr, ranges = disassemble_binary(binary_path)
        det = UAFDetector(use_win64_abi="pei" in fmt.lower())
        if ranges:
            det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins) or det.findings
        return [{'type': 'uaf', 'verdict': str(getattr(f, 'verdict', ''))}
                for f in findings]
    except Exception as e:
        return [{'error': str(e)[:100]}]

DETECTORS = {
    'format_string': run_format_string_detector,
    'heap_overflow': run_heap_overflow_detector,
    'uaf': run_uaf_detector,
}

def scan_binary(manifest_entry: Dict) -> ScanResult:
    binary = manifest_entry.get('binary', '')
    cve = manifest_entry.get('cve', 'unknown')
    vtype = manifest_entry.get('type', 'unknown')

    if not binary or not os.path.exists(binary):
        return ScanResult(binary=binary, cve_id=cve, vuln_type=vtype,
                          compiler=manifest_entry.get('compiler',''),
                          opt_level=manifest_entry.get('opt',''),
                          detected=False, error='binary not found')

    t0 = time.perf_counter()
    mem0 = get_peak_memory_mb()

    # 选择与漏洞类型匹配的检测器
    detector_fn = DETECTORS.get(vtype)
    findings = []
    if detector_fn:
        try:
            findings = detector_fn(binary)
        except Exception as e:
            return ScanResult(binary=binary, cve_id=cve, vuln_type=vtype,
                              compiler=manifest_entry.get('compiler',''),
                              opt_level=manifest_entry.get('opt',''),
                              detected=False, error=str(e)[:200])

    scan_time = (time.perf_counter() - t0) * 1000
    peak_mem = get_peak_memory_mb() - mem0

    detected = len(findings) > 0 and not any('error' in f for f in findings)
    result = ScanResult(
        binary=binary, cve_id=cve, vuln_type=vtype,
        compiler=manifest_entry.get('compiler', ''),
        opt_level=manifest_entry.get('opt', ''),
        detected=detected,
        detection_type=findings[0].get('type','') if findings else '',
        confidence=findings[0].get('confidence', 0.0) if findings else 0.0,
        scan_time_ms=round(scan_time, 2),
        peak_memory_mb=round(peak_mem, 2),
    )

    # Ground truth 比较
    if detected and vtype in str(findings):
        result.is_true_positive = True
    elif detected:
        result.is_false_positive = True
    elif not detected and vtype != 'unknown':
        result.is_false_negative = True

    return result

def scan_all() -> List[ScanResult]:
    manifest_path = BUILD_ROOT / 'manifest.json'
    if not manifest_path.exists():
        print(f'manifest not found: {manifest_path}. Run compile_samples.py first.')
        return []
    with open(manifest_path) as f:
        manifest = json.load(f)
    results = []
    for entry in manifest:
        if not entry.get('compiled'):
            continue
        print(f'  scanning {entry["cve"]} ({entry["compiler"]}-{entry["opt"]})...')
        r = scan_binary(entry)
        results.append(r)
        status = 'TP' if r.is_true_positive else ('FP' if r.is_false_positive else ('FN' if r.is_false_negative else '--'))
        print(f'    {status} time={r.scan_time_ms:.0f}ms mem={r.peak_memory_mb:.1f}MB')

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_ROOT / 'scan_results.json'
    with open(out_path, 'w') as f:
        json.dump([{
            'binary': r.binary, 'cve': r.cve_id, 'type': r.vuln_type,
            'compiler': r.compiler, 'opt': r.opt_level,
            'detected': r.detected, 'confidence': r.confidence,
            'tp': r.is_true_positive, 'fp': r.is_false_positive, 'fn': r.is_false_negative,
            'time_ms': r.scan_time_ms, 'mem_mb': r.peak_memory_mb,
            'error': r.error,
        } for r in results], f, indent=2)
    print(f'Results written to {out_path}')
    return results

if __name__ == '__main__':
    scan_all()
