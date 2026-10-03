# 扫描调度模块——对编译产物执行堆溢出检测
# 同时运行原始三阶段过滤器和增强四级过滤器，对比检测效果
# 输出: 每个样本的检测报告(检出/漏报/误报/耗时)

import subprocess
import sys
import json
import time
import re
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple

# 将项目根目录加入path以导入检测模块
_PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

BUILD_DIR = Path(__file__).parent.parent / "build"
RESULTS_FILE = Path(__file__).parent / "scan_results.json"


# 每个样本的ground truth——标记哪些是真正的漏洞
GROUND_TRUTH = {}
# 动态生成: 从README.md或样本名推断


@dataclass
class ScanReport:
    sample_name: str
    opt_level: str
    # 原始过滤器结果
    original_confirmed: int
    original_likely: int
    original_filtered: int
    original_time_ms: float
    # 增强过滤器结果
    enhanced_confirmed: int
    enhanced_likely: int
    enhanced_filtered: int
    enhanced_time_ms: float
    # 判定
    is_true_positive: bool   # GT中是否有漏洞
    original_detected: bool  # 原始是否检出
    enhanced_detected: bool  # 增强是否检出
    original_fp: bool        # 原始误报(检出但实际无漏洞)
    enhanced_fp: bool        # 增强误报
    original_fn: bool        # 原始漏报(未检出但实际有漏洞)
    enhanced_fn: bool        # 增强漏报
    error: str = ""


def is_vuln_sample(name: str) -> bool:
    """判断样本是否是真的漏洞样本(而非负样本)"""
    name_lower = name.lower()
    # 负样本关键词
    safe_keywords = ['safe', 'no_overflow', 'alignment_edge_case']
    for kw in safe_keywords:
        if kw in name_lower:
            return False
    return True


def disassemble_instructions(binary_path: str) -> List[str]:
    """用objdump反汇编二进制，返回指令行列表"""
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary_path],
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return []
        lines = []
        in_text = False
        for line in proc.stdout.split('\n'):
            if '<.text>' in line or 'Disassembly of section .text' in line:
                in_text = True
                continue
            if in_text and line.strip():
                # 提取指令部分(去除地址和字节码)
                if ':\t' in line:
                    instr_part = line.split(':\t', 1)[-1]
                    # 进一步去除字节码: "48 89 e5\tmov rbp, rsp"
                    if '\t' in instr_part:
                        instr_part = instr_part.split('\t', 1)[-1]
                    lines.append(instr_part.strip())
        return lines
    except Exception:
        return []


def extract_function_instructions(instructions: List[str],
                                   func_name: str = "") -> List[Tuple[str, List[str]]]:
    """从objdump输出中提取函数边界和指令"""
    funcs = []
    current_name = ""
    current_instrs = []
    func_start_pattern = re.compile(r'<([^>]+)>:')

    for instr in instructions:
        m = func_start_pattern.search(instr)
        if m:
            if current_instrs:
                funcs.append((current_name, current_instrs))
            current_name = m.group(1)
            current_instrs = []
            continue
        if current_name:
            current_instrs.append(instr)

    if current_instrs:
        funcs.append((current_name, current_instrs))

    return funcs


def run_original_filter(instructions: List[str],
                         func_name: str) -> Tuple[int, int, int, float]:
    """运行原始三阶段过滤器"""
    from src.detect.heap_overflow_filter import (
        HeapOverflowFilter, FilterVerdict)
    t0 = time.perf_counter()
    try:
        f = HeapOverflowFilter()
        bb_boundaries = [(0, len(instructions))]
        cfg_edges = [(0, 0)]
        reports = f.analyze_function(
            instructions, bb_boundaries, cfg_edges, func_name)
        elapsed = (time.perf_counter() - t0) * 1000
        confirmed = sum(1 for r in reports
                       if r.verdict == FilterVerdict.CONFIRMED)
        likely = sum(1 for r in reports
                    if r.verdict == FilterVerdict.LIKELY)
        filtered = sum(1 for r in reports
                      if r.verdict == FilterVerdict.FILTERED)
        return confirmed, likely, filtered, elapsed
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return 0, 0, 0, elapsed


def run_enhanced_filter(instructions: List[str],
                         bb_boundaries, cfg_edges,
                         func_name: str) -> Tuple[int, int, int, float]:
    """运行增强四级过滤器"""
    from src.detect.analysis.enhanced_heap_filter import (
        EnhancedHeapFilter, EnhancedVerdict)
    t0 = time.perf_counter()
    try:
        f = EnhancedHeapFilter()
        reports = f.analyze_function(
            instructions, bb_boundaries, cfg_edges, func_name)
        elapsed = (time.perf_counter() - t0) * 1000
        confirmed = sum(1 for r in reports
                       if r.verdict == EnhancedVerdict.CONFIRMED)
        likely = sum(1 for r in reports
                    if r.verdict == EnhancedVerdict.LIKELY)
        filtered = sum(1 for r in reports
                      if r.verdict == EnhancedVerdict.FILTERED)
        return confirmed, likely, filtered, elapsed
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return 0, 0, 0, elapsed


def scan_binary(binary_path: str, sample_name: str,
                opt_level: str) -> ScanReport:
    """扫描单个二进制——同时运行原始和增强过滤器"""
    instructions = disassemble_instructions(binary_path)
    if not instructions:
        return ScanReport(
            sample_name=sample_name, opt_level=opt_level,
            original_confirmed=0, original_likely=0, original_filtered=0,
            original_time_ms=0, enhanced_confirmed=0, enhanced_likely=0,
            enhanced_filtered=0, enhanced_time_ms=0,
            is_true_positive=is_vuln_sample(sample_name),
            original_detected=False, enhanced_detected=False,
            original_fp=False, enhanced_fp=False,
            original_fn=False, enhanced_fn=False,
            error="Disassembly failed")

    funcs = extract_function_instructions(instructions)

    orig_c, orig_l, orig_f, orig_t = 0, 0, 0, 0
    enh_c, enh_l, enh_f, enh_t = 0, 0, 0, 0

    for fname, finstrs in funcs:
        if len(finstrs) < 3:
            continue
        bb = [(0, len(finstrs))]
        cfg = [(0, 0)]

        oc, ol, of_, ot = run_original_filter(finstrs, fname)
        orig_c += oc; orig_l += ol; orig_f += of_; orig_t += ot

        ec, el, ef_, et = run_enhanced_filter(finstrs, bb, cfg, fname)
        enh_c += ec; enh_l += el; enh_f += ef_; enh_t += et

    is_vuln = is_vuln_sample(sample_name)
    orig_detected = (orig_c + orig_l) > 0
    enh_detected = (enh_c + enh_l) > 0

    return ScanReport(
        sample_name=sample_name, opt_level=opt_level,
        original_confirmed=orig_c, original_likely=orig_l,
        original_filtered=orig_f, original_time_ms=orig_t,
        enhanced_confirmed=enh_c, enhanced_likely=enh_l,
        enhanced_filtered=enh_f, enhanced_time_ms=enh_t,
        is_true_positive=is_vuln,
        original_detected=orig_detected,
        enhanced_detected=enh_detected,
        original_fp=orig_detected and not is_vuln,
        enhanced_fp=enh_detected and not is_vuln,
        original_fn=not orig_detected and is_vuln,
        enhanced_fn=not enh_detected and is_vuln,
    )


def scan_all() -> List[ScanReport]:
    """扫描build/目录下所有编译好的二进制"""
    results = []
    binaries = list(BUILD_DIR.rglob("target"))
    if not binaries:
        print("No compiled binaries found. Run compile_samples.py first.")
        return results

    for binary in sorted(binaries):
        # 解析路径: build/SAMPLE_NAME/O0/target
        parts = binary.relative_to(BUILD_DIR).parts
        if len(parts) >= 2:
            sample_name = parts[0]
            opt_level = parts[1] if len(parts) > 1 else "O0"
        else:
            sample_name = binary.parent.name
            opt_level = "O0"

        print(f"  Scanning: {sample_name} [{opt_level}]")
        report = scan_binary(str(binary), sample_name, opt_level)
        results.append(report)

        status = "DETECTED" if report.enhanced_detected else "CLEAN"
        print(f"    Original: {report.original_confirmed}C/{report.original_likely}L "
              f"| Enhanced: {report.enhanced_confirmed}C/{report.enhanced_likely}L "
              f"→ {status}")

    return results


def main():
    print("Running heap overflow scan on compiled binaries...")
    results = scan_all()

    if results:
        with open(RESULTS_FILE, 'w') as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"\nResults saved to {RESULTS_FILE}")

        # 简要统计
        tp_samples = [r for r in results if r.is_true_positive]
        fp_samples = [r for r in results if not r.is_true_positive]

        if tp_samples:
            orig_recall = sum(1 for r in tp_samples if r.original_detected) / len(tp_samples)
            enh_recall = sum(1 for r in tp_samples if r.enhanced_detected) / len(tp_samples)
            print(f"Original recall: {orig_recall:.1%} | Enhanced recall: {enh_recall:.1%}")

        if fp_samples:
            orig_fpr = sum(1 for r in fp_samples if r.original_fp) / len(fp_samples)
            enh_fpr = sum(1 for r in fp_samples if r.enhanced_fp) / len(fp_samples)
            print(f"Original FPR: {orig_fpr:.1%} | Enhanced FPR: {enh_fpr:.1%}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
