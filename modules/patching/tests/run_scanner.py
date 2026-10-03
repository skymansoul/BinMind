# 扫描调度模块 — 对每个编译好的样本运行堆溢出检测
"""扫描调度模块: 对编译后的binary运行BinMind堆溢出检测，收集结构化结果。

独立于compile_samples和collect_results，通过中间JSON文件通信。
用法:
  python tests/run_scanner.py              # 扫描所有样本
  python tests/run_scanner.py --sample CVE-2021-3156  # 扫描单个
"""

import os, sys, json, time, subprocess, argparse

SAMPLE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_samples")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results")


def disassemble_binary(binary_path: str) -> list:
    """用objdump反汇编binary，返回行列表。"""
    try:
        r = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            capture_output=True, text=True, timeout=30)
        lines = r.stdout.split('\n') if r.returncode == 0 else []
    except FileNotFoundError:
        # objdump不可用，尝试用python直接读rodata+text段
        lines = _fallback_disasm(binary_path)
    except Exception:
        lines = []
    # 规范化MinGW <addr> <func> 调用格式与操作数大小写
    try:
        from src.asm_normalize import normalize_asm_lines
        return normalize_asm_lines(lines)
    except ImportError:
        return lines


def _fallback_disasm(binary_path: str) -> list:
    """objdump不可用时的回退方案——用capstone尝试。"""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        with open(binary_path, 'rb') as f:
            code = f.read()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        lines = []
        # 粗略扫描: 尝试从ELF入口附近开始
        offset = 0x1000
        for i in md.disasm(code[offset:offset + 0x10000], offset):
            lines.append(f"  {i.address:x}: {i.mnemonic} {i.op_str}")
        return lines
    except ImportError:
        return []
    except Exception:
        return []


def detect_vulns_in_binary(binary_path: str, sample_name: str) -> dict:
    """对单个binary运行堆溢出检测。"""
    t0 = time.time()

    result = {
        'sample': sample_name,
        'binary': binary_path,
        'tool': 'BinMind',
        'vuln_type': 'heap_overflow',
        'detected': False,
        'findings_count': 0,
        'tp_count': 0,
        'fp_count': 0,
        'uncertain_count': 0,
        'fp_reduction_pct': 0.0,
        'phase_contributions': {},
        'time_secs': 0,
        'error': None,
    }

    try:
        asm_lines = disassemble_binary(binary_path)
        if not asm_lines:
            result['error'] = 'disassembly failed'
            result['time_secs'] = round(time.time() - t0, 2)
            return result

        # 尝试使用集成的堆溢出检测器
        from src.heap_overflow_detector import HeapOverflowDetector
        detector = HeapOverflowDetector()
        report = detector.detect(asm_lines, function_name=sample_name)

        result['detected'] = report.true_positives > 0
        result['findings_count'] = report.total_findings
        result['tp_count'] = report.true_positives
        result['fp_count'] = report.false_positives
        result['uncertain_count'] = report.uncertain
        result['fp_reduction_pct'] = report.fp_reduction_pct
        result['phase_contributions'] = report.phase_contributions

        # 导出详细findings
        result['details'] = report.to_dict()

    except ImportError as e:
        # 模块不可用时回退到基础检测逻辑
        result['error'] = f'import error: {e}'
        vulns = _basic_vuln_scan(asm_lines)
        result['detected'] = len(vulns) > 0
        result['findings_count'] = len(vulns)
        result['tp_count'] = len(vulns)
        result['details'] = {'vulns': vulns}

    except Exception as e:
        result['error'] = str(e)[:200]

    result['time_secs'] = round(time.time() - t0, 2)
    return result


def _basic_vuln_scan(asm_lines: list) -> list:
    """基础漏洞扫描（回退方案）。检查malloc+memcpy模式。"""
    import re
    vulns = []
    for i, line in enumerate(asm_lines):
        if not re.search(r'call.*malloc', line, re.I):
            continue
        for j in range(i, min(i + 20, len(asm_lines))):
            if re.search(r'call.*memcpy', asm_lines[j], re.I):
                vulns.append({
                    'alloc_line': i, 'write_line': j,
                    'type': 'heap_overflow_suspect',
                })
                break
    return vulns


def scan_all(sample_filter: str = None) -> list:
    """扫描所有样本（或过滤指定样本）。"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results = []

    for d in sorted(os.listdir(SAMPLE_ROOT)):
        if sample_filter and sample_filter not in d:
            continue
        sample_dir = os.path.join(SAMPLE_ROOT, d)
        if not os.path.isdir(sample_dir):
            continue

        # 优先用debug版
        binary = os.path.join(sample_dir, "vuln_debug")
        if not os.path.isfile(binary):
            binary = os.path.join(sample_dir, "vuln_debug.exe")
        if not os.path.isfile(binary):
            # 尝试release版
            binary = os.path.join(sample_dir, "vuln_release")
        if not os.path.isfile(binary):
            continue

        print(f"  Scanning {d}...")
        result = detect_vulns_in_binary(binary, d)
        results.append(result)

        # 写单个结果文件
        out_path = os.path.join(OUTPUT_DIR, f"{d}.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    # 写汇总
    summary_path = os.path.join(OUTPUT_DIR, "scan_summary.json")
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump({
            'total_samples': len(results),
            'successful_scans': sum(1 for r in results if not r.get('error')),
            'detected_count': sum(1 for r in results if r.get('detected')),
            'results': [{k: r[k] for k in ['sample', 'detected', 'tp_count',
                         'fp_count', 'time_secs', 'error']} for r in results],
        }, f, indent=2, ensure_ascii=False)

    return results


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sample", help="Scan only matching sample dir")
    args = p.parse_args()
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    results = scan_all(args.sample)
    print(f"\nScanned {len(results)} samples. Results in {OUTPUT_DIR}/")
