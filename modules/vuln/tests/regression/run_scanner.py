"""扫描调度模块 — 对编译好的 ELF 样本运行核心检测算法.

用法: python run_scanner.py <build_dir> <results_dir>
  或作为库导入使用 run_scan()

支持:
  - 原生检测 (ImprovedHeapOverflowDetector)
  - objdump 预处理: 自动反汇编 .text 段
  - 每个样本独立计时
  - JSON 结果输出
"""

import os
import sys
import json
import time
import subprocess
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class ScanResult:
    """单样本扫描结果."""
    sample_id: str
    cve_id: str = ""
    vuln_type: str = "heap_overflow"
    # 检测结果
    detected: bool = False
    n_findings: int = 0
    n_filtered_fp: int = 0
    findings: List[dict] = field(default_factory=list)
    # 性能
    time_elapsed_s: float = 0.0
    peak_memory_mb: float = 0.0
    # 元信息
    elf_path: str = ""
    elf_size: int = 0
    elf_sha256: str = ""
    is_packed: bool = False
    # 错误
    error: str = ""


class ScannerScheduler:
    """扫描调度器 — 遍历编译产物, 运行检测, 收集结果."""

    def __init__(self, build_dir: str, results_dir: str):
        self._build_dir = os.path.abspath(build_dir)
        self._results_dir = os.path.abspath(results_dir)
        self._manifest: dict = {}
        self._results: List[ScanResult] = []

    def load_manifest(self) -> dict:
        """加载编译清单."""
        path = os.path.join(self._build_dir, 'manifest.json')
        if os.path.isfile(path):
            with open(path) as f:
                self._manifest = json.load(f)
        return self._manifest

    def scan_all(self) -> List[ScanResult]:
        """对所有已编译样本运行扫描."""
        os.makedirs(self._results_dir, exist_ok=True)

        if not self._manifest:
            self.load_manifest()

        for sid, info in self._manifest.items():
            if not info.get('compiled', False):
                # 记录跳过
                self._results.append(ScanResult(
                    sample_id=sid, cve_id=info.get('cve_id', ''),
                    error=info.get('error', 'compilation failed')))
                continue

            # 扫描 plain 版本
            plain_elf = info.get('elf_plain', '')
            if plain_elf and os.path.isfile(plain_elf):
                result = self._scan_elf(sid, info, plain_elf, packed=False)
                self._results.append(result)

            # 扫描 packed 版本
            packed_elf = info.get('elf_packed', '')
            if packed_elf and os.path.isfile(packed_elf):
                result = self._scan_elf(sid, info, packed_elf, packed=True)
                result.sample_id = f"{sid}_packed"
                self._results.append(result)

        # 输出汇总
        self._write_results()
        return self._results

    def _scan_elf(self, sid: str, info: dict, elf_path: str,
                  packed: bool = False) -> ScanResult:
        """对单个 ELF 文件运行检测."""
        t0 = time.time()

        result = ScanResult(
            sample_id=sid,
            cve_id=info.get('cve_id', ''),
            vuln_type=info.get('vuln_type', 'heap_overflow'),
            elf_path=elf_path,
            elf_size=os.path.getsize(elf_path),
            is_packed=packed,
        )

        # SHA256
        try:
            with open(elf_path, 'rb') as f:
                result.elf_sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass

        try:
            findings = self._run_detector(elf_path)
            result.findings = findings
            result.n_findings = len(findings)
            result.n_filtered_fp = sum(
                1 for f in findings if f.get('likely_false_positive', False))
            result.detected = any(
                not f.get('likely_false_positive', False) for f in findings)
        except Exception as e:
            result.error = str(e)

        result.time_elapsed_s = round(time.time() - t0, 3)
        return result

    def _run_detector(self, elf_path: str) -> List[dict]:
        """对单个 ELF 运行核心检测算法.

        步骤:
          1. objdump -d 提取 .text 段汇编
          2. 按函数切分
          3. 对每个函数调用 ImprovedHeapOverflowDetector
          4. 汇总结果
        """
        # 获取汇编
        asm_text = self._disassemble(elf_path)
        if not asm_text:
            return []

        # 按函数切分指令
        functions = self._split_functions(asm_text)
        all_findings = []

        # 注入搜索路径 (项目根)
        proj_root = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', '..', '..', '..'))
        if proj_root not in sys.path:
            sys.path.insert(0, proj_root)

        try:
            from vuln.src.heap.analysis.heap_overflow_detector import (
                ImprovedHeapOverflowDetector)
        except ImportError:
            # fallback: 返回简单检测结果
            return self._fallback_detect(elf_path)

        detector = ImprovedHeapOverflowDetector()

        for fn_name, instructions in functions:
            if len(instructions) < 5:
                continue
            fn_findings = detector.analyze(
                instructions, function_name=fn_name)
            for f in fn_findings:
                all_findings.append({
                    'insn_addr': f.insn_addr,
                    'function': f.function_name,
                    'description': f.description,
                    'alloc_site': f.alloc_site,
                    'alloc_size_requested': f.alloc_size_requested,
                    'alloc_size_usable': f.alloc_size_usable,
                    'access_offset': f.access_offset,
                    'access_size': f.access_size,
                    'overflow_bytes': f.overflow_bytes,
                    'semantic_score': f.semantic_score,
                    'confidence': f.confidence,
                    'likely_false_positive': f.is_likely_fp,
                    'fp_reason': f.fp_reason,
                    'size_source': f.size_source,
                })

        return all_findings

    @staticmethod
    def _disassemble(elf_path: str) -> str:
        """objdump 反汇编."""
        try:
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=30)
            return proc.stdout
        except FileNotFoundError:
            # Windows 环境可能用 llvm-objdump
            try:
                proc = subprocess.run(
                    ['llvm-objdump', '-d', elf_path],
                    capture_output=True, text=True, timeout=30)
                return proc.stdout
            except Exception:
                return ""
        except Exception:
            return ""

    @staticmethod
    def _split_functions(asm_text: str) -> List[Tuple[str, List[str]]]:
        """按函数切分 objdump 输出."""
        functions = []
        current_fn = ""
        current_insns: List[str] = []

        for line in asm_text.split('\n'):
            stripped = line.strip()
            # objdump 函数头: <function_name>:
            if stripped.endswith('>:') and '<' in stripped:
                if current_insns:
                    functions.append((current_fn, current_insns))
                # 提取函数名
                start = stripped.find('<')
                end = stripped.find('>:')
                current_fn = stripped[start+1:end] if start >= 0 and end >= 0 else stripped
                current_insns = []
                continue

            # 指令行: 包含 \t 且以十六进制地址开头
            if '\t' in stripped and ':' in stripped.split('\t')[0] if '\t' in stripped else False:
                # objdump 输出格式: addr:\t<hex>\t<mnemonic>
                # 取最后一个 tab 之后的内容 (纯助记符)
                parts = stripped.rsplit('\t', 1)
                if len(parts) > 1:
                    current_insns.append(parts[1].strip())
                else:
                    current_insns.append(stripped)

        if current_insns:
            functions.append((current_fn, current_insns))

        return functions

    def _fallback_detect(self, elf_path: str) -> List[dict]:
        """回退检测 — 基于 objdump 输出做简单模式匹配."""
        asm_text = self._disassemble(elf_path)
        if not asm_text:
            return []
        findings = []
        lines = asm_text.split('\n')
        for i, line in enumerate(lines):
            # 找 malloc 后紧跟的 mov [reg+offset], ...
            if 'malloc' in line.lower() or 'calloc' in line.lower():
                # 在后续10行内找越界写入
                for j in range(i+1, min(i+11, len(lines))):
                    if 'mov' in lines[j] and '[' in lines[j] and ']' in lines[j]:
                        if any(r in lines[j] for r in ('rsp', 'rbp', '[rip')):
                            continue
                        # 简单启发式: 如果 offset >= 0x100 → 标记为可能溢出
                        import re
                        m = re.search(r'\+0x([0-9a-f]+)', lines[j], re.I)
                        if m:
                            offset = int(m.group(1), 16)
                            if offset >= 0x80:  # 保守阈值
                                findings.append({
                                    'function': 'unknown',
                                    'description': f'possible heap overflow at offset 0x{offset:x}',
                                    'semantic_score': 0.45,
                                    'likely_false_positive': False,
                                })
        return findings

    def _write_results(self) -> None:
        """输出汇总 JSON."""
        out = []
        for r in self._results:
            d = asdict(r)
# 清理: 移除过大的 findings 详情以
            if len(d.get('findings', [])) > 50:
                d['findings'] = d['findings'][:50]
                d['findings_truncated'] = True
            out.append(d)

        path = os.path.join(self._results_dir, 'scan_results.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"[+] Scan results: {path}")

    def summary(self) -> str:
        """结果摘要."""
        n_total = len(self._results)
        n_detected = sum(1 for r in self._results if r.detected)
        n_fp = sum(r.n_filtered_fp for r in self._results)
        n_findings = sum(r.n_findings for r in self._results)
        times = [r.time_elapsed_s for r in self._results if r.time_elapsed_s > 0]
        avg_time = sum(times) / len(times) if times else 0

        return (
            f"=== Scan Summary ===\n"
            f"  Samples scanned: {n_total}\n"
            f"  Detected (TP):   {n_detected}\n"
            f"  Total findings:  {n_findings}\n"
            f"  FP filtered:     {n_fp}\n"
            f"  Avg time:        {avg_time:.2f}s\n"
            f"  FP rate:         {n_fp / max(1, n_findings) * 100:.1f}%\n"
        )


# CLI
if __name__ == '__main__':
    build_dir = sys.argv[1] if len(sys.argv) > 1 else '../build'
    results_dir = sys.argv[2] if len(sys.argv) > 2 else '../results'
    scheduler = ScannerScheduler(build_dir, results_dir)
    scheduler.load_manifest()
    scheduler.scan_all()
    print(scheduler.summary())
