# coding: utf-8
# 创建: 2026-08-10  |  扫描调度——调用检测器对编译后的ELF样本执行漏洞检测
#
"""
扫描调度模块——加载编译后样本，调用检测管线，收集原始输出。
"""

import os
import sys
import json
import time
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ScanResult:
    sample_name: str
    cve_id: str
    vuln_type: str
    # 检测结果
    detected: bool
    confidence: float = 0.0
    findings: List[Dict] = field(default_factory=list)
    # 性能
    elapsed_ms: float = 0.0
    peak_memory_mb: float = 0.0
    # 元数据
    error: str = ""


class ScanRunner:
    """扫描调度器——从编译后的样本目录加载ELF，调用核心检测器。"""

    def __init__(self, project_root: str = None):
        if project_root is None:
            project_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self._root = project_root

    def scan(self, binary_path: str, sample_meta: dict
              ) -> ScanResult:
        """对单个ELF二进制执行检测管线。

        当前管线: 反汇编→堆溢出检测+UAF检测+格式化字符串检测
        """
        t0 = time.time()
        result = ScanResult(
            sample_name=os.path.basename(binary_path),
            cve_id=sample_meta.get('cve_id', ''),
            vuln_type=sample_meta.get('vuln_type', ''))

        try:
            # 反汇编——调用objdump提取指令
            disasm = self._disassemble(binary_path)
            if not disasm:
                result.error = "反汇编失败"
                return result

            # 按函数分组指令
            func_insns = self._group_by_function(disasm)

            # 对每个函数调用检测器
            all_findings = []
            for func_name, insns in func_insns.items():
                findings = self._run_detectors(func_name, insns)
                all_findings.extend(findings)

            result.findings = all_findings
            result.detected = len(all_findings) > 0
            if all_findings:
                result.confidence = max(
                    f.get('confidence', 0.0) for f in all_findings)

        except Exception as e:
            result.error = str(e)

        result.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return result

    def _disassemble(self, binary_path: str) -> str:
        """调用objdump反汇编二进制。"""
        try:
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', binary_path],
                capture_output=True, text=True, timeout=30)
            return proc.stdout if proc.returncode == 0 else ''
        except Exception:
            # objdump不可用时回退——加载预生成的反汇编
            return ''

    def _group_by_function(self, disasm: str) -> Dict[str, List[str]]:
        """将反汇编输出按函数分组。"""
        funcs = {}
        current_func = None
        for line in disasm.split('\n'):
            stripped = line.strip()
            # 匹配函数标签: <function_name>:
            if stripped.endswith('>:') and '<' in stripped:
                m_start = stripped.find('<')
                m_end = stripped.find('>')
                if m_start >= 0 and m_end > m_start:
                    current_func = stripped[m_start + 1:m_end]
                    funcs[current_func] = []
                    continue
            if current_func and stripped:
                funcs[current_func].append(stripped)
        return funcs

    def _run_detectors(self, func_name: str,
                        insns: List[str]) -> List[Dict]:
        """对单函数运行三个核心检测器。"""
        findings = []
        try:
            from modules.vuln.detection.heap_overflow_detector import (
                detect_heap_overflow)
            # 尝试提取常量(简化: 扫描立即数)
            constants = {}
            for insn in insns:
                import re
                if 'mov' in insn.lower():
                    m = re.search(
                        r'mov\s+\w+,\s*(?:0x)?(\d+)', insn, re.IGNORECASE)
                    if m:
                        constants[insn.split(',')[0].split()[-1].strip()
                                   ] = int(m.group(1))

            ho = detect_heap_overflow(insns, constants)
            for f in ho:
                findings.append({
                    'type': 'heap_overflow',
                    'function': func_name,
                    'confidence': 0.85 if f.confidence == 'confirmed' else 0.5,
                    'detail': str(f),
                })
        except ImportError:
            pass

        try:
            from modules.vuln.detection.uaf_detector import detect_uaf
            uaf = detect_uaf(insns)
            for f in uaf:
                findings.append({
                    'type': 'uaf',
                    'function': func_name,
                    'confidence': 0.8 if f.confidence == 'confirmed' else 0.5,
                    'detail': str(f),
                })
        except ImportError:
            pass

        try:
            from modules.vuln.detection.format_string_detector import (
                FormatStringDetector)
            fmt = FormatStringDetector().detect(insns, func_name)
            for f in fmt:
                findings.append({
                    'type': 'format_string',
                    'function': func_name,
                    'confidence': f.confidence,
                    'detail': str(f.evidence),
                })
        except ImportError:
            pass

        return findings

    def scan_all(self, build_dir: str,
                  sample_metas: List[Any]) -> List[ScanResult]:
        """批量扫描编译后的所有样本。"""
        results = []
        for meta in sample_metas:
            if not meta.compile_success:
                results.append(ScanResult(
                    sample_name=meta.cve_id, cve_id=meta.cve_id,
                    vuln_type=meta.vuln_type,
                    error=f'编译失败: {meta.compile_error}'))
                continue

            r = self.scan(meta.binary_path, {
                'cve_id': meta.cve_id,
                'vuln_type': meta.vuln_type,
            })
            results.append(r)
            status = "FOUND" if r.detected else "MISSED"
            print(f"  [{r.cve_id}] {status} ({r.elapsed_ms:.0f}ms)")

        return results


if __name__ == '__main__':
    build_dir = sys.argv[1] if len(sys.argv) > 1 else 'tests/build'
    runner = ScanRunner()
    # 简化：直接扫描build目录下所有ELF
    results = []
    for f in sorted(os.listdir(build_dir)):
        path = os.path.join(build_dir, f)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            r = runner.scan(path, {'cve_id': f, 'vuln_type': 'unknown'})
            results.append(r)
            print(f"  [{f}] {'FOUND' if r.detected else 'MISSED'}")
