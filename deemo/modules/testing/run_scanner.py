"""扫描调度模块 — 对编译好的测试样本运行堆溢出检测.

支持两种模式:
  1. import 模式 (默认): 直接导入检测器类, 通过 Python API 调用
  2. subprocess 模式: 通过命令行调用外部扫描脚本

检测器列表:
  - heap_overflow: 现有 AAVSA 管线 (Ptmalloc2 + VSA + Controllability)
  - ppahav: PPA-HAV 增强管线 (Provenance + ObjectModel + Validation)
  - taint: 轻量级污点传播 (TaintTracker)
  - format_string: 格式化字符串检测
  - uaf: UAF/Double-Free 检测

输出: 每个样本每个检测器的检测结果 JSON
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ScanResult:
    sample_name: str
    detector: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str = ""
    # 统计
    n_heap_overflow: int = 0
    n_uaf: int = 0
    n_format_string: int = 0
    n_integer_overflow: int = 0
    n_total: int = 0


class BinaryScanner:
    """二进制扫描器 — 调度多个检测器对 ELF 执行静态分析.

    当前实现使用 radare2 + Python 检测管线.
    若 r2 不可用, 回退到基于 objdump 的轻量级分析.
    """

    def __init__(self, use_ppahav: bool = True):
        self._use_ppahav = use_ppahav
        self._r2_available = self._check_r2()

    @staticmethod
    def _check_r2() -> bool:
        try:
            subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, binary_path: str, sample_name: str) -> List[ScanResult]:
        """扫描单个二进制文件, 返回所有检测器的结果."""
        if not os.path.isfile(binary_path):
            return [ScanResult(sample_name=sample_name, detector="all",
                              error=f"binary not found: {binary_path}")]

        results = []

        # 检测器1: 基于 objdump 的堆操作检测 (基础)
        t0 = time.perf_counter()
        heap_findings = self._scan_heap_operations(binary_path)
        elapsed = (time.perf_counter() - t0) * 1000
        sr = ScanResult(sample_name=sample_name, detector="heap_ops",
                        findings=heap_findings, elapsed_ms=elapsed)
        sr.n_heap_overflow = len([f for f in heap_findings
                                  if f.get("type") == "heap_overflow"])
        sr.n_total = len(heap_findings)
        results.append(sr)

        # 检测器2: 基于符号的污点追踪 (若 r2 可用)
        if self._r2_available:
            t0 = time.perf_counter()
            taint_findings = self._scan_taint_r2(binary_path)
            elapsed = (time.perf_counter() - t0) * 1000
            sr2 = ScanResult(sample_name=sample_name, detector="taint_r2",
                            findings=taint_findings, elapsed_ms=elapsed)
            sr2.n_format_string = len([f for f in taint_findings
                                      if f.get("type") == "format_string"])
            sr2.n_total = len(taint_findings)
            results.append(sr2)

        # 检测器3: PPA-HAV 二进制级检测 (objdump → 真实五层管线)
        if self._use_ppahav:
            t0 = time.perf_counter()
            ppa_findings = self._scan_ppahav_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr3 = ScanResult(sample_name=sample_name, detector="ppahav",
                            findings=ppa_findings, elapsed_ms=elapsed)
            sr3.n_heap_overflow = len([f for f in ppa_findings
                                       if f.get("type") == "heap_overflow"])
            sr3.n_uaf = len([f for f in ppa_findings
                            if f.get("type") in ("uaf", "use_after_free", "double_free")])
            sr3.n_format_string = len([f for f in ppa_findings
                                       if f.get("type") == "format_string"])
            sr3.n_integer_overflow = len([f for f in ppa_findings
                                          if f.get("type") == "integer_overflow"])
            sr3.n_total = len(ppa_findings)
            results.append(sr3)

        # 检测器4: PPA-HAV 源码级启发式 ([DEPRECATED] 保留作为对照基线)
        if self._use_ppahav:
            t0 = time.perf_counter()
            src_findings = self._scan_ppahav_heuristic(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr4 = ScanResult(sample_name=sample_name, detector="ppahav_src",
                            findings=src_findings, elapsed_ms=elapsed)
            sr4.n_heap_overflow = len([f for f in src_findings
                                       if f.get("type") == "heap_overflow"])
            sr4.n_uaf = len([f for f in src_findings
                            if f.get("type") in ("uaf", "use_after_free", "double_free")])
            sr4.n_format_string = len([f for f in src_findings
                                       if f.get("type") == "format_string"])
            sr4.n_integer_overflow = len([f for f in src_findings
                                          if f.get("type") == "integer_overflow"])
            sr4.n_total = len(src_findings)
            results.append(sr4)

        # 检测器5: 抽象解释引擎 (objdump → 逐指令值集分析 → 判定)
        if self._use_ppahav:
            t0 = time.perf_counter()
            absint_findings = self._scan_absint_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr5 = ScanResult(sample_name=sample_name, detector="absint",
                            findings=absint_findings, elapsed_ms=elapsed)
            sr5.n_heap_overflow = len([f for f in absint_findings
                                       if f.get("type") == "heap_overflow"])
            sr5.n_uaf = len([f for f in absint_findings
                            if f.get("type") in ("uaf", "use_after_free")])
            sr5.n_format_string = len([f for f in absint_findings
                                       if f.get("type") == "format_string"])
            sr5.n_total = len(absint_findings)
            results.append(sr5)

        # 检测器6: 二进制 UAF 扫描器
        if self._use_ppahav:
            t0 = time.perf_counter()
            uaf_findings = self._scan_uaf_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr6 = ScanResult(sample_name=sample_name, detector="uaf_binary",
                            findings=uaf_findings, elapsed_ms=elapsed)
            sr6.n_uaf = len([f for f in uaf_findings
                            if f.get("type") in ("uaf", "use_after_free",
                                                  "double_free")])
            sr6.n_heap_overflow = len([f for f in uaf_findings
                                       if f.get("type") == "heap_overflow"])
            sr6.n_total = len(uaf_findings)
            results.append(sr6)

        # 检测器7: 二进制格式字符串扫描器
        if self._use_ppahav:
            t0 = time.perf_counter()
            fmt_findings = self._scan_fmt_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr7 = ScanResult(sample_name=sample_name, detector="fmt_binary",
                            findings=fmt_findings, elapsed_ms=elapsed)
            sr7.n_format_string = len([f for f in fmt_findings
                                        if f.get("type") == "format_string"])
            sr7.n_total = len(fmt_findings)
            results.append(sr7)

        # 检测器8: 二进制整数溢出扫描器 (I-GUARD)
        if self._use_ppahav:
            t0 = time.perf_counter()
            io_findings = self._scan_int_overflow_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr8 = ScanResult(sample_name=sample_name, detector="int_overflow_binary",
                            findings=io_findings, elapsed_ms=elapsed)
            sr8.n_integer_overflow = len([f for f in io_findings
                                          if f.get("type") == "integer_overflow"])
            sr8.n_heap_overflow = len([f for f in io_findings
                                        if f.get("type") == "heap_overflow"])
            sr8.n_total = len(io_findings)
            results.append(sr8)

        # 检测器9: GIVA — 溯源门控写入界验证 (PG-WBV 误报抑制管线)
        if self._use_ppahav:
            t0 = time.perf_counter()
            giva_findings = self._scan_giva_binary(binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr9 = ScanResult(sample_name=sample_name, detector="giva",
                            findings=giva_findings, elapsed_ms=elapsed)
            sr9.n_heap_overflow = len([f for f in giva_findings
                                       if f.get("type") == "heap_overflow"])
            sr9.n_total = len(giva_findings)
            results.append(sr9)

        # 检测器10: UAF-FPMIN — UAF 误报融合抑制 (S1-S7 证据过滤)
        if self._use_ppahav:
            t0 = time.perf_counter()
            fpmin_findings = self._scan_uaf_fpmin_binary(
                binary_path, sample_name)
            elapsed = (time.perf_counter() - t0) * 1000
            sr10 = ScanResult(sample_name=sample_name, detector="uaf_fpmin",
                             findings=fpmin_findings, elapsed_ms=elapsed)
            sr10.n_uaf = len([f for f in fpmin_findings
                              if f.get("type") in ("uaf", "use_after_free",
                                                   "double_free")])
            sr10.n_total = len(fpmin_findings)
            results.append(sr10)

        return results

    @staticmethod
    def _objdump_txt(binary_path: str) -> Optional[str]:
        try:
            return subprocess.run(
                ["objdump", "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=30).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def _scan_ppahav_binary(self, binary_path: str,
                             sample_name: str) -> List[dict]:
        """PPA-HAV 二进制级检测 — objdump 反汇编 → 五层过滤管线.

        与 _scan_ppahav_heuristic 的本质区别:
          不读取源码, 仅基于反汇编指令做指针溯源+对象建模+三维验证.
        """
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        # 导入 PPA-HAV 二进制扫描器
        try:
            # deemo 根目录: __file__ → testing/ → modules/ → deemo/
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.heap_analysis.binary_ppahav_scanner import (
                BinaryPpahavScanner)
        except ImportError as e:
            return self._scan_heap_operations_findings(binary_path, str(e))

        # 解析函数边界用于 func 字段
        try:
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
            funcs = InstructionParser.parse_functions(txt)
        except ImportError:
            funcs = {}

        scanner = BinaryPpahavScanner()
        result = scanner.scan(txt, sample_name, user_code_only=True)

        findings = []
        for v in result.real_vulnerabilities:
            addr = v.get("insn_addr", 0)
            findings.append({
                "type": v.get("type", "heap_overflow"),
                "subtype": v.get("subtype", ""),
                "address": hex(addr),
                "func": InstructionParser.resolve_function(addr, funcs)
                        or "?",
                "reason": v.get("reason", ""),
                "confidence": v.get("confidence", 0.0),
                "alloc_size": v.get("alloc_size", 0),
                "write_size": v.get("write_size", 0),
                "usable_size": v.get("usable_size", 0),
                "source": "binary_ppahav",
            })
        return findings

    def _scan_absint_binary(self, binary_path: str,
                             sample_name: str) -> List[dict]:
        """抽象解释引擎 — objdump → 逐指令值集分析 → 堆越界判定.

        与 binary_ppahav_scanner 的区别:
          absint 在每条指令上追踪寄存器值集, 发现通过指针算术的
          直接写入 (mov [reg+off]), 而非仅依赖 call memcpy 模式.
        """
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.heap_analysis.instruction_parser import \
                InstructionParser
            from modules.analysis.static.heap_analysis.absint_engine import \
                AbstractInterpreter
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"absint import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)
        insns = InstructionParser.parse(txt)
        user_insns = InstructionParser.filter_user_instructions(insns, funcs)

        engine = AbstractInterpreter()
        engine.feed_instructions(user_insns)
        engine.set_functions(funcs)
        real, filtered = engine.analyze_all()

        findings = []
        for v in real:
            addr = v.get("insn_addr", 0)
            findings.append({
                "type": v.get("type", "heap_overflow"),
                "subtype": v.get("subtype", "absint"),
                "address": hex(addr),
                "func": InstructionParser.resolve_function(addr, funcs)
                        or "?",
                "reason": v.get("reason", ""),
                "confidence": v.get("confidence", 0.0),
                "alloc_size": v.get("alloc_size", 0),
                "write_size": v.get("write_size", 0),
                "usable_size": v.get("usable_size", 0),
                "source": "absint",
            })
        return findings

    def _scan_uaf_binary(self, binary_path: str,
                          sample_name: str) -> List[dict]:
        """二进制 UAF 扫描器 — objdump → free 追踪 → 释放后使用检测."""
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.uaf_analysis.binary_uaf_scanner import \
                BinaryUafScanner
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"uaf scanner import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)

        scanner = BinaryUafScanner()
        findings = scanner.scan(txt, sample_name, user_code_only=True)

        for f in findings:
            f["source"] = "binary_uaf"
            # 使用 insn_addr (int), 回退 address (hex str)
            addr = f.get("insn_addr", f.get("address", 0))
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            f["func"] = InstructionParser.resolve_function(
                addr, funcs) or "?"
        return findings

    def _scan_fmt_binary(self, binary_path: str,
                          sample_name: str) -> List[dict]:
        """二进制格式字符串扫描器 — objdump → printf 调用 → 格式字符串来源分析."""
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.format_string_analysis.binary_fmt_scanner import \
                BinaryFmtScanner
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"fmt scanner import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)

        scanner = BinaryFmtScanner()
        findings = scanner.scan(txt, sample_name, user_code_only=True,
                                binary_path=binary_path)

        for f in findings:
            f["type"] = "format_string"
            f["source"] = "binary_fmt"
            # 使用 insn_addr (int), 回退 address (hex str)
            addr = f.get("insn_addr", f.get("address", 0))
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            f["func"] = InstructionParser.resolve_function(
                addr, funcs) or "?"
        return findings

    def _scan_giva_binary(self, binary_path: str,
                           sample_name: str) -> List[dict]:
        """GIVA 检测 — objdump → 抽象解释 + 溯源门控写入界验证.

        与 absint 的关系: 同一引擎中间数据, 增加三层误报抑制
        (分配归属 / 写入大小界定 / 循环界分析), 输出低误报判定.
        """
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.heap_analysis.giva_detector import \
                GivaScanner
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"giva scanner import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)
        scanner = GivaScanner(binary_path=binary_path)
        res = scanner.scan(txt, sample_name)

        findings = []
        for v in res.get("real", []):
            addr = v.get("insn_addr", 0)
            findings.append({
                "type": "heap_overflow",
                "subtype": v.get("subtype", "giva"),
                "address": hex(addr),
                "func": InstructionParser.resolve_function(addr, funcs)
                        or "?",
                "reason": v.get("reason", ""),
                "confidence": v.get("confidence", 0.0),
                "alloc_size": v.get("alloc_size", 0),
                "write_size": v.get("write_size", 0),
                "usable_size": v.get("usable_size", 0),
                "source": "giva",
            })
        return findings

    def _scan_uaf_fpmin_binary(self, binary_path: str,
                                sample_name: str) -> List[dict]:
        """UAF-FPMIN 检测 — BinaryUafScanner + S1-S7 误报抑制.

        与 uaf_binary 的关系: 同一原始 findings, 增加证据过滤
        (无害传递/分支互斥/置空free/伪逃逸/realloc语义/判空守卫/
        陈旧标记), 输出低误报判定.
        """
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.uaf_analysis.uaf_fpmin_scanner import \
                UafFpminScanner
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"uaf fpmin scanner import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)
        scanner = UafFpminScanner(binary_path=binary_path)
        res = scanner.scan(txt, sample_name, user_code_only=True)

        findings = []
        for v in res.get("findings", []):
            addr = v.get("insn_addr", v.get("address", 0))
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            findings.append({
                "type": "uaf",
                "subtype": v.get("subtype", "uaf"),
                "address": hex(addr),
                "func": InstructionParser.resolve_function(addr, funcs)
                        or "?",
                "reason": v.get("reason", ""),
                "confidence": v.get("confidence", 0.0),
                "source": "uaf_fpmin",
            })
        return findings

    def _scan_int_overflow_binary(self, binary_path: str,
                                   sample_name: str) -> List[dict]:
        """二进制整数溢出扫描器 (I-GUARD) — objdump → imul/shl → malloc 检测."""
        txt = self._objdump_txt(binary_path)
        if not txt or not txt.strip():
            return []

        try:
            _proj_root = os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
            if _proj_root not in sys.path:
                sys.path.insert(0, _proj_root)
            from modules.analysis.static.integer_overflow_analysis.binary_int_overflow_scanner import \
                BinaryIntOverflowScanner
            from modules.analysis.static.heap_analysis.instruction_parser import (
                InstructionParser)
        except ImportError as e:
            return [{"type": "meta",
                     "reason": f"int overflow scanner import failed: {e}",
                     "confidence": 0.0}]

        funcs = InstructionParser.parse_functions(txt)

        scanner = BinaryIntOverflowScanner()
        findings = scanner.scan(txt, sample_name, user_code_only=True)

        for f in findings:
            f["type"] = "integer_overflow"
            f["source"] = "binary_i_guard"
            addr = f.get("insn_addr", f.get("address", 0))
            if isinstance(addr, str):
                addr = int(addr, 16) if addr.startswith("0x") else int(addr)
            f["func"] = InstructionParser.resolve_function(
                addr, funcs) or "?"
        return findings

    # [DEPRECATED] 以下方法已被 _scan_ppahav_binary 取代,
    # 保留作为对照基线, 待论文数据收集完成后可移除.
    def _scan_heap_operations_findings(self, binary_path: str,
                                        error: str = "") -> List[dict]:
        """objdump 单独分析 — PPA-HAV 导入失败时的回退."""
        findings = self._scan_heap_operations(binary_path)
        if error:
            findings.append({
                "type": "meta", "reason": f"PPA-HAV import failed: {error}",
                "confidence": 0.0})
        return findings

    # CRT/startup 函数前缀 — heap_ops regex 扫描跳过这些
    _CRT_FUNC_PREFIXES = ('__', '.', '_', 'mingw_', 'deregister', 'register')

    def _scan_heap_operations(self, binary_path: str) -> List[dict]:
        """基于 objdump 的堆操作检测 — 识别 malloc/memcpy/free 模式.
        [DEPRECATED] 精度不足: 不追踪寄存器, 无指针身份验证.
        保留用于与 absint_engine 的对比基线.
        """
        findings = []
        try:
            txt = subprocess.run(
                ["objdump", "-d", binary_path],
                capture_output=True, text=True, timeout=30).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return findings

        lines = txt.split("\n")
        alloc_sites = {}  # addr → (reg, size)
        current_func = ""  # 当前所在函数名 (原始大小写)

        for i, line in enumerate(lines):
            # 追踪函数边界: <function_name>:
            func_match = re.search(r'^[0-9a-f]+\s+<([^>]+)>:$', line)
            if func_match:
                current_func = func_match.group(1).strip()

            # 跳过 CRT/startup 函数内的指令
            if current_func and any(
                    current_func.lower().startswith(p)
                    or current_func.lower() == p
                    for p in self._CRT_FUNC_PREFIXES):
                continue

            # 匹配 call malloc
            if "call" in line and "malloc" in line:
                addr_match = re.search(r'^\s*([0-9a-f]+):', line)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    for j in range(i-1, max(0, i-5), -1):
                        if "edi" in lines[j] or "rdi" in lines[j]:
                            size_match = re.search(
                                r'\$0x([0-9a-f]+)', lines[j])
                            if size_match:
                                size = int(size_match.group(1), 16)
                                alloc_sites[addr] = ("rax", size)
                                break

            # 匹配 call memcpy
            if "call" in line and "memcpy" in line:
                addr_match = re.search(r'^\s*([0-9a-f]+):', line)
                if addr_match:
                    addr = int(addr_match.group(1), 16)
                    for j in range(i-1, max(0, i-5), -1):
                        if "rdx" in lines[j] or "edx" in lines[j]:
                            sz_match = re.search(
                                r'\$0x([0-9a-f]+)', lines[j])
                            if sz_match:
                                copy_sz = int(sz_match.group(1), 16)
                                for malloc_addr, (_, alloc_sz) in sorted(
                                        alloc_sites.items(), reverse=True):
                                    if malloc_addr < addr:
                                        if copy_sz > alloc_sz:
                                            findings.append({
                                                "type": "heap_overflow",
                                                "address": hex(addr),
                                                "func": current_func,
                                                "reason": f"memcpy({copy_sz}) > malloc({alloc_sz})",
                                                "confidence": 0.75,
                                            })
                                        break

            # 匹配 call free → UAF (仅用户函数)
            if "call" in line and "free" in line:
                addr_match = re.search(r'^\s*([0-9a-f]+):', line)
                if addr_match:
                    free_addr = int(addr_match.group(1), 16)
                    findings.append({
                        "type": "potential_uaf",
                        "address": hex(free_addr),
                        "func": current_func,
                        "reason": "pointer freed — check for subsequent use",
                        "confidence": 0.30,
                    })

        return findings

    def _scan_taint_r2(self, binary_path: str) -> List[dict]:
        """基于 radare2 的污点分析 — 识别 printf(user_input) 模式."""
        findings = []
        try:
            # 获取所有 call 指令
            result = subprocess.run(
                ["r2", "-q", "-c", "aa;afl", binary_path],
                capture_output=True, text=True, timeout=30)
            # 检查格式化字符串调用
            funcs = result.stdout.lower()
            for sink in ["printf", "fprintf", "sprintf", "snprintf"]:
                if sink in funcs:
                    # 查找这些函数的交叉引用
                    try:
                        xref = subprocess.run(
                            ["r2", "-q", "-c", f"aa;axt sym.imp.{sink}",
                             binary_path],
                            capture_output=True, text=True, timeout=10)
                        if xref.stdout.strip():
                            for line in xref.stdout.strip().split("\n")[:10]:
                                findings.append({
                                    "type": "format_string",
                                    "function": sink,
                                    "xref": line.strip()[:80],
                                    "confidence": 0.40,
                                })
                    except subprocess.TimeoutExpired:
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return findings

    def _scan_ppahav_heuristic(self, binary_path: str,
                                sample_name: str) -> List[dict]:
        """PPA-HAV 启发式检测 — 结合源码模式 + 二进制模式.

        多维度检测策略:
          - 静态模式匹配: alloc/copy size mismatch, off-by-one, loop bound
          - 来源感知: malloc返回的指针是否被越界写入 (variable-indexed write)
          - 边界检查审计: 判定的上界是否与分配大小一致
        """
        findings = []

        # 读取源码分析样本类型
        src_path = os.path.join(
            os.path.dirname(binary_path), "src", "vuln.c")
        src = ""
        if os.path.isfile(src_path):
            with open(src_path, "r", errors="ignore") as f:
                src = f.read()

        if not src:
            return findings

        # 辅助: 提取 malloc 调用及其分配大小
        import re as _re
        alloc_sizes = []  # [(size_literal_or_var, line_context)]
        for m in _re.finditer(
                r'(?:malloc|calloc)\s*\(\s*([^,)]+(?:,\s*[^)]+)?)\s*\)', src):
            size_expr = m.group(1).strip()
            try:
                sz = int(size_expr)
                alloc_sizes.append((sz, size_expr))
            except ValueError:
                alloc_sizes.append((None, size_expr))

        # 辅助: 判断参数是否来自用户输入
        def _is_user_controlled(var_expr: str) -> bool:
            """检查表达式是否可能来自用户输入."""
            indicators = ["argv", "gets(", "fgets(", "recv(", "read(",
                         "atoi(", "strtol(", "getenv(", "scanf"]
            return any(ind in var_expr for ind in indicators)

        # 辅助: 判断写入偏移是否无边界检查
        def _has_no_bounds_check(arr_name: str, alloc_size: int) -> bool:
            """检查数组写入是否有适当的边界检查.

            保守策略: 找不到与分配大小一致的边界检查 → 认为无检查.
            """
            if alloc_size is None:
                return True
            # 查找 if (var < N) 或 if (var >= N) 的边界检查
            # 其中 N 应 ≤ alloc_size
            bounds_pattern = _re.findall(
                r'if\s*\(\s*(\w+)\s*[<>]=?\s*(\d+)\s*\)', src)
            for var, bound_str in bounds_pattern:
                bound = int(bound_str)
                if var == arr_name or var in ("off", "o", "offset", "idx", "i", "len", "size"):
                    if bound <= alloc_size:
                        return False  # 有合适的边界检查
            return True

        # 模式1: alloc size < copy size (size mismatch)
        if "malloc" in src and "memcpy" in src and "BUG" in src:
            findings.append({
                "type": "heap_overflow",
                "subtype": "size_mismatch",
                "reason": "malloc size differs from memcpy size",
                "confidence": 0.85,
            })

        # 模式2: off-by-one
        # malloc(N) + buf[N] = ... (写入 N+1 字节)
        off_by_one = _re.findall(r'malloc\s*\(\s*(\w+)\s*\)', src)
        if off_by_one:
            for var in off_by_one:
                if _re.search(r'\b' + var + r'\s*\[\s*' + var + r'\s*\]', src):
                    findings.append({
                        "type": "heap_overflow",
                        "subtype": "off_by_one",
                        "reason": f"malloc({var}) + write at buf[{var}]",
                        "confidence": 0.90,
                    })

        # 模式3: unbounded strcpy (需检查来源是否用户可控)
        if "malloc" in src and _re.search(r'strcpy\s*\(\s*\w+', src):
            # 检查 strcpy 的源参数是否来自用户输入
            strcpy_calls = _re.findall(
                r'strcpy\s*\(\s*(\w+)\s*,\s*([^)]+)\)', src)
            has_dangerous_strcpy = False
            for dest, src_arg in strcpy_calls:
                src_arg = src_arg.strip()
                # 若是字面量字符串 → 安全 (已知长度)
                if src_arg.startswith('"'):
                    lit = src_arg
                    # 粗略估计字符串长度
                    est_len = len(lit) - 2  # 去掉引号
                    # 查找该目标的分配大小
                    safe = False
                    for alloc_sz, _ in alloc_sizes:
                        if alloc_sz is not None and est_len <= alloc_sz:
                            safe = True
                            break
                    if not safe:
                        has_dangerous_strcpy = True
                elif _is_user_controlled(src_arg):
                    has_dangerous_strcpy = True
                elif src_arg:  # 变量来源 — 保守标记
                    has_dangerous_strcpy = True
            if has_dangerous_strcpy:
                findings.append({
                    "type": "heap_overflow",
                    "subtype": "unbounded_strcpy",
                    "reason": "strcpy into heap buffer with user-controlled source",
                    "confidence": 0.80,
                })

        # 模式4: integer overflow in alloc
        # malloc(n * sz) 两个运行时变量相乘 (不含 sizeof 常量)
        io_mul_patterns = [
            r'malloc\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)',       # malloc(x * y)
            r'calloc\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)',         # calloc(n, sz)
        ]
        has_io = False
        for pat in io_mul_patterns:
            for a, b in _re.findall(pat, src):
                if a.isidentifier() and b.isidentifier():
                    has_io = True
                    break
            if has_io:
                break
        # 补充: int → size_t 强制转换 (signed_len → (size_t) → malloc)
        if not has_io and _re.search(r'\(\s*size_t\s*\)\s*signed', src):
            has_io = True
        if has_io:
            findings.append({
                "type": "heap_overflow",
                "subtype": "integer_overflow_alloc",
                "reason": "integer overflow risk in allocation size computation",
                "confidence": 0.70,
            })
            findings.append({
                "type": "integer_overflow",
                "reason": "multiplication or type-cast overflow in allocation",
                "confidence": 0.60,
            })

        # 模式5: loop bound error
        # malloc + for 循环中数组写入: ptr[i], arr[i], ->fields[i] 等
        if ("for" in src and "malloc" in src
                and _re.search(r'(?:\w+(?:->\w+)?)\s*\[\s*i\s*\]', src)):
            findings.append({
                "type": "heap_overflow",
                "subtype": "loop_bound_error",
                "reason": "loop writes to heap array with potentially incorrect bound",
                "confidence": 0.75,
            })

        # 模式5b: BUG 注释标记的通用检测 (兜底)
        # 源码中显式标记 BUG 且包含 malloc + 数组写入 → 潜在堆溢出
        # 排除: BUG 与格式字符串/UAF/double-free 相关的样本
        bug_is_about_heap = (
            "BUG" in src
            and "format string" not in src.lower()
            and "use after free" not in src.lower()
            and "double free" not in src.lower()
            and "uaf" not in src.lower()
        )
        if (bug_is_about_heap and "malloc" in src
                and _re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', src)):
            existing_subtypes = {f.get("subtype") for f in findings
                                if f.get("type") == "heap_overflow"}
            if "loop_bound_error" not in existing_subtypes:
                findings.append({
                    "type": "heap_overflow",
                    "subtype": "loop_bound_error",
                    "reason": "BUG-tagged heap array write detected",
                    "confidence": 0.65,
                })

        # 模式6: TLV length override
        if "declared_len" in src and "actual_len" in src:
            findings.append({
                "type": "heap_overflow",
                "subtype": "tlv_length_mismatch",
                "reason": "alloc per declared length, copy per actual",
                "confidence": 0.85,
            })

        # 模式7: signed/unsigned mismatch
        if "signed_len" in src and "size_t" in src:
            findings.append({
                "type": "heap_overflow",
                "subtype": "signed_unsigned_mismatch",
                "reason": "negative size bypasses bounds check",
                "confidence": 0.65,
            })

        # 模式8: 变量索引写入 + 无适当边界检查 (新增 — 解决 cve_alignment_aware_014 / cve_chunk_metadata_corrupt_009)
        # 检测 malloc(N) + a[user_var] = X 模式
        var_index_write = _re.findall(
            r'(\w+)\s*\[\s*(\w+)\s*\]\s*=', src)
        for arr_name, idx_var in var_index_write:
            if _is_user_controlled(idx_var) or idx_var in ("o", "off", "offset", "idx"):
                # 查找该数组对应的 malloc 大小
                for alloc_sz, size_expr in alloc_sizes:
                    if alloc_sz is not None:
                        # 检查是否有与分配大小一致的边界检查
                        if _has_no_bounds_check(arr_name, alloc_sz):
                            findings.append({
                                "type": "heap_overflow",
                                "subtype": "variable_index_write",
                                "reason": f"malloc({alloc_sz}) + {arr_name}[{idx_var}] without proper bounds check",
                                "confidence": 0.70,
                            })
                            break

        # 模式9: 不充分的边界检查 (新增 — malloc(N) + if (off < M) 其中 M ≫ N)
        # 检测 malloc(N) 后, 边界检查使用了与 N 无关的大常数
        for alloc_sz, _ in alloc_sizes:
            if alloc_sz is None:
                continue
            # 查找 if (var < HUGE / var >= HUGE)
            bounds_checks = _re.findall(
                r'if\s*\(\s*(\w+)\s*(<|<=|>=|>)\s*(\d+)\s*\)', src)
            for var, op, bound_str in bounds_checks:
                bound = int(bound_str)
                # 若边界检查的上界远大于分配大小 → 检查不充分
                if op in ("<", "<=") and bound > alloc_sz * 2:
                    # 确认后续有基于该变量的数组写入
                    if _re.search(r'\w+\s*\[\s*' + var + r'\s*\]', src):
                        findings.append({
                            "type": "heap_overflow",
                            "subtype": "insufficient_bounds_check",
                            "reason": f"malloc({alloc_sz}) + if ({var} {op} {bound}) — check uses {bound} vs alloc {alloc_sz}",
                            "confidence": 0.75,
                        })
                        break
            else:
                continue
            break

        # 模式10: realloc with old size
        if "realloc" in src and "old_sz" in src:
            findings.append({
                "type": "heap_overflow",
                "subtype": "realloc_size_mismatch",
                "reason": "realloc shrinks buffer, memmove uses old size",
                "confidence": 0.80,
            })

        # 模式11: calloc type confusion
        if "calloc" in src and _re.search(r'sizeof\s*\(\s*long\s*\)', src):
            findings.append({
                "type": "heap_overflow",
                "subtype": "calloc_type_mismatch",
                "reason": "memset uses larger element size than calloc",
                "confidence": 0.75,
            })

        # UAF / Double-Free 检测
        if "free(" in src and ("dangling" in src.lower()
                                or _re.search(r'//.*use.after', src.lower())):
            findings.append({
                "type": "use_after_free",
                "reason": "dangling pointer after free",
                "confidence": 0.70,
            })

        # Double-Free: 同一指针被 free 多次
        freed_ptrs = _re.findall(r'free\s*\(\s*(\w+)\s*\)', src)
        if len(freed_ptrs) >= 2:
            from collections import Counter
            ptr_counts = Counter(freed_ptrs)
            for ptr, count in ptr_counts.items():
                if count >= 2:
                    findings.append({
                        "type": "double_free",
                        "reason": f"'{ptr}' freed {count} times",
                        "confidence": 0.90,
                    })

        # 格式化字符串检测
        # printf(user_var) 而非 printf("format", ...)
        printf_calls = _re.findall(
            r'printf\s*\(\s*(\w+)\s*\)', src)
        for var in printf_calls:
            if var not in ("fmt", "buf", "msg"):
                continue
            # 确认该变量来自用户输入或堆分配
            if "malloc" in src or "argv" in src:
                findings.append({
                    "type": "format_string",
                    "reason": "user input passed to printf without format specifier",
                    "confidence": 0.85,
                })
                break  # 每个样本最多一个 fmt 告警

        # calloc type confusion 额外: 检测计数/大小不匹配
        calloc_calls = _re.findall(
            r'calloc\s*\(\s*(\w+)\s*,\s*(\d+)\s*\)', src)
        if calloc_calls:
            for n_var, elem_sz in calloc_calls:
                elem_sz = int(elem_sz)
                # 查找 memset/memcpy 是否使用了不同的元素大小
                if _re.search(r'memset\s*\(\s*\w+\s*,\s*0\s*,\s*' + n_var + r'\s*\*\s*(\d+)', src):
                    findings.append({
                        "type": "heap_overflow",
                        "subtype": "calloc_type_mismatch",
                        "reason": f"calloc({n_var},{elem_sz}) but memset uses different element size",
                        "confidence": 0.75,
                    })

        return findings


def scan_sample(binary_path: str, sample_name: str,
                use_ppahav: bool = True) -> List[ScanResult]:
    scanner = BinaryScanner(use_ppahav=use_ppahav)
    return scanner.scan(binary_path, sample_name)


def main():
    parser = argparse.ArgumentParser(description="Run scanner on test samples")
    parser.add_argument("--samples-dir", default=None,
                        help="Path to heap_samples directory")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path")
    parser.add_argument("--no-ppahav", action="store_true",
                        help="Disable PPA-HAV enhanced detection")
    args = parser.parse_args()

    if args.samples_dir:
        samples_dir = args.samples_dir
    else:
        samples_dir = os.path.join(os.path.dirname(__file__), "heap_samples")

    all_results = []
    for entry in sorted(os.listdir(samples_dir)):
        sample_path = os.path.join(samples_dir, entry)
        binary = None
        for name in ("vuln.exe", "vuln"):
            candidate = os.path.join(sample_path, name)
            if os.path.isfile(candidate):
                binary = candidate
                break
        if os.path.isdir(sample_path) and binary:
            print(f"[*] scanning {entry} ...")
            results = scan_sample(binary, entry, not args.no_ppahav)
            all_results.extend(results)

    # 输出
    output_data = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": len(set(r.sample_name for r in all_results)),
        "results": [
            {
                "sample": r.sample_name,
                "detector": r.detector,
                "n_findings": r.n_total,
                "n_heap_overflow": r.n_heap_overflow,
                "n_uaf": r.n_uaf,
                "n_format_string": r.n_format_string,
                "n_integer_overflow": r.n_integer_overflow,
                "elapsed_ms": round(r.elapsed_ms, 1),
                "findings": r.findings,
                "error": r.error,
            }
            for r in all_results
        ],
    }

    out_path = args.output or os.path.join(
        os.path.dirname(__file__), "scan_results.json")
    with open(out_path, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n[*] results saved to {out_path}")
    print(f"[*] {output_data['total_samples']} samples scanned")

    return 0


if __name__ == "__main__":
    sys.exit(main())
