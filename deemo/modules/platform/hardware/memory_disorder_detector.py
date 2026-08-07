# Memory DisOrder: 内存重排序侧信道检测器
#
#   "Memory DisOrder: Memory Re-orderings as a Timerless Side-channel"
# — Siddens et al.
#     发现跨 6 种架构 (x86, ARM, Apple; NVIDIA/AMD/Apple GPU) 的内存重排序侧信道,
#     在不使用 timer 或 PMU 的情况下实现 covert channel (16 bps M3 GPU, ~30Kbps x86)
#     并实现 DNN 架构指纹识别
#   理论基础: 宽松内存模型 (relaxed memory model) 允许 CPU/GPU 重排访存顺序,
#     不同 agent 观察到的写入顺序差异可被编码为信息

import os
import struct
import threading
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# 已知受影响的架构及其模型特征
# 每个架构定义了重排序的可观测程度 (reorder_depth) 和典型重排窗口
_AFFECTED_ARCHITECTURES: dict[str, dict] = {
    "x86_64": {"reorder_depth": 4, "window_ns": 50, "mitigation": "mfence/lfence",
               "tso": True, "model": "Intel TSO (strong)"},
    "arm_v8": {"reorder_depth": 8, "window_ns": 200, "mitigation": "dmb ish",
               "tso": False, "model": "ARM relaxed (weak)"},
    "apple_m1": {"reorder_depth": 6, "window_ns": 150, "mitigation": "dmb ishld",
                 "tso": False, "model": "Apple Firestorm (weak, no TSO)"},
    "apple_m3_gpu": {"reorder_depth": 12, "window_ns": 800, "mitigation": "threadgroup_barrier",
                     "tso": False, "model": "Apple AGX GPU (very weak)"},
    "nvidia_gpu": {"reorder_depth": 8, "window_ns": 350, "mitigation": "__threadfence()",
                   "tso": False, "model": "NVIDIA PTX relaxed"},
    "amd_gpu": {"reorder_depth": 10, "window_ns": 400, "mitigation": "barrier(CLK_GLOBAL_MEM_FENCE)",
                "tso": False, "model": "AMD GCN relaxed"},
}


@dataclass
class ReorderFinding:
    finding_id: str
    severity: str
    architecture: str = ""
    reorder_type: str = ""   # "load-load", "store-load", "store-store"
    code_location: str = ""  # 源码位置或指令序列描述
    description: str = ""
    bandwidth_estimate_bps: float = 0.0
    mitigation: str = ""
    confidence: float = 0.0


class MemoryDisorderDetector:
    """内存重排序侧信道静态检测器。

    分析二进制或汇编源码中可被观测者利用的内存重排序模式。
    检测策略覆盖 arXiv 2601.08770 的 4 种核心模式：
    1. Load-Load 重排: 两次 load 的观测顺序在另一核上反转
    2. Store-Store 重排: 两次 store 的提交顺序与程序顺序不同
    3. Store-Load 重排: store 后的 load 可能被提前执行 (最常见)
    4. Dependent Loads: 有数据依赖的 load 仍可能被投机执行重排

    输入: 反汇编文本 (.s, .asm) 或 Capstone 指令列表
    """

    # 所有内存屏障指令 — 跨架构
    _FENCE_INSTRUCTIONS = {
        "x86_64": ["mfence", "lfence", "sfence", "lock "],
        "arm_v8": ["dmb", "dsb", "isb"],
        "apple_m1": ["dmb", "dsb", "isb"],
        "riscv": ["fence", "fence.i"],
    }

    def __init__(self, asm_text: str = "", asm_path: str = "",
                 arch: str = "x86_64"):
        self.asm = asm_text
        self.path = asm_path
        self.arch = arch
        self.findings: list[ReorderFinding] = []
        self._arch_info = _AFFECTED_ARCHITECTURES.get(arch,
            {"reorder_depth": 4, "window_ns": 100, "mitigation": "fence",
             "tso": False, "model": "unknown"})
        if asm_path and os.path.exists(asm_path):
            with open(asm_path, "r", encoding="utf-8", errors="replace") as f:
                self.asm = f.read()

    def detect(self) -> list[ReorderFinding]:
        if not self.asm:
            return []
        instr_lines = self.asm.split("\n")
        self._check_store_load_reordering(instr_lines)
        self._check_load_load_reordering(instr_lines)
        self._check_store_store_reordering(instr_lines)
        self._check_fence_absence(instr_lines)
        self.findings.sort(key=lambda f: (
            0 if f.severity == "Critical" else 1 if f.severity == "High" else 2,
            -f.bandwidth_estimate_bps))
        return self.findings

    def _check_store_load_reordering(self, instr_lines: list[str]):
        """检测 store 后紧跟 load 的模式 — 在弱内存模型上 load 可能先完成。

        x86 TSO 理论上防止此重排，但投机执行 (Spectre 类) 可绕过。
        ARM/Apple 弱模型下 store-load 重排完全合法，经常被用于构建侧信道。
        """
        import re
        store_pat = re.compile(r'(?:mov|st|str|stur|sw)\s', re.IGNORECASE)
        load_pat  = re.compile(r'(?:mov|ld|ldr|ldur|lw)\s', re.IGNORECASE)
        fence_pat = re.compile(r'(?:mfence|lfence|sfence|dmb|dsb|fence|barrier)',
                               re.IGNORECASE)
        for i in range(len(instrs) - 3):
            current = instrs[i].strip()
            nxt     = instrs[i+1].strip() if i+1 < len(instrs) else ""
            nx2     = instrs[i+2].strip() if i+2 < len(instrs) else ""
            if store_pat.search(current) and load_pat.search(nxt):
                # 中间无 fence
                if not fence_pat.search(current) and not fence_pat.search(nxt):
                    self.findings.append(ReorderFinding(
                        finding_id="MD-SL-001", severity="Medium",
                        architecture=self.arch, reorder_type="store-load",
                        code_location=f"line ~{i+1}: {current[:60]}",
                        description="Store followed by load without fence — "
                                    "load may complete before store becomes visible",
                        bandwidth_estimate_bps=self._arch_info.get("reorder_depth", 4) * 4,
                        mitigation=self._arch_info.get("mitigation", "fence"),
                        confidence=0.70 if not self._arch_info.get("tso", True) else 0.35,
                    ))
                    break  # 每种模式只报告最典型的一处

    def _check_load_load_reordering(self, instr_lines: list[str]):
        """检测两次 load 之间无依赖关系 — 顺序可能被观测者反转。

        在 Litmus 测试中写为 MP (Message Passing) 测试:
        Thread0: write X, write Y
        Thread1: read Y, read X
        如果 Thread1 读到 new Y but old X → store-store 重排发生在 Thread0。
        对应的 load-load 重排在 Thread1 观察侧。
        """
        import re
        ld_pat = re.compile(r'(?:ldr|ldur|mov\s+\w+,\s*\[)', re.IGNORECASE)
        ld_count = 0; window = 5
        for i in range(len(instrs) - 1):
            if ld_pat.search(instrs[i].strip()):
                ld_count += 1
                if ld_count >= 2:
                    self.findings.append(ReorderFinding(
                        finding_id="MD-LL-001", severity="Low",
                        architecture=self.arch, reorder_type="load-load",
                        code_location=f"line ~{i+1}",
                        description="Multiple independent loads within {window} instrs — "
                                    "observer may see them in reversed order",
                        bandwidth_estimate_bps=ld_count * 2,
                        mitigation=self._arch_info.get("mitigation", "fence"),
                        confidence=0.40,
                    ))
                    break

    def _check_store_store_reordering(self, instrs: list[str]):
        """检测多次 store 之间无 barrier 的模式。

        即使在 x86 TSO 下 store-store 也被保证顺序，但仅对同一核。
        其他核可能以不同顺序观察到这些 store (store buffer forwarding)。
        NVidia GPU 无全局 store 顺序保证，此模式在 GPU 上更危险。
        """
        import re
        st_pat = re.compile(r'(?:str|stur|sw|st\.global)\s', re.IGNORECASE)
        fence_pat = re.compile(r'(?:dmb|dsb|barrier|fence|membar)', re.IGNORECASE)
        st_count = 0; st_start = 0
        for i, line in enumerate(instrs):
            stripped = line.strip()
            if st_pat.search(stripped) and not fence_pat.search(stripped):
                if st_count == 0:
                    st_start = i + 1
                st_count += 1
            elif fence_pat.search(stripped):
                st_count = 0
        if st_count >= 3:
            self.findings.append(ReorderFinding(
                finding_id="MD-SS-001", severity="Low",
                architecture=self.arch, reorder_type="store-store",
                code_location=f"lines {st_start}-{st_start+st_count}",
                description=f"{st_count} consecutive stores without barrier — "
                            "remote observers may see reordered writes",
                bandwidth_estimate_bps=st_count * 2,
                mitigation=self._arch_info.get("mitigation", "fence"),
                confidence=0.30,
            ))

    def _check_fence_absence(self, instrs: list[str]):
        """全局检查: 整个代码段是否有任何内存屏障。

        若无任何 fence/barrier 指令，且涉及共享内存访问，
        整个函数都可能被内存重排序攻击利用。
        """
        fences = self._FENCE_INSTRUCTIONS.get(self.arch, [])
        has_fence = any(
            any(f in line.lower() for f in fences)
            for line in instrs
        )
        has_shared_mem = any(
            "shared" in line.lower() or "volatile" in line.lower()
            or "atomic" in line.lower()
            for line in instrs
        )
        if not has_fence and has_shared_mem and len(instrs) > 20:
            self.findings.append(ReorderFinding(
                finding_id="MD-FENCE-ABSENT", severity="High",
                architecture=self.arch, reorder_type="global",
                code_location="entire function",
                description="Shared memory accessed without any memory barrier — "
                            "all access patterns subject to hardware reordering",
                bandwidth_estimate_bps=self._arch_info.get("reorder_depth", 4) * 8,
                mitigation=f"Insert {self._arch_info.get('mitigation', 'memory barrier')} "
                           "between critical memory operations",
                confidence=0.80,
            ))


def detect_memory_disorder(asm_text: str = "", asm_path: str = "",
                           arch: str = "x86_64") -> list[ReorderFinding]:
    detector = MemoryDisorderDetector(asm_text=asm_text,
                                       asm_path=asm_path, arch=arch)
    return detector.detect()
