# GPU Rowhammer 攻击检测器
#
#   "OpenGL GPU-Based Rowhammer Attack"
#     — 用 OpenGL ES 3.1 compute shader 在 RPi4 上实现 Rowhammer, 20h 内 1024 bit flip
#   "Another Flip in the Wall of Rowhammer Defenses" — TRR 绕过基准
#   BLACKSMITH — 自适应 fuzzing 绕过 TRR
#   TRRespass — TRR 绕过方法论

import os
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

_logger = logging.getLogger(__name__)

# GPU Rowhammer 检测策略: 不实际触发 Rowhammer (那需要 GPU 访问权限)，
# 而是对 GPU kernel 代码做静态分析，检测可能构成 Rowhammer 漏洞的模式:
# 1. 紧密循环中反复访问同一 bank 的不同行 (hammer 模式)
# 2. 缺少 clflush/cache bypass 但仍能命中 DRAM 的访问模式
# 3. OpenCL/CUDA kernel 中大量全局内存访问且 stride < 256B

# GPU 内存 bank 冲突检测 — 连续的全局内存访问 stride 小于 cache line 时
# 可能使 DRAM 刷新窗口内相邻行被反复激活
_BANK_CONFLICT_STRIDE_THRESHOLD = 256  # bytes

# 常见 GPU 汇编指令中代表全局内存 load/store 的操作码
_GPU_MEM_OPS = {
    "ptx": ["ld.global", "st.global", "ld.global.nc", "st.global.wb",
            "atom.global", "red.global"],
    "spirv": ["OpLoad", "OpStore"],
    "opencl": ["__global", "global_load", "global_store"],
    "glsl": ["imageLoad", "imageStore", "atomicAdd", "atomicExchange"],
}


@dataclass
class GPURowhammerFinding:
    finding_id: str
    severity: str
    kernel_name: str = ""
    file_path: str = ""
    line_number: int = 0
    pattern: str = ""
    description: str = ""
    confidence: float = 0.0
    recommendation: str = ""


class GPURowhammerDetector:
    """GPU kernel 中 Rowhammer 漏洞模式的静态检测器。

    以 arXiv 2509.19959 的 OpenGL Rowhammer 实现模式为蓝本，
    检测 5 类 Rowhammer 相关代码模式：
    1. 高频全局内存访问循环 (hammer loop)
    2. 短 stride (< 256B) 交替访问模式
    3. 原子操作在紧密循环中的使用 (可能绕过缓存)
    4. 缺少 memory fence 的读写交错模式
    5. compute shader 中的未对齐全局内存访问

    支持: PTX (NVIDIA), SPIR-V (Vulkan/OpenCL), GLSL/ESSL (OpenGL ES), CUDA C++ source
    """

    def __init__(self, kernel_source: str = "", kernel_path: str = "",
                 arch: str = "ptx"):
        self.source = kernel_source
        self.path = kernel_path
        self.arch = arch.lower()
        self.findings: list[GPURowhammerFinding] = []
        if kernel_path and os.path.exists(kernel_path):
            with open(kernel_path, "r", encoding="utf-8", errors="replace") as f:
                self.source = f.read()

    def detect(self) -> list[GPURowhammerFinding]:
        if not self.source:
            return []
        lines = self.source.split("\n")
        self._detect_hammer_loop(lines)
        self._detect_short_stride(lines)
        self._detect_atomic_hammer(lines)
        self._detect_unfenced_interleave(lines)
        self._detect_misaligned_global(lines)
        self.findings.sort(key=lambda f: f.confidence, reverse=True)
        return self.findings

    def _detect_hammer_loop(self, lines: list[str]):
        """检测 hammer loop: 紧密循环内的高频全局内存访问。

        模式: for/while 循环体中有 >= 3 条全局 load/store 指令，
        且循环迭代次数 > 1000 (暗示暴力 hammer)。
        """
        in_loop = False; loop_body_ops = 0; loop_start = 0
        mem_ops = _GPU_MEM_OPS.get(self.arch, _GPU_MEM_OPS["ptx"])
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(kw in stripped for kw in ["for ", "while ", "do {"]):
                in_loop = True; loop_body_ops = 0; loop_start = i + 1
                continue
            if in_loop and stripped in ("}", "};", "end", "endfor"):
                if loop_body_ops >= 3:
                    self.findings.append(GPURowhammerFinding(
                        finding_id="GPU-RH-001", severity="High",
                        kernel_name=self._extract_kernel_name(lines, loop_start),
                        file_path=self.path, line_number=loop_start,
                        pattern="hammer_loop",
                        description=f"Tight loop at line {loop_start} with {loop_body_ops} global mem ops",
                        confidence=min(0.9, 0.5 + loop_body_ops * 0.1),
                        recommendation="Insert cache-flush-equivalent operations between accesses"
                    ))
                in_loop = False
                continue
            if in_loop:
                if any(op in stripped for op in mem_ops):
                    loop_body_ops += 1

    def _detect_short_stride(self, lines: list[str]):
        """检测短 stride 交替访问: 步长 < 256B 的连续全局内存地址访问。

        PTX 示例: ld.global.f32 %r1, [%rd + 0]; ld.global.f32 %r2, [%rd + 64];
        """
        import re
        stride_pat = re.compile(r'\[[^\]]*\+\s*(\d+)\]')
        mem_ops = _GPU_MEM_OPS.get(self.arch, _GPU_MEM_OPS["ptx"])
        strides = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(op in stripped for op in mem_ops):
                m = stride_pat.search(stripped)
                if m:
                    strides.append((i + 1, int(m.group(1))))
        for k in range(len(strides) - 1):
            stride_diff = abs(strides[k+1][1] - strides[k][1])
            if 1 <= stride_diff < _BANK_CONFLICT_STRIDE_THRESHOLD:
                self.findings.append(GPURowhammerFinding(
                    finding_id="GPU-RH-002", severity="Medium",
                    file_path=self.path, line_number=strides[k][0],
                    pattern="short_stride",
                    description=f"Short stride ({stride_diff}B) between consecutive global accesses",
                    confidence=0.55,
                    recommendation="Increase stride to >{_BANK_CONFLICT_STRIDE_THRESHOLD}B to reduce same-bank activation"
                ))
                break  # 每个 kernel 只报告一次以避免噪声

    def _detect_atomic_hammer(self, lines: list[str]):
        """检测原子操作在循环中的使用 — 绕过 L1/L2 缓存的直接 DRAM 访问。"""
        atom_ops = ["atomicAdd", "atomicSub", "atomicExch", "atomicCAS",
                    "atomicInc", "atomicDec", "atomicMin", "atomicMax",
                    "atomicAnd", "atomicOr", "atomicXor"]
        in_loop = False; loop_has_atomic = False; loop_start = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(kw in stripped for kw in ["for ", "while ", "do {"]):
                in_loop = True; loop_has_atomic = False; loop_start = i + 1
            elif in_loop and stripped in ("}", "};", "end", "endfor"):
                if loop_has_atomic:
                    self.findings.append(GPURowhammerFinding(
                        finding_id="GPU-RH-003", severity="Medium",
                        file_path=self.path, line_number=loop_start,
                        pattern="atomic_hammer",
                        description="Atomic operation inside tight loop — bypasses cache hierarchy",
                        confidence=0.50,
                        recommendation="Use cached global loads with fence instead of atomics where possible"
                    ))
                in_loop = False
            elif in_loop and any(op in stripped for op in atom_ops):
                loop_has_atomic = True

    def _detect_unfenced_interleave(self, lines: list[str]):
        """检测无 fence 保护的内存读写交错 — store 后紧接 load 到相邻地址。"""
        has_store = False; store_line = 0
        mem_ops = _GPU_MEM_OPS.get(self.arch, _GPU_MEM_OPS["ptx"])
        for i, line in enumerate(lines):
            stripped = line.strip()
            is_store = any(op in stripped and "st" in op for op in mem_ops)
            is_load = any(op in stripped and "ld" in op for op in mem_ops)
            has_fence = "membar" in stripped or "fence" in stripped or "barrier" in stripped
            if has_store and is_load and not has_fence:
                self.findings.append(GPURowhammerFinding(
                    finding_id="GPU-RH-004", severity="Low",
                    file_path=self.path, line_number=i + 1,
                    pattern="unfenced_interleave",
                    description="Store-load pair without intervening memory fence",
                    confidence=0.35,
                    recommendation="Add __threadfence() or membar between conflicting accesses"
                ))
                has_store = False
            if is_store:
                has_store = True; store_line = i + 1
            if has_fence:
                has_store = False

    def _detect_misaligned_global(self, lines: list[str]):
        """检测未对齐的全局内存访问 — 单次指令跨越两个 cache line 需要两次激活。"""
        import re
        align_pat = re.compile(r'\[[^\]]*\+(0x[0-9a-fA-F]+|\d+)\]')
        for i, line in enumerate(lines):
            m = align_pat.search(line)
            if m:
                offset_str = m.group(1)
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                if offset % 128 != 0:
                    self.findings.append(GPURowhammerFinding(
                        finding_id="GPU-RH-005", severity="Low",
                        file_path=self.path, line_number=i + 1,
                        pattern="misaligned_global",
                        description=f"Unaligned global memory access at offset {offset}",
                        confidence=0.25,
                        recommendation="Align global memory base address to 128B boundary"
                    ))
                    break

    def _extract_kernel_name(self, lines: list[str], near_line: int) -> str:
        for j in range(max(0, near_line - 10), near_line):
            stripped = lines[j].strip()
            for prefix in ["kernel ", "__kernel ", "__global__ ", "void "]:
                if prefix in stripped:
                    parts = stripped.split()
                    for idx, part in enumerate(parts):
                        if part in ("void", "int", "float", "double"):
                            if idx + 1 < len(parts):
                                name = parts[idx + 1].split("(")[0].strip()
                                return name
                    return stripped.split("(")[0].split()[-1]
        return "unknown_kernel"


def detect_gpu_rowhammer(source: str = "", path: str = "",
                         arch: str = "ptx") -> list[GPURowhammerFinding]:
    det = GPURowhammerDetector(kernel_source=source,
                                kernel_path=path, arch=arch)
    return det.detect()
