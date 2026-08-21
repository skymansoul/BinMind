import logging
import os
import re
import struct
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VMInfo:
    vm_type: str = ''; confidence: float = 0.0
    dispatch_addr: int = 0; handler_table: int = 0
    num_instructions: int = 0; binary_section: str = ''
    handler_kinds: dict = field(default_factory=dict)
    handler_size_uniformity: float = 0.0
    opcode_distribution: Dict[str, float] = field(default_factory=dict)
    handler_addresses: List[int] = field(default_factory=list)
    # 新增：handler 相似聚类结果
    handler_clusters: List[List[int]] = field(default_factory=list)

    def __post_init__(self):
        self.vm_type = str(self.vm_type) if self.vm_type else ''
        self.confidence = float(self.confidence) if self.confidence is not None else 0.0
        self.dispatch_addr = int(self.dispatch_addr) if self.dispatch_addr is not None else 0
        self.handler_table = int(self.handler_table) if self.handler_table is not None else 0
        self.num_instructions = int(self.num_instructions) if self.num_instructions is not None else 0
        self.binary_section = str(self.binary_section) if self.binary_section else ''


_VM_PATTERNS = {
    'vmprotect': {'sigs': [b'VMProtect', b'\xE8\x00\x00\x00\x00'],
        'disp': r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*[\+\-]', 'base': 0.9},
    'themida': {'sigs': [b'Themida', b'WinLicense', b'Oreans'],
        'disp': r'mov\s+r\w+,\s*\[r\w+\s*[\+\-]', 'base': 0.85},
    'code_virtualizer': {'sigs': [b'Code Virtualizer', b'CV\x00'],
        'disp': r'push\s+r\w+\s*\n\s*mov\s+r\w+,\s*\[r\w+\]', 'base': 0.8},
    'custom_vm': {'sigs': [],
        'disp': r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*\*\s*[0-9]', 'base': 0.4},
    'tigress': {'sigs': [b'tigress', b'@1337code', b'TGRS'],
        'disp': r'mov\s+r\w+,\s*\[r\w+\s*[\*\+].*\n.*jmp\s+r\w+', 'base': 0.75},
    'obsidium': {'sigs': [b'Obsidium', b'OBSIDIUM'],
        'disp': r'call\s+(?:qword\s+)?\[r\w+\]', 'base': 0.7},
    'enigma_protector': {'sigs': [b'.enigma', b'ENIGMA'],
        'disp': r'push\s+r\w+\s*\n\s*jmp\s+r\w+', 'base': 0.65},
}

_OPCODE_CLASSES = {
    "data_mov": [0x88, 0x89, 0x8A, 0x8B, 0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB8, 0xC6, 0xC7],
    "arith": [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0xF6, 0xF7, 0x69, 0x6B],
    "logic": [0x08, 0x09, 0x0A, 0x0B, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x84, 0x85],
    "control": [0x70, 0x80, 0xE8, 0xE9, 0xEB, 0xC2, 0xC3, 0xFF],
    "stack": [0x50, 0x58, 0x9C, 0x9D, 0x6A, 0x68, 0x8F],
}


# Handler 相似聚类 - 基于 Jaccard 相似度的层次聚类
# 原理: 对每个 handler，提取其 opcode 频率向量，计算两两 Jaccard
# 相似度。相似度 > 0.7 的 handler 合并为一类。这对于识别 VM 指令集
# 中的"指令族"（如所有算术指令、所有内存指令）有效
# VMDragonSlayer 的 ML-driven 处理器 分类

def _handler_opcode_vector(raw: bytes, addr: int, size: int = 64) -> Dict[int, int]:
    """提取 handler 地址处的操作码频率向量"""
    vec: Dict[int, int] = {}
    chunk = raw[addr:min(len(raw), addr + size)]
    for b in chunk:
        vec[b] = vec.get(b, 0) + 1
    return vec


def _jaccard_similarity(v1: Dict[int, int], v2: Dict[int, int]) -> float:
    """计算两个频率向量的 Jaccard 相似度（基于出现与否，非频率加权）"""
    keys1 = set(v1.keys())
    keys2 = set(v2.keys())
    if not keys1 and not keys2:
        return 0.0
    intersection = len(keys1 & keys2)
    union = len(keys1 | keys2)
    return intersection / union if union > 0 else 0.0


def _cluster_handlers_by_opcode(raw: bytes, handler_addrs: List[int],
                                  threshold: float = 0.65) -> List[List[int]]:
    """基于操作码向量的 Jaccard 相似度进行层次聚类
    threshold: 相似度阈值，低于此值的不合并
    """
    if len(handler_addrs) < 2:
        return [[a] for a in handler_addrs]

    vecs = {addr: _handler_opcode_vector(raw, addr) for addr in handler_addrs}

    # 单链层次聚类
    clusters: List[Set[int]] = [{addr} for addr in handler_addrs]

    while True:
        best_i, best_j, best_sim = -1, -1, 0.0
        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                # 计算两个聚类的平均相似度
                sims = []
                for ai in clusters[i]:
                    vi = vecs.get(ai, {})
                    for aj in clusters[j]:
                        vj = vecs.get(aj, {})
                        sims.append(_jaccard_similarity(vi, vj))
                avg_sim = sum(sims) / len(sims) if sims else 0.0
                if avg_sim > best_sim:
                    best_sim, best_i, best_j = avg_sim, i, j

        if best_sim < threshold or best_i < 0:
            break

        clusters[best_i] |= clusters[best_j]
        clusters.pop(best_j)

    return [sorted(list(c)) for c in clusters]


class EmbeddedVMIdentifier:

    def __init__(self, binpath):
        if binpath is None:
            raise ValueError("binary path required")
        self._path = os.path.abspath(binpath)

    def _classify_handlers(self, asm):
        kinds = {"arith": 0, "mem": 0, "ctrl": 0, "sys": 0}
        for kind, pat in [("arith", r"\b(add|sub|imul|idiv|xor|and|or|shl|shr|rol|ror)\b"),
                           ("mem", r"\b(mov|lea|push|pop|xchg)\b.*\["),
                           ("ctrl", r"\b(jmp|jz|jnz|je|jne|jl|jg|jle|jge|call|ret)\b"),
                           ("sys", r"\b(syscall|int\s+0x80|sysenter|int\s+0x2e)\b")]:
            kinds[kind] = len(re.findall(pat, asm, re.IGNORECASE))
        return kinds

    def _opcode_frequency_distribution(self, raw):
        if len(raw) < 256: return {}
        freq = {"data_mov": 0, "arith": 0, "logic": 0, "control": 0, "stack": 0}
        for b in raw[:4096]:
            for cls_name, opcodes in _OPCODE_CLASSES.items():
                if b in opcodes: freq[cls_name] += 1; break
        total = max(sum(freq.values()), 1)
        return {k: round(v / total, 3) for k, v in freq.items()}

    def _handler_size_coefficient(self, asm):
        sizes = []
        line_count = 0
        for line in asm.split("\n"):
            if line.strip().startswith("0x"): line_count += 1
            elif line_count > 0:
                if 5 < line_count < 100: sizes.append(line_count)
                line_count = 0
        if len(sizes) < 4: return 0.0
        mean_s = sum(sizes) / len(sizes)
        if mean_s == 0: return 0.0
        variance = sum((s - mean_s) ** 2 for s in sizes) / len(sizes)
        return round((variance ** 0.5) / mean_s, 3)

    def _cross_reference_handlers(self, asm, raw):
        candidates: Set[int] = set()
        for m in re.finditer(
            r'(?:jmp|call)\s+(?:qword\s+)?\[(\w+)\s*[\+\-]\s*(0x[0-9a-fA-F]+|\d+)\]',
            asm, re.IGNORECASE):
            try: disp = int(m.group(2), 0)
            except ValueError: continue
            base = disp & ~0xFFF
            for trial in range(base, base + 0x1000, 4):
                if 0x1000 <= trial < len(raw) - 16: candidates.add(trial)
        for m in re.finditer(
            r'mov\s+\w+,\s*\[(0x[0-9a-fA-F]+)(?:\s*[\+\*]\s*\w+)?\]',
            asm, re.IGNORECASE):
            try:
                table_addr = int(m.group(1), 16)
                if 0x1000 <= table_addr < len(raw) - 256:
                    for i in range(0, 256, struct.calcsize("P")):
                        ptr_off = table_addr + i
                        if ptr_off + 4 > len(raw): break
                        potential = struct.unpack_from("<I", raw, ptr_off)[0]
                        if 0x1000 <= potential < len(raw) - 16: candidates.add(potential)
            except (ValueError, struct.error): pass
        return sorted(candidates)[:64]

    def identify(self):
        found = []
        try:
            with open(self._path, 'rb') as fh: raw = fh.read()
        except Exception as e:
            logger.warning(f"VM identify: cannot read {self._path}: {e}"); return found
        asm = ''
        try:
            r = subprocess.run(['r2', '-q', '-c', 'pD $SS @ $S; q', self._path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace')
            asm = r.stdout
        except Exception as e:
            logger.debug(f"radare2 disassembly failed: {e}", exc_info=True)

        size_uniform = self._handler_size_coefficient(asm) if asm else 0.0
        opcode_dist = self._opcode_frequency_distribution(raw)
        handler_candidates = self._cross_reference_handlers(asm, raw) if asm else []

        # 对 handler 执行相似聚类
        clusters = _cluster_handlers_by_opcode(raw, handler_candidates) if handler_candidates else []

        for vm_name, vm_info in _VM_PATTERNS.items():
            score = 0.0
            for sig in vm_info['sigs']:
                if sig in raw: score += 0.3
            disp_matches = []
            if asm:
                disp_matches = list(re.finditer(vm_info['disp'], asm, re.IGNORECASE))
            if len(disp_matches) > 5: score += 0.5
            final_conf = vm_info['base'] * (1.0 + score)
            if final_conf > 1.0: final_conf = 1.0
            if score > 0:
                found.append(VMInfo(
                    vm_type=vm_name, confidence=final_conf,
                    dispatch_addr=disp_matches[0].start() if disp_matches else 0,
                    num_instructions=len(disp_matches) // 2 if disp_matches else 0,
                    handler_kinds=self._classify_handlers(asm) if asm else {},
                    handler_size_uniformity=size_uniform,
                    opcode_distribution=opcode_dist,
                    handler_addresses=handler_candidates,
                    handler_clusters=clusters))
        found.sort(key=lambda x: x.confidence, reverse=True)
        return found


def identify_embedded_vms(binpath):
    eng = EmbeddedVMIdentifier(binpath)
    vms = eng.identify()
    out = []
    for v in vms:
        out.append({
            'type': v.vm_type, 'confidence': v.confidence,
            'instructions': v.num_instructions,
            'handler_kinds': v.handler_kinds,
            'handler_size_cv': v.handler_size_uniformity,
            'opcode_distribution': v.opcode_distribution,
            'handler_addresses': v.handler_addresses,
            'handler_clusters': [c for c in v.handler_clusters],
        })
    return {'success': True, 'vms': out}
