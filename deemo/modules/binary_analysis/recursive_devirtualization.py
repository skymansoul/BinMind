layer: int = 0
import logging
import os
import re
import subprocess
import hashlib
from dataclasses import dataclass, field
from typing import List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class VirtualizationLayer:
    layer
    type
    entry_point
    vm_dispatch_addr
    bytecode_offset
    bytecode_size
    unpacked_code = None
    confidence = 0.0

@dataclass
class DevirtualizationResult:
    success
    layers
    final_code = None
    total_layers = 0

    layers_removed = 0

class VMDetector:
    # 虚拟化保护壳检测器

    VM_SIGNATURES = {
        "vmprotect": [
            b"VMProtect", b"VMP", b"\xE8\x00\x00\x00\x00",
        ],
        "themida": [
            b"Themida", b"WinLicense", b"Oreans",
        ],
        "code_virtualizer": [
            b"Code Virtualizer", b"CV\x00",
        ],
        "ollvm": [
            b"__obfuscated", b"bcf_", b"fla_", b"sub_",
        ],
        "tigress": [
            b"tigress", b"TIGRESS",
        ],
    }

    DISPATCHER_PATTERNS = [
        r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*[\+\-]\s*0x[0-9a-f]+\]',
        r'(?:jmp|call)\s+(?:qword\s+)?\[r\w+\s*\*\s*[0-9]+\s*\+\s*r\w+\]',
    ]

    def detect_vm_types(self, binary_data: bytes, disasm: str) -> List[Tuple[str, float]]:
        detected = []
        for vm_type, sigs in self.VM_SIGNATURES.items():
            score = 0.0
            for sig in sigs:
                count = binary_data.count(sig) if isinstance(sig, bytes) else 0
                if count > 0:
                    score += min(0.5, count * 0.1)
            if score > 0:
                detected.append((vm_type, min(1.0, score)))
        return sorted(detected, key=lambda x: x[1], reverse=True)

    def detect_dispatcher(self, disasm: str) -> List[int]:
        dispatchers = []
        for pattern in self.DISPATCHER_PATTERNS:
            for m in re.finditer(pattern, disasm, re.IGNORECASE):
                line_start = disasm.rfind('\n', 0, m.start()) + 1
                addr_match = re.match(r'\s*0x([0-9a-f]+)', disasm[line_start:])
                if addr_match:
                    dispatchers.append(int(addr_match.group(1), 16))
        return list(set(dispatchers))

    def estimate_bytecode_region(self, disasm: str, dispatch_addr: int) -> Tuple[int, int]:
        offset = dispatch_addr
        size = 4096
        data_refs = re.findall(
            r'0x([0-9a-f]+)\s*[<\[]',
            disasm[max(0, disasm.find(hex(dispatch_addr)) - 500):
                   disasm.find(hex(dispatch_addr)) + 500]
        )
        if data_refs:
            offset = int(data_refs[0], 16)
        return offset, size


class RecursiveDevirtualizer:
    # 多层虚拟化递归剥离器

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.layers: List[VirtualizationLayer] = []
        self._detector = VMDetector()
        self._binary_data: bytes = b""
        self._disasm: str = ""
        self._max_layers = 10

    def _load_binary(self) -> bytes:
        try:
            with open(self.binary_path, "rb") as f:
                self._binary_data = f.read()
        except Exception as e:
            logger.error(f"loadbinaryfailed: {e}")
        return self._binary_data

    def _load_disasm(self) -> str:
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            self._disasm = r.stdout
        except Exception as e:
            logger.warning(f"disassemblyloadfailed: {e}")
        return self._disasm

    def unpack_layer(self, layer: int) -> bool:
        self._load_binary()
        self._load_disasm()

        vm_types = self._detector.detect_vm_types(self._binary_data, self._disasm)
        if not vm_types:
            logger.info(f"第 {layer} 层: 未detected虚拟化feature, 剥离complete")
            return False

        vm_type, confidence = vm_types[0]
        dispatchers = self._detector.detect_dispatcher(self._disasm)

        if not dispatchers:
            logger.warning(f"第 {layer} 层: detected {vm_type} 但未found调度器")
            return False

        dispatch_addr = dispatchers[0]
        bytecode_offset, bytecode_size = self._detector.estimate_bytecode_region(
            self._disasm, dispatch_addr
        )

        bytecode = b""
        if bytecode_offset < len(self._binary_data):
            end = min(bytecode_offset + bytecode_size, len(self._binary_data))
            bytecode = self._binary_data[bytecode_offset:end]

        vl = VirtualizationLayer(
            layer=layer,
            type=vm_type,
            entry_point=0,
            vm_dispatch_addr=dispatch_addr,
            bytecode_offset=bytecode_offset,
            bytecode_size=len(bytecode),
            unpacked_code=bytecode if bytecode else None,
            confidence=confidence,
        )
        self.layers.append(vl)

        logger.info(
            f"第 {layer} 层: {vm_type} (confidence={confidence:.2f}), "
            f"调度器=0x{dispatch_addr:x}, 字节码={len(bytecode)} 字节"
        )
        return True

    def run(self) -> DevirtualizationResult:
        logger.info(f"start递归去虚拟化: {self.binary_path}")

        self._load_binary()
        self._load_disasm()

        layer = 0
        while layer < self._max_layers:
            if not self.unpack_layer(layer):
                break
            layer += 1

        final_code = self._binary_data
        if self.layers:
            last = self.layers[-1]
            if last.unpacked_code:
                final_code = last.unpacked_code

        logger.info(
            f"去虚拟化complete: 共 {len(self.layers)} 层"
        )
        return DevirtualizationResult(
            success=len(self.layers) > 0,
            layers=self.layers,
            final_code=final_code,
            total_layers=len(self.layers),
            layers_removed=len(self.layers),
        )


def create_recursive_devirtualizer(binary_path: str) -> RecursiveDevirtualizer:
    return RecursiveDevirtualizer(binary_path)
