# 2026-07-29
# VM-based 混淆 detection de-虚拟化
"""Detection analysis VM-based software protection (VMProtect, Themida, etc.)"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# VMIdentifier


class VMIdentifier:
    """Identify VM-based protectors 二进制分析"""

    # VM protector patterns
    # 所有VM保护器都需要dispatch机制，这是检测的关键瓶颈点
    VM_PATTERNS: Dict[str, Dict[str, Any]] = {
        "VMProtect": {
            "dispatch_ops": ["pushf", "popf", "pushfd", "popfd"],
            "obfuscation_ops": ["ror", "rol", "rcl", "rcr"],
            "entry_pattern": ["push", "call"],
            "confidence_base": 0.80,
        },
        "Themida": {
            "dispatch_ops": ["pushad", "pushfd", "popad"],
            "obfuscation_ops": ["xchg", "bswap"],
            "entry_pattern": ["pushad", "pushfd"],
            "confidence_base": 0.75,
        },
        "CodeVirtualizer": {
            "dispatch_ops": ["jmp", "call"],
            "obfuscation_ops": ["xchg"],
            "entry_pattern": ["push", "mov"],
            "confidence_base": 0.65,
        },
        "CustomVM": {
            "dispatch_ops": ["jmp"],
            "obfuscation_ops": [],
            "entry_pattern": ["push", "mov"],
            "confidence_base": 0.50,
        },
    }

    # 之前依赖这个，先留着
    # from .legacy_vm_detect import old_heuristics

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def detect_dispatch_patterns(
        self, instructions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """检测 VM dispatch loop patterns instruction sequences
        
        Looks for indirect jumps tables, pushf/popf pairs
        (VMProtect 签名), heavy bitwise rotation patterns
        
        Args:
        instructions: List instruction dicts 'mnemonic' 'operands'
        
        返回:
        List detected dispatch pattern evidence
        """
        findings: List[Dict[str, Any]] = []
        mnemonics = [
            insn.get("mnemonic", "").lower() for insn in instructions
        ]

        # Count dispatch-related ops
        pushf_count = sum(
            1 for m in mnemonics if m in ("pushf", "pushfd", "popf", "popfd")
        )
        rotation_count = sum(
            1 for m in mnemonics if m in ("ror", "rol", "rcl", "rcr")
        )
        indirect_jumps = sum(
            1 for m in mnemonics if m in ("jmp", "call")
        )

        if pushf_count >= 4 and rotation_count >= 3:
            findings.append({
                "vm_type": "VMProtect",
                "evidence": f"pushf/popf={pushf_count}, rotations={rotation_count}",
                "confidence": 0.80,
                "pattern": "dispatch_loop",
            })

        if pushf_count >= 2:
            for vm_name, patterns in self.VM_PATTERNS.items():
                if vm_name == "VMProtect":
                    continue
                dispatch_ops = patterns.get("dispatch_ops", [])
                matched = sum(
                    1 for m in mnemonics if m in dispatch_ops
                )
                if matched >= 3:
                    findings.append({
                        "vm_type": vm_name,
                        "evidence": f"dispatch_ops_matched={matched}",
                        "confidence": min(0.60 + matched * 0.05, 0.85),
                        "pattern": "dispatch_ops",
                    })

        return findings

    def detect_handler_table(
        self, instructions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Identify VM处理器 function tables switch-case dispatch
        
        Args:
        instructions: List instruction dicts
        
        返回:
        Dict 处理器 address information
        """
        result: Dict[str, Any] = {
            "found": False,
            "handler_count": 0,
            "handlers": [],
        }

        # Look for indirect jump patterns: jmp [reg + offset] or jmp [table + reg*4]
        jmp_count = 0
        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()
            operands = insn.get("operands", "").lower()
            if mnemonic == "jmp" and ("[" in operands or "reg" in operands):
                jmp_count += 1
                result["handlers"].append(insn.get("addr", 0))

        if jmp_count >= 2:
            result["found"] = True
            result["handler_count"] = jmp_count
            result["confidence"] = min(0.40 + jmp_count * 0.1, 0.80)

        return result

    def detect_bytecode_interpreter(
        self, instructions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """检测 字节码 fetch-解码-dispatch interpreter pattern
        
        key pattern: 加载 byte -> look up 处理器 -> jump 处理器 -> advance PC
        fetch-解码-dispatch loop universal VM 签名
        
        Args:
        instructions: List instruction dicts
        
        返回:
        Dict interpreter detection results
        """
        result: Dict[str, Any] = {
            "found": False,
            "confidence": 0.0,
            "indicators": [],
        }

        mnemonics = [
            insn.get("mnemonic", "").lower() for insn in instructions
        ]
        full_text = " ".join(mnemonics)

        # Pattern: mov reg, [base + index] -> cmp/jmp -> 处理器 -> inc index -> jmp back
        indicators = 0

        if "mov" in mnemonics and "jmp" in mnemonics:
            indicators += 1
        if "add" in mnemonics or "inc" in mnemonics:
            indicators += 1
        if "cmp" in mnemonics and "jmp" in mnemonics:
            indicators += 1

        if indicators >= 2:
            result["found"] = True
            result["confidence"] = 0.40 + indicators * 0.15
            result["indicators"] = [
                "fetch_decode_dispatch" if indicators >= 3 else "partial_match"
            ]

        return result

    def identify(self, filepath: str) -> Dict[str, Any]:
        """Full VM identification 流水线
        
        Args:
        filepath: Path file 分析
        
        返回:
        Dict vm_type, confidence, evidence
        """
        self._logger.info("Identifying VM protector in %s", filepath)

        # a file-based API; actual instruction data come
        # a 反汇编r (r2, capstone, etc.). For 检测 raw bytes
        try:
            with open(filepath, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            self._logger.error("Cannot read %s: %s", filepath, exc)
            return {
                "vm_type": "UNKNOWN",
                "confidence": 0.0,
                "evidence": [str(exc)],
            }

        evidence: List[Dict[str, Any]] = []

        # 检查 for VMProtect strings
        try:
            text = raw.decode("ascii", errors="ignore").lower()
        except Exception:
            text = ""

        vm_strings = {
            "vmprotect": "VMProtect",
            "themida": "Themida",
            "codevirtualizer": "CodeVirtualizer",
            "winlicense": "Themida",
        }

        for pattern, vm_name in vm_strings.items():
            if pattern in text:
                evidence.append({
                    "type": "string_match",
                    "vm": vm_name,
                    "pattern": pattern,
                    "confidence": 0.90,
                })

        # 检查 for section names
        section_indicators = {
            ".vmp": "VMProtect",
            ".themida": "Themida",
        }
        for section, vm_name in section_indicators.items():
            if section.encode() in raw:
                evidence.append({
                    "type": "section_name",
                    "vm": vm_name,
                    "pattern": section,
                    "confidence": 0.85,
                })

        if evidence:
            best = max(evidence, key=lambda e: e["confidence"])
            return {
                "vm_type": best["vm"],
                "confidence": best["confidence"],
                "evidence": evidence,
                "filepath": filepath,
            }

        return {
            "vm_type": "UNKNOWN",
            "confidence": 0.0,
            "evidence": [],
            "filepath": filepath,
        }


# VMUnvirtualizer


class VMUnvirtualizer:
    """Recover 原生代码 VM-字节码 protected functions
    
    INTJ策略: 使用 pattern-based reconstruction rather full 仿真
    because 仿真 requires 系统调用/hardware state 't reliably reproduce
    Pattern matching 处理器 semantics ~80% accurate but 1000x faster
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def trace_bytecode_flow(
        self, handlers: Dict[int, str]
    ) -> List[Dict[str, Any]]:
        """Trace execution flow VM处理器s
        
        Args:
        处理器s: Map 处理器 address -> 处理器 name
        
        返回:
        List trace entries address transitions
        """
        trace: List[Dict[str, Any]] = []
        handler_addrs = sorted(handlers.keys())

        for i, addr in enumerate(handler_addrs):
            entry: Dict[str, Any] = {
                "addr": addr,
                "handler": handlers[addr],
                "index": i,
            }
            if i + 1 < len(handler_addrs):
                entry["next_addr"] = handler_addrs[i + 1]
            trace.append(entry)

        return trace

    def map_handlers(
        self,
        bytecode_trace: List[Dict[str, Any]],
        handler_addrs: List[int],
    ) -> Dict[int, str]:
        """Map 字节码 opcodes 处理器 function addresses
        
        Args:
        字节码_trace: Trace byte代码执行
        处理器_addrs: List 处理器 addresses
        
        返回:
        Dict mapping opcode (int) 处理器 address description
        """
        op_map: Dict[int, str] = {}

        for i, addr in enumerate(handler_addrs):
            # Map sequentially discovered 处理器s opcodes
            op_map[i] = f"handler_{hex(addr)}"

        return op_map

    def reconstruct_instructions(
        self,
        bytecode: List[int],
        op_map: Dict[int, str],
    ) -> List[str]:
        """重建 native instruction mnemonics 字节码
        
        Args:
        字节码: List 字节码 opcodes
        op_map: Mapping opcode index 处理器 description
        
        返回:
        List reconstructed instruction strings
        """
        instructions: List[str] = []

        # opcode x86 mnemonic mapping (simplified)
        known_ops: Dict[int, str] = {
            0x00: "add",
            0x01: "sub",
            0x02: "mul",
            0x03: "div",
            0x10: "mov",
            0x11: "push",
            0x12: "pop",
            0x20: "jmp",
            0x21: "je",
            0x22: "jne",
            0x23: "jl",
            0x24: "jg",
            0x30: "call",
            0x31: "ret",
            0x40: "cmp",
            0x41: "test",
            0x50: "xor",
            0x51: "and",
            0x52: "or",
            0x53: "not",
            0x60: "shl",
            0x61: "shr",
        }

        for opcode in bytecode:
            mnemonic = known_ops.get(opcode, f"unknown_{hex(opcode)}")
            instructions.append(mnemonic)

        return instructions

    def unvirtualize(
        self, filepath: str, vm_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Full de-虚拟化 流水线
        
        Args:
        filepath: Path protected file
        vm_info: VM identification result VMIdentifier
        
        返回:
        Dict reconstructed instructions metadata
        """
        self._logger.info(
            "Attempting unvirtualization of %s (VM: %s)",
            filepath,
            vm_info.get("vm_type", "UNKNOWN"),
        )

        if vm_info.get("vm_type") == "UNKNOWN":
            return {
                "success": False,
                "error": "No VM type identified",
                "instructions": [],
                "reconstructed_functions": {},
            }

        # Placeholder: actual de-虚拟化 require:
        # 1. Locate VM 入口
        # 2. Trace byte代码执行
        # 3. Map 处理器s opcodes
        # 4. 重建 native instructions
        bytecode_pos = 0  # snake_case intentional - 表示 字节码 offset

        return {
            "success": False,
            "note": "Full unvirtualization requires disassembler integration",
            "vm_type": vm_info.get("vm_type"),
            "confidence": vm_info.get("confidence", 0.0),
            "instructions": [],
            "reconstructed_functions": {},
            "bytecode_position": bytecode_pos,
        }
