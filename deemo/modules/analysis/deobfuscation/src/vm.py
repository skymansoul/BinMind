# VM 混淆检测与去虚拟化

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VMIdentifier:

    # 所有 VM 保护器都需要 dispatch 机制，这是检测的关键瓶颈点
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
        findings: List[Dict[str, Any]] = []
        mnemonics = [
            insn.get("mnemonic", "").lower() for insn in instructions
        ]

        # 统计 dispatch 相关操作
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
        result: Dict[str, Any] = {
            "found": False,
            "handler_count": 0,
            "handlers": [],
        }

        # 查找间接跳转模式: jmp [reg + offset] 或 jmp [table + reg*4]
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
        result: Dict[str, Any] = {
            "found": False,
            "confidence": 0.0,
            "indicators": [],
        }

        mnemonics = [
            insn.get("mnemonic", "").lower() for insn in instructions
        ]
        full_text = " ".join(mnemonics)

        # 模式: mov reg, [base + index] -> cmp/jmp -> 处理器 -> inc index -> jmp back
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
        self._logger.info("识别 VM 保护器: %s", filepath)

        # 基于文件的 API; 实际指令数据来自
        # 反汇编器 (r2, capstone 等)。检测原始字节
        try:
            with open(filepath, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            self._logger.error("无法读取 %s: %s", filepath, exc)
            return {
                "vm_type": "UNKNOWN",
                "confidence": 0.0,
                "evidence": [str(exc)],
            }

        evidence: List[Dict[str, Any]] = []

        # 检查 VMProtect 字符串
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

        # 检查节名
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




class VMUnvirtualizer:

    def __init__(self) -> None:
        self._logger = logging.getLogger(__name__)

    def trace_bytecode_flow(
        self, handlers: Dict[int, str]
    ) -> List[Dict[str, Any]]:
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
        op_map: Dict[int, str] = {}

        for i, addr in enumerate(handler_addrs):
            # 按发现顺序把 handler 映射到 opcode
            op_map[i] = f"handler_{hex(addr)}"

        return op_map

    def reconstruct_instructions(
        self,
        bytecode: List[int],
        op_map: Dict[int, str],
    ) -> List[str]:
        instructions: List[str] = []

        # opcode 到 x86 助记符映射 (简化版)
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
        self._logger.info(
            "尝试去虚拟化 %s (VM: %s)",
            filepath,
            vm_info.get("vm_type", "UNKNOWN"),
        )

        if vm_info.get("vm_type") == "UNKNOWN":
            return {
                "success": False,
                "error": "未识别 VM 类型",
                "instructions": [],
                "reconstructed_functions": {},
            }

        # 完整去虚拟化需要反汇编器集成:
        # 1. 定位 VM 入口
        # 2. 追踪字节码执行
        # 3. 把 handler 映射到 opcode
        # 4. 重建原生指令
        # 无反汇编器时返回失败标记与可用证据, 不伪造重建结果
        bytecode_pos = 0  # 字节码偏移
        handlers = vm_info.get("handlers") or []
        handler_addrs = [
            h if isinstance(h, int) else h.get("addr", 0) for h in handlers
        ]
        op_map = self.map_handlers([], handler_addrs) if handler_addrs else {}
        bytecode = vm_info.get("bytecode") or []
        instructions = self.reconstruct_instructions(bytecode, op_map)

        return {
            "success": False,
            "note": "完整去虚拟化需要反汇编器集成",
            "vm_type": vm_info.get("vm_type"),
            "confidence": vm_info.get("confidence", 0.0),
            "instructions": instructions,
            "op_map": op_map,
            "reconstructed_functions": {},
            "bytecode_position": bytecode_pos,
        }
