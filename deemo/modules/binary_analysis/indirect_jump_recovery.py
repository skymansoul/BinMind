import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

logger = logging.getLogger(__name__)


class JumpTableType(Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    CASE_OFFSET = "case_offset"
    SWITCH_TABLE = "switch_table"


@dataclass
class JumpTarget:
    address: int
    case_value: Optional[int] = None
    target_function: Optional[str] = None
    is_valid: bool = True


@dataclass
class JumpTable:
    table_address: int
    table_type: JumpTableType
    entries: List[JumpTarget]
    base_address: int = 0
    entry_count: int = 0
    entry_size: int = 4
    min_case: Optional[int] = None
    max_case: Optional[int] = None


@dataclass
class SwitchCaseStructure:
    switch_address: int
    condition_register: str
    jump_table: JumpTable
    default_target: Optional[int] = None
    cases: list = field(default_factory=list)
    coverage: float = 0.0


@dataclass
class RecoveryResult:
    success: bool
    switch_structures: List[SwitchCaseStructure]
    jump_tables: List[JumpTable]
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class BaseJumpTableDetector:
    def detect(self, binary_path: str) -> List[JumpTable]:
        return []


class Radare2JumpTableDetector(BaseJumpTableDetector):
    def detect(self, binary_path: str) -> List[JumpTable]:
        jump_tables = []
        try:
            cmd = ["r2", "-q", "-e", "io.color=false", "-c", "aaa; ij", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                import json
                try:
                    info = json.loads(result.stdout)
                    if "bins" in info:
                        for bin_info in info["bins"]:
                            if "tables" in bin_info:
                                for table in bin_info["tables"]:
                                    if isinstance(table, dict):
                                        table_addr = table.get("addr", 0)
                                        jump_tables.append(JumpTable(
                                            table_address=table_addr,
                                            table_type=JumpTableType.DIRECT,
                                            entries=[]))
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            pass
        return jump_tables


class PatternBasedDetector(BaseJumpTableDetector):
    def detect(self, binary_path: str) -> List[JumpTable]:
        jump_tables = []
        try:
            with open(binary_path, "rb") as f:
                content = f.read()
            import re
            patterns = [r"\xff\x25....", r"\xff\x15...."]
            for pattern in patterns:
                for match in re.finditer(pattern.encode(), content):
                    offset = match.start()
                    if offset + 6 <= len(content):
                        table_addr = int.from_bytes(content[offset+2:offset+6], "little")
                        entries = []
                        entry_count = 0
                        table_offset = table_addr
                        while table_offset + 4 <= len(content):
                            entry_value = int.from_bytes(content[table_offset:table_offset+4], "little")
                            if entry_value == 0:
                                break
                            entries.append(JumpTarget(address=entry_value))
                            entry_count += 1
                            table_offset += 4
                            if entry_count > 100:
                                break
                        if entry_count >= 2:
                            jump_tables.append(JumpTable(
                                table_address=table_addr,
                                table_type=JumpTableType.DIRECT,
                                entries=entries,
                                entry_count=entry_count))
        except Exception as e:
            pass
        return jump_tables


class IndirectJumpRecovery:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"File not found: {self.binary_path}")
        self.detectors = [Radare2JumpTableDetector(), PatternBasedDetector()]
        self.jump_tables: List[JumpTable] = []
        self.switch_structures: List[SwitchCaseStructure] = []
        logger.info(f"IndirectJumpRecovery initialized: {binary_path}")

    def detect_jump_tables(self) -> List[JumpTable]:
        logger.info("Detecting jump tables...")
        all_tables = []
        seen_addrs = set()
        for detector in self.detectors:
            tables = detector.detect(self.binary_path)
            for table in tables:
                if table.table_address not in seen_addrs:
                    seen_addrs.add(table.table_address)
                    all_tables.append(table)
        self.jump_tables = all_tables
        logger.info(f"Found {len(all_tables)} jump tables")
        return all_tables

    def recover_switch_structures(self) -> List[SwitchCaseStructure]:
        logger.info("Recovering switch-case structures...")
        if not self.jump_tables:
            self.detect_jump_tables()
        structures = []
        for table in self.jump_tables:
            cases = []
            case_values = []
            for i, entry in enumerate(table.entries):
                if entry.is_valid:
                    case_value = table.min_case + i if table.min_case else i
                    case_values.append(case_value)
                    cases.append((case_value, entry.address))
            if cases:
                min_c, max_c = min(case_values), max(case_values)
                coverage = len(case_values) / (max_c - min_c + 1)
                structures.append(SwitchCaseStructure(
                    switch_address=table.table_address,
                    condition_register="eax",
                    jump_table=table,
                    cases=cases,
                    coverage=coverage))
        self.switch_structures = structures
        logger.info(f"Recovered {len(structures)} switch-case structures")
        return structures

    def generate_pseudocode(self, switch_struct: SwitchCaseStructure) -> str:
        lines = []
        lines.append(f"switch ({switch_struct.condition_register}) {{")
        for case_value, target_addr in sorted(switch_struct.cases):
            lines.append(f"    case {case_value}:")
            lines.append(f"        // jump to 0x{target_addr:x}")
            lines.append(f"        break;")
        if switch_struct.default_target:
            lines.append(f"    default:")
            lines.append(f"        // jump to 0x{switch_struct.default_target:x}")
            lines.append(f"        break;")
        lines.append("}")
        return "\n".join(lines)

    def generate_report(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append("Indirect Jump Table Recovery Report")
        lines.append("=" * 60)
        lines.append(f"Jump tables: {len(self.jump_tables)}")
        lines.append(f"Switch structures: {len(self.switch_structures)}")
        return "\n".join(lines)

    def run(self) -> RecoveryResult:
        logger.info("Running jump table recovery...")
        try:
            self.detect_jump_tables()
            self.recover_switch_structures()
            return RecoveryResult(
                success=True,
                switch_structures=self.switch_structures,
                jump_tables=self.jump_tables)
        except Exception as e:
            logger.error(f"Recovery failed: {e}")
            return RecoveryResult(success=False, switch_structures=[], jump_tables=[], errors=[str(e)])


def create_jump_table_recovery(binary_path: str) -> IndirectJumpRecovery:
    return IndirectJumpRecovery(binary_path)
