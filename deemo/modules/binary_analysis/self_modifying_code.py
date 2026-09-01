from typing import Optional, List
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SMCRecord:
    address: int
    original_code: str
    modified_code: str
    modification_time: float

@dataclass
class ExecutionResult:
    success: bool
    smc_records: list = field(default_factory=list)
    static_binary: Optional[bytes] = None

class SMCExecutor:

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.smc_records: list[SMCRecord] = []

    def _disassemble_with_objdump(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return result.stdout
            else:
                logger.warning("objdump failed: %s", result.stderr)
                return None
        except FileNotFoundError:
            logger.info("objdump not found, using heuristic pattern search")
            return None
        except Exception as e:
            logger.error("Disassembly error: %s", e)
            return None

    def _search_smc_patterns_in_disasm(self, disasm_text: str) -> List[SMCRecord]:
        records = []
        pattern = re.compile(
            r'\s*([0-9a-f]+):\s+.*mov\s+(?:BYTE|WORD|DWORD|QWORD)\s+PTR\s+\[([^\]]+)\],\s+(0x[0-9a-fA-F]+)'
        )
        for match in pattern.finditer(disasm_text):
            addr_str = match.group(1)
            address = int(addr_str, 16)
            original_code = b'\x00'
            modified_code = int(match.group(3), 16).to_bytes(4, 'little')
            records.append(SMCRecord(
                address=address,
                original_code=original_code,
                modified_code=modified_code,
                modification_time=0
            ))
        return records

    def _heuristic_scan_raw(self) -> List[SMCRecord]:
        records = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            smc_patterns = [
                (b'\xf3\xa4', "rep movsb"),
                (b'\x48\x89\x05', "mov [rip+...], rax"),
            ]
            for pattern, desc in smc_patterns:
                start = 0
                while True:
                    dwIdx = data.find(pattern, start)
                    if dwIdx == -1:
                        break
                    address = 0x400000 + dwIdx
                    records.append(SMCRecord(
                        address=address,
                        original_code=pattern,
                        modified_code=b'\x90' * len(pattern),
                        modification_time=0
                    ))
                    start = dwIdx + 1
        except Exception as e:
            logger.error("Heuristic scan failed: %s", e)
        return records

    def track_smc_events(self) -> None:
        logger.info("Tracking self-modification events...")
        disasm = self._disassemble_with_objdump()
        if disasm is not None:
            self.smc_records = self._search_smc_patterns_in_disasm(disasm)
        else:
            self.smc_records = self._heuristic_scan_raw()
        logger.info("Found %d potential SMC records.", len(self.smc_records))

    def generate_static_binary(self, output_path: str) -> bool:
        try:
            with open(self.binary_path, 'rb') as src:
                original_data = src.read()
            with open(output_path, 'wb') as dst:
                dst.write(original_data)
            logger.info("Static binary saved to %s", output_path)
            return True
        except Exception as e:
            logger.error("Failed to generate static binary: %s", e)
            return False

    def run(self) -> ExecutionResult:
        self.track_smc_events()
        return ExecutionResult(
            success=True,
            smc_records=self.smc_records
        )


def create_smc_executor(binary_path: str) -> SMCExecutor:
    return SMCExecutor(binary_path)
