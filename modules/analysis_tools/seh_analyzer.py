#!/usr/bin/env python3
# Entry points: SEHHandler and 3 sibling classes.
# Depends on os, subprocess.
# Time O(1), space O(n).
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

@dataclass
class SEHHandler:
    address: int = 0
    handler_address: int = 0
    scope_start: int = 0
    scope_end: int = 0
    type_info: Optional[str] = None
    is_suspicious: bool = False
    abuse_score: float = 0.0

@dataclass
class SEHAbuse:
    address: int = 0
    description: str = ""
    exploit_potential: float = 0.0
    triggering_input: Optional[str] = None

@dataclass
class AnalysisResult:
    success: bool = False
    handlers: List[SEHHandler] = field(default_factory=list)
    abuse_paths: List[SEHAbuse] = field(default_factory=list)
    warnings: list = field(default_factory=list)

class SEHScanner:
    # SEH scanner.

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.handlers: List[SEHHandler] = []

    def scan_pe_handlers(self) -> List[SEHHandler]:
        # Scans PE exception handling table (.pdata / SafeSEH).
        handlers = []
        try:
            import struct
            with open(self.binary_path, "rb") as f:
                data = f.read()
            # 定位 .pdata 节: PE32 头 + 节表, 解析异常目录项。
            if len(data) < 0x40 or data[:2] != b"MZ":
                return handlers
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
                return handlers
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            section_table = pe_offset + 24 + opt_size
            for i in range(num_sections):
                sec_off = section_table + i * 40
                if sec_off + 40 > len(data):
                    break
                name = data[sec_off:sec_off+8].rstrip(b"\x00").decode("ascii", "ignore")
                if name != ".pdata":
                    continue
                vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec_off + 8)
                raw_end = min(raw_ptr + raw_size, len(data))
                # .pdata 每项 12 字节: BeginAddress, EndAddress, UnwindInfoAddress
                for off in range(raw_ptr, raw_end - 11, 12):
                    begin, end, unwind = struct.unpack_from("<III", data, off)
                    if begin == 0 and unwind == 0:
                        continue
                    handlers.append(SEHHandler(
                        address=begin,
                        handler_address=unwind,
                        scope_start=begin,
                        scope_end=end,
                        type_info="pdata"))
                break
            if handlers:
                logger.info("PE handler scan: %d handler(s) from .pdata", len(handlers))
        except Exception as e:
            logger.warning(f"PE handler scan aborted: {e}")
        return handlers

    def scan_elf_handlers(self) -> List[SEHHandler]:
        # Scans ELF LSDA/GCC exception handling.
        handlers = []
        try:
            result = subprocess.run(
                ["readelf", "-S", self.binary_path],
                capture_output=True, text=True, timeout=30,)

            if result.returncode == 0 and ".eh_frame" in result.stdout:
                for line in result.stdout.split("\n"):
                    if ".eh_frame" in line or ".gcc_except_table" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                addr = int(parts[3], 16)
                                handlers.append(SEHHandler(
                                    address=addr,
                                    handler_address=addr,
                                    scope_start=addr,
                                    scope_end=addr + 0x100,))

                            except (ValueError, IndexError):
                                pass
        except Exception as e:
            logger.warning(f"ELF handler scan aborted: {e}")
        return handlers

class SEHAbuseDetector:
    # SEH abuse detector.

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.scanner = SEHScanner(binary_path)
        self.abuse_paths: List[SEHAbuse] = []

    def detect_abuse(self, handlers: List[SEHHandler]) -> List[SEHAbuse]:
        # Detects SEH abuse patterns.
        abuse = []
        for h in handlers:
            # Checks if handler sits on stack frame.
            if self._is_unusual_handler(h):
                a = SEHAbuse(
                    address=h.address,
                    description=f"Suspicious SEH handler at 0x{h.handler_address:x}",
                    exploit_potential=0.7,
                    triggering_input="crafted exception to hijack control flow",)
                abuse.append(a)
        return abuse

    def _is_unusual_handler(self, handler: SEHHandler) -> bool:
        """Determines whether handler is anomalous."""
        # Simplified heuristic.
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", f"pd 20 @ {hex(handler.handler_address)}", self.binary_path],
                capture_output=True, text=True, timeout=30,)
            if result.returncode == 0:
                # Detects dangerous API calls.
                dangerous = ["memcpy", "strcpy", "VirtualProtect", "WriteProcessMemory"]
                for d in dangerous:
                    if d in result.stdout:
                        return True
        except Exception:
            logger.debug("handler disassembly failed", exc_info=True)
        return False

    def generate_hijack_input(self, abuse: SEHAbuse) -> Optional[bytes]:
        # Generates exception input to hijack control flow.
        try:
            # Constructs exception-triggering payload.
            payload = b"A" * 0x1000
            payload += b"\x00" * 16
            return payload
        except Exception:
            return None

    def run(self) -> AnalysisResult:
        try:
            handlers = self.scanner.scan_pe_handlers() + self.scanner.scan_elf_handlers()
            for h in handlers:
                h.is_suspicious = self._is_unusual_handler(h)
            self.abuse_paths = self.detect_abuse(handlers)
            return AnalysisResult(
                success=True, handlers=handlers, abuse_paths=self.abuse_paths,)

        except Exception as e:
            logger.error(f"SEH analysis aborted: {e}")
            return AnalysisResult(success=False, handlers=[], abuse_paths=[])

def create_seh_analyzer(binary_path: str) -> SEHAbuseDetector:
    return SEHAbuseDetector(binary_path)
