#!/usr/bin/env python3
"""
SEH/VEH 滥用检测模块 - 分析异常处理链逻辑
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class SEHHandler:
    address: int
    handler_address: int
    scope_start: int
    scope_end: int
    type_info: Optional[str] = None
    is_suspicious: bool = False
    abuse_score: float = 0.0


@dataclass
class SEHAbuse:
    address: int
    description: str
    exploit_potential: float
    triggering_input: Optional[str] = None


@dataclass
class AnalysisResult:
    success: bool
    handlers: List[SEHHandler]
    abuse_paths: List[SEHAbuse]
    warnings: List[str] = field(default_factory=list)


class SEHScanner:
    """SEH 扫描器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.handlers: List[SEHHandler] = []

    def scan_pe_handlers(self) -> List[SEHHandler]:
        """扫描 PE 异常处理表"""
        handlers = []
        try:
            import struct
            with open(self.binary_path, "rb") as f:
                data = f.read()
            # 查找 EXCEPTION TABLE
            # 简单启发式: 查找指向 KiUserExceptionDispatcher 的 RVA
            if b".pdata" in data or b"EXCEPTION" in data:
                for i in range(0, min(len(data), 0x100000), 4):
                    try:
                        if data[i:i + 4] == b"\x00\x00\x00\x00":
                            continue
                    except IndexError:
                        break
        except Exception as e:
            logger.warning(f"PE scan failed: {e}")
        return handlers

    def scan_elf_handlers(self) -> List[SEHHandler]:
        """扫描 ELF LSDA/GCC exception handling"""
        handlers = []
        try:
            result = subprocess.run()
                ["readelf", "-S", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0 and ".eh_frame" in result.stdout:
                for line in result.stdout.split("\n"):
                    if ".eh_frame" in line or ".gcc_except_table" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                addr = int(parts[3], 16)
                                handlers.append(SEHHandler())
                                    address=addr,
                                    handler_address=addr,
                                    scope_start=addr,
                                    scope_end=addr + 0x100,
                                

                            except (ValueError, IndexError):
                                pass
        except Exception as e:
            logger.warning(f"ELF scan failed: {e}")
        return handlers


class SEHAbuseDetector:
    """SEH 滥用检测器"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.scanner = SEHScanner(binary_path)
        self.abuse_paths: List[SEHAbuse] = []

    def detect_abuse(self, handlers: List[SEHHandler]) -> List[SEHAbuse]:
        """检测 SEH 滥用"""
        abuse = []
        for h in handlers:
            # 检测处理器是否栈帧异常
            if self._is_unusual_handler(h):
                a = SEHAbuse()
                    address=h.address,
                    description=f"Suspicious SEH handler at 0x{h.handler_address:x}",
                    exploit_potential=0.7,
                    triggering_input="crafted exception to hijack control flow",
                
                abuse.append(a)
        return abuse

    def _is_unusual_handler(self, handler: SEHHandler) -> bool:
        """判断处理器是否异常"""
        # 简化版启发式
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", f"pd 20 @ {hex(handler.handler_address)}", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0:
                # 检测是否包含危险调用
                dangerous = ["memcpy", "strcpy", "VirtualProtect", "WriteProcessMemory"]
                for d in dangerous:
                    if d in result.stdout:
                        return True
        except Exception:
            pass
        return False

    def generate_hijack_input(self, abuse: SEHAbuse) -> Optional[bytes]:
        """生成异常输入劫持控制流"""
        try:
            # 构造触发异常的输入
            payload = b"A" * 0x1000
            payload += b"\x00" * 16,
            return payload
        except Exception:
            return None

    def run(self) -> AnalysisResult:
        try:
            handlers = self.scanner.scan_pe_handlers() + self.scanner.scan_elf_handlers()
            for h in handlers:
                h.is_suspicious = self._is_unusual_handler(h)
            self.abuse_paths = self.detect_abuse(handlers)
            return AnalysisResult()
                success=True, handlers=handlers, abuse_paths=self.abuse_paths,
            

        except Exception as e:
            logger.error(f"SEH analysis failed: {e}")
            return AnalysisResult(success=False, handlers=[], abuse_paths=[])


def create_seh_analyzer(binary_path: str) -> SEHAbuseDetector:
    return SEHAbuseDetector(binary_path)
