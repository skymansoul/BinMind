#!/usr/bin/env python3
# 入口: SEH处理器 3 sibling classes. 依赖 os, subprocess
#
# 2025 升级: VEH (Vectored 异常处理) 链分析 + SEH 覆写检测
# SEH 利用的两条路径：(1) 栈溢出覆盖 SEH 链中的 handler 指针；
# (2) 通过 AddVectored异常处理器(1,.) 注册的 VEH 在 SEH 之前触发
# 本模块增加对 VEH 优先级的建模和 handler 地址的可写性检查
import logging, os, subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)

@dataclass
class SEHHandler:
    address: int = 0; handler_address: int = 0
    scope_start: int = 0; scope_end: int = 0
    type_info: Optional[str] = None
    is_suspicious: bool = False; abuse_score: float = 0.0
    in_writable_section: bool = False  # handler 地址是否在可写段内

@dataclass
class SEHAbuse:
    address: int = 0; description: str = ""
    exploit_potential: float = 0.0
    triggering_input: Optional[bytes] = None

@dataclass
class AnalysisResult:
    success: bool = False
    handlers: List[SEHHandler] = field(default_factory=list)
    abuse_paths: List[SEHAbuse] = field(default_factory=list)
    warnings: list = field(default_factory=list)


# VEH 优先级分析
# VEH (Vectored Exception Handler) 通过 AddVectoredExceptionHandler 注册，
# 优先级高于 SEH —— 在 SEH 链遍历之前先调用 VEH 链
# 若 VEH handler 地址位于可写内存段，攻击者可通过任意写原语劫持 VEH
# 无需触发 SEH 异常即可获得代码执行


class VEHAnalyzer:
    """VEH 链分析器——检测通过 RtlAddVectored异常处理器 注册的 处理器
    VEH 优先级高于 SEH，在 kernel32!Unhandled异常Filter 之前被调用
    """
    _VEH_PAT = __import__('re').compile(
        rb'RtlAddVectoredExceptionHandler|AddVectoredExceptionHandler', re.I)

    def detect_veh_registration(self, binary_data: bytes) -> List[int]:
        """定位 VEH 注册调用点——返回调用指令的偏移列表"""
        offsets: List[int] = []
        for m in self._VEH_PAT.finditer(binary_data):
            offsets.append(m.start())
        return offsets

    def check_handler_writable(self, binary_path: str, handler_addr: int) -> bool:
        """检查 handler 地址所在的段是否有写权限——若有则存在被覆写风险"""
        try:
            import json as _j
            r = subprocess.run(
                ['r2', '-q', '-c', 'iSj; q', binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace')
            sections = _j.loads(r.stdout) if r.stdout.strip() else []
            for sec in sections:
                va = sec.get('vaddr', 0)
                vsize = sec.get('vsize', 0)
                if va <= handler_addr < va + vsize:
                    return 'w' in sec.get('perm', '')
        except Exception:
            pass
        return False


class SEHScanner:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.handlers: List[SEHHandler] = []
        self._veh_analyzer = VEHAnalyzer()

    def scan_pe_handlers(self) -> List[SEHHandler]:
        handlers = []
        try:
            import struct
            with open(self.binary_path, "rb") as f:
                data = f.read()
            if b".pdata" in data or b"EXCEPTION" in data:
                pdata_off = data.find(b".pdata")
                if pdata_off > 0:
                    for i in range(0, min(len(data) - pdata_off, 0x10000), 12):
                        try:
                            begin_addr = struct.unpack_from('<I', data, pdata_off + i)[0]
                            end_addr = struct.unpack_from('<I', data, pdata_off + i + 4)[0]
                            unwind_addr = struct.unpack_from('<I', data, pdata_off + i + 8)[0]
                            if 0x1000 < begin_addr < 0x7FFFFFFF:
                                writable = self._veh_analyzer.check_handler_writable(
                                    self.binary_path, unwind_addr)
                                handlers.append(SEHHandler(
                                    address=begin_addr, handler_address=unwind_addr,
                                    scope_start=begin_addr, scope_end=end_addr,
                                    in_writable_section=writable))
                        except (struct.error, IndexError):
                            break
        except Exception as e:
            logger.warning(f"PE handler scan aborted: {e}")
        return handlers

    def scan_elf_handlers(self) -> List[SEHHandler]:
        handlers = []
        try:
            result = subprocess.run(
                ["readelf", "-S", self.binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and ".eh_frame" in result.stdout:
                for line in result.stdout.split("\n"):
                    if ".eh_frame" in line or ".gcc_except_table" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                addr = int(parts[3], 16)
                                writable = self._veh_analyzer.check_handler_writable(
                                    self.binary_path, addr)
                                handlers.append(SEHHandler(
                                    address=addr, handler_address=addr,
                                    scope_start=addr, scope_end=addr + 0x100,
                                    in_writable_section=writable))
                            except (ValueError, IndexError):
                                pass
        except Exception as e:
            logger.warning(f"ELF handler scan aborted: {e}")
        return handlers


class SEHAbuseDetector:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.scanner = SEHScanner(binary_path)
        self.abuse_paths: List[SEHAbuse] = []

    def detect_abuse(self, handlers: List[SEHHandler]) -> List[SEHAbuse]:
        abuse = []
        for h in handlers:
            # handler 地址在可写段内 = 极高被覆写风险
            if h.in_writable_section:
                abuse.append(SEHAbuse(
                    address=h.address,
                    description=f"Handler at 0x{h.handler_address:x} in WRITABLE section — trivial overwrite target",
                    exploit_potential=0.95,
                    triggering_input=b"A" * 0x1000))
            elif self._is_unusual_handler(h):
                abuse.append(SEHAbuse(
                    address=h.address,
                    description=f"Suspicious SEH handler at 0x{h.handler_address:x}",
                    exploit_potential=0.7,
                    triggering_input=b"crafted exception to hijack control flow"))
        return abuse

    def _is_unusual_handler(self, handler: SEHHandler) -> bool:
        try:
            result = subprocess.run(
                ["r2", "-q", "-c", f"pd 20 @ {hex(handler.handler_address)}",
                 self.binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                dangerous = ["memcpy", "strcpy", "VirtualProtect", "WriteProcessMemory"]
                for d in dangerous:
                    if d in result.stdout: return True
        except Exception:
            logger.debug("error containment activated", exc_info=True)
        return False

    def generate_hijack_input(self, abuse: SEHAbuse) -> Optional[bytes]:
        return abuse.triggering_input

    def run(self) -> AnalysisResult:
        try:
            handlers = self.scanner.scan_pe_handlers() + self.scanner.scan_elf_handlers()
            for h in handlers:
                h.is_suspicious = self._is_unusual_handler(h)
            self.abuse_paths = self.detect_abuse(handlers)
            # 增加可写段统计
            writable_count = sum(1 for h in handlers if h.in_writable_section)
            if writable_count > 0:
                logger.warning(f"{writable_count} handlers in writable sections — high risk")
            return AnalysisResult(
                success=True, handlers=handlers, abuse_paths=self.abuse_paths)
        except Exception as e:
            logger.error(f"SEH analysis aborted: {e}")
            return AnalysisResult(success=False, handlers=[], abuse_paths=[])

def create_seh_analyzer(binary_path: str) -> SEHAbuseDetector:
    return SEHAbuseDetector(binary_path)
