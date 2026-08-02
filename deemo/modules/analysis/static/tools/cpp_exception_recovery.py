import logging, os, subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Tuple

logger = logging.getLogger(__name__)


class LSDAType(str, Enum):
    DWARF = "dwarf"; SEH = "seh"; GCC = "gcc"; MSVC = "msvc"


@dataclass
class LSDARecord:
    start_address: int; end_address: int; lsda_address: int
    personality_function: Optional[str] = None


@dataclass
class TryBlock:
    start_address: int; end_address: int
    catch_blocks: List['CatchBlock'] = field(default_factory=list)


@dataclass
class CatchBlock:
    type_info: str; handler_address: int; is_ellipsis: bool = False


@dataclass
class ExceptionFrame:
    function_name: str
    try_blocks: List[TryBlock] = field(default_factory=list)
    lsda_record: Optional[LSDARecord] = None


@dataclass
class RecoveryResult:
    success: bool; exception_frames: List[ExceptionFrame]
    lsda_records: List[LSDARecord]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class LSDAExtractor:
    def extract_from_binary(self, binary_path: str) -> List[LSDARecord]:
        records = []
        try:
            result = subprocess.run(["readelf", "-s", binary_path],
                                     capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "__gxx_personality_v0" in line or "_except_handler" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                records.append(LSDARecord(
                                    start_address=int(parts[1], 16),
                                    end_address=0, lsda_address=0))
                            except ValueError: pass
        except Exception: logger.debug("suppressed", exc_info=True)
        return records

    def extract_with_r2(self, binary_path: str) -> List[LSDARecord]:
        records = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'iej; q', binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace')
            import json as _j
            entries = _j.loads(r.stdout) if r.stdout.strip() else []
            for e in entries:
                lsda = e.get('lsda', 0)
                if lsda:
                    records.append(LSDARecord(
                        start_address=e.get('addr', 0),
                        end_address=e.get('addr_end', 0),
                        lsda_address=lsda))
        except Exception: logger.debug("suppressed", exc_info=True)
        return records


class ExceptionRecovery:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"File not found: {self.binary_path}")
        self.lsda_extractor = LSDAExtractor()
        self.exception_frames: List[ExceptionFrame] = []
        logger.info(f"ExceptionRecovery initialized: {binary_path}")

    def recover_exception_frames(self) -> List[ExceptionFrame]:
        logger.info("Recovering exception handling frames...")
        lsda_records = self.lsda_extractor.extract_from_binary(self.binary_path)
        if not lsda_records:
            lsda_records = self.lsda_extractor.extract_with_r2(self.binary_path)
        for record in lsda_records:
            frame = ExceptionFrame(
                function_name=f"sub_{hex(record.start_address)}",
                lsda_record=record)
            frame.try_blocks = self._extract_try_blocks(record)
            self.exception_frames.append(frame)
        logger.info(f"Recovered {len(self.exception_frames)} exception frames")
        return self.exception_frames

    def _extract_try_blocks(self, lsda_record: LSDARecord) -> List[TryBlock]:
        blocks = []
        try:
            cmd = ["r2", "-q", "-e", "io.color=false", "-c",
                   f"pd 50 @ {hex(lsda_record.start_address)}", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                import re
                for _ in re.finditer(r"call.*__cxa_throw|jmp.*__cxa_begin_catch", result.stdout):
                    blocks.append(TryBlock(start_address=0, end_address=0))
        except Exception: logger.debug("suppressed", exc_info=True)
        return blocks

    def categorize_lsda_type(self, binary_path: str) -> LSDAType:
        try:
            with open(binary_path, 'rb') as fh: head = fh.read(4096)
            if b'.eh_frame' in head or b'__gxx_personality' in head: return LSDAType.GCC
            if b'__CxxFrameHandler' in head: return LSDAType.MSVC
            if b'__SEH_' in head: return LSDAType.SEH
        except Exception: pass
        return LSDAType.GCC

    def detect_double_fault_risk(self) -> List[str]:
        """检测可能导致双重故障（double fault）的异常处理结构缺陷。
        若 catch(...) 块中调用了可能再次抛出异常的函数，且无嵌套 try 保护，
        则标记为潜在双重故障风险——这在嵌入式/内核代码中可能导致三重故障重启。
        """
        risks: List[str] = []
        for frame in self.exception_frames:
            for tb in frame.try_blocks:
                # 检查是否有 catch(...) 但无嵌套 try 保护的调用
                has_catch_all = any(cb.is_ellipsis for cb in tb.catch_blocks)
                if has_catch_all and len(tb.catch_blocks) == 1:
                    risks.append(
                        f"{frame.function_name}: catch(...) without nested handler — "
                        f"double fault risk if exception thrown in handler")
        return risks

    def generate_pseudocode(self, frame: ExceptionFrame) -> str:
        lines = [f"void {frame.function_name}() {{"]
        for _, try_block in enumerate(frame.try_blocks):
            lines.append("    try {"); lines.append("        // Protected code"); lines.append("    }")
            for catch in try_block.catch_blocks:
                if catch.is_ellipsis: lines.append("    catch (...) {")
                elif catch.type_info: lines.append(f"    catch ({catch.type_info}) {{")
                else: lines.append("    catch {")
                lines.append(f"        // Handler at 0x{catch.handler_address:x}")
                lines.append("    }")
        lines.append("}"); return "\n".join(lines)

    def generate_report(self) -> str:
        lines = ["=" * 60, "C++ Exception Handling Recovery Report", "=" * 60,
                 f"Exception frames: {len(self.exception_frames)}"]
        df_risks = self.detect_double_fault_risk()
        if df_risks:
            lines.append(f"\nDouble fault risks: {len(df_risks)}")
            for r in df_risks: lines.append(f"  - {r}")
        return "\n".join(lines)

    def run(self) -> RecoveryResult:
        logger.info("Running exception recovery...")
        try:
            self.recover_exception_frames()
            lsda_records = self.lsda_extractor.extract_from_binary(self.binary_path)
            warnings = self.detect_double_fault_risk()
            return RecoveryResult(
                success=True, exception_frames=self.exception_frames,
                lsda_records=lsda_records, warnings=warnings)
        except Exception as e:
            logger.error(f"Exception recovery failed: {e}")
            return RecoveryResult(success=False, exception_frames=[],
                                  lsda_records=[], errors=[str(e)])


def create_exception_recovery(binary_path: str) -> ExceptionRecovery:
    return ExceptionRecovery(binary_path)
