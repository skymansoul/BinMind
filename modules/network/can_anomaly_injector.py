"""
CAN 总线异常注入器 —— 面向车载网络的模糊测试框架。

注入仲裁错误/位翻转/CRC 错误等异常，评估控制器响应。
"""

from __future__ import annotations

import json
import logging
import os
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CANFrameType(Enum):
    DATA_FRAME = "data_frame"
    REMOTE_FRAME = "remote_frame"
    ERROR_FRAME = "error_frame"
    OVERLOAD_FRAME = "overload_frame"


class AnomalyType(Enum):
    ARBITRATION_ERROR = "arbitration_error"
    BIT_FLIP = "bit_flip"
    CRC_ERROR = "crc_error"
    ACK_ERROR = "ack_error"
    FORM_ERROR = "form_error"


class ResponseType(Enum):
    NORMAL = "normal"
    RESTART = "restart"
    DEADLOCK = "deadlock"
    TIMEOUT = "timeout"


class SeverityLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CANFrame:
    can_id: int = 0
    data: bytes = b""
    dlc: int = 0
    is_extended: bool = False
    is_remote: bool = False
    timestamp: int = 0


@dataclass
class AnomalyConfig:
    anomaly_type: AnomalyType = AnomalyType.BIT_FLIP
    probability: float = 0.5
    target_id: int = 0
    bit_position: int = -1
    description: str = ""


@dataclass
class InjectionResult:
    anomaly_type: AnomalyType = AnomalyType.BIT_FLIP
    frame: Optional[CANFrame] = None
    success: bool = False
    description: str = ""


@dataclass
class Vulnerability:
    anomaly_type: AnomalyType = AnomalyType.BIT_FLIP
    can_id: int = 0
    response_type: ResponseType = ResponseType.NORMAL
    severity: SeverityLevel = SeverityLevel.INFO
    description: str = ""
    location: int = 0
    recommended_fix: str = ""


@dataclass
class CANAnalysisResult:
    success: bool = False
    total_injections: int = 0
    successful_injections: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    injection_results: List[InjectionResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class ArbitrationErrorInjector:
    """仲裁错误注入 —— 修改 CAN ID 模拟总线仲裁冲突。"""

    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        new_id = frame.can_id ^ 0x800
        return CANFrame(can_id=new_id, data=frame.data, dlc=frame.dlc,
                        is_extended=frame.is_extended, is_remote=frame.is_remote,
                        timestamp=frame.timestamp)


class BitFlipInjector:
    """位翻转注入 —— 翻转数据字节中的指定位。"""

    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        data = bytearray(frame.data)
        if not data:
            return CANFrame(can_id=frame.can_id, data=b"", dlc=0)
        if config.bit_position >= 0:
            byte_idx = config.bit_position // 8
            bit_idx = config.bit_position % 8
            if byte_idx < len(data):
                data[byte_idx] ^= (1 << bit_idx)
        else:
            byte_idx = random.randrange(len(data))
            bit_idx = random.randrange(8)
            data[byte_idx] ^= (1 << bit_idx)
        return CANFrame(can_id=frame.can_id, data=bytes(data), dlc=len(data),
                        is_extended=frame.is_extended, is_remote=frame.is_remote,
                        timestamp=frame.timestamp)


class CRCErrorInjector:
    """CRC 错误注入 —— 破坏数据尾字节。"""

    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        data = bytearray(frame.data)
        if data:
            data[-1] ^= 0xFF
        return CANFrame(can_id=frame.can_id, data=bytes(data), dlc=len(data),
                        is_extended=frame.is_extended, is_remote=frame.is_remote,
                        timestamp=frame.timestamp)


class CANAnomalyInjector:
    """CAN 异常注入主引擎。"""

    _INJECTORS = {
        AnomalyType.ARBITRATION_ERROR: ArbitrationErrorInjector,
        AnomalyType.BIT_FLIP: BitFlipInjector,
        AnomalyType.CRC_ERROR: CRCErrorInjector,
    }

    def __init__(self):
        self.firmware: Optional[bytes] = None

    def load_firmware(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        with open(path, 'rb') as fh:
            self.firmware = fh.read()
        return True

    def _inject_frame(self, frame: CANFrame, anomaly_type: AnomalyType) -> InjectionResult:
        injector_cls = self._INJECTORS.get(anomaly_type)
        if injector_cls is None:
            return InjectionResult(anomaly_type=anomaly_type, frame=frame,
                                   success=False, description="未知注入类型")
        injector = injector_cls()
        config = AnomalyConfig(anomaly_type=anomaly_type)
        result_frame = injector.inject(frame, config)
        return InjectionResult(anomaly_type=anomaly_type, frame=result_frame,
                               success=True, description=anomaly_type.value)

    def inject_anomaly(self, frame: CANFrame, anomaly_type: AnomalyType) -> InjectionResult:
        return self._inject_frame(frame, anomaly_type)

    def run_test_suite(self, frames: List[CANFrame],
                       anomaly_types: List[AnomalyType]) -> CANAnalysisResult:
        injections: List[InjectionResult] = []
        total = 0
        success = 0
        for frame in frames:
            for atype in anomaly_types:
                total += 1
                result = self._inject_frame(frame, atype)
                injections.append(result)
                if result.success:
                    success += 1
        return CANAnalysisResult(
            success=True, total_injections=total, successful_injections=success,
            injection_results=injections, vulnerabilities=[], warnings=[])

    def generate_test_frames(self, can_ids: List[int], count: int = 1) -> List[CANFrame]:
        frames = []
        for cid in can_ids:
            for _ in range(count):
                frames.append(CANFrame(can_id=cid, data=bytes(8), dlc=8))
        return frames

    def generate_report(self, result: CANAnalysisResult) -> str:
        lines = [
            "CAN异常注入分析报告",
            "=" * 40,
            f"总注入次数: {result.total_injections}",
            f"成功注入: {result.successful_injections}",
            f"发现漏洞数: {len(result.vulnerabilities)}",
        ]
        for v in result.vulnerabilities:
            lines.append(f"  [{v.severity.value}] {v.anomaly_type.value} @ 0x{v.can_id:X}: {v.description}")
        return "\n".join(lines)

    def save_result(self, result: CANAnalysisResult, output_path: str) -> bool:
        try:
            data = {
                'success': result.success,
                'total_injections': result.total_injections,
                'successful_injections': result.successful_injections,
                'injection_results': [
                    {
                        'anomaly_type': r.anomaly_type.value,
                        'success': r.success,
                        'can_id': r.frame.can_id if r.frame else 0,
                    }
                    for r in result.injection_results
                ],
                'vulnerabilities': [
                    {
                        'anomaly_type': v.anomaly_type.value,
                        'can_id': v.can_id,
                        'severity': v.severity.value,
                        'description': v.description,
                    }
                    for v in result.vulnerabilities
                ],
            }
            with open(output_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            return True
        except OSError:
            return False

    def analyze_firmware(self, firmware_path: str, frames: List[CANFrame]) -> CANAnalysisResult:
        if not self.load_firmware(firmware_path):
            return CANAnalysisResult(
                success=False, total_injections=0, successful_injections=0,
                vulnerabilities=[], injection_results=[],
                warnings=["固件加载失败"])
        suite = self.run_test_suite(
            frames, [AnomalyType.BIT_FLIP, AnomalyType.CRC_ERROR,
                     AnomalyType.ARBITRATION_ERROR])
        return CANAnalysisResult(
            success=True, total_injections=suite.total_injections,
            successful_injections=suite.successful_injections,
            injection_results=suite.injection_results,
            vulnerabilities=[], warnings=[])
