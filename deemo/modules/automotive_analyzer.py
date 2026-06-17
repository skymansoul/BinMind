#!/usr/bin/env python3
"""
CAN/UDS 汽车固件分析模块 - 逆向 CAN 通信矩阵，检测诊断服务权限绕过
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class UDSService(Enum):
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    READ_DATA_BY_ID = 0x22
    SECURITY_ACCESS = 0x27
    TESTER_PRESENT = 0x3E
    WRITE_DATA_BY_ID = 0x2E


class SecurityLevel(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    EXTENDED = "extended"


@dataclass
class CANMessage:
    can_id: int
    data: bytes
    dlc: int
    cycle_time_ms: int
    source_ecu: str


@dataclass
class UDSCommand:
    service: UDSService
    sub_function: int
    security_level: SecurityLevel
    description: str


@dataclass
class SecurityBypass:
    service: UDSService
    severity: str
    description: str
    exploit_steps: List[str]


@dataclass
class CANAnalysisResult:
    success: bool
    messages: List[CANMessage]
    uds_commands: List[UDSCommand]
    bypasses: List[SecurityBypass]


class CANMatrixExtractor:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def extract(self) -> List[CANMessage]:
        messages = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            for i in range(0, min(len(data), 0x10000), 8):
                chunk = data[i:i + 8]
                if len(chunk) == 8 and chunk[0] != 0:
                    can_id = int.from_bytes(chunk[0:4], "little") & 0x7FF
                    messages.append(CANMessage(
                        can_id=can_id, data=chunk[4:8], dlc=4,
                        cycle_time_ms=100, source_ecu="ECU_" + hex(can_id & 0xFF),
                    

        except Exception:
            pass
        return messages[:100]


class UDSParser:
    UDS_SERVICES = {
        0x10: UDSService.DIAGNOSTIC_SESSION_CONTROL,
        0x11: UDSService.ECU_RESET,
        0x22: UDSService.READ_DATA_BY_ID,
        0x27: UDSService.SECURITY_ACCESS,
        0x3E: UDSService.TESTER_PRESENT,
        0x2E: UDSService.WRITE_DATA_BY_ID,
    }

    @staticmethod
    def parse_messages(messages: List[CANMessage]) -> List[UDSCommand]:
        commands = []
        for msg in messages:
            if len(msg.data) >= 1 and msg.data[0] in UDSParser.UDS_SERVICES:
                sub = msg.data[1] if len(msg.data) > 1 else 0
                commands.append(UDSCommand(
                    service=UDSParser.UDS_SERVICES[msg.data[0]],
                    sub_function=sub,
                    security_level=SecurityLevel.LOCKED,
                    description="UDS command " + hex(msg.data[0]),
                

        return commands


class BypassDetector:
    @staticmethod
    def detect(commands: List[UDSCommand]) -> List[SecurityBypass]:
        bypasses = []
        for cmd in commands:
            if cmd.service in (UDSService.WRITE_DATA_BY_ID, UDSService.ECU_RESET):
                bypasses.append(SecurityBypass(
                    service=cmd.service,
                    severity="critical" if cmd.service == UDSService.WRITE_DATA_BY_ID else "high",
                    description="Unauthenticated " + cmd.service.name,
                    exploit_steps=["Connect to OBD-II", "Send " + hex(cmd.service.value)],
                

        return bypasses


class AutomotiveAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.can_extractor = CANMatrixExtractor(binary_path)
        self.uds_parser = UDSParser()
        self.bypass_detector = BypassDetector()

    def run(self) -> CANAnalysisResult:
        try:
            messages = self.can_extractor.extract()
            commands = self.uds_parser.parse_messages(messages)
            bypasses = self.bypass_detector.detect(commands)
            return CANAnalysisResult(
                success=True, messages=messages, uds_commands=commands, bypasses=bypasses)
            

        except Exception as e:
            logger.error("Automotive analysis failed: %s", e)
            return CANAnalysisResult(success=False, messages=[], uds_commands=[], bypasses=[])


def create_automotive_analyzer(binary_path: str) -> AutomotiveAnalyzer:
    return AutomotiveAnalyzer(binary_path)))))))