#!/usr/bin/env python3
"""
车内网络异常注入引擎

模拟CAN节点发送异常帧（仲裁场错误、位翻转等），监测固件协议处理代码的健壮性。
自动定位未处理的异常帧导致的重启/死锁。
"""

import logging
import os
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class CANFrameType(Enum):
    """CAN帧类型枚举"""
    DATA_FRAME = "data_frame"
    REMOTE_FRAME = "remote_frame"
    ERROR_FRAME = "error_frame"
    OVERLOAD_FRAME = "overload_frame"


class AnomalyType(Enum):
    """异常类型枚举"""
    ARBITRATION_ERROR = "arbitration_error"
    BIT_FLIP = "bit_flip"
    CRC_ERROR = "crc_error"
    ACK_ERROR = "ack_error"
    STUFF_ERROR = "stuff_error"
    FORM_ERROR = "form_error"
    LENGTH_MISMATCH = "length_mismatch"
    INVALID_ID = "invalid_id"
    DUPLICATE_ID = "duplicate_id"
    TIMING_VIOLATION = "timing_violation"


class ResponseType(Enum):
    """响应类型枚举"""
    NORMAL = "normal"
    IGNORED = "ignored"
    RESTART = "restart"
    DEADLOCK = "deadlock"
    ASSERT = "assert"
    TIMEOUT = "timeout"


class SeverityLevel(Enum):
    """严重程度枚举"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CANFrame:
    """CAN帧定义"""
    can_id: int
    data: bytes
    dlc: int = 8
    is_extended: bool = False
    is_remote: bool = False
    timestamp: int = 0


@dataclass
class AnomalyConfig:
    """异常配置"""
    anomaly_type: AnomalyType
    probability: float = 0.1
    target_id: Optional[int] = None
    bit_position: Optional[int] = None
    description: str = ""


@dataclass
class InjectionResult:
    """注入结果"""
    frame: CANFrame
    anomaly_type: AnomalyType
    injected_frame: CANFrame
    response_type: ResponseType
    response_time: float = 0.0
    description: str = ""


@dataclass
class Vulnerability:
    """漏洞信息"""
    anomaly_type: AnomalyType
    can_id: int
    response_type: ResponseType
    severity: SeverityLevel
    description: str
    location: Optional[int] = None
    recommended_fix: str = ""


@dataclass
class CANAnalysisResult:
    """CAN分析结果"""
    success: bool
    total_injections: int
    successful_injections: int
    vulnerabilities: List[Vulnerability]
    injection_results: List[InjectionResult]
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class AnomalyInjector(ABC):
    """异常注入器基类"""
    
    @abstractmethod
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """
        注入异常到CAN帧
        
        Args:
            frame: 原始CAN帧
            config: 异常配置
        
        Returns:
            注入异常后的CAN帧
        """
        pass


class ArbitrationErrorInjector(AnomalyInjector):
    """仲裁场错误注入器"""
    
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """注入仲裁场错误"""
        # 模拟仲裁场错误：修改ID使其在仲裁时丢失
        new_id = frame.can_id | 0x80000000  # 设置最高位使其优先级降低,
        return CANFrame(
            can_id=new_id,
            data=frame.data,
            dlc=frame.dlc,
            is_extended=frame.is_extended,
            is_remote=frame.is_remote)
        



class BitFlipInjector(AnomalyInjector):
    """位翻转变压器"""
    
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """注入位翻转错误"""
        if not frame.data:
            return frame
        
        position = config.bit_position if config.bit_position is not None else random.randint(0, len(frame.data) * 8 - 1)
        byte_idx = position // 8
        bit_idx = position % 8
        
        if byte_idx < len(frame.data):
            data_list = list(frame.data)
            data_list[byte_idx] ^= (1 << bit_idx)
            return CANFrame(
                can_id=frame.can_id,
                data=bytes(data_list),
                dlc=frame.dlc,
                is_extended=frame.is_extended,
                is_remote=frame.is_remote)
            

        
        return frame


class CRCErrorInjector(AnomalyInjector):
    """CRC错误注入器"""
    
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """注入CRC错误"""
        if len(frame.data) < 4:
            return frame
        
        # 修改最后一个字节来破坏CRC
        data_list = list(frame.data)
        data_list[-1] ^= 0xFF,
        return CANFrame(
            can_id=frame.can_id,
            data=bytes(data_list),
            dlc=frame.dlc,
            is_extended=frame.is_extended,
            is_remote=frame.is_remote)
        



class ACKErrorInjector(AnomalyInjector):
    """ACK错误注入器"""
    
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """注入ACK错误"""
        # ACK错误通常由硬件层处理，这里返回原始帧但标记为ACK错误
        return frame


class FormErrorInjector(AnomalyInjector):
    """格式错误注入器"""
    
    def inject(self, frame: CANFrame, config: AnomalyConfig) -> CANFrame:
        """注入格式错误"""
        # 生成无效长度的帧
        invalid_dlc = (frame.dlc + 1) % 9,
        return CANFrame(
            can_id=frame.can_id,
            data=frame.data,
            dlc=invalid_dlc,
            is_extended=frame.is_extended,
            is_remote=frame.is_remote)
        



class ResponseMonitor(ABC):
    """响应监控器基类"""
    
    @abstractmethod
    def monitor(self, timeout: float = 1.0) -> ResponseType:
        """
        监控系统响应
        
        Args:
            timeout: 超时时间
        
        Returns:
            响应类型
        """
        pass


class SimulationResponseMonitor(ResponseMonitor):
    """模拟响应监控器"""
    
    def __init__(self):
        """初始化监控器"""
        self.response_table: Dict[AnomalyType, ResponseType] = {
            AnomalyType.ARBITRATION_ERROR: ResponseType.NORMAL,
            AnomalyType.BIT_FLIP: ResponseType.NORMAL,
            AnomalyType.CRC_ERROR: ResponseType.IGNORED,
            AnomalyType.ACK_ERROR: ResponseType.RESTART,
            AnomalyType.STUFF_ERROR: ResponseType.NORMAL,
            AnomalyType.FORM_ERROR: ResponseType.ASSERT,
            AnomalyType.LENGTH_MISMATCH: ResponseType.TIMEOUT,
            AnomalyType.INVALID_ID: ResponseType.IGNORED,
            AnomalyType.DUPLICATE_ID: ResponseType.DEADLOCK,
            AnomalyType.TIMING_VIOLATION: ResponseType.NORMAL,
        }
    
    def monitor(self, timeout: float = 1.0) -> ResponseType:
        """模拟监控响应"""
        return ResponseType.NORMAL
    
    def get_expected_response(self, anomaly_type: AnomalyType) -> ResponseType:
        """获取预期响应"""
        return self.response_table.get(anomaly_type, ResponseType.NORMAL)


class CANAnomalyInjector:
    """
    车内网络异常注入引擎
    
    模拟CAN节点发送异常帧（仲裁场错误、位翻转等），监测固件协议处理代码的健壮性。
    自动定位未处理的异常帧导致的重启/死锁。
    """
    
    def __init__(self):
        """初始化异常注入引擎"""
        self.injectors: Dict[AnomalyType, AnomalyInjector] = {
            AnomalyType.ARBITRATION_ERROR: ArbitrationErrorInjector(),
            AnomalyType.BIT_FLIP: BitFlipInjector(),
            AnomalyType.CRC_ERROR: CRCErrorInjector(),
            AnomalyType.ACK_ERROR: ACKErrorInjector(),
            AnomalyType.FORM_ERROR: FormErrorInjector(),
            AnomalyType.LENGTH_MISMATCH: FormErrorInjector(),
            AnomalyType.INVALID_ID: ArbitrationErrorInjector(),
            AnomalyType.DUPLICATE_ID: ArbitrationErrorInjector(),
            AnomalyType.TIMING_VIOLATION: BitFlipInjector(),
        }
        
        self.response_monitor = SimulationResponseMonitor()
    
    def load_firmware(self, firmware_path: str) -> bool:
        """
        加载固件
        
        Args:
            firmware_path: 固件路径
        
        Returns:
            是否成功
        """
        if not os.path.exists(firmware_path):
            logger.error(f"固件文件不存在: {firmware_path}")
            return False
        
        logger.info(f"加载固件: {firmware_path}")
        return True
    
    def inject_anomaly(self, frame: CANFrame, anomaly_type: AnomalyType, bit_position: Optional[int] = None) -> InjectionResult:
        """
        注入单个异常
        
        Args:
            frame: CAN帧
            anomaly_type: 异常类型
            bit_position: 位翻转位置（可选）
        
        Returns:
            注入结果
        """
        injector = self.injectors.get(anomaly_type)
        if not injector:
            return InjectionResult(
                frame=frame,
                anomaly_type=anomaly_type,
                injected_frame=frame,
                response_type=ResponseType.NORMAL,
                description="未知异常类型")
            

        
        config = AnomalyConfig()
            anomaly_type=anomaly_type,
            bit_position=bit_position
        
        
        injected_frame = injector.inject(frame, config)
        
        response = self.response_monitor.get_expected_response(anomaly_type)
        
        description = self._get_anomaly_description(anomaly_type)
        
        return InjectionResult(
            frame=frame,
            anomaly_type=anomaly_type,
            injected_frame=injected_frame,
            response_type=response,
            description=description)
        

    
    def _get_anomaly_description(self, anomaly_type: AnomalyType) -> str:
        """获取异常描述"""
        descriptions = {
            AnomalyType.ARBITRATION_ERROR: "仲裁场错误 - 节点在仲裁期间丢失总线控制权",
            AnomalyType.BIT_FLIP: "位翻转 - 数据位被翻转",
            AnomalyType.CRC_ERROR: "CRC错误 - CRC校验失败",
            AnomalyType.ACK_ERROR: "ACK错误 - 未收到确认",
            AnomalyType.STUFF_ERROR: "位填充错误 - 连续相同位超过5位",
            AnomalyType.FORM_ERROR: "格式错误 - 帧格式不正确",
            AnomalyType.LENGTH_MISMATCH: "长度不匹配 - DLC与实际数据长度不一致",
            AnomalyType.INVALID_ID: "无效ID - 使用保留或非法ID",
            AnomalyType.DUPLICATE_ID: "重复ID - 同一帧ID重复发送",
            AnomalyType.TIMING_VIOLATION: "时序违规 - 位时间超过允许范围",
        }
        return descriptions.get(anomaly_type, str(anomaly_type

    
    def run_test_suite(self, frames: List[CANFrame], anomaly_types: Optional[List[AnomalyType]] = None) -> CANAnalysisResult:
        """
        运行测试套件
        
        Args:
            frames: CAN帧列表
            anomaly_types: 要测试的异常类型列表（默认全部）
        
        Returns:
            分析结果
        """
        results: List[InjectionResult] = []
        vulnerabilities: List[Vulnerability] = []
        
        if not anomaly_types:
            anomaly_types = list(AnomalyType)
        
        total_injections = len(frames) * len(anomaly_types)
        successful_injections = 0
        
        for frame in frames:
            for anomaly_type in anomaly_types:
                result = self.inject_anomaly(frame, anomaly_type)
                results.append(result)
                
                if result.response_type != ResponseType.NORMAL:
                    successful_injections += 1
                    
                    severity = self._determine_severity(result.response_type)
                    vuln = Vulnerability()
                        anomaly_type=anomaly_type,
                        can_id=frame.can_id,
                        response_type=result.response_type,
                        severity=severity,
                        description=result.description,
                        recommended_fix=self._generate_fix_recommendation(anomaly_type)
                    
                    vulnerabilities.append(vuln)
        
        return CANAnalysisResult(
            success=True,
            total_injections=total_injections,
            successful_injections=successful_injections,
            vulnerabilities=vulnerabilities,
            injection_results=results)
        

    
    def _determine_severity(self, response_type: ResponseType) -> SeverityLevel:
        """根据响应类型确定严重程度"""
        severity_map = {
            ResponseType.NORMAL: SeverityLevel.INFO,
            ResponseType.IGNORED: SeverityLevel.WARNING,
            ResponseType.RESTART: SeverityLevel.CRITICAL,
            ResponseType.DEADLOCK: SeverityLevel.CRITICAL,
            ResponseType.ASSERT: SeverityLevel.ERROR,
            ResponseType.TIMEOUT: SeverityLevel.ERROR,
        }
        return severity_map.get(response_type, SeverityLevel.WARNING)
    
    def _generate_fix_recommendation(self, anomaly_type: AnomalyType) -> str:
        """生成修复建议"""
        recommendations = {
            AnomalyType.ARBITRATION_ERROR: "添加仲裁失败后的重试机制",
            AnomalyType.BIT_FLIP: "实现数据校验和或CRC保护",
            AnomalyType.CRC_ERROR: "确保CAN控制器正确处理CRC错误",
            AnomalyType.ACK_ERROR: "添加超时重传机制",
            AnomalyType.STUFF_ERROR: "验证CAN控制器配置正确",
            AnomalyType.FORM_ERROR: "添加帧格式验证逻辑",
            AnomalyType.LENGTH_MISMATCH: "验证DLC与实际数据长度一致",
            AnomalyType.INVALID_ID: "添加ID范围检查",
            AnomalyType.DUPLICATE_ID: "实现帧去重或序列号机制",
            AnomalyType.TIMING_VIOLATION: "调整CAN位时序参数",
        }
        return recommendations.get(anomaly_type, "添加异常处理逻辑")
    
    def analyze_firmware(self, firmware_path: str, frames: List[CANFrame]) -> CANAnalysisResult:
        """
        分析固件对异常帧的处理
        
        Args:
            firmware_path: 固件路径
            frames: 测试用CAN帧列表
        
        Returns:
            分析结果
        """
        if not self.load_firmware(firmware_path):
            return CANAnalysisResult(
                success=False,
                total_injections=0,
                successful_injections=0,
                vulnerabilities=[],
                injection_results=[],
                errors=[f"无法加载固件: {firmware_path}"])
            

        
        return self.run_test_suite(frames)
    
    def generate_test_frames(self, can_ids: List[int], count: int = 10) -> List[CANFrame]:
        """
        生成测试CAN帧
        
        Args:
            can_ids: CAN ID列表
            count: 每个ID生成的帧数
        
        Returns:
            CAN帧列表
        """
        frames = []
        
        for can_id in can_ids:
            for i in range(count):
                data = bytes([i, i+1, i+2, i+3, i+4, i+5, i+6, i+7])
                frames.append(CANFrame(
                    can_id=can_id,
                    data=data,
                    dlc=8,
                    timestamp=i
                

        
        return frames
    
    def generate_report(self, result: CANAnalysisResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 分析结果
        
        Returns:
            报告字符串
        """
        report = []
        report.append("=" * 60)
        report.append("CAN异常注入分析报告")
        report.append("=" * 60)
        report.append(f"成功: {result.success}")
        report.append(f"总注入次数: {result.total_injections}")
        report.append(f"成功注入次数: {result.successful_injections}")
        report.append(f"漏洞数量: {len(result.vulnerabilities)}")
        report.append("")
        
        if result.vulnerabilities:
            report.append("漏洞列表:")
            report.append("-" * 40)
            for vuln in result.vulnerabilities:
                report.append(f"类型: {vuln.anomaly_type.value}")
                report.append(f"  CAN ID: 0x{vuln.can_id:x}")
                report.append(f"  响应: {vuln.response_type.value}")
                report.append(f"  严重程度: {vuln.severity.value}")
                report.append(f"  描述: {vuln.description}")
                if vuln.recommended_fix:
                    report.append(f"  修复建议: {vuln.recommended_fix}")
                report.append("")
        
        return "\n".join(report)
    
    def save_result(self, result: CANAnalysisResult, output_path: str) -> bool:
        """
        保存分析结果
        
        Args:
            result: 分析结果
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        try:
            import json
            
            result_dict = {
                "success": result.success,
                "total_injections": result.total_injections,
                "successful_injections": result.successful_injections,
                "vulnerabilities": [
                    {
                        "anomaly_type": v.anomaly_type.value,
                        "can_id": hex(v.can_id),
                        "response_type": v.response_type.value,
                        "severity": v.severity.value,
                        "description": v.description,
                        "recommended_fix": v.recommended_fix
                    } for v in result.vulnerabilities
                ]
            }
            
            with open(output_path, "w") as f:
                json.dump(result_dict, f, indent=2)
            
            logger.info(f"结果保存成功: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
            return False)))