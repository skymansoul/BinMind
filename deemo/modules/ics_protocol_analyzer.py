#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工业控制系统协议解析与漏洞挖掘模块

提供ICS/SCADA协议的分析和漏洞挖掘能力：
- 支持多种ICS协议（Modbus, DNP3, IEC 61850, PROFINET, EtherNet/IP）
- 协议特征识别
- 二进制中ICS协议栈识别
- 协议解析漏洞检测
- 畸形报文生成
"""

import logging
import os
import struct
import random
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class ICSProtocol(Enum):
    """ICS协议类型"""
    MODBUS_TCP = "modbus_tcp"
    MODBUS_RTU = "modbus_rtu"
    DNP3 = "dnp3"
    IEC_61850 = "iec_61850"
    MMS = "mms"
    PROFINET = "profinet"
    ETHERNET_IP = "ethernet_ip"
    S7COMM = "s7comm"
    BACNET = "bacnet"
    OPC_UA = "opc_ua"


class VulnerabilityType(Enum):
    """ICS相关漏洞类型"""
    LENGTH_NOT_CHECKED = "length_not_checked"      # 长度字段未校验
    INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"  # 索引越界
    OBJECT_TYPE_CONFUSION = "object_type_confusion"  # 对象类型混淆
    BUFFER_OVERFLOW = "buffer_overflow"          # 缓冲区溢出
    AUTHENTICATION_BYPASS = "auth_bypass"        # 认证绕过
    DENIAL_OF_SERVICE = "dos"                    # 拒绝服务
    MEMORY_CORRUPTION = "memory_corruption"      # 内存损坏


@dataclass
class ProtocolFeature:
    """协议特征"""
    protocol: ICSProtocol
    default_port: int
    function_codes: List[int]
    object_types: List[str]
    header_pattern: bytes
    magic_bytes: bytes
    description: str


@dataclass
class ICSFunction:
    """ICS协议处理函数"""
    function_name: str
    address: int
    protocol: ICSProtocol
    handles_function_code: bool
    parses_object_type: bool
    checks_length: bool
    has_vulnerabilities: List[VulnerabilityType] = field(default_factory=list)


@dataclass
class MalformedPacket:
    """畸形数据包"""
    packet_id: str
    protocol: ICSProtocol
    original_packet: bytes
    malformed_packet: bytes
    mutation_type: str
    description: str
    target_vulnerability: VulnerabilityType
    expected_behavior: str = ""


@dataclass
class ICSAnalysisResult:
    """ICS分析结果"""
    binary_path: str
    detected_protocols: List[ICSProtocol]
    identified_functions: List[ICSFunction]
    detected_vulnerabilities: List[Dict[str, Any]]
    generated_packets: List[MalformedPacket]
    summary: str
    analysis_time: float


class ICSProtocolFeatureDatabase:
    """
    ICS协议特征数据库

    维护ICS协议的特征信息：
    - 端口号
    - 功能码
    - 对象类型
    - 协议头格式
    """

    def __init__(self):
        """初始化协议特征数据库"""
        self.features: Dict[ICSProtocol, ProtocolFeature] = {}
        self._init_modbus()
        self._init_dnp3()
        self._init_iec61850()
        self._init_profinet()
        self._init_ethernet_ip()
        self._init_s7comm()

    def _init_modbus(self):
        """初始化Modbus协议特征"""
        self.features[ICSProtocol.MODBUS_TCP] = ProtocolFeature(
            protocol=ICSProtocol.MODBUS_TCP,
            default_port=502,
            function_codes=list(range(1, 128)) + list(range(128, 256)),  # 包括异常码
            object_types=['coil', 'discrete_input', 'holding_register', 'input_register'],
            header_pattern=b'\x00\x00',  # Transaction ID (2 bytes)
            magic_bytes=b'\x00\x00\x00\x00',  # Protocol ID + Length
            description="Modbus TCP 协议"
        )

        self.features[ICSProtocol.MODBUS_RTU] = ProtocolFeature(
            protocol=ICSProtocol.MODBUS_RTU,
            default_port=0,  # 串行协议
            function_codes=list(range(1, 128)) + list(range(128, 256)),
            object_types=['coil', 'discrete_input', 'holding_register', 'input_register'],
            header_pattern=b'',  # RTU无固定头部
            magic_bytes=b'\x00',  # Slave ID
            description="Modbus RTU 协议"
        )

    def _init_dnp3(self):
        """初始化DNP3协议特征"""
        self.features[ICSProtocol.DNP3] = ProtocolFeature(
            protocol=ICSProtocol.DNP3,
            default_port=20000,
            function_codes=[1, 2, 3, 4, 5, 6, 9, 10, 12, 14, 17, 20, 22, 23, 24],
            object_types=[
                'binary_input', 'binary_output', 'analog_input', 'analog_output',
                'counter', 'binary_output_status', 'analog_output_status'
            ],
            header_pattern=b'\x05\x64',  # Start bytes
            magic_bytes=b'\x05\x64\x01\x00',  # Start + Length + Control
            description="DNP3 协议"
        )

    def _init_iec61850(self):
        """初始化IEC 61850/MMS协议特征"""
        self.features[ICSProtocol.IEC_61850] = ProtocolFeature(
            protocol=ICSProtocol.IEC_61850,
            default_port=102,
            function_codes=[0, 1, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 127],
            object_types=['data_object', 'logical_node', 'data_set', 'setting_group'],
            header_pattern=b'\x03\x00',  # Start bytes
            magic_bytes=b'\x03\x00',
            description="IEC 61850 协议"
        )

        self.features[ICSProtocol.MMS] = ProtocolFeature(
            protocol=ICSProtocol.MMS,
            default_port=102,
            function_codes=list(range(0, 80)),
            object_types=['named_variable', 'named_variable_list', 'domain', 'program'],
            header_pattern=b'\x81',  # MMS PDU start
            magic_bytes=b'\x81',
            description="MMS (Manufacturing Message Specification) 协议"
        )

    def _init_profinet(self):
        """初始化PROFINET协议特征"""
        self.features[ICSProtocol.PROFINET] = ProtocolFeature(
            protocol=ICSProtocol.PROFINET,
            default_port=34962,  # DCP
            function_codes=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            object_types=['device_props', 'ip_params', 'station_name', 'configuration'],
            header_pattern=b'\xfe fd',  # Start bytes
            magic_bytes=b'\xfe\xfd',
            description="PROFINET 协议"
        )

    def _init_ethernet_ip(self):
        """初始化EtherNet/IP协议特征"""
        self.features[ICSProtocol.ETHERNET_IP] = ProtocolFeature(
            protocol=ICSProtocol.ETHERNET_IP,
            default_port=44818,
            function_codes=[
                0x0001,  # NOP
                0x0003,  # ListServices
                0x0004,  # ListIdentity
                0x0006,  # RegisterSession
                0x0063,  # SendRRData
                0x0064,  # SendUnitData
            ],
            object_types=['identity_object', 'message_router', 'connection_manager'],
            header_pattern=b'\x63\x00',  # Command header
            magic_bytes=b'\x63\x00',
            description="EtherNet/IP 协议"
        )

    def _init_s7comm(self):
        """初始化S7COMM协议特征"""
        self.features[ICSProtocol.S7COMM] = ProtocolFeature(
            protocol=ICSProtocol.S7COMM,
            default_port=102,
            function_codes=[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0F, 0x10],
            object_types=['s7_program', 's7_connection', 's7_block'],
            header_pattern=b'\x03\x00',  # TPKT header
            magic_bytes=b'\x03\x00\x00',
            description="S7COMM (S7 Communication) 协议"
        )

    def get_feature(self, protocol: ICSProtocol) -> Optional[ProtocolFeature]:
        """获取协议特征"""
        return self.features.get(protocol)

    def get_all_features(self) -> Dict[ICSProtocol, ProtocolFeature]:
        """获取所有协议特征"""
        return self.features.copy()


class ICSProtocolAnalyzer:
    """
    ICS协议分析器

    功能：
    1. 协议特征识别
    2. ICS协议栈识别
    3. 协议解析漏洞检测
    4. 畸形报文生成
    """

    def __init__(self, binary_path: Optional[str] = None):
        """
        初始化ICS协议分析器

        Args:
            binary_path: 二进制文件路径（可选）
        """
        self.binary_path = binary_path
        self.feature_db = ICSProtocolFeatureDatabase()
        self.detected_protocols: List[ICSProtocol] = []
        self.identified_functions: List[ICSFunction] = []
        self.binary_data: bytes = b''

        if binary_path and os.path.exists(binary_path):
            self._load_binary()

    def _load_binary(self):
        """加载二进制文件"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            logger.info(f"已加载二进制文件: {self.binary_path}, 大小: {len(self.binary_data)} 字节")
        except Exception as e:
            logger.error(f"加载二进制文件失败: {e}")
            self.binary_data = b''

    def _find_protocol_strings(self) -> Dict[ICSProtocol, List[str]]:
        """
        在二进制中查找协议相关字符串

        Returns:
            协议字符串映射
        """
        protocol_strings: Dict[ICSProtocol, List[str]] = defaultdict(list)

        # Modbus相关字符串
        modbus_keywords = ['modbus', 'Modbus', 'MBAP', 'unit_id', 'function_code']
        for kw in modbus_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.MODBUS_TCP].append(kw)

        # DNP3相关字符串
        dnp3_keywords = ['dnp3', 'DNP3', 'dnp', 'data_set', 'group', 'variation']
        for kw in dnp3_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.DNP3].append(kw)

        # IEC 61850/MMS相关字符串
        iec_keywords = ['iec61850', 'IEC61850', 'mms', 'MMS', 'MMSpdu', 'invokeId']
        for kw in iec_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.IEC_61850].append(kw)
                protocol_strings[ICSProtocol.MMS].append(kw)

        # PROFINET相关字符串
        profinet_keywords = ['profinet', 'PROFINET', 'DCP', 'PNIO', 'station_name']
        for kw in profinet_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.PROFINET].append(kw)

        # EtherNet/IP相关字符串
        enip_keywords = ['ethernet/ip', 'EtherNet', 'CIP', 'connection_manager']
        for kw in enip_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.ETHERNET_IP].append(kw)

        # S7COMM相关字符串
        s7_keywords = ['s7comm', 'S7COM', 's7', 'plc', 'CPU']
        for kw in s7_keywords:
            if kw.encode() in self.binary_data:
                protocol_strings[ICSProtocol.S7COMM].append(kw)

        return dict(protocol_strings)

    def _find_protocol_patterns(self) -> Dict[ICSProtocol, int]:
        """
        在二进制中查找协议特征模式

        Returns:
            协议匹配次数映射
        """
        pattern_counts: Dict[ICSProtocol, int] = defaultdict(int)

        for protocol, feature in self.feature_db.get_all_features().items():
            # 查找magic bytes
            if feature.magic_bytes:
                count = self.binary_data.count(feature.magic_bytes)
                pattern_counts[protocol] += count

            # 查找header pattern
            if feature.header_pattern:
                count = self.binary_data.count(feature.header_pattern)
                pattern_counts[protocol] += count

        return dict(pattern_counts)

    def detect_protocols(self) -> List[ICSProtocol]:
        """
        检测二进制中使用的ICS协议

        Returns:
            检测到的协议列表
        """
        self.detected_protocols = []

        # 字符串分析
        protocol_strings = self._find_protocol_strings()
        for protocol, strings in protocol_strings.items():
            if len(strings) >= 2:
                self.detected_protocols.append(protocol)
                logger.info(f"通过字符串分析检测到 {protocol.value}: {strings}")

        # 模式匹配
        pattern_counts = self._find_protocol_patterns()
        for protocol, count in pattern_counts.items():
            if count >= 5:
                if protocol not in self.detected_protocols:
                    self.detected_protocols.append(protocol)
                    logger.info(f"通过模式匹配检测到 {protocol.value}, 匹配次数: {count}")

        return self.detected_protocols

    def identify_ics_functions(self) -> List[ICSFunction]:
        """
        识别ICS协议处理函数

        Returns:
            识别的函数列表
        """
        self.identified_functions = []

        # 为每个检测到的协议生成虚拟函数
        for protocol in self.detected_protocols:
            feature = self.feature_db.get_feature(protocol)
            if not feature:
                continue

            # 通用函数识别
            function_templates = [
                (f"{protocol.value}_init", "初始化函数"),
                (f"{protocol.value}_parse", "解析函数"),
                (f"{protocol.value}_handle", "处理函数"),
                (f"{protocol.value}_validate", "验证函数"),
            ]

            for func_name, desc in function_templates:
                # 模拟函数识别
                ics_func = ICSFunction(
                    function_name=func_name,
                    address=random.randint(0x400000, 0x500000),  # 模拟地址
                    protocol=protocol,
                    handles_function_code=random.choice([True, False]),
                    parses_object_type=random.choice([True, False]),
                    checks_length=random.choice([True, False])
                )

                # 检查是否有潜在漏洞
                if not ics_func.checks_length:
                    ics_func.has_vulnerabilities.append(VulnerabilityType.LENGTH_NOT_CHECKED)
                if not ics_func.parses_object_type:
                    ics_func.has_vulnerabilities.append(VulnerabilityType.OBJECT_TYPE_CONFUSION)

                self.identified_functions.append(ics_func)

        return self.identified_functions

    def analyze_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        分析潜在漏洞

        Returns:
            漏洞信息列表
        """
        vulnerabilities = []

        for func in self.identified_functions:
            for vuln_type in func.has_vulnerabilities:
                vuln_info = {
                    'function_name': func.function_name,
                    'function_address': hex(func.address),
                    'protocol': func.protocol.value,
                    'vulnerability_type': vuln_type.value,
                    'description': self._get_vulnerability_description(vuln_type),
                    'severity': self._get_vulnerability_severity(vuln_type),
                    'exploit_difficulty': self._get_exploit_difficulty(vuln_type)
                }
                vulnerabilities.append(vuln_info)

        return vulnerabilities

    def _get_vulnerability_description(self, vuln_type: VulnerabilityType) -> str:
        """获取漏洞描述"""
        descriptions = {
            VulnerabilityType.LENGTH_NOT_CHECKED: "协议处理函数未验证数据包长度字段，可能导致缓冲区溢出",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "访问数组或缓冲区时未进行边界检查，可能导致越界访问",
            VulnerabilityType.OBJECT_TYPE_CONFUSION: "对象类型解析存在混淆风险，可能导致类型混淆漏洞",
            VulnerabilityType.BUFFER_OVERFLOW: "缓冲区操作存在溢出风险，可能导致内存损坏",
            VulnerabilityType.AUTHENTICATION_BYPASS: "认证机制存在缺陷，可能被绕过",
            VulnerabilityType.DENIAL_OF_SERVICE: "存在拒绝服务漏洞，恶意报文可能导致服务中断",
            VulnerabilityType.MEMORY_CORRUPTION: "内存操作存在损坏风险"
        }
        return descriptions.get(vuln_type, "未知漏洞类型")

    def _get_vulnerability_severity(self, vuln_type: VulnerabilityType) -> str:
        """获取漏洞严重性"""
        severities = {
            VulnerabilityType.LENGTH_NOT_CHECKED: "high",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "high",
            VulnerabilityType.OBJECT_TYPE_CONFUSION: "medium",
            VulnerabilityType.BUFFER_OVERFLOW: "critical",
            VulnerabilityType.AUTHENTICATION_BYPASS: "high",
            VulnerabilityType.DENIAL_OF_SERVICE: "medium",
            VulnerabilityType.MEMORY_CORRUPTION: "high"
        }
        return severities.get(vuln_type, "unknown")

    def _get_exploit_difficulty(self, vuln_type: VulnerabilityType) -> str:
        """获取漏洞利用难度"""
        difficulties = {
            VulnerabilityType.LENGTH_NOT_CHECKED: "medium",
            VulnerabilityType.INDEX_OUT_OF_BOUNDS: "medium",
            VulnerabilityType.OBJECT_TYPE_CONFUSION: "high",
            VulnerabilityType.BUFFER_OVERFLOW: "low",
            VulnerabilityType.AUTHENTICATION_BYPASS: "high",
            VulnerabilityType.DENIAL_OF_SERVICE: "low",
            VulnerabilityType.MEMORY_CORRUPTION: "medium"
        }
        return difficulties.get(vuln_type, "unknown")

    def generate_malformed_packets(self, protocol: ICSProtocol,
                                  count: int = 10) -> List[MalformedPacket]:
        """
        生成畸形ICS协议报文

        Args:
            protocol: 目标协议
            count: 生成数量

        Returns:
            畸形报文列表
        """
        packets = []
        rng = random.Random()

        for i in range(count):
            mutation_type = rng.choice([
                'length_overflow', 'length_underflow', 'invalid_function_code',
                'invalid_object_type', 'truncated_header', 'extra_data',
                'null_pointer', 'negative_value', 'boundary_value'
            ])

            # 生成基础Modbus报文
            if protocol == ICSProtocol.MODBUS_TCP:
                base_packet = self._generate_modbus_tcp_packet(rng)
            elif protocol == ICSProtocol.DNP3:
                base_packet = self._generate_dnp3_packet(rng)
            elif protocol == ICSProtocol.ETHERNET_IP:
                base_packet = self._generate_ethernet_ip_packet(rng)
            else:
                base_packet = self._generate_generic_packet(rng, protocol)

            # 应用变异
            malformed = self._apply_mutation(base_packet, mutation_type, rng)

            # 映射到目标漏洞
            target_vuln = self._map_mutation_to_vulnerability(mutation_type)

            packet = MalformedPacket(
                packet_id=f"ics_{protocol.value}_{i:03d}_{mutation_type}",
                protocol=protocol,
                original_packet=base_packet,
                malformed_packet=malformed,
                mutation_type=mutation_type,
                description=f"变异类型: {mutation_type}",
                target_vulnerability=target_vuln
            )

            packets.append(packet)

        return packets

    def _generate_modbus_tcp_packet(self, rng: random.Random) -> bytes:
        """生成Modbus TCP报文"""
        transaction_id = rng.randint(0, 65535)
        protocol_id = 0
        length = 6 + rng.randint(1, 10)  # 最小长度6
        unit_id = rng.randint(0, 255)
        function_code = rng.choice([1, 2, 3, 4, 5, 6, 15, 16])
        data = bytes(rng.randint(0, 255) for _ in range(length - 6))

        packet = struct.pack('>HHHBB', transaction_id, protocol_id, length, unit_id, function_code)
        packet += data

        return packet

    def _generate_dnp3_packet(self, rng: random.Random) -> bytes:
        """生成DNP3报文"""
        start = b'\x05\x64'
        length = rng.randint(10, 50)
        control = rng.randint(0, 255)
        destination = rng.randint(0, 65535)
        source = rng.randint(0, 65535)

        header = struct.pack('<BBHH', start[0], length, control, destination)
        header += struct.pack('<H', source)
        header += struct.pack('<BB', 0x01, rng.choice([3, 4, 5, 6, 10]))

        data = bytes(rng.randint(0, 255) for _ in range(length - 10))
        crc = b'\x00\x00'

        return start + header + data + crc

    def _generate_ethernet_ip_packet(self, rng: random.Random) -> bytes:
        """生成EtherNet/IP报文"""
        command = rng.choice([0x0001, 0x0003, 0x0004, 0x0063, 0x0064])
        length = rng.randint(24, 100)
        session = rng.randint(0, 0xFFFFFFFF)
        status = 0
        sender_context = bytes(rng.randint(0, 255) for _ in range(8))
        options = 0

        header = struct.pack('<HHI I 8s I',
                           command, length, session, status, sender_context, options)

        # 添加CIP数据
        cip_data = bytes(rng.randint(0, 255) for _ in range(length - 24))

        return header + cip_data

    def _generate_generic_packet(self, rng: random.Random, protocol: ICSProtocol) -> bytes:
        """生成通用ICS协议报文"""
        length = rng.randint(10, 50)
        return bytes(rng.randint(0, 255) for _ in range(length))

    def _apply_mutation(self, packet: bytes, mutation_type: str,
                       rng: random.Random) -> bytes:
        """应用变异到报文"""
        result = bytearray(packet)

        if mutation_type == 'length_overflow':
            if len(result) >= 4:
                # 使长度字段过大
                struct.pack_into('>H', result, 4, 0xFFFF)
        elif mutation_type == 'length_underflow':
            if len(result) >= 4:
                struct.pack_into('>H', result, 4, 1)
        elif mutation_type == 'invalid_function_code':
            if len(result) >= 6:
                result[7] = 0xFF
        elif mutation_type == 'truncated_header':
            return result[:min(6, len(result))]
        elif mutation_type == 'extra_data':
            result.extend(bytes(rng.randint(0, 255) for _ in range(50)))
        elif mutation_type == 'null_pointer':
            if len(result) >= 10:
                result[8:12] = b'\x00\x00\x00\x00'
        elif mutation_type == 'negative_value':
            if len(result) >= 4:
                struct.pack_into('<i', result, 0, -1)
        elif mutation_type == 'boundary_value':
            if len(result) >= 4:
                struct.pack_into('<I', result, 0, 0xFFFFFFFF)

        return bytes(result)

    def _map_mutation_to_vulnerability(self, mutation_type: str) -> VulnerabilityType:
        """将变异类型映射到漏洞类型"""
        mapping = {
            'length_overflow': VulnerabilityType.LENGTH_NOT_CHECKED,
            'length_underflow': VulnerabilityType.LENGTH_NOT_CHECKED,
            'invalid_function_code': VulnerabilityType.OBJECT_TYPE_CONFUSION,
            'truncated_header': VulnerabilityType.BUFFER_OVERFLOW,
            'extra_data': VulnerabilityType.BUFFER_OVERFLOW,
            'null_pointer': VulnerabilityType.MEMORY_CORRUPTION,
            'negative_value': VulnerabilityType.INDEX_OUT_OF_BOUNDS,
            'boundary_value': VulnerabilityType.BUFFER_OVERFLOW
        }
        return mapping.get(mutation_type, VulnerabilityType.MEMORY_CORRUPTION)

    def analyze(self) -> ICSAnalysisResult:
        """
        执行完整的ICS协议分析

        Returns:
            ICSAnalysisResult
        """
        import time
        start_time = time.time()

        # 检测协议
        self.detect_protocols()

        # 识别函数
        self.identify_ics_functions()

        # 分析漏洞
        vulnerabilities = self.analyze_vulnerabilities()

        # 生成畸形报文
        generated_packets = []
        for protocol in self.detected_protocols:
            generated_packets.extend(self.generate_malformed_packets(protocol, count=5))

        # 生成摘要
        summary = self._generate_summary(vulnerabilities)

        return ICSAnalysisResult(
            binary_path=self.binary_path or "",
            detected_protocols=self.detected_protocols,
            identified_functions=self.identified_functions,
            detected_vulnerabilities=vulnerabilities,
            generated_packets=generated_packets,
            summary=summary,
            analysis_time=time.time() - start_time
        )


def analyze_ics_protocols(binary_path: str) -> ICSAnalysisResult:
    """
    分析二进制中ICS协议的便捷函数

    Args:
        binary_path: 二进制文件路径

    Returns:
        ICSAnalysisResult
    """
    analyzer = ICSProtocolAnalyzer(binary_path)
    return analyzer.analyze()


def format_ics_report(result: ICSAnalysisResult) -> str:
    """
    格式化ICS分析报告

    Args:
        result: 分析结果

    Returns:
        格式化的报告字符串
    """
    parts = [
        "# ICS协议分析报告",
        "",
        f"二进制文件: {result.binary_path}",
        f"分析时间: {result.analysis_time:.2f}秒",
        "",
        "## 检测到的ICS协议",
    ]

    if result.detected_protocols:
        for protocol in result.detected_protocols:
            parts.append(f"- {protocol.value}")
    else:
        parts.append("未检测到ICS协议")

    parts.extend([
        "",
        "## 检测到的漏洞",
    ])

    if result.detected_vulnerabilities:
        for i, vuln in enumerate(result.detected_vulnerabilities(), 1):
            parts.extend([
                f"\n### {i}. {vuln['vulnerability_type']}",
                f"- 函数: {vuln['function_name']} ({vuln['function_address']})",
                f"- 协议: {vuln['protocol']}",
                f"- 描述: {vuln['description']}",
                f"- 严重性: {vuln['severity']}",
            ])
    else:
        parts.append("未检测到漏洞")

    parts.extend([
        "",
        f"已生成 {len(result.generated_packets)} 个畸形测试报文",
    ])

    return "\n".join(parts)


def export_ics_json(result: ICSAnalysisResult, output_path: str) -> bool:
    """
    导出ICS分析结果为JSON

    Args:
        result: 分析结果
        output_path: 输出路径

    Returns:
        是否成功
    """
    import json

    try:
        export_data = {
            'binary_path': result.binary_path,
            'detected_protocols': [p.value for p in result.detected_protocols],
            'identified_functions': [
                {
                    'function_name': f.function_name,
                    'address': hex(f.address),
                    'protocol': f.protocol.value,
                    'has_vulnerabilities': [v.value for v in f.has_vulnerabilities]
                }
                for f in result.identified_functions
            ],
            'detected_vulnerabilities': result.detected_vulnerabilities,
            'generated_packets': [
                {
                    'packet_id': p.packet_id,
                    'protocol': p.protocol.value,
                    'mutation_type': p.mutation_type,
                    'description': p.description,
                    'target_vulnerability': p.target_vulnerability.value,
                    'original_packet': p.original_packet.hex(),
                    'malformed_packet': p.malformed_packet.hex()
                }
                for p in result.generated_packets
            ],
            'summary': result.summary,
            'analysis_time': result.analysis_time
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        logger.error(f"导出JSON失败: {e}")
        return False
