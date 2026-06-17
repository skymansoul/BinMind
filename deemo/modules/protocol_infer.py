#!/usr/bin/env python3
"""
协议逆向工程引擎

输入网络包或二进制序列化样本，通过动态执行与内存标记比对推断字段边界、类型、变长字段、校验和。
生成Wireshark Lua解析器或Scapy定义文件。
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class ProtocolFieldType(Enum):
    """协议字段类型枚举"""
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    STRING = "string"
    BYTES = "bytes"
    FLOAT = "float"
    DOUBLE = "double"
    LENGTH_PREFIXED = "length_prefixed"
    NULL_TERMINATED = "null_terminated"
    CHECKSUM = "checksum"
    MAGIC = "magic"


class FieldEndianness(Enum):
    """字段字节序枚举"""
    LITTLE_ENDIAN = "little"
    BIG_ENDIAN = "big"
    NATIVE = "native"


@dataclass
class ProtocolField:
    """协议字段定义"""
    name: str
    type: ProtocolFieldType
    offset: int
    size: int
    description: str = ""
    endianness: FieldEndianness = FieldEndianness.LITTLE_ENDIAN
    is_variable_length: bool = False
    length_field: Optional[str] = None
    checksum_algorithm: Optional[str] = None
    magic_value: Optional[int] = None
    enum_values: Optional[Dict[int, str]] = None


@dataclass
class ProtocolMessage:
    """协议消息定义"""
    name: str
    fields: List[ProtocolField]
    magic: Optional[int] = None
    description: str = ""
    min_length: int = 0
    max_length: int = 0


@dataclass
class ProtocolDefinition:
    """协议定义"""
    name: str
    messages: List[ProtocolMessage]
    port: Optional[int] = None
    transport: str = "tcp"
    description: str = ""


@dataclass
class ProtocolInferenceResult:
    """协议推断结果"""
    success: bool
    protocol: ProtocolDefinition
    samples_analyzed: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ProtocolParser(ABC):
    """协议解析器基类"""
    
    @abstractmethod
    def parse(self, data: bytes) -> Dict[str, Any]:
        """
        解析协议数据
        
        Args:
            data: 原始数据
        
        Returns:
            解析后的字段字典
        """
        pass
    
    @abstractmethod
    def generate_code(self) -> str:
        """生成解析器代码"""
        pass


class FieldInferrer(ABC):
    """字段推断器基类"""
    
    @abstractmethod
    def infer(self, samples: List[bytes]) -> List[ProtocolField]:
        """
        从样本推断字段
        
        Args:
            samples: 样本数据列表
        
        Returns:
            推断出的字段列表
        """
        pass


class HeuristicFieldInferrer(FieldInferrer):
    """启发式字段推断器"""
    
    def infer(self, samples: List[bytes]) -> List[ProtocolField]:
        """从样本推断字段"""
        fields = []
        
        if not samples:
            return fields
        
        # 找到所有样本的公共前缀长度
        min_len = min(len(s) for s in samples)
        
        # 分析每个字节位置
        for offset in range(min_len):
            bytes_at_offset = [s[offset] for s in samples]
            
            # 检测魔数（所有样本相同）
            if len(set(bytes_at_offset)) == 1:
                if offset == 0:
                    fields.append(ProtocolField(
                        name=f"magic_{offset}",
                        type=ProtocolFieldType.MAGIC,
                        offset=offset,
                        size=1,
                        magic_value=bytes_at_offset[0],
                        description="魔数字节"
                    

                    continue
            
            # 检测整数类型
            if offset + 4 <= min_len:
                int32_values = []
                for s in samples:
                    try:
                        int32_values.append(int.from_bytes(s[offset:offset+4], 'little'

                    except:
                        pass
                
                if len(int32_values) == len(samples):
                    # 检查是否看起来像长度字段
                    if self._looks_like_length(int32_values, samples, offset):
                        fields.append(ProtocolField(
                            name=f"length_{offset}",
                            type=ProtocolFieldType.UINT32,
                            offset=offset,
                            size=4,
                            description="长度字段",
                            is_variable_length=True
                        

                        continue
            
            # 检测字符串
            if self._looks_like_string(samples, offset):
                str_len = self._find_string_length(samples, offset)
                if str_len > 0:
                    fields.append(ProtocolField(
                        name=f"string_{offset}",
                        type=ProtocolFieldType.STRING,
                        offset=offset,
                        size=str_len,
                        description="字符串字段"
                    

                    continue
            
            # 默认作为字节
            fields.append(ProtocolField(
                name=f"byte_{offset}",
                type=ProtocolFieldType.BYTES,
                offset=offset,
                size=1,
                description="未知字段"
            

        
        return fields
    
    def _looks_like_length(self, values: List[int], samples: List[bytes], offset: int) -> bool:
        """检查是否看起来像长度字段"""
        for val, sample in zip(values, samples):
            if val > 0 and val <= len(sample) - offset - 4:
                return True
        return False
    
    def _looks_like_string(self, samples: List[bytes], offset: int) -> bool:
        """检查是否看起来像字符串"""
        for s in samples:
            if offset < len(s):
                if s[offset] == 0:
                    return False
                # 检查是否是可打印字符
                if offset + 1 < len(s) and not (0x20 <= s[offset] <= 0x7E):
                    return False
        return True
    
    def _find_string_length(self, samples: List[bytes], offset: int) -> int:
        """查找字符串长度"""
        max_len = 0,
        for s in samples:
            if offset >= len(s):
                continue
            pos = offset,
            while pos < len(s) and s[pos] != 0 and 0x20 <= s[pos] <= 0x7E:
                pos += 1
            max_len = max(max_len, pos - offset)
        return max_len


class MagicDetector:
    """魔数检测器"""
    
    def detect(self, samples: List[bytes]) -> Optional[int]:
        """检测公共魔数"""
        if not samples:
            return None
        
        min_len = min(len(s) for s in samples)
        if min_len < 4:
            return None
        
        # 检查前4字节是否相同
        first_four = set(s[:4] for s in samples)
        if len(first_four) == 1:
            magic = int.from_bytes(list(first_four)[0], 'little')
            logger.info(f"检测到魔数: 0x{magic:x}")
            return magic
        
        return None


class ChecksumDetector:
    """校验和检测器"""
    
    def detect(self, data: bytes) -> List[Tuple[str, int]]:
        """检测校验和字段"""
        algorithms = ['crc32', 'crc16', 'xor', 'adler32']
        results = []
        
        for algo in algorithms:
            pos = self._find_checksum(data, algo)
            if pos != -1:
                results.append((algo, pos

        
        return results
    
    def _find_checksum(self, data: bytes, algorithm: str) -> int:
        """查找校验和位置"""
        # 简化实现：检查末尾是否有校验和
        if algorithm == 'crc32' and len(data) >= 4:
            return len(data) - 4
        elif algorithm == 'crc16' and len(data) >= 2:
            return len(data) - 2
        return -1


class ProtocolInferEngine:
    """
    协议逆向工程引擎
    
    输入网络包或二进制序列化样本，通过动态执行与内存标记比对推断字段边界、类型、
    变长字段、校验和，生成Wireshark Lua解析器或Scapy定义文件。
    """
    
    def __init__(self):
        """初始化协议逆向引擎"""
        self.field_inferrer = HeuristicFieldInferrer()
        self.magic_detector = MagicDetector()
        self.checksum_detector = ChecksumDetector()
    
    def analyze_samples(self, samples: List[bytes], protocol_name: str = "unknown") -> ProtocolInferenceResult:
        """
        分析样本推断协议结构
        
        Args:
            samples: 样本数据列表
            protocol_name: 协议名称
        
        Returns:
            协议推断结果
        """
        if not samples:
            return ProtocolInferenceResult(
                success=False,
                protocol=ProtocolDefinition(name=protocol_name, messages=[]),
                errors=["样本数据为空"])
            

        
        try:
            # 检测魔数
            magic = self.magic_detector.detect(samples)
            
            # 推断字段
            fields = self.field_inferrer.infer(samples)
            
            # 创建消息定义
            message = ProtocolMessage()
                name="default",
                fields=fields,
                magic=magic,
                min_length=min(len(s) for s in samples),
                max_length=max(len(s) for s in samples)
            
            
            # 创建协议定义
            protocol = ProtocolDefinition()
                name=protocol_name,
                messages=[message],
                description=f"自动推断的协议，基于 {len(samples)} 个样本"
            
            
            return ProtocolInferenceResult(
                success=True,
                protocol=protocol,
                samples_analyzed=len(samples))
            

        
        except Exception as e:
            logger.error(f"分析样本失败: {e}")
            return ProtocolInferenceResult(
                success=False,
                protocol=ProtocolDefinition(name=protocol_name, messages=[]),
                errors=[str(e)])
            

    
    def analyze_pcap(self, pcap_path: str, protocol_name: str = "unknown") -> ProtocolInferenceResult:
        """
        从PCAP文件分析协议
        
        Args:
            pcap_path: PCAP文件路径
            protocol_name: 协议名称
        
        Returns:
            协议推断结果
        """
        if not os.path.exists(pcap_path):
            return ProtocolInferenceResult(
                success=False,
                protocol=ProtocolDefinition(name=protocol_name, messages=[]),
                errors=[f"PCAP文件不存在: {pcap_path}"])
            

        
        try:
            samples = self._extract_payloads_from_pcap(pcap_path)
            return self.analyze_samples(samples, protocol_name)
        except Exception as e:
            logger.error(f"分析PCAP文件失败: {e}")
            return ProtocolInferenceResult(
                success=False,
                protocol=ProtocolDefinition(name=protocol_name, messages=[]),
                errors=[str(e)])
            

    
    def _extract_payloads_from_pcap(self, pcap_path: str) -> List[bytes]:
        """从PCAP文件提取payload"""
        samples = []
        
        try:
            import dpkt
            
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data,
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp = ip.data,
                                if tcp.data:
                                    samples.append(bytes(tcp.data

                            elif isinstance(ip.data, dpkt.udp.UDP):
                                udp = ip.data,
                                if udp.data:
                                    samples.append(bytes(udp.data

                    except Exception as e:
                        logger.debug(f"解析包失败: {e}")
        
        except ImportError:
            logger.warning("dpkt未安装，无法解析PCAP文件")
        
        return samples
    
    def generate_scapy_code(self, protocol: ProtocolDefinition) -> str:
        """
        生成Scapy协议定义代码
        
        Args:
            protocol: 协议定义
        
        Returns:
            Scapy代码字符串
        """
        lines = []
        lines.append("# 自动生成的Scapy协议定义")
        lines.append("# 协议名称: {}".format(protocol.name

        lines.append("")
        lines.append("from scapy.all import *")
        lines.append("")
        
        for message in protocol.messages:
            class_name = self._to_pascal_case(message.name) + "Message"
            lines.append(f"class {class_name}(Packet):")
            lines.append(f"    \"\"\"{message.description}\"\"\"")
            lines.append("    name = \"{}\"".format(message.name

            lines.append("    fields_desc = [")
            
            for field in message.fields:
                scapy_type = self._field_type_to_scapy(field.type)
                line = f"        {scapy_type}(name=\"{field.name}\"")
                
                if field.size > 1:
                    line += f", length={field.size}"
                
                if field.is_variable_length and field.length_field:
                    line += f", length_from=lambda pkt: pkt.{field.length_field}"
                
                line += ")"
                lines.append(line)
            
            lines.append("    ]")
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_wireshark_lua(self, protocol: ProtocolDefinition) -> str:
        """
        生成Wireshark Lua解析器
        
        Args:
            protocol: 协议定义
        
        Returns:
            Lua代码字符串
        """
        lines = []
        lines.append("-- 自动生成的Wireshark Lua解析器")
        lines.append("-- 协议名称: {}".format(protocol.name

        lines.append("")
        lines.append(f"local {protocol.name} = Proto(\"{protocol.name}\", \"{protocol.description}\")")
        lines.append("")
        
        # 定义字段
        field_defs = []
        for message in protocol.messages:
            for field in message.fields:
                lua_type = self._field_type_to_lua(field.type)
                field_defs.append(f"local {field.name} = {protocol.name}.fields[\"{field.name}\"]")
                lines.append(f"{protocol.name}.fields[\"{field.name}\"] = ProtoField.{lua_type}(\"{protocol.name}.{field.name}\", \"{field.name}\", base.DEC)")
        
        lines.append("")
        lines.append("\n".join(field_defs

        lines.append("")
        
        # 解析器函数
        lines.append("function {}_dissect(tvb, pinfo, tree)".format(protocol.name

        lines.append("    pinfo.cols.protocol = \"{}\"".format(protocol.name.upper(

        lines.append("    local subtree = tree:add({}, tvb())".format(protocol.name

        
        offset = 0,
        for message in protocol.messages:
            for field in message.fields:
                lines.append(f"    subtree:add({field.name}, tvb({offset}, {field.size}))")
                offset += field.size
        
        lines.append("end")
        lines.append("")
        lines.append("{}:register_post dissector(\"tcp.port\", {}_dissect)".format(protocol.name, protocol.name

        
        return "\n".join(lines)
    
    def _field_type_to_scapy(self, field_type: ProtocolFieldType) -> str:
        """将字段类型转换为Scapy类型"""
        type_map = {
            ProtocolFieldType.UINT8: "ByteField",
            ProtocolFieldType.UINT16: "ShortField",
            ProtocolFieldType.UINT32: "IntField",
            ProtocolFieldType.UINT64: "LongField",
            ProtocolFieldType.INT8: "SignedByteField",
            ProtocolFieldType.INT16: "SignedShortField",
            ProtocolFieldType.INT32: "SignedIntField",
            ProtocolFieldType.INT64: "SignedLongField",
            ProtocolFieldType.STRING: "StrField",
            ProtocolFieldType.BYTES: "StrField",
            ProtocolFieldType.FLOAT: "FloatField",
            ProtocolFieldType.DOUBLE: "DoubleField",
        }
        return type_map.get(field_type, "StrField")
    
    def _field_type_to_lua(self, field_type: ProtocolFieldType) -> str:
        """将字段类型转换为Lua类型"""
        type_map = {
            ProtocolFieldType.UINT8: "uint8",
            ProtocolFieldType.UINT16: "uint16",
            ProtocolFieldType.UINT32: "uint32",
            ProtocolFieldType.UINT64: "uint64",
            ProtocolFieldType.INT8: "int8",
            ProtocolFieldType.INT16: "int16",
            ProtocolFieldType.INT32: "int32",
            ProtocolFieldType.INT64: "int64",
            ProtocolFieldType.STRING: "string",
            ProtocolFieldType.BYTES: "bytes",
            ProtocolFieldType.FLOAT: "float",
            ProtocolFieldType.DOUBLE: "double",
        }
        return type_map.get(field_type, "bytes")
    
    def _to_pascal_case(self, name: str) -> str:
        """转换为帕斯卡命名"""
        words = re.split(r'[_-]', name)
        return ''.join(word.capitalize( for word in words))
    
    def generate_report(self, result: ProtocolInferenceResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 协议推断结果
        
        Returns:
            报告字符串
        """
        report = []
        report.append("=" * 60)
        report.append("协议逆向工程分析报告")
        report.append("=" * 60)
        report.append(f"协议名称: {result.protocol.name}")
        report.append(f"成功: {result.success}")
        report.append(f"分析样本数: {result.samples_analyzed}")
        report.append("")
        
        if result.protocol.messages:
            for message in result.protocol.messages:
                report.append(f"消息: {message.name}")
                report.append(f"  描述: {message.description}")
                report.append(f"  魔数: 0x{message.magic:x}" if message.magic else "  魔数: 无")
                report.append(f"  长度范围: {message.min_length}-{message.max_length} bytes")
                report.append("  字段:")
                report.append("  " + "-" * 40)
                
                for field in message.fields:
                    report.append(f"    {field.name}:")
                    report.append(f"      类型: {field.type.value}")
                    report.append(f"      偏移: {field.offset}")
                    report.append(f"      大小: {field.size}")
                    if field.description:
                        report.append(f"      描述: {field.description}")
                    report.append("")
        
        return "\n".join(report)
    
    def save_result(self, result: ProtocolInferenceResult, output_path: str) -> bool:
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
                "protocol_name": result.protocol.name,
                "samples_analyzed": result.samples_analyzed,
                "messages": [
                    {
                        "name": msg.name,
                        "magic": hex(msg.magic) if msg.magic else None,
                        "fields": [
                            {
                                "name": f.name,
                                "type": f.type.value,
                                "offset": f.offset,
                                "size": f.size,
                                "description": f.description
                            } for f in msg.fields
                        ]
                    } for msg in result.protocol.messages
                ]
            }
            
            with open(output_path, "w") as f:
                json.dump(result_dict, f, indent=2)
            
            logger.info(f"结果保存成功: {output_path}")
            return True
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
            return False))))))))))))))))))))))))))))))))