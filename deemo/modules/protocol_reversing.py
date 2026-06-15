import logging
import os
import subprocess
import tempfile
import uuid
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum

from config import Config

logger = logging.getLogger(__name__)


class ProtocolFieldType(Enum):
    """协议字段类型"""
    UINT8 = 'uint8'
    UINT16 = 'uint16'
    UINT32 = 'uint32'
    UINT64 = 'uint64'
    INT8 = 'int8'
    INT16 = 'int16'
    INT32 = 'int32'
    INT64 = 'int64'
    STRING = 'string'
    BYTES = 'bytes'
    LENGTH_PREFIXED_STRING = 'length_prefixed_string'
    NESTED_STRUCT = 'nested_struct'
    ENUM = 'enum'
    BIT_FIELD = 'bit_field'


class ProtocolField:
    """协议字段定义"""
    
    def __init__(
        self,
        name: str,
        field_type: ProtocolFieldType,
        offset: int = 0,
        size: int = 0,
        length_field: str = None,
        min_value: int = None,
        max_value: int = None,
        enum_values: Dict[int, str] = None,
        description: str = None
    ):
        self.name = name
        self.field_type = field_type
        self.offset = offset
        self.size = size
        self.length_field = length_field
        self.min_value = min_value
        self.max_value = max_value
        self.enum_values = enum_values or {}
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.field_type.value,
            'offset': self.offset,
            'size': self.size,
            'length_field': self.length_field,
            'min_value': self.min_value,
            'max_value': self.max_value,
            'enum_values': self.enum_values,
            'description': self.description
        }


class ProtocolMessage:
    """协议消息定义"""
    
    def __init__(self, name: str, fields: List[ProtocolField] = None):
        self.name = name
        self.fields = fields or []
    
    def add_field(self, field: ProtocolField):
        self.fields.append(field)
    
    def get_total_size(self) -> int:
        if not self.fields:
            return 0
        last_field = self.fields[-1]
        return last_field.offset + last_field.size
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'fields': [f.to_dict() for f in self.fields],
            'total_size': self.get_total_size()
        }


class ProtocolFormatInferrer:
    """
    协议格式推断器
    
    通过静态分析二进制程序，识别网络协议格式：
    1. 识别 recv/read 等接收点
    2. 分析后续解析逻辑（ntohs/ntohl、memcmp等）
    3. 构建消息格式假设
    """
    
    def __init__(self, binary_path: str):
        """
        初始化协议格式推断器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = self._validate_path(binary_path)
        self.messages: List[ProtocolMessage] = []
        self.pcap_samples: List[bytes] = []
        self.raw_bytes: List[bytes] = []
        
        logger.info(f"ProtocolFormatInferrer 初始化完成: binary={self.binary_path}")
    
    def _validate_path(self, path: str) -> str:
        """验证二进制路径"""
        if not path or not isinstance(path, str):
            raise ValueError("二进制路径不能为空")
        
        try:
            abs_path = os.path.abspath(os.path.expanduser(path))
        except Exception as e:
            raise ValueError(f"无法解析路径: {e}")
        
        if not os.path.exists(abs_path):
            raise ValueError(f"文件不存在: {abs_path}")
        
        return abs_path
    
    def add_pcap_sample(self, pcap_path: str) -> bool:
        """
        添加 PCAP 样本文件
        
        Args:
            pcap_path: PCAP 文件路径
        
        Returns:
            是否成功
        """
        try:
            samples = self._parse_pcap(pcap_path)
            self.pcap_samples.extend(samples)
            logger.info(f"从 PCAP 文件加载 {len(samples)} 个数据包样本")
            return True
        except Exception as e:
            logger.error(f"解析 PCAP 文件失败 {pcap_path}: {e}")
            return False
    
    def _parse_pcap(self, pcap_path: str) -> List[bytes]:
        """解析 PCAP 文件提取原始数据包"""
        samples = []
        
        try:
            import scapy.all as scapy
            packets = scapy.rdpcap(pcap_path)
            
            for pkt in packets:
                if pkt.haslayer(scapy.Raw):
                    raw_data = bytes(pkt[scapy.Raw].load)
                    if raw_data:
                        samples.append(raw_data)
                        if len(samples) >= 100:
                            break
            
        except ImportError:
            logger.warning("scapy 未安装，尝试手动解析 PCAP")
            samples = self._parse_pcap_manual(pcap_path)
        except Exception as e:
            logger.debug(f"scapy 解析失败: {e}")
        
        return samples
    
    def _parse_pcap_manual(self, pcap_path: str) -> List[bytes]:
        """手动解析 PCAP 文件（不依赖 scapy）"""
        samples = []
        
        try:
            with open(pcap_path, 'rb') as f:
                data = f.read()
            
            if len(data) < 24:
                return samples
            
            magic = data[:4]
            is_big_endian = magic == b'\xa1\xb2\xc3\xd4'
            
            def read_u32(offset):
                if is_big_endian:
                    return int.from_bytes(data[offset:offset+4], 'big')
                else:
                    return int.from_bytes(data[offset:offset+4], 'little')
            
            header_len = 24
            if magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xd4\xc3\xb2\xa1':
                version_major = read_u32(4)
                version_minor = read_u32(8)
                
                if version_major == 2 and version_minor == 4:
                    offset = 24
                    while offset + 16 <= len(data):
                        ts_sec = read_u32(offset)
                        ts_usec = read_u32(offset + 4)
                        incl_len = read_u32(offset + 8)
                        orig_len = read_u32(offset + 12)
                        
                        packet_data = data[offset + 16 : offset + 16 + incl_len]
                        
                        if len(packet_data) >= 14:
                            eth_type = int.from_bytes(packet_data[12:14], 'big')
                            ip_offset = 14
                            
                            if eth_type == 0x0806:
                                ip_offset += 42
                            elif eth_type == 0x0800:
                                ip_hdr_len = (packet_data[ip_offset] & 0x0F) * 4
                                ip_offset += ip_hdr_len
                                
                                if ip_offset + 2 <= len(packet_data):
                                    proto = packet_data[ip_offset - 1]
                                    if proto == 6:
                                        tcp_hdr_len = ((packet_data[ip_offset + 12] >> 4) & 0x0F) * 4
                                        ip_offset += tcp_hdr_len
                                    elif proto == 17:
                                        ip_offset += 8
                            
                            if ip_offset < len(packet_data):
                                payload = packet_data[ip_offset:]
                                if payload:
                                    samples.append(payload)
                    
                        offset += 16 + incl_len
        
        except Exception as e:
            logger.debug(f"手动解析 PCAP 失败: {e}")
        
        return samples
    
    def add_raw_sample(self, raw_data: bytes):
        """添加原始字节样本"""
        self.raw_bytes.append(raw_data)
    
    def infer_protocol(self) -> List[ProtocolMessage]:
        """
        推断协议格式
        
        Returns:
            推断出的协议消息列表
        """
        logger.info("开始协议格式推断")
        
        patterns = self._analyze_binary()
        self.messages = self._build_protocol_messages(patterns)
        
        if self.pcap_samples:
            self._refine_with_pcap()
        
        logger.info(f"协议推断完成，发现 {len(self.messages)} 个消息类型")
        
        return self.messages
    
    def _analyze_binary(self) -> Dict[str, Any]:
        """分析二进制程序提取协议模式"""
        patterns = {
            'length_fields': [],
            'magic_values': [],
            'enum_patterns': [],
            'string_patterns': [],
            'struct_sizes': []
        }
        
        try:
            patterns.update(self._analyze_with_radare2())
        except Exception as e:
            logger.debug(f"radare2 分析失败: {e}")
        
        patterns.update(self._analyze_raw_binary())
        
        return patterns
    
    def _analyze_with_radare2(self) -> Dict[str, Any]:
        """使用 radare2 分析二进制"""
        patterns = {
            'length_fields': [],
            'magic_values': [],
            'enum_patterns': [],
            'string_patterns': [],
            'struct_sizes': []
        }
        
        try:
            cmd = [
                'r2', '-q', '-e', 'io.color=false', '-c', 'pd -p 1000',
                self.binary_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                patterns.update(self._parse_radare2_output(result.stdout))
        
        except Exception as e:
            logger.debug(f"radare2 执行失败: {e}")
        
        return patterns
    
    def _parse_radare2_output(self, output: str) -> Dict[str, Any]:
        """解析 radare2 输出"""
        patterns = {
            'length_fields': [],
            'magic_values': [],
            'enum_patterns': [],
            'string_patterns': [],
            'struct_sizes': []
        }
        
        import re
        
        ntoh_patterns = [
            r'ntohs\s*\(\s*(\w+)\s*\)',
            r'ntohl\s*\(\s*(\w+)\s*\)',
            r'ntohll\s*\(\s*(\w+)\s*\)'
        ]
        
        for pattern in ntoh_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                patterns['length_fields'].append(match)
        
        magic_patterns = [
            r'memcmp\s*\(\s*(\w+)\s*,\s*["\']([^\'"]+)["\']',
            r'strcmp\s*\(\s*(\w+)\s*,\s*["\']([^\'"]+)["\']'
        ]
        
        for pattern in magic_patterns:
            matches = re.findall(pattern, output)
            for var, magic in matches:
                patterns['magic_values'].append((var, magic))
        
        return patterns
    
    def _analyze_raw_binary(self) -> Dict[str, Any]:
        """直接分析二进制文件"""
        patterns = {
            'length_fields': [],
            'magic_values': [],
            'enum_patterns': [],
            'string_patterns': [],
            'struct_sizes': []
        }
        
        try:
            with open(self.binary_path, 'rb') as f:
                content = f.read()
            
            common_magic_values = [
                b'\x00\x00', b'\x01\x00', b'\xff\xff',
                b'\x00\x01', b'\x80\x00', b'\x00\x80'
            ]
            
            for magic in common_magic_values:
                if magic in content:
                    patterns['magic_values'].append(('binary', magic.hex()))
            
            import re
            for match in re.finditer(rb'recvfrom|recv|read', content):
                patterns['length_fields'].append(f"recv_at_0x{match.start():x}")
            
        except Exception as e:
            logger.debug(f"二进制分析失败: {e}")
        
        return patterns
    
    def _build_protocol_messages(self, patterns: Dict[str, Any]) -> List[ProtocolMessage]:
        """基于分析结果构建协议消息"""
        messages = []
        
        if self.pcap_samples:
            for sample in self.pcap_samples[:5]:
                msg = self._infer_from_sample(sample)
                if msg:
                    messages.append(msg)
        
        if not messages:
            default_msg = ProtocolMessage('GenericMessage')
            default_msg.add_field(ProtocolField(
                name='magic',
                field_type=ProtocolFieldType.UINT16,
                offset=0,
                size=2
            ))
            default_msg.add_field(ProtocolField(
                name='length',
                field_type=ProtocolFieldType.UINT16,
                offset=2,
                size=2
            ))
            default_msg.add_field(ProtocolField(
                name='payload',
                field_type=ProtocolFieldType.BYTES,
                offset=4,
                size=0,
                length_field='length'
            ))
            messages.append(default_msg)
        
        return messages
    
    def _infer_from_sample(self, sample: bytes) -> Optional[ProtocolMessage]:
        """从单个样本推断消息格式"""
        if len(sample) < 4:
            return None
        
        msg = ProtocolMessage(f'Message_{len(sample)}_bytes')
        
        offset = 0
        
        if len(sample) >= 2:
            first_word = int.from_bytes(sample[0:2], 'big')
            second_word = int.from_bytes(sample[2:4], 'big') if len(sample) >= 4 else 0
            
            if first_word == len(sample) or second_word == len(sample):
                if first_word == len(sample):
                    msg.add_field(ProtocolField(
                        name='length',
                        field_type=ProtocolFieldType.UINT16,
                        offset=0,
                        size=2
                    ))
                    offset += 2
                
                if second_word == len(sample) and first_word != len(sample):
                    msg.add_field(ProtocolField(
                        name='magic',
                        field_type=ProtocolFieldType.UINT16,
                        offset=0,
                        size=2
                    ))
                    msg.add_field(ProtocolField(
                        name='length',
                        field_type=ProtocolFieldType.UINT16,
                        offset=2,
                        size=2
                    ))
                    offset += 4
        
        remaining = len(sample) - offset
        
        if remaining > 0:
            msg.add_field(ProtocolField(
                name='payload',
                field_type=ProtocolFieldType.BYTES,
                offset=offset,
                size=remaining
            ))
        
        return msg
    
    def _refine_with_pcap(self):
        """使用 PCAP 样本优化推断结果"""
        if not self.messages or not self.pcap_samples:
            return
        
        for msg in self.messages:
            length_fields = [f for f in msg.fields if f.name == 'length']
            
            if length_fields:
                length_field = length_fields[0]
                
                for sample in self.pcap_samples:
                    if len(sample) >= length_field.offset + length_field.size:
                        expected_len = int.from_bytes(
                            sample[length_field.offset:length_field.offset + length_field.size],
                            'big'
                        )
                        if expected_len != len(sample):
                            length_field.description = f"注意: 声明长度({expected_len}) != 实际长度({len(sample)})"
    
    def generate_protocol_spec(self) -> str:
        """生成协议规格文档"""
        lines = []
        lines.append("# 协议格式规格说明")
        lines.append("")
        
        for msg in self.messages:
            lines.append(f"## {msg.name}")
            lines.append("")
            lines.append("| 字段名 | 类型 | 偏移 | 大小 | 说明 |")
            lines.append("|--------|------|------|------|------|")
            
            for field in msg.fields:
                description = field.description or ""
                lines.append(f"| {field.name} | {field.field_type.value} | {field.offset} | {field.size} | {description} |")
            
            lines.append("")
        
        return '\n'.join(lines)


class ProtocolFuzzGenerator:
    """
    协议模糊测试用例生成器
    
    基于推断的协议格式生成针对性的模糊测试用例
    """
    
    def __init__(self, protocol_messages: List[ProtocolMessage]):
        """
        初始化模糊测试生成器
        
        Args:
            protocol_messages: 协议消息定义列表
        """
        self.protocol_messages = protocol_messages
        self.generated_cases: List[bytes] = []
        
        logger.info(f"ProtocolFuzzGenerator 初始化完成: {len(protocol_messages)} 个消息类型")
    
    def generate_seed_cases(self, count: int = 10) -> List[bytes]:
        """
        生成有效种子消息
        
        Args:
            count: 生成数量
        
        Returns:
            种子消息列表
        """
        cases = []
        
        for _ in range(count):
            for msg in self.protocol_messages:
                seed = self._generate_valid_seed(msg)
                if seed:
                    cases.append(seed)
        
        self.generated_cases.extend(cases)
        return cases
    
    def _generate_valid_seed(self, msg: ProtocolMessage) -> Optional[bytes]:
        """生成单个有效种子"""
        total_size = msg.get_total_size()
        
        if total_size == 0:
            total_size = 64
        
        seed = bytearray(total_size)
        
        offset = 0
        for field in msg.fields:
            if offset + field.size > len(seed):
                break
            
            if field.field_type in [
                ProtocolFieldType.UINT8, ProtocolFieldType.UINT16,
                ProtocolFieldType.UINT32, ProtocolFieldType.UINT64
            ]:
                value = len(seed) if field.name == 'length' else 0x12345678
                packed = self._pack_value(value, field.field_type)
                seed[offset:offset + min(field.size, len(packed))] = packed[:field.size]
            
            elif field.field_type == ProtocolFieldType.STRING:
                seed[offset:offset + field.size] = b'test_string\x00'[:field.size]
            
            elif field.field_type == ProtocolFieldType.BYTES:
                seed[offset:offset + field.size] = b'\x00' * field.size
            
            offset += field.size
        
        return bytes(seed)
    
    def _pack_value(self, value: int, field_type: ProtocolFieldType) -> bytes:
        """打包值为字节"""
        if field_type == ProtocolFieldType.UINT8:
            return bytes([value & 0xFF])
        elif field_type == ProtocolFieldType.UINT16:
            return (value & 0xFFFF).to_bytes(2, 'big')
        elif field_type == ProtocolFieldType.UINT32:
            return (value & 0xFFFFFFFF).to_bytes(4, 'big')
        elif field_type == ProtocolFieldType.UINT64:
            return (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')
        return b'\x00'
    
    def generate_mutation_cases(self, seed: bytes, count: int = 5) -> List[bytes]:
        """
        对种子应用变异策略
        
        Args:
            seed: 原始种子
            count: 变异数量
        
        Returns:
            变异后的消息列表
        """
        mutations = []
        
        mutations.append(self._bit_flip_mutation(seed))
        mutations.append(self._length_overflow(seed))
        mutations.append(self._special_values(seed))
        mutations.append(self._truncation(seed))
        mutations.append(self._append_garbage(seed))
        
        return mutations[:count]
    
    def _bit_flip_mutation(self, seed: bytes) -> bytes:
        """比特翻转变异"""
        result = bytearray(seed)
        for i in range(min(3, len(result))):
            result[i] ^= 0xFF
        return bytes(result)
    
    def _length_overflow(self, seed: bytes) -> bytes:
        """长度字段溢出"""
        result = bytearray(seed)
        
        if len(result) >= 4:
            result[0:4] = b'\xFF\xFF\xFF\xFF'
        elif len(result) >= 2:
            result[0:2] = b'\xFF\xFF'
        
        return bytes(result)
    
    def _special_values(self, seed: bytes) -> bytes:
        """特殊值变异"""
        result = bytearray(seed)
        
        special_values = [0x00, 0xFF, 0x7F, 0x80, 0x41414141]
        
        for i in range(min(len(special_values), len(result) // 4)):
            offset = i * 4
            if offset + 4 <= len(result):
                result[offset:offset + 4] = special_values[i].to_bytes(4, 'big')
        
        return bytes(result)
    
    def _truncation(self, seed: bytes) -> bytes:
        """截断变异"""
        if len(seed) <= 1:
            return seed
        
        truncate_to = max(1, len(seed) // 2)
        return seed[:truncate_to]
    
    def _append_garbage(self, seed: bytes) -> bytes:
        """追加垃圾数据"""
        garbage = b'\x41' * 100
        return seed + garbage
    
    def generate_fuzzing_harness(self, output_path: str = None) -> str:
        """
        生成 LibFuzzer 风格的 harness 代码
        
        Args:
            output_path: 输出文件路径（可选）
        
        Returns:
            Harness 代码字符串
        """
        harness_code = self._generate_harness_code()
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(harness_code)
            logger.info(f"Fuzzer harness 已保存: {output_path}")
        
        return harness_code
    
    def _generate_harness_code(self) -> str:
        """生成 harness C 代码"""
        message_defs = []
        for msg in self.protocol_messages:
            fields = []
            for field in msg.fields:
                c_type = self._field_type_to_c_type(field.field_type)
                fields.append(f"    {c_type} {field.name};")
            message_defs.append(f"struct {msg.name.lower()} {{\n" + "\n".join(fields) + "\n};")
        
        harness = f"""/*
 * Protocol Fuzzing Harness
 * Generated by Deemo Vulnerability Analysis Tool
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)

{chr(10).join(message_defs)}

#pragma pack(pop)

extern void process_protocol_message(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0 || data == NULL) {{
        return 0;
    }}
    
    process_protocol_message(data, size);
    
    return 0;
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{
        return 1;
    }}
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {{
        return 1;
    }}
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *buf = malloc(size);
    if (!buf) {{
        fclose(f);
        return 1;
    }}
    
    fread(buf, 1, size, f);
    fclose(f);
    
    process_protocol_message(buf, size);
    free(buf);
    
    return 0;
}}
"""
        return harness
    
    def _field_type_to_c_type(self, field_type: ProtocolFieldType) -> str:
        """将协议字段类型转换为 C 类型"""
        mapping = {
            ProtocolFieldType.UINT8: 'uint8_t',
            ProtocolFieldType.UINT16: 'uint16_t',
            ProtocolFieldType.UINT32: 'uint32_t',
            ProtocolFieldType.UINT64: 'uint64_t',
            ProtocolFieldType.INT8: 'int8_t',
            ProtocolFieldType.INT16: 'int16_t',
            ProtocolFieldType.INT32: 'int32_t',
            ProtocolFieldType.INT64: 'int64_t',
            ProtocolFieldType.STRING: 'char[256]',
            ProtocolFieldType.BYTES: 'uint8_t[256]',
        }
        return mapping.get(field_type, 'uint8_t')
    
    def generate_afl_dict(self, output_path: str = None) -> str:
        """
        生成 AFL 字典文件
        
        Args:
            output_path: 输出文件路径（可选）
        
        Returns:
            字典内容字符串
        """
        dict_entries = []
        
        for msg in self.protocol_messages:
            for field in msg.fields:
                if field.enum_values:
                    for value, name in field.enum_values.items():
                        dict_entries.append(f"{name}={value.to_bytes(4, 'big').hex()}")
        
        dict_content = '\n'.join(dict_entries)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(dict_content)
            logger.info(f"AFL 字典已保存: {output_path}")
        
        return dict_content
    
    def get_all_cases(self) -> List[bytes]:
        """获取所有生成的测试用例"""
        return self.generated_cases.copy()


def create_protocol_inferrer(binary_path: str) -> ProtocolFormatInferrer:
    """
    创建协议格式推断器的便捷函数
    
    Args:
        binary_path: 目标二进制路径
    
    Returns:
        ProtocolFormatInferrer 实例
    """
    return ProtocolFormatInferrer(binary_path)


def create_fuzz_generator(protocol_messages: List[ProtocolMessage]) -> ProtocolFuzzGenerator:
    """
    创建协议模糊测试生成器的便捷函数
    
    Args:
        protocol_messages: 协议消息定义列表
    
    Returns:
        ProtocolFuzzGenerator 实例
    """
    return ProtocolFuzzGenerator(protocol_messages)