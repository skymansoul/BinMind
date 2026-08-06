# ICS协议方言指纹识别 —— 通过实现级行为偏差识别工控设备厂商/固件。
#
# Modbus/DNP3/S7等ICS协议虽有标准规范, 各厂商实现存在微妙差异。
# 这些"方言"特征不依赖显式banner字段(如Modbus MEI的VendorName,
# 它可能被禁用或伪造), 而是从协议行为推断。
#
# 方言标记维度:
#   1. 功能码响应谱: 对支持的/不支持的功能码返回不同的异常码映射
#   2. 时序签名: 标准查询的响应延迟分布(均值/方差/分位数)
#   3. 边界行为: 最大PDU尺寸/超出范围输入的截断策略
#   4. 字节序: 多字节字段(扩展地址/长度)的字节序
#   5. 异常细节: 异常码的粒度(粗粒度=仅0x01/0x02, 细粒度=完整异常码)
#   6. 可选扩展: 对厂商特定功能码(0x41-0x48)的响应模式
#
# 与现有工作的差异:
#   - zgrab2 banner抓取: 仅获取显式vendor字段, 可禁用/伪造
#   - 物理指纹(时序): 需物理访问, 不可规模化
#   - 未见2024-2025文献涉及协议方言级别的ICS设备指纹识别
#
# 输出: 方言指纹向量 + 最佳匹配厂商(含匹配置信度)。

from __future__ import annotations

import hashlib
import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# Modbus功能码分组 —— 用于构造探测序列
_MODBUS_FC = {
    "read_coils": 0x01,
    "read_discrete_inputs": 0x02,
    "read_holding_registers": 0x03,
    "read_input_registers": 0x04,
    "write_single_coil": 0x05,
    "write_single_register": 0x06,
    "write_multiple_coils": 0x0F,
    "write_multiple_registers": 0x10,
    "report_server_id": 0x11,       # 必支持, 返回vendor信息
    "read_file_record": 0x14,       # 可选的
    "write_file_record": 0x15,      # 可选的
    "mask_write_register": 0x16,    # 可选的
    "read_write_multiple_registers": 0x17,  # 可选的
}

# 厂商特定功能码范围
_VENDOR_FC_RANGE = list(range(0x41, 0x49)) + list(range(0x64, 0x6E))

# 常见Modbus异常码
_EXCEPTION_CODES = {
    0x01: "illegal_function",
    0x02: "illegal_data_address",
    0x03: "illegal_data_value",
    0x04: "slave_device_failure",
    0x05: "acknowledge",
    0x06: "slave_device_busy",
    0x07: "negative_acknowledge",
    0x08: "memory_parity_error",
    0x0A: "gateway_path_unavailable",
    0x0B: "gateway_target_failed",
}


@dataclass
class DialectProbe:
    """单次探测的定义与响应"""
    function_code: int
    payload: bytes
    description: str = ""
    response_raw: Optional[bytes] = None
    response_latency_ms: float = 0.0
    is_exception: bool = False
    exception_code: int = 0
    response_len: int = 0


@dataclass
class DialectFingerprint:
    """ICS设备方言指纹 —— 多维特征向量"""
    device_address: int = 1
    protocol: str = "modbus"
    # 特征维度
    supported_fc: Set[int] = field(default_factory=set)
    exception_map: Dict[int, int] = field(default_factory=dict)
    # fc→exception_code
    latency_stats: Dict[str, float] = field(default_factory=dict)
    # mean/median/std/p90(ms)
    max_pdu_size: int = 253
    byte_order: str = "big"           # "big" / "little" / "mixed"
    vendor_fc_responses: Dict[int, int] = field(default_factory=dict)
    # 厂商特定fc→响应模式(0=none,1=exception,2=data)
    exception_granularity: str = "standard"
    # "coarse"=仅0x01/02, "standard"=完整, "extended"=含厂商异常
    fingerprint_id: str = ""          # SHA-256截断标识
    matched_vendor: str = ""
    match_confidence: float = 0.0


class IcsDialectProber:
    """ICS协议方言探测器 —— 发送标准化探测序列并收集响应特征。

    探测序列设计原则(S^3):
      1. 覆盖标准功能码(必支持)与可选功能码(区分实现)
      2. 包含边界输入(最大地址/零地址/越界地址)
      3. 包含厂商特定功能码空间(0x41-0x48)
    对每个探测记录: 响应是否异常/异常码/延迟/响应长度。
    """

    def __init__(self, protocol: str = "modbus",
                 device_address: int = 1):
        self._proto = protocol
        self._addr = device_address
        self._probes: List[DialectProbe] = []

    def build_probe_sequence(self) -> List[DialectProbe]:
        """构造模组探测序列。调用方注入send_fn后执行探测。"""
        probes: List[DialectProbe] = []

        # 标准功能码: 读取类(必支持)
        for name, fc in _MODBUS_FC.items():
            if fc <= 0x06:
                probes.append(DialectProbe(
                    fc, self._modbus_read_pdu(fc),
                    f"standard_read_{name}"))
            elif fc == 0x11:
                probes.append(DialectProbe(
                    fc, bytes([self._addr, fc, 0, 0]),
                    "report_server_id"))

        # 可选功能码
        for name, fc in _MODBUS_FC.items():
            if fc > 0x11:
                probes.append(DialectProbe(
                    fc, self._modbus_write_pdu(fc),
                    f"optional_{name}"))

        # 边界探测: 最大/最小地址
        probes.append(DialectProbe(
            0x03, struct.pack('>BBHH', self._addr, 0x03, 0xFFFF, 1),
            "boundary_max_addr"))
        probes.append(DialectProbe(
            0x03, struct.pack('>BBHH', self._addr, 0x03, 0x0000, 1),
            "boundary_zero_addr"))
        # 大长度请求(>125寄存器 → 可能超过设备限制)
        probes.append(DialectProbe(
            0x03, struct.pack('>BBHH', self._addr, 0x03, 0x0000, 125),
            "boundary_large_read"))

        # 无效功能码
        probes.append(DialectProbe(
            0x7F, bytes([self._addr, 0x7F, 0, 0]),
            "invalid_fc_reserved"))

        # 厂商特定功能码探测(0x41-0x48)
        for vfc in _VENDOR_FC_RANGE[:8]:
            probes.append(DialectProbe(
                vfc, bytes([self._addr, vfc, 0, 0]),
                f"vendor_fc_{vfc:02X}"))

        self._probes = probes
        return probes

    def _modbus_read_pdu(self, fc: int) -> bytes:
        """构造Modbus读取类请求PDU(不含地址/CRC, 由调用方组装)"""
        return struct.pack('>BBHH', self._addr, fc, 0x0000, 1)

    def _modbus_write_pdu(self, fc: int) -> bytes:
        """构造Modbus写入类请求PDU"""
        if fc == 0x05:
            return struct.pack('>BBHH', self._addr, fc, 0x0000, 0xFF00)
        elif fc == 0x06:
            return struct.pack('>BBHH', self._addr, fc, 0x0000, 0x1234)
        elif fc == 0x0F:
            return struct.pack('>BBHHB', self._addr, fc, 0x0000, 1, 0x01) + bytes([0xFF])
        elif fc == 0x10:
            return struct.pack('>BBHHB', self._addr, fc, 0x0000, 1, 2) + struct.pack('>H', 0xABCD)
        return bytes([self._addr, fc, 0, 0])

    def record_response(self, probe_index: int,
                         response: Optional[bytes],
                         latency_ms: float) -> None:
        """记录单次探测的响应数据"""
        if probe_index < 0 or probe_index >= len(self._probes):
            return
        p = self._probes[probe_index]
        p.response_latency_ms = latency_ms
        if response is None:
            p.is_exception = True  # 超时视为异常
            return
        p.response_raw = response
        p.response_len = len(response)
        # Modbus异常: 功能码最高位置1
        if len(response) >= 2 and response[1] & 0x80:
            p.is_exception = True
            p.exception_code = response[2] if len(response) > 2 else 0
        else:
            p.is_exception = False


from .dialect_matcher import DialectFingerprinter, fingerprint_device


__all__ = [
    "DialectProbe", "DialectFingerprint",
    "IcsDialectProber", "fingerprint_device",
]
