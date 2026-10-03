"""隐蔽信道检测 —— 公共类型与常量定义。

独立出数据类和阈值常量，供各子检测器共享引用，
避免循环依赖。
"""
import math
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Any

_log = logging.getLogger(__name__)

# 熵值阈值 —— DNS/ICMP负载的字符分布异常判定线
_HIGH_ENTROPY_THRESHOLD = 4.0  # 接近随机分布的熵值（base64/加密数据）
# IAT抖动比阈值 —— 低于此值表示过度规律（可能编码了信息）
_IAT_JITTER_COVERT = 0.05
# 包长序列周期检测的类FFT自相关阈值
_AUTOCORR_THRESHOLD = 0.7


@dataclass
class CovertChannelAlert:
    channel_type: str   # timing / storage / dns_tunnel / icmp_tunnel / header_field
    description: str
    severity: str = "high"
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
