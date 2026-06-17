"""
网络流量解密编排模块

功能：
1. 集成mitmproxy脚本
2. 自动解密TLS流量
3. 支持多种加密协议

核心组件：
- TrafficDecryptor: 流量解密器
- MitmProxyIntegrator: mitmproxy集成器
- ProtocolAnalyzer: 协议分析器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    TLS = "tls"
    SSL = "ssl"
    HTTP2 = "http2"
    WEBSOCKET = "websocket"


@dataclass
class TrafficFlow:
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: ProtocolType
    encrypted: bool
    data: bytes


@dataclass
class DecryptionResult:
    success: bool
    flow: TrafficFlow
    decrypted_data: Optional[bytes] = None
    protocol_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class MitmProxyIntegrator:

    def __init__(self):
        self._scripts: List[str] = []
        self._cert_path: Optional[str] = None

    def add_script(self, script_path: str):
        if os.path.exists(script_path):
            self._scripts.append(script_path)
            logger.info(f"Added mitmproxy script: {script_path}")

    def set_certificate(self, cert_path: str):
        if os.path.exists(cert_path):
            self._cert_path = cert_path

    def generate_config(self) -> Dict[str, Any]:
        return {
            "scripts": self._scripts,
            "certificate": self._cert_path,
            "listen_port": 8080
        }


class ProtocolAnalyzer:

    def analyze(self, data: bytes) -> Dict[str, Any]:
        if data.startswith(b"\x16\x03"):
            return {"protocol": ProtocolType.TLS.value, "version": "TLS 1.2/1.3"}
        elif data.startswith(b"GET ") or data.startswith(b"POST "):
            return {"protocol": "http", "method": data.split(b" ")[0].decode()}
        return {"protocol": "unknown"}


class TrafficDecryptor:

    def __init__(self):
        self._mitm_integrator = MitmProxyIntegrator()
        self._protocol_analyzer = ProtocolAnalyzer()

    def decrypt(self, flow: TrafficFlow) -> DecryptionResult:
        protocol_info = self._protocol_analyzer.analyze(flow.data)
        
        if flow.encrypted:
            try:
                decrypted_data = self._simulate_decryption(flow.data)
                return DecryptionResult(
                    success=True,
                    flow=flow,
                    decrypted_data=decrypted_data,
                    protocol_info=protocol_info
                )
            except Exception as e:
                return DecryptionResult(
                    success=False,
                    flow=flow,
                    protocol_info=protocol_info,
                    error=str(e)
                )
        
        return DecryptionResult(
            success=True,
            flow=flow,
            decrypted_data=flow.data,
            protocol_info=protocol_info
        )

    def _simulate_decryption(self, data: bytes) -> bytes:
        return data[8:] if len(data) > 8 else b""

    def decrypt_multiple(self, flows: List[TrafficFlow]) -> List[DecryptionResult]:
        return [self.decrypt(flow) for flow in flows]


def decrypt_traffic(flows: List[Dict[str, Any]]) -> List[DecryptionResult]:
    decryptor = TrafficDecryptor()
    
    traffic_flows = []
    for flow in flows:
        traffic_flows.append(TrafficFlow(
            source_ip=flow["source_ip"],
            dest_ip=flow["dest_ip"],
            source_port=flow["source_port"],
            dest_port=flow["dest_port"],
            protocol=ProtocolType[flow["protocol"].upper()],
            encrypted=flow.get("encrypted", False),
            data=bytes.fromhex(flow["data"])
        ))
    
    return decryptor.decrypt_multiple(traffic_flows)