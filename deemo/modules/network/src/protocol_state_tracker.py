# 协议状态追踪器 —— 跨协议(TCP/TLS/HTTP/DNS)响应分类与状态转移检测。
#
# 对每个协议维护状态转移模板。当目标响应触发的转移不在模板中时,
# 标记为异常。分类策略按协议使用不同的字节级特征:
#   TCP: 标志位(SYN/ACK/FIN/RST)
#   TLS: 记录类型(handshake/change_cipher/app_data/alert)
#   HTTP: 状态行+Connection头
#   DNS: QR标志+响应码

from __future__ import annotations

import time
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple


class ProtoState(Enum):
    INIT       = auto()
    CONNECTING = auto()
    HANDSHAKE  = auto()
    ACTIVE     = auto()
    CLOSING    = auto()
    CLOSED     = auto()
    ERROR      = auto()


_PROTO_STATE_TEMPLATES: Dict[str, Dict[Tuple[ProtoState, str], ProtoState]] = {
    "TCP": {
        (ProtoState.INIT, "syn_ack"): ProtoState.CONNECTING,
        (ProtoState.CONNECTING, "ack"): ProtoState.ACTIVE,
        (ProtoState.ACTIVE, "fin"): ProtoState.CLOSING,
        (ProtoState.CLOSING, "ack"): ProtoState.CLOSED,
        (ProtoState.ACTIVE, "rst"): ProtoState.CLOSED,
    },
    "TLS": {
        (ProtoState.INIT, "client_hello"): ProtoState.CONNECTING,
        (ProtoState.CONNECTING, "server_hello"): ProtoState.HANDSHAKE,
        (ProtoState.HANDSHAKE, "certificate"): ProtoState.HANDSHAKE,
        (ProtoState.HANDSHAKE, "finished"): ProtoState.ACTIVE,
        (ProtoState.ACTIVE, "close_notify"): ProtoState.CLOSING,
    },
    "HTTP": {
        (ProtoState.INIT, "request_sent"): ProtoState.ACTIVE,
        (ProtoState.ACTIVE, "response_2xx"): ProtoState.ACTIVE,
        (ProtoState.ACTIVE, "response_4xx"): ProtoState.ACTIVE,
        (ProtoState.ACTIVE, "response_5xx"): ProtoState.ERROR,
        (ProtoState.ACTIVE, "connection_close"): ProtoState.CLOSING,
    },
}


class ProtocolStateTracker:
    """协议状态追踪器 —— 根据协议类型和响应分类追踪状态转移。"""

    def __init__(self, protocol: str = "TCP"):
        self._proto = protocol
        self._template = _PROTO_STATE_TEMPLATES.get(protocol, {})
        self._state = ProtoState.INIT
        self._history: List[Tuple[float, ProtoState]] = [
            (time.time(), ProtoState.INIT)]

    @property
    def current_state(self) -> ProtoState:
        return self._state

    @property
    def state_path(self) -> List[Tuple[float, str]]:
        return [(ts, s.name) for ts, s in self._history]

    def classify_response(self, response_bytes: bytes,
                           prev_packet: bytes = None) -> str:
        if not response_bytes:
            return "empty"
        if self._proto == "TCP":
            return self._classify_tcp(response_bytes)
        elif self._proto == "TLS":
            return self._classify_tls(response_bytes)
        elif self._proto == "HTTP":
            return self._classify_http(response_bytes)
        elif self._proto == "DNS":
            return self._classify_dns(response_bytes)
        return "unknown"

    def transition(self, response_label: str) -> Tuple[bool, Optional[str]]:
        key = (self._state, response_label)
        ts = time.time()
        if key in self._template:
            self._state = self._template[key]
            self._history.append((ts, self._state))
            return True, None
        else:
            anomaly = (f"协议{self._proto}: 非预期转移 "
                       f"({self._state.name} + {response_label})")
            self._history.append((ts, self._state))
            return False, anomaly

    def state_coverage(self) -> float:
        all_states = {ProtoState.INIT, ProtoState.CONNECTING,
                      ProtoState.HANDSHAKE, ProtoState.ACTIVE,
                      ProtoState.CLOSING, ProtoState.CLOSED, ProtoState.ERROR}
        visited = set(s for _, s in self._history)
        return len(visited) / len(all_states)

    # ---- 协议特定分类器 ----
    @staticmethod
    def _classify_tcp(data: bytes) -> str:
        if len(data) < 14:
            return "short_packet"
        flags = data[13] if len(data) > 13 else 0
        if flags & 0x02:
            return "syn_ack" if flags & 0x10 else "syn"
        if flags & 0x01:
            return "fin"
        if flags & 0x04:
            return "rst"
        if flags & 0x10:
            return "ack"
        return "data"

    @staticmethod
    def _classify_tls(data: bytes) -> str:
        if len(data) < 6:
            return "short_packet"
        ct = data[0] if data else 0
        ct_map = {0x16: "handshake", 0x14: "change_cipher_spec",
                  0x17: "application_data", 0x15: "alert"}
        return ct_map.get(ct, f"tls_ct_{ct}")

    @staticmethod
    def _classify_http(data: bytes) -> str:
        try:
            text = data[:120].decode('latin-1', errors='replace')
        except Exception:
            return "binary"
        if text.startswith("HTTP/1.") or text.startswith("HTTP/2"):
            try:
                code = int(text.split()[1])
                if 200 <= code < 300:
                    return "response_2xx"
                elif 400 <= code < 500:
                    return "response_4xx"
                elif 500 <= code < 600:
                    return "response_5xx"
            except (IndexError, ValueError):
                pass
        if "Connection: close" in text or "Connection: Close" in text:
            return "connection_close"
        return "http_other"

    @staticmethod
    def _classify_dns(data: bytes) -> str:
        if len(data) < 4:
            return "short_packet"
        flags = (data[2] << 8 | data[3]) if len(data) > 3 else 0
        qr = (flags >> 15) & 1
        rcode = flags & 0x0F
        if not qr:
            return "query"
        if rcode == 0:
            return "response_noerror"
        elif rcode == 3:
            return "response_nxdomain"
        return f"response_rcode_{rcode}"


__all__ = ["ProtoState", "ProtocolStateTracker"]
