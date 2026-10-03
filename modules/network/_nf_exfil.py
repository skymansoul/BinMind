"""网络取证——数据外泄与端口协议不匹配检测。"""
from typing import List, Dict, Any

from ._nf_types import (
    FlowRecord, EXFIL_RATIO_WARN, EXFIL_RATIO_DEFINITE, KNOWN_PORTS,
)


def traffic_asymmetry(flow: FlowRecord) -> Dict[str, Any]:
    """流量不对称性分析：出/入字节比。

    上传/外泄场景：bytes_out >> bytes_in。比值>20:1警告，>100:1确认。
    反向极低比值可能为下载/接收通道。
    """
    _out = flow.bytes_out
    _in = flow.bytes_in
    if _in <= 0 and _out > 0:
        return {"ratio": float("inf"), "severity": "definite", "direction": "outbound_only"}
    if _out <= 0 and _in > 0:
        return {"ratio": 0.0, "severity": "definite", "direction": "inbound_only"}
    if _out <= 0 and _in <= 0:
        return {"ratio": 1.0, "severity": "normal", "direction": "balanced"}

    _ratio = _out / _in
    if _ratio >= EXFIL_RATIO_DEFINITE:
        _sev = "definite"
    elif _ratio >= EXFIL_RATIO_WARN:
        _sev = "warning"
    else:
        _sev = "normal"
    return {"ratio": _ratio, "severity": _sev, "direction": "outbound" if _ratio > 10 else "balanced"}


def check_port_protocol_mismatch(flow: FlowRecord) -> List[str]:
    """检测端口与协议不匹配的可疑行为。

    例如：UDP在端口80上、TCP在DNS端口53上大流量传输、SSH在443端口等。
    返回告警信息列表。
    """
    alerts: List[str] = []
    _proto = flow.protocol
    _dport = flow.dst_port
    _sport = flow.src_port

    # UDP在常见TCP端口上
    if _proto == 17:
        if _dport in (80, 443, 22):
            alerts.append(f"UDP on port {_dport} ({KNOWN_PORTS.get(_dport, 'unknown')}) - unusual")
        if _sport in (80, 443, 22):
            alerts.append(f"UDP from port {_sport} ({KNOWN_PORTS.get(_sport, 'unknown')}) - unusual")

    # TCP DNS 区域传输
    if _proto == 6 and (_dport == 53 or _sport == 53) and flow.bytes_sum > 512:
        alerts.append("TCP on port 53 with large payload (>512 bytes) - possible zone transfer or DNS tunnel")

    # 已知C2常用端口
    _c2_ports = {4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321}
    if _dport in _c2_ports or _sport in _c2_ports:
        alerts.append(f"C2-associated port {_dport if _dport in _c2_ports else _sport}")

    return alerts
