"""网络取证——五元组流追踪器。"""
import logging
from typing import List, Dict, Optional, Tuple
from time import time as _time_now

from ._nf_types import (
    FlowRecord, TCP_IDLE_TIMEOUT, UDP_IDLE_TIMEOUT, FLOW_HARD_TIMEOUT,
)

_log = logging.getLogger(__name__)


class FlowTracker:
    """对网络流量进行五元组流追踪，支持超时回收和统计。

    设计决策：使用字典键 (src_ip, dst_ip, src_port, dst_port, proto) 追踪流。
    区分出/入方向但存入同一FlowRecord中。超时回收避免内存膨胀。
    """

    def __init__(self):
        self._flows: Dict[Tuple, FlowRecord] = {}
        self._expired_count = 0

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, protocol: int) -> Tuple:
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def update_flow(self, src_ip: str, dst_ip: str, src_port: int,
                    dst_port: int, protocol: int, payload_len: int,
                    ts: Optional[float] = None, direction: str = "out") -> None:
        """更新流统计：累加字节数、包数、记录首末时间戳。

        方向判定：'out'从源到目的，'in'从目的到源。payload_len
        需含L4以上负载。时间戳默认使用当前时间。
        """
        _key = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        _now = ts if ts is not None else _time_now()

        if _key not in self._flows:
            _r = FlowRecord(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol, start_ts=_now, last_ts=_now,
            )
            self._flows[_key] = _r

        _r = self._flows[_key]
        _r.bytes_sum += payload_len
        _r.packets += 1
        _r.last_ts = _now

        # 记录时间戳序列（信标检测）
        if len(_r._timestamps) > 0:
            _interval = _now - _r._timestamps[-1]
            if _interval > 0:
                _r._intervals.append(_interval)
        _r._timestamps.append(_now)

        if direction == "out":
            _r.bytes_out += payload_len
        else:
            _r.bytes_in += payload_len

    def expire_stale(self, now: Optional[float] = None) -> List[FlowRecord]:
        """回收超时流，释放内存"""
        _now = now or _time_now()
        _stale: List[FlowRecord] = []
        _to_del: List[Tuple] = []

        for _key, _flow in self._flows.items():
            _idle_threshold = TCP_IDLE_TIMEOUT if _flow.protocol == 6 else UDP_IDLE_TIMEOUT
            if _now - _flow.last_ts > _idle_threshold or _now - _flow.start_ts > FLOW_HARD_TIMEOUT:
                _stale.append(_flow)
                _to_del.append(_key)

        for _k in _to_del:
            del self._flows[_k]
        self._expired_count += len(_stale)
        return _stale

    def get_active_flows(self) -> List[FlowRecord]:
        return list(self._flows.values())

    def get_flow_count(self) -> int:
        self.expire_stale()
        return len(self._flows)
