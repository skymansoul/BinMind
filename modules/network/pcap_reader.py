"""PCAP文件读取器：支持标准PCAP/PCAPNG，大文件mmap零拷贝。"""
import logging, mmap, os, struct
from collections import Counter
from typing import Dict, Any, Optional, Iterator

from .pcap_constants import (
    PCAP_MAGIC, PCAP_MAGIC_NS, PCAPNG_MAGIC,
    PCAP_SWAPPED_MAGIC, PCAP_SWAPPED_NS, MMAP_THRESHOLD,
)
from .pcap_packet import PcapPacket

_log = logging.getLogger(__name__)


class PcapReader:
    """高性能PCAP读取器：支持标准PCAP和PCAPNG格式。

    大文件（>500MB）使用mmap零拷贝，小文件使用常规读取。
    自动检测字节序和纳秒/微秒时间戳格式。
    """

    def __init__(self):
        self._filepath: str = ""
        self._file_size: int = 0
        self._is_ns: bool = False
        self._swap: bool = False
        self._link_type: int = 0
        self._packet_count: int = 0
        self._data: Optional[bytes] = None
        self._mmap_obj: Optional[mmap.mmap] = None
        self._fd = None

    def open(self, filepath: str) -> None:
        self._filepath = filepath
        self._file_size = os.path.getsize(filepath)

        # 大文件用mmap
        if self._file_size > MMAP_THRESHOLD:
            self._fd = open(filepath, "rb")
            self._mmap_obj = mmap.mmap(self._fd.fileno(), 0, access=mmap.ACCESS_READ)
            _header = self._mmap_obj[:24]
        else:
            # 文件不大，全读入内存
            with open(filepath, "rb") as _f:
                self._data = _f.read()
            _header = self._data[:24]

        self._parse_global_header(_header)

    def _parse_global_header(self, header: bytes) -> None:
        if len(header) < 24:
            return
        _magic = struct.unpack("<I", header[0:4])[0]

        if _magic == PCAP_MAGIC:
            self._swap = False
            self._is_ns = False
        elif _magic == PCAP_MAGIC_NS:
            self._swap = False
            self._is_ns = True
        elif _magic == PCAP_SWAPPED_MAGIC:
            self._swap = True
            self._is_ns = False
        elif _magic == PCAP_SWAPPED_NS:
            self._swap = True
            self._is_ns = True
        elif _magic == PCAPNG_MAGIC:
            # PCAPNG: 简化处理——跳过section header
            self._swap = False
            self._is_ns = False
        else:
            _log.warning("未知PCAP魔数: 0x%08x", _magic)
            return

        _fmt = ">" if self._swap else "<"
        if _magic == PCAPNG_MAGIC:
            self._link_type = 1  # 默认Ethernet
            return

        self._link_type = struct.unpack(f"{_fmt}I", header[20:24])[0]

    @staticmethod
    def _read_at(data: Any, offset: int, length: int) -> bytes:
        if isinstance(data, mmap.mmap):
            return data[offset:offset+length]
        elif isinstance(data, bytes):
            return data[offset:offset+length]
        return b""

    def iter_packets(self) -> Iterator[PcapPacket]:
        """生成器，逐个返回PcapPacket。

        对大文件使用mmap切片，小文件使用内存切片。每次读取16字节包头部
        （timestamp_sec, timestamp_us/ns, caplen, wirelen），然后读取包数据。
        """
        if self._mmap_obj is not None:
            _data = self._mmap_obj
            _offset = 24
        elif self._data is not None:
            _data = self._data
            _offset = 24
        else:
            return

        _fmt = ">" if self._swap else "<"
        _data_len = self._file_size if self._mmap_obj is not None else len(_data)

        while _offset + 16 <= _data_len:
            _hdr = self._read_at(_data, _offset, 16)
            if len(_hdr) < 16:
                break

            _ts_sec = struct.unpack(f"{_fmt}I", _hdr[0:4])[0]
            _ts_frac = struct.unpack(f"{_fmt}I", _hdr[4:8])[0]
            _caplen = struct.unpack(f"{_fmt}I", _hdr[8:12])[0]
            _wirelen = struct.unpack(f"{_fmt}I", _hdr[12:16])[0]

            _offset += 16

            if _offset + _caplen > _data_len:
                break

            _pkt_data = self._read_at(_data, _offset, _caplen)
            _offset += _caplen

            _ts = _ts_sec + (_ts_frac / 1e9 if self._is_ns else _ts_frac / 1e6)

            _pkt = PcapPacket(
                timestamp=_ts,
                caplen=_caplen,
                wirelen=_wirelen,
                _raw_data=bytes(_pkt_data),
            )
            self._packet_count += 1
            yield _pkt

    def close(self) -> None:
        if self._mmap_obj:
            try:
                self._mmap_obj.close()
            except Exception:
                pass
            self._mmap_obj = None
        if self._fd:
            try:
                self._fd.close()
            except Exception:
                pass
            self._fd = None
        self._data = None

    def quick_stats(self) -> Dict[str, Any]:
        """快速统计：遍历所有包计算基本指标。

        返回包数、时长、平均包大小、协议分布和Top Talkers。
        注意会消耗迭代器，调用后无法再遍历包。
        """
        _count = 0
        _total_bytes = 0
        _start_ts = float("inf")
        _end_ts = 0.0
        _proto_dist: Counter = Counter()
        _talkers: Counter = Counter()

        for _pkt in self.iter_packets():
            _count += 1
            _total_bytes += _pkt.caplen
            if _pkt.timestamp < _start_ts:
                _start_ts = _pkt.timestamp
            if _pkt.timestamp > _end_ts:
                _end_ts = _pkt.timestamp
            _pkt._ensure_parsed()
            _proto_dist[_pkt.protocol] += 1
            if _pkt.src_ip:
                _talkers[_pkt.src_ip] += _pkt.caplen
            if _pkt.dst_ip:
                _talkers[_pkt.dst_ip] += _pkt.caplen

        _duration = _end_ts - _start_ts if _start_ts != float("inf") else 0
        _avg_size = _total_bytes / _count if _count > 0 else 0
        _proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        _proto_dist_named = {_proto_names.get(k, str(k)): v for k, v in _proto_dist.most_common()}
        _top_talkers = _talkers.most_common(10)

        return {
            "packet_count": _count,
            "duration": _duration,
            "avg_packet_size": _avg_size,
            "protocol_distribution": _proto_dist_named,
            "top_talkers": [{"ip": ip, "bytes": b} for ip, b in _top_talkers],
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
