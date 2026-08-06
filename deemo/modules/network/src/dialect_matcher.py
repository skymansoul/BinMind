# ICS方言匹配器 —— 从探测特征提取指纹并与已知厂商库匹配。

import hashlib
import math
from typing import Dict, List, Set, Tuple

from .ics_dialect_fingerprint import DialectFingerprint, DialectProbe


class DialectFingerprinter:
    """方言指纹提取器 —— 从探测结果集提取多维特征向量。

    各特征维度独立归一化, 加权混合相似度匹配已知厂商库。
    权重基于特征区分度经验设定: FC谱(Jaccard)=0.35,
    异常粒度=0.20, 字节序=0.15, PDU尺寸=0.15, 时序=0.15。
    """

    def __init__(self):
        self._vendor_db: Dict[str, DialectFingerprint] = {}
        self._init_vendor_db()

    def _init_vendor_db(self) -> None:
        vendors = {
            "schneider_m340": DialectFingerprint(
                supported_fc={1, 2, 3, 4, 5, 6, 15, 16, 17, 43},
                max_pdu_size=250, byte_order="big",
                exception_granularity="standard",
                latency_stats={"mean": 15.0, "median": 12.0, "std": 5.0, "p90": 25.0}),
            "siemens_s7_1200": DialectFingerprint(
                supported_fc={1, 2, 3, 4, 5, 6, 15, 16},
                max_pdu_size=240, byte_order="big",
                exception_granularity="coarse",
                latency_stats={"mean": 8.0, "median": 7.0, "std": 2.0, "p90": 12.0}),
            "allen_bradley_mlogix": DialectFingerprint(
                supported_fc={1, 3, 4, 5, 6, 15, 16, 17, 20, 21},
                max_pdu_size=230, byte_order="little",
                exception_granularity="standard",
                latency_stats={"mean": 25.0, "median": 22.0, "std": 8.0, "p90": 40.0}),
            "wago_750": DialectFingerprint(
                supported_fc={1, 2, 3, 4, 5, 6, 15, 16, 17, 22, 23, 24},
                max_pdu_size=246, byte_order="big",
                exception_granularity="extended",
                latency_stats={"mean": 10.0, "median": 9.0, "std": 3.0, "p90": 16.0}),
            "generic_modbus": DialectFingerprint(
                supported_fc={1, 2, 3, 4, 5, 6, 15, 16, 17},
                max_pdu_size=253, byte_order="big",
                exception_granularity="standard",
                latency_stats={"mean": 20.0, "median": 18.0, "std": 6.0, "p90": 35.0}),
        }
        for name, fp in vendors.items():
            fp.fingerprint_id = self._compute_id(fp)
            self._vendor_db[name] = fp

    def extract(self, probes: List[DialectProbe],
                device_addr: int = 1) -> DialectFingerprint:
        fp = DialectFingerprint(device_address=device_addr, protocol="modbus")

        for p in probes:
            if p.response_raw is not None and not p.is_exception:
                fp.supported_fc.add(p.function_code)
            elif p.is_exception and p.exception_code > 0:
                fp.exception_map[p.function_code] = p.exception_code

        latencies = [p.response_latency_ms for p in probes
                    if p.response_latency_ms > 0 and not p.is_exception]
        if latencies:
            sorted_l = sorted(latencies)
            n = len(sorted_l)
            fp.latency_stats["mean"] = round(sum(latencies) / n, 2)
            fp.latency_stats["median"] = round(sorted_l[n // 2], 2)
            fp.latency_stats["std"] = round(
                math.sqrt(sum((x - fp.latency_stats["mean"]) ** 2
                             for x in latencies) / n), 2)
            fp.latency_stats["p90"] = round(
                sorted_l[int(n * 0.9)] if n > 1 else sorted_l[0], 2)

        max_len = 253
        for p in probes:
            if p.response_len > 0 and not p.is_exception:
                max_len = max(max_len, p.response_len)
        fp.max_pdu_size = max_len

        for p in probes:
            if (p.function_code == 0x10 and p.response_raw
                    and len(p.response_raw) >= 6):
                if len(p.response_raw) >= 5:
                    addr_bytes = p.response_raw[2:4]
                    if addr_bytes == b'\x00\x00':
                        fp.byte_order = "big"
                break

        for p in probes:
            if 0x41 <= p.function_code <= 0x6E:
                if p.response_raw and not p.is_exception:
                    fp.vendor_fc_responses[p.function_code] = 2
                elif p.is_exception and p.exception_code > 0:
                    fp.vendor_fc_responses[p.function_code] = 1
                else:
                    fp.vendor_fc_responses[p.function_code] = 0

        exc_codes_used = set(fp.exception_map.values())
        if exc_codes_used <= {0x01, 0x02}:
            fp.exception_granularity = "coarse"
        elif exc_codes_used & {0x08, 0x0A, 0x0B}:
            fp.exception_granularity = "extended"
        else:
            fp.exception_granularity = "standard"

        fp.fingerprint_id = self._compute_id(fp)
        return fp

    def match(self, fp: DialectFingerprint) -> Tuple[str, float]:
        best_vendor, best_score = "unknown", 0.0
        for vname, vfp in self._vendor_db.items():
            score = self._similarity(fp, vfp)
            if score > best_score:
                best_score = score
                best_vendor = vname
        return best_vendor, round(best_score, 4)

    @staticmethod
    def _similarity(a: DialectFingerprint,
                    b: DialectFingerprint) -> float:
        sa, sb = a.supported_fc or set(), b.supported_fc or set()
        fc_jaccard = len(sa & sb) / max(len(sa | sb), 1)
        exc_score = 1.0 if a.exception_granularity == b.exception_granularity else 0.3
        bo_score = 1.0 if a.byte_order == b.byte_order else 0.2
        pdu_diff = abs(a.max_pdu_size - b.max_pdu_size)
        pdu_score = max(0, 1.0 - pdu_diff / 50.0)
        timing_score = 0.5
        la, lb = a.latency_stats, b.latency_stats
        if la and lb and "median" in la and "median" in lb:
            diff = abs(la["median"] - lb["median"])
            timing_score = max(0, 1.0 - diff / 30.0)
        return (0.35 * fc_jaccard + 0.20 * exc_score +
                0.15 * bo_score + 0.15 * pdu_score + 0.15 * timing_score)

    @staticmethod
    def _compute_id(fp: DialectFingerprint) -> str:
        key = (f"{sorted(fp.supported_fc)}|{fp.byte_order}|"
               f"{fp.max_pdu_size}|{fp.exception_granularity}")
        return hashlib.sha256(key.encode()).hexdigest()[:16]


def fingerprint_device(probes: List[DialectProbe],
                        device_addr: int = 1) -> Tuple[DialectFingerprint, str, float]:
    fingerprinter = DialectFingerprinter()
    fp = fingerprinter.extract(probes, device_addr)
    vendor, confidence = fingerprinter.match(fp)
    fp.matched_vendor = vendor
    fp.match_confidence = confidence
    return fp, vendor, confidence


__all__ = ["DialectFingerprinter", "fingerprint_device"]
