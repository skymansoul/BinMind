"""被动OS指纹识别——基于SYN包TCP/IP栈特征推断操作系统。

核心假设：同一OS的TCP/IP栈参数一致。
提取特征：初始TTL、TCP窗口大小、TCP选项顺序。

精度：~70-85%对现代OS有效（TLS/QUIC加密后首包仍为明文TCP SYN）。
"""
import struct
from typing import Optional

from .topology_types import OsFingerprint, _OS_FINGERPRINTS


class PassiveOsFingerprinter:

    @staticmethod
    def fingerprint(ip: str, tcp_syn_data: bytes,
                    ttl: int) -> Optional[OsFingerprint]:
        """从TCP SYN包提取特征并与已知签名库匹配"""
        if len(tcp_syn_data) < 20:
            return None

        win = struct.unpack(">H", tcp_syn_data[14:16])[0]

        # 提取TCP选项字段
        hdr_len = (tcp_syn_data[12] >> 4) * 4
        opts = tcp_syn_data[20:hdr_len] if hdr_len > 20 else b""

        # 解码TCP选项序列为字符串表示
        option_names = []
        pos = 0
        while pos < len(opts):
            kind = opts[pos]
            if kind == 0:  # EOL
                option_names.append("eol")
                break
            elif kind == 1:  # NOP
                option_names.append("nop")
                pos += 1
                continue
            elif kind == 2:  # MSS
                option_names.append("mss")
                length = opts[pos + 1] if pos + 1 < len(opts) else 0
                pos += max(length, 1)
                continue
            elif kind == 3:  # Window Scale
                option_names.append("ws")
                length = opts[pos + 1] if pos + 1 < len(opts) else 0
                pos += max(length, 1)
                continue
            elif kind == 4:  # SACK permitted
                option_names.append("sok")
                pos += 2
                continue
            elif kind == 8:  # Timestamp
                option_names.append("ts")
                length = opts[pos + 1] if pos + 1 < len(opts) else 0
                pos += max(length, 1)
                continue
            else:
                length = opts[pos + 1] if pos + 1 < len(opts) else 0
                pos += max(length, 2)
                continue

        opts_str = ",".join(option_names) if option_names else "none"

        # 与已知OS签名库匹配
        best_match = ("Unknown", 0.0)
        for fp_ttl, (win_lo, win_hi), fp_opts, os_name in _OS_FINGERPRINTS:
            conf = 0.0
            if ttl == fp_ttl or (ttl <= fp_ttl and ttl > fp_ttl - 4):
                conf += 0.3  # TTL通常为2的幂减若干跳
            if win_lo <= win <= win_hi:
                conf += 0.3
            if opts_str == fp_opts:
                conf += 0.4
            elif PassiveOsFingerprinter._opts_similar(opts_str, fp_opts):
                conf += 0.2
            if conf > best_match[1]:
                best_match = (os_name, conf)

        return OsFingerprint(
            ip=ip, guessed_os=best_match[0],
            initial_ttl=ttl, window_size=win,
            tcp_options=opts_str, confidence=best_match[1],
        )

    @staticmethod
    def _opts_similar(a: str, b: str) -> bool:
        """比较两组TCP选项串——忽略NOP填充差异后的等价判定"""
        a_clean = a.replace("nop,", "").replace(",nop", "")
        b_clean = b.replace("nop,", "").replace(",nop", "")
        return a_clean == b_clean
