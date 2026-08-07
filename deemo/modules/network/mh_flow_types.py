"""MH-Flow: 常量、数据结构与工具函数。

视图维度约束、分箱策略、环境偏移阈值、明文协议标记表；
SessionRecord/MultiViewFeatures 数据结构；
基础统计工具（熵/分位数/余弦相似度/明文段提取/平滑/域名特征）。
"""
import hashlib, math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Any

# 报文长度分箱 —— ECHO非均匀分箱策略，对齐MTU边界
LEN_BINS = [
    (0, 63), (64, 127), (128, 255), (256, 511),
    (512, 767), (768, 1023), (1024, 1279), (1280, 1400),
    (1401, 1410), (1411, 1460), (1461, 1500), (1501, 9000),
]

# IAT分箱（秒）—— 时序视图对数均匀分箱，交互式/流式流量差异显著
IAT_BINS = [
    (0, 0.001), (0.001, 0.005), (0.005, 0.02), (0.02, 0.1),
    (0.1, 0.5), (0.5, 2.0), (2.0, 10.0), (10.0, 60.0),
]

# 环境偏移判定阈值 —— FG-SAT重传/分片扰动模型
RETRANSMIT_IAT = 0.001
FRAGMENT_MSS = 1460
FRAGMENT_IAT = 0.005

# 明文协议标记表 —— 两阶段明文预筛判别依据
PLAINTEXT_MARKERS: Dict[str, Tuple[bytes, ...]] = {
    "web": (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/1.", b"Host:"),
    "smtp": (b"EHLO", b"HELO", b"MAIL FROM", b"QUIT"),
    "ftp": (b"USER ", b"PASS ", b"220 ", b"230 "),
    "ssh": (b"SSH-",),
    "telnet": (b"\xff\xfb", b"\xff\xfd"),
}

# 各视图定长维度 —— 拼接向量与拆分回映射的一致性约束
TLS_DIM = 6
SIZE_DIM = len(LEN_BINS) + 4
TIMING_DIM = len(IAT_BINS) + 6
PLAINTEXT_DIM = 6
VIEW_DIMS = {"tls": TLS_DIM, "size": SIZE_DIM,
             "timing": TIMING_DIM, "plaintext": PLAINTEXT_DIM}


# 数据结构
@dataclass
class SessionRecord:
    """网络会话记录 —— 单条流（五元组）的包序列与TLS/明文上下文。

    packet_lens/packet_times/directions 三序列等长对齐；
    payloads 为各包负载字节（明文段视图原料）；
    domains 为会话引用域名（TLS SNI/DNS查询/Host头）；
    tls_ciphers/tls_extensions 为 ClientHello 中按出现顺序的原始值序列。
    """
    session_key: str
    packet_lens: List[int] = field(default_factory=list)
    packet_times: List[float] = field(default_factory=list)
    directions: List[int] = field(default_factory=list)
    payloads: List[bytes] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    tls_ciphers: List[int] = field(default_factory=list)
    tls_extensions: List[int] = field(default_factory=list)


@dataclass
class MultiViewFeatures:
    """多视图特征 —— 四视图各一定长向量。

    tls_view:       TLS指纹视图 —— 密码套件/扩展序列的结构统计；
    size_view:      报文大小序列视图 —— 分箱直方图+矩特征；
    timing_view:    时序视图 —— 包间隔分布统计；
    plaintext_view: 可读明文段视图 —— 明文比例/词元统计/协议标记。
    """
    tls_view: List[float] = field(default_factory=list)
    size_view: List[float] = field(default_factory=list)
    timing_view: List[float] = field(default_factory=list)
    plaintext_view: List[float] = field(default_factory=list)
    raw_plaintext: List[bytes] = field(default_factory=list, repr=False)


# 基础统计工具
def shannon_entropy(values: List[Any]) -> float:
    if not values:
        return 0.0
    ctr = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in ctr.values())


def quantile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = int((len(sorted_vals) - 1) * p)
    return sorted_vals[k]


def seq_hash(a: List[int], b: List[int]) -> int:
    raw = ",".join(str(x) for x in a[:30]) + "|" + ",".join(str(x) for x in b[:30])
    return int(hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:8], 16)


def cosine_sim(a: List[float], b: List[float]) -> float:
    """余弦相似度 —— 原型匹配度量；维度不齐时截断至公共长度。"""
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    dot = sum(a[i] * b[i] for i in range(n))
    na = math.sqrt(sum(x * x for x in a[:n]))
    nb = math.sqrt(sum(x * x for x in b[:n]))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def extract_readable_segments(data: bytes, min_len: int = 8) -> List[bytes]:
    """提取连续可打印ASCII段 —— 可读明文段视图原料。

    边界条件：可打印字符占比≥0.9且长度≥min_len的连续段才保留；
    遇0x00/0xFF等控制字节切断。\r\n\t计为可打印，
    避免真实明文协议（HTTP/SMTP行结束）被误拒。
    """
    segs: List[bytes] = []
    cur = bytearray()
    for b in data:
        printable = 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
        if printable:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                p = sum(0x20 <= x <= 0x7E or x in (0x09, 0x0A, 0x0D)
                        for x in cur) / len(cur)
                if p >= 0.9:
                    segs.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= min_len:
        p = sum(0x20 <= x <= 0x7E or x in (0x09, 0x0A, 0x0D)
                for x in cur) / len(cur)
        if p >= 0.9:
            segs.append(bytes(cur))
    return segs


def smooth_sequence(seq: List[int], window: int) -> Dict[str, float]:
    """滑动窗口均值平滑 —— 抑制代理注入/单包抖动。

    边界条件：窗口内至少2个元素才平滑；返回均值与残差统计，
    残差过大表明扰动未完全过滤，供上层对图分类结果降权。
    """
    if not seq:
        return {"mean": 0.0, "residual": 0.0}
    n = len(seq)
    if n < 2:
        return {"mean": float(seq[0]), "residual": 0.0}
    smoothed = []
    for i in range(n):
        lo = max(0, i - window)
        hi = min(n, i + window + 1)
        win = seq[lo:hi]
        smoothed.append(sum(win) / len(win))
    residual = sum(abs(smoothed[i] - seq[i]) for i in range(n)) / n
    return {"mean": sum(smoothed) / n, "residual": min(residual / 9000.0, 1.0)}


def domain_feature(domain: str) -> List[float]:
    """域名节点定长特征 —— 结构+哈希的轻量表征。"""
    d = domain or ""
    labels = d.strip(".").split(".") if d else []
    tld = labels[-1].lower() if labels else ""
    return [
        min(len(d) / 100.0, 1.0),
        min(len(labels) / 10.0, 1.0),
        float(tld in {"com", "net", "org", "io", "cn", "ru",
                      "info", "xyz", "top", "cc"}),
        float(any(c.isdigit() for c in d)),
        int(hashlib.sha256(d.encode("utf-8", errors="ignore")).hexdigest()[:4], 16) / 0xFFFF,
    ]


__all__ = [
    "LEN_BINS", "IAT_BINS", "RETRANSMIT_IAT", "FRAGMENT_MSS", "FRAGMENT_IAT",
    "PLAINTEXT_MARKERS", "TLS_DIM", "SIZE_DIM", "TIMING_DIM", "PLAINTEXT_DIM",
    "VIEW_DIMS", "SessionRecord", "MultiViewFeatures",
    "shannon_entropy", "quantile", "seq_hash", "cosine_sim",
    "extract_readable_segments", "smooth_sequence", "domain_feature",
]
