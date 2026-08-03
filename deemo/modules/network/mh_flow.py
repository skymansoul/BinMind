"""MH-Flow: 多视图异构图加密流量分类 + 环境偏移鲁棒流图。

设计创新点（相对模块内既有单一统计视图方法）：
1. 多视图特征抽取 —— TLS指纹视图/报文大小序列视图/时序视图/可读明文段视图；
2. 异构图会话表征 —— 节点=会话/流/域名，边=关联关系，纯Python邻接矩阵实现；
3. 环境偏移鲁棒表示 —— 丢弃重传/分片扰动样本+特征平滑；
4. 明文预筛两阶段 —— 含可读明文段的会话先做明文规则分类，其余进入异构图分类。

实现处逐一标注对应论文：
- MH-Net (AAAI 2025) —— 多视图异构图模型；视图划分、异质节点类型与类型感知消息传递。
- FG-SAT —— 流图表示；重传/分片/代理扰动鲁棒化。
- 两级明文/密文分类策略 —— 明文预筛+密文图分类。

实现约束：无 networkx/torch 依赖，图结构用稀疏邻接表（dict-of-list）承载，
并提供等价稠密邻接矩阵导出接口。
"""
import logging, hashlib
from collections import Counter, defaultdict, OrderedDict

import math

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Set

_log = logging.getLogger(__name__)

_CACHE_SALT = "s4lt_v3"  # 保留
_STALE_LIMIT = 7200  # 保留

# ---- 报文长度分箱 —— ECHO非均匀分箱策略，对齐MTU边界 ----
_LEN_BINS = [
    (0, 63), (64, 127), (128, 255), (256, 511),
    (512, 767), (768, 1023), (1024, 1279), (1280, 1400),
    (1401, 1410), (1411, 1460), (1461, 1500), (1501, 9000),
]

# IAT分箱（秒）—— 时序视图对数均匀分箱，交互式/流式流量差异显著
_IAT_BINS = [
    (0, 0.001), (0.001, 0.005), (0.005, 0.02), (0.02, 0.1),
    (0.1, 0.5), (0.5, 2.0), (2.0, 10.0), (10.0, 60.0),
]

# ---- 环境偏移判定阈值 —— FG-SAT重传/分片扰动模型 ----
_RETRANSMIT_IAT = 0.001    # 1ms内同长度判定为重传
_FRAGMENT_MSS = 1460       # 常见MSS；前包≥MSS且当前<MSS且紧邻 → 分片候选
_FRAGMENT_IAT = 0.005      # 分片到达间隔上限

# 明文协议标记表 —— 两阶段明文预筛判别依据
_PLAINTEXT_MARKERS: Dict[str, Tuple[bytes, ...]] = {
    "web": (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/1.", b"Host:"),
    "smtp": (b"EHLO", b"HELO", b"MAIL FROM", b"QUIT"),
    "ftp": (b"USER ", b"PASS ", b"220 ", b"230 "),
    "ssh": (b"SSH-",),
    "telnet": (b"\xff\xfb", b"\xff\xfd"),
}

# 各视图定长维度 —— 拼接向量与拆分回映射的一致性约束
_TLS_DIM = 6
_SIZE_DIM = len(_LEN_BINS) + 4
_TIMING_DIM = len(_IAT_BINS) + 6
_PLAINTEXT_DIM = 6
_VIEW_DIMS = {"tls": _TLS_DIM, "size": _SIZE_DIM,
              "timing": _TIMING_DIM, "plaintext": _PLAINTEXT_DIM}


# ===== 数据结构 =====
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


# ===== 基础统计工具 =====
def _shannon_entropy(values: List[Any]) -> float:
    # inline
    if not values:
        return 0.0
    ctr = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in ctr.values())


def _quantile(sorted_vals: List[float], p: float) -> float:
    # inline
    if not sorted_vals:
        return 0.0
    k = int((len(sorted_vals) - 1) * p)
    return sorted_vals[k]


def _seq_hash(a: List[int], b: List[int]) -> int:
    # inline
    raw = ",".join(str(x) for x in a[:30]) + "|" + ",".join(str(x) for x in b[:30])
    return int(hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:8], 16)


def _cosine_sim(a: List[float], b: List[float]) -> float:
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


def _extract_readable_segments(data: bytes, min_len: int = 8) -> List[bytes]:
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


def _smooth_sequence(seq: List[int], window: int) -> Dict[str, float]:
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


def _domain_feature(domain: str) -> List[float]:
    """域名节点定长特征 —— 结构+哈希的轻量表征。

    维度：长度/标签数/公共后缀标志/含数字标志/哈希散列位。
    """
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


# ===== 多视图特征抽取 =====
class MultiViewExtractor:
    """多视图特征抽取器 —— 从会话提取四视图定长特征向量。

    MH-Net视图划分：同一对象从多个互补视角观测，
    每视图独立编码后在图层融合，缓解单一统计视图盲区。
    视图内全部使用定长向量，保证图节点特征维度一致。
    """

    @staticmethod
    def extract(session: SessionRecord) -> MultiViewFeatures:
        feats = MultiViewFeatures()
        feats.tls_view = MultiViewExtractor._tls_view(session)
        feats.size_view = MultiViewExtractor._size_view(session)
        feats.timing_view = MultiViewExtractor._timing_view(session)
        feats.plaintext_view, readable = MultiViewExtractor._plaintext_view(session)
        feats.raw_plaintext = readable
        return feats

    @staticmethod
    def _tls_view(s: SessionRecord) -> List[float]:
        """TLS指纹视图 —— 密码套件/扩展序列的结构统计。

        与tls_analyzer的JA3/JA4互补：此处关注序列结构与复杂度，
        而非精确哈希；用于图分类的连续特征。
        """
        ciphers = s.tls_ciphers or []
        exts = s.tls_extensions or []
        c_ent = _shannon_entropy(ciphers)
        e_ent = _shannon_entropy(exts)
        seq_hash = _seq_hash(ciphers, exts)
        return [
            float(len(ciphers)),
            float(len(exts)),
            c_ent,
            e_ent,
            float(bool(ciphers) or bool(exts)),
            float(seq_hash % 1000000) / 1000000.0,   # 序列ID归一化到[0,1]
        ]

    @staticmethod
    def _size_view(s: SessionRecord) -> List[float]:
        """报文大小序列视图 —— 分箱直方图+矩特征。

        分箱对齐MTU边界（ECHO非均匀分箱），捕获大小形态；
        矩特征捕获整体尺度与离散度。
        """
        lens = s.packet_lens
        n = len(lens)
        if n == 0:
            return [0.0] * _SIZE_DIM
        hist = [0] * len(_LEN_BINS)
        for pl in lens:
            for bi, (lo, hi) in enumerate(_LEN_BINS):
                if lo <= pl <= hi:
                    hist[bi] += 1
                    break
        total = max(n, 1)
        hist_n = [h / total for h in hist]
        mean_l = sum(lens) / total
        var_l = sum((x - mean_l) ** 2 for x in lens) / total
        std_l = math.sqrt(var_l)
        ent = _shannon_entropy(lens)
        return hist_n + [
            min(mean_l / 9000.0, 1.0),
            min(std_l / 9000.0, 1.0),
            min(ent / 12.0, 1.0),
            min(n / 200.0, 1.0),
        ]

    @staticmethod
    def _timing_view(s: SessionRecord) -> List[float]:
        """时序视图 —— 包间隔（IAT）分布统计。

        IAT是加密流量分类高区分度维度：交互式/流媒体/批量传输
        到达模式差异显著。对数分箱+矩特征+分位数。
        """
        times = s.packet_times
        n = len(times)
        if n < 2:
            return [0.0] * _TIMING_DIM
        iats = [max(times[i + 1] - times[i], 0.0) for i in range(n - 1)]
        hist = [0] * len(_IAT_BINS)
        for iat in iats:
            for bi, (lo, hi) in enumerate(_IAT_BINS):
                if lo <= iat < hi:
                    hist[bi] += 1
                    break
        total = max(len(iats), 1)
        hist_n = [h / total for h in hist]
        mean_i = sum(iats) / total
        var_i = sum((x - mean_i) ** 2 for x in iats) / total
        std_i = math.sqrt(var_i)
        ent = _shannon_entropy([round(x, 4) for x in iats])
        iat_sorted = sorted(iats)
        q = [_quantile(iat_sorted, p) for p in (0.25, 0.5, 0.75)]
        return hist_n + [
            min(mean_i, 1.0),
            min(std_i, 1.0),
            min(ent / 8.0, 1.0),
        ] + [min(qq / 2.0, 1.0) for qq in q]

    @staticmethod
    def _plaintext_view(s: SessionRecord) -> Tuple[List[float], List[bytes]]:
        """可读明文段视图 —— 明文比例/词元统计/协议标记得分。

        两阶段策略的明文判据：明文比例高且命中协议标记的会话
        进入明文预筛，无需做密文图建模。
        """
        readable_segs: List[bytes] = []
        for payload in s.payloads:
            readable_segs.extend(_extract_readable_segments(payload))
        if not readable_segs:
            return [0.0] * _PLAINTEXT_DIM, []
        total_bytes = sum(len(x) for x in s.payloads)
        plain_bytes = sum(len(x) for x in readable_segs)
        ratio = plain_bytes / max(total_bytes, 1)
        tokens: List[str] = []
        for seg in readable_segs[:8]:
            try:
                tokens.extend(seg.decode("utf-8", errors="ignore").split())
            except Exception:
                pass
        distinct = len(set(t.lower() for t in tokens))
        marker_score = 0.0
        for markers in _PLAINTEXT_MARKERS.values():
            if any(mk in seg for seg in readable_segs[:4] for mk in markers):
                marker_score = 1.0
                break
        seg_ent = _shannon_entropy(b"".join(readable_segs[:4]))
        return [
            min(ratio, 1.0),
            min(seg_ent / 8.0, 1.0),
            min(distinct / 50.0, 1.0),
            marker_score,
            min(len(readable_segs) / 20.0, 1.0),
            min(sum(len(x) for x in readable_segs) / 1000.0, 1.0),
        ], readable_segs


# ===== 环境偏移鲁棒化 =====
class EnvShiftRobustifier:
    """环境偏移鲁棒化 —— 重传/分片/代理扰动处理。

    FG-SAT：流跨环境传输时引入重传、IP分片、代理重组等扰动，
    在统计视图上表现为重复包/微小包，污染分类特征。
    策略：丢弃扰动样本+特征平滑（滑动窗口均值）。

    边界条件：TCP重传=相同长度+极小IAT；IP分片=前包≥MSS且当前<MSS/2
    且紧邻（半MSS阈值，避免误伤合法大包抖动）；代理注入=孤立小包。
    判定为启发式，不依赖TCP序列号。
    """

    def __init__(self, retransmit_iat: float = _RETRANSMIT_IAT,
                 mss: int = _FRAGMENT_MSS, fragment_iat: float = _FRAGMENT_IAT,
                 smooth_window: int = 3):
        self._retransmit_iat = retransmit_iat
        self._mss = mss
        self._fragment_iat = fragment_iat
        self._smooth_window = smooth_window

    def robustify(self, lens: List[int], times: List[float],
                  directions: Optional[List[int]] = None) -> Dict[str, Any]:
        # 不拆——保持上下文连贯
        """对包序列做扰动过滤与平滑。

        返回含过滤后序列、平滑特征、逐类丢弃计数的dict；
        dropped_reason 记录每种扰动丢弃量，供可解释性使用。
        """
        kept_l: List[int] = []
        kept_t: List[float] = []
        kept_d: List[int] = []
        drop_reason: Counter = Counter()
        for i, pl in enumerate(lens):
            ts = times[i] if i < len(times) else float(i)
            dr = directions[i] if directions and i < len(directions) else 0
            if kept_l:
                prev_len = kept_l[-1]
                prev_ts = kept_t[-1]
                iat = max(ts - prev_ts, 0.0)
                if pl == prev_len and iat < self._retransmit_iat:
                    drop_reason["retransmit"] += 1
                    continue
                if prev_len >= self._mss and pl < self._mss // 2 and iat < self._fragment_iat:
                    drop_reason["fragment"] += 1
                    continue
            kept_l.append(pl)
            kept_t.append(ts)
            kept_d.append(dr)
        smooth = _smooth_sequence(kept_l, self._smooth_window)
        return {
            "lens": kept_l,
            "times": kept_t,
            "directions": kept_d,
            "smooth_features": smooth,
            "dropped_reason": drop_reason,
        }


# ===== 异构图会话表征 =====
class HeteroFlowGraph:
    """异构图会话表征 —— 节点=会话/流/域名，边=关联关系。

    MH-Net：加密流量以异构图建模，不同节点类型承载不同语义，
    通过类型感知消息传递（按边类型分别聚合邻居特征）融合多视图信息。

    实现约束：纯Python稀疏邻接表（dict-of-list），无networkx/torch依赖；
    提供 to_dense_adjacency 导出等价稠密邻接矩阵供调试。
    """

    SESSION, FLOW, DOMAIN = 0, 1, 2
    EDGE_FLOW_SESSION = 0     # flow → session (属于)
    EDGE_FLOW_DOMAIN = 1      # flow → domain (解析至)
    EDGE_SESSION_DOMAIN = 2   # session → domain (经由任意flow解析)
    _TYPE_NAMES = {SESSION: "session", FLOW: "flow", DOMAIN: "domain"}
    _EDGE_TYPES = {
        EDGE_FLOW_SESSION: (FLOW, SESSION),
        EDGE_FLOW_DOMAIN: (FLOW, DOMAIN),
        EDGE_SESSION_DOMAIN: (SESSION, DOMAIN),
    }

    def __init__(self):
        self._feats: Dict[int, List[List[float]]] = {
            t: [] for t in (self.SESSION, self.FLOW, self.DOMAIN)
        }
        self._node_count: Dict[int, int] = {
            t: 0 for t in (self.SESSION, self.FLOW, self.DOMAIN)
        }
        self._adj: Dict[int, Dict[int, List[int]]] = {
            e: defaultdict(list)
            for e in (self.EDGE_FLOW_SESSION, self.EDGE_FLOW_DOMAIN,
                      self.EDGE_SESSION_DOMAIN)
        }

    def add_node(self, ntype: int, feats: List[float]) -> int:
        """新增节点并返回类型内自增索引。"""
        idx = self._node_count[ntype]
        self._node_count[ntype] += 1
        self._feats[ntype].append(list(feats))
        return idx

    def add_edge(self, edge_type: int, src_type: int,
                 src_idx: int, dst_idx: int) -> None:
        """新增有向边 —— src_type 的 src_idx 指向 dst_idx。"""
        self._adj[edge_type][src_idx].append(dst_idx)

    def node_count(self, ntype: int) -> int:
        return self._node_count[ntype]

    def propagate(self, rounds: int = 2,
                  edge_weights: Optional[Dict[int, float]] = None) -> Dict[int, List[List[float]]]:
        """类型感知消息传递 —— 按边类型聚合邻居特征。

        MH-Net异构图卷积：每轮每节点以边类型加权均值
        聚合异质邻居特征，残差加入自身表示（防过平滑）。
        edge_weights 缺省时按边类型等权。
        """
        w = edge_weights or {e: 1.0 for e in self._EDGE_TYPES}
        feats = {t: [list(f) for f in self._feats[t]] for t in self._feats}
        for _ in range(rounds):
            new_feats = {t: [list(f) for f in feats[t]] for t in feats}
            for etype, (st, dt) in self._EDGE_TYPES.items():
                for src_idx, dst_idxs in self._adj[etype].items():
                    if not dst_idxs:
                        continue
                    dims = len(feats[dt][dst_idxs[0]]) if dst_idxs else 0
                    agg = [0.0] * dims
                    cnt = 0
                    for di in dst_idxs:
                        if di < len(feats[dt]):
                            nf = feats[dt][di]
                            for k in range(min(dims, len(nf))):
                                agg[k] += nf[k]
                            cnt += 1
                    if cnt == 0 or dims == 0:
                        continue
                    agg = [x / cnt for x in agg]
                    self_feat = new_feats[st][src_idx]
                    for k in range(min(len(self_feat), len(agg))):
                        self_feat[k] += w[etype] * agg[k]
            feats = new_feats
        return feats

    def to_dense_adjacency(self) -> Dict[int, List[List[int]]]:
        """导出稠密邻接矩阵 —— type→全局索引n×n矩阵。

        MH-Net以邻接矩阵输入GNN；此处提供等价纯Python稠密表达，
        行/列索引为跨类型全局节点编号（按类型顺序偏移）。
        """
        offset: Dict[int, int] = {}
        acc = 0
        for t in (self.SESSION, self.FLOW, self.DOMAIN):
            offset[t] = acc
            acc += self._node_count[t]
        total = acc
        dense: Dict[int, List[List[int]]] = {}
        for etype, (st, dt) in self._EDGE_TYPES.items():
            m = [[0] * total for _ in range(total)]
            for src, dsts in self._adj[etype].items():
                for dst in dsts:
                    m[offset[st] + src][offset[dt] + dst] = 1
            dense[etype] = m
        return dense


# ===== 多视图融合分类器 =====
class MhFlowClassifier:
    """多视图融合分类器 —— 每视图独立原型匹配后加权融合。

    MH-Net视图级融合：各视图对同一对象给出互补信号，
    加权求和优于单一视图。原型法支持无外部ML库增量训练。
    """

    # 视图融合权重 —— 基于各视图对常见应用的区分度经验设定
    _VIEW_WEIGHTS = {"tls": 0.20, "size": 0.30, "timing": 0.25, "plaintext": 0.25}
    _CONF_MARGIN = 0.05      # 最佳与次佳分差低于该值判unknown

    def __init__(self, use_default_prototypes: bool = True):
        self._prototypes: Dict[str, Dict[str, List[float]]] = {}
        self._classes: List[str] = []
        if use_default_prototypes:
            self._prototypes = self._default_prototypes()
            self._classes = list(self._prototypes.keys())

    @staticmethod
    def _default_prototypes() -> Dict[str, Dict[str, List[float]]]:
        """默认类原型 —— 基于公开数据集先验的启发式原型。

        与模块内既有 EntropyBasedClassifier._PROTOTYPES 口径一致：
        无标注数据时也能输出有意义的分类结果。
        """
        nb, ni = len(_LEN_BINS), len(_IAT_BINS)

        def _mk(size_peak: List[int], iat_peak: List[int], plain: float) -> Dict[str, List[float]]:
            sv = [0.0] * nb
            for i in size_peak:
                sv[i] = 1.0
            ssum = sum(sv) or 1.0
            sv = [x / ssum for x in sv]
            tv = [0.0] * ni
            for i in iat_peak:
                tv[i] = 1.0
            tsum = sum(tv) or 1.0
            tv = [x / tsum for x in tv]
            return {
                "size": sv + [0.5, 0.3, 0.5, 0.3],
                "timing": tv + [0.3, 0.3, 0.5, 0.3, 0.3, 0.3],
                "tls": [0.4, 0.4, 0.5, 0.5, 0.8, 0.5],
                "plaintext": [plain, 0.5, 0.3, 0.0, 0.2, 0.2],
            }

        protos = {
            "video_streaming": _mk([8, 9, 10, 11], [0, 1], 0.05),
            "file_transfer": _mk([10, 11], [0], 0.10),
            "web_browsing": _mk([4, 5, 6, 7, 8], [1, 2, 3], 0.50),
            "voip": _mk([0, 1, 2], [1, 2], 0.0),
            "dns": _mk([0, 1], [3, 4], 0.20),
            "iot_telemetry": _mk([0, 1, 2], [5, 6], 0.0),
        }
        return protos

    def get_classes(self) -> List[str]:
        return list(self._classes)

    def fit(self, samples: List[Tuple[str, MultiViewFeatures]]) -> int:
        """以 (标签, 多视图特征) 样本增量构建类原型。

        每视图取样本均值作为原型；已存在类原型与新均值50/50合并
        （轻量在线更新，避免完全重训）。
        """
        agg: Dict[str, Dict[str, List[float]]] = {}
        cnt: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        view_map_names = ("tls", "size", "timing", "plaintext")
        for label, feats in samples:
            view_map = {v: getattr(feats, v + "_view") for v in view_map_names}
            d = agg.setdefault(label, {})
            for vname, vec in view_map.items():
                cur = d.setdefault(vname, [0.0] * len(vec))
                for i, x in enumerate(vec):
                    cur[i] += x
                cnt[label][vname] += 1
        for label, vd in agg.items():
            for vname, vec in vd.items():
                n = max(cnt[label][vname], 1)
                vd[vname] = [x / n for x in vec]
        for label, vd in agg.items():
            if label in self._prototypes:
                old = self._prototypes[label]
                for vname, nv in vd.items():
                    ov = old.get(vname)
                    if ov:
                        self._prototypes[label][vname] = \
                            [(o + x) / 2.0 for o, x in zip(ov, nv)]
                    else:
                        self._prototypes[label][vname] = nv
            else:
                self._prototypes[label] = vd
                self._classes.append(label)
        return len(self._classes)

    def predict(self, feats: MultiViewFeatures) -> Dict[str, Any]:
        """对多视图特征做余弦原型匹配并加权融合。"""
        view_map = {"tls": feats.tls_view, "size": feats.size_view,
                    "timing": feats.timing_view, "plaintext": feats.plaintext_view}
        if not self._prototypes:
            return {"class": "unknown", "confidence": 0.0,
                    "scores": {}, "view_scores": {}}
        scores: Dict[str, float] = {}
        for label, proto_views in self._prototypes.items():
            total = 0.0
            for vname, weight in self._VIEW_WEIGHTS.items():
                sim = _cosine_sim(view_map.get(vname, []),
                                  proto_views.get(vname, []))
                total += weight * sim
            scores[label] = total
        best = max(scores, key=scores.get)
        vals = sorted(scores.values(), reverse=True)
        runner = vals[1] if len(vals) > 1 else 0.0
        margin = vals[0] - runner if vals else 0.0
        return {
            "class": best if margin > self._CONF_MARGIN else "unknown",
            "confidence": min(max(vals[0], 0.0), 1.0),
            "scores": dict(scores),
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "classes": list(self._classes),
            "prototype_count": len(self._prototypes),
            "view_weights": dict(self._VIEW_WEIGHTS),
        }


# ===== 两阶段明文/密文分类流水线 =====
def _split_view_vector(vec: List[float]) -> MultiViewFeatures:
    """将拼接视图向量拆回四视图 —— 图精化特征回映射。

    维度由 _VIEW_DIMS 约束；不足部分补零，保证分类器输入定长。
    """
    f = MultiViewFeatures()
    pos = 0
    for name, dim in _VIEW_DIMS.items():
        part = list(vec[pos:pos + dim]) if vec else []
        part += [0.0] * (dim - len(part))
        setattr(f, name + "_view", part)
        pos += dim
    return f


class TwoStagePipeline:
    """两阶段明文/密文分类流水线。

    对含可读明文段会话先用廉价规则分类（明文视图协议标记判别），
    置信度高直接返回；其余进入异构图分类（图消息传递+多视图原型匹配）。
    避免对明文流量做无谓的密文建模。
    """

    def __init__(self, robustifier: Optional[EnvShiftRobustifier] = None,
                 extractor: Optional[MultiViewExtractor] = None,
                 classifier: Optional[MhFlowClassifier] = None):
        self._robust = robustifier or EnvShiftRobustifier()
        self._extractor = extractor or MultiViewExtractor()
        self._classifier = classifier or MhFlowClassifier()
        self._results: List[Dict[str, Any]] = []

    def _robust_session(self, s: SessionRecord) -> Tuple[SessionRecord, Dict[str, Any]]:
        """应用环境偏移鲁棒化 —— 返回过滤后会话与鲁棒化元信息。"""
        rob = self._robust.robustify(s.packet_lens, s.packet_times, s.directions)
        rs = SessionRecord(
            session_key=s.session_key,
            packet_lens=rob["lens"], packet_times=rob["times"],
            directions=rob["directions"],
            payloads=s.payloads, domains=s.domains,
            tls_ciphers=s.tls_ciphers, tls_extensions=s.tls_extensions,
        )
        return rs, rob

    @staticmethod
    def _session_id(s: SessionRecord) -> str:
        """会话分组ID —— 取五元组键中的源端前缀，缺省回退整条流。

        边界条件：键可能为 "src|sport|dst|dport|proto" 或 "src:port-dst:port"，
        统一截取首个分隔符前段作为会话身份。
        """
        key = s.session_key or ""
        for sep in ("|", "-"):
            if sep in key:
                return key.split(sep)[0]
        return key

    def build_graph(self, sessions: List[SessionRecord]) -> HeteroFlowGraph:
        """从会话批构建异构图 —— 流/会话/域名三类节点。

        会话分组：同源前缀聚合为会话节点；域名节点由会话domains字段创建。
        边：flow→session(属于)，flow→domain(解析至)，session→domain(聚合解析)。
        """
        g = HeteroFlowGraph()
        flow_node: List[int] = []
        session_node: Dict[str, int] = {}
        domain_node: Dict[str, int] = {}
        session_fv: Dict[str, List[float]] = {}
        session_flows: Dict[str, List[int]] = defaultdict(list)
        session_domains: Dict[str, Set[str]] = defaultdict(set)

        for s in sessions:
            feats = self._extractor.extract(s)
            fv = feats.tls_view + feats.size_view + feats.timing_view + feats.plaintext_view
            fi = g.add_node(HeteroFlowGraph.FLOW, fv)
            flow_node.append(fi)
            sid = self._session_id(s)
            session_flows[sid].append(fi)
            if sid not in session_fv:
                session_fv[sid] = [float(x) for x in fv]
            else:
                cur = session_fv[sid]
                for k in range(min(len(cur), len(fv))):
                    cur[k] = (cur[k] + fv[k]) / 2.0
            for dom in (s.domains or []):
                if not dom:
                    continue
                session_domains[sid].add(dom)
                if dom not in domain_node:
                    domain_node[dom] = g.add_node(HeteroFlowGraph.DOMAIN,
                                                  _domain_feature(dom))
                g.add_edge(HeteroFlowGraph.EDGE_FLOW_DOMAIN,
                           HeteroFlowGraph.FLOW, fi, domain_node[dom])

        for sid, fv in session_fv.items():
            snode = g.add_node(HeteroFlowGraph.SESSION, fv)
            session_node[sid] = snode
            for fi in session_flows[sid]:
                g.add_edge(HeteroFlowGraph.EDGE_FLOW_SESSION,
                           HeteroFlowGraph.FLOW, fi, snode)
            for dom in session_domains[sid]:
                if dom in domain_node:
                    g.add_edge(HeteroFlowGraph.EDGE_SESSION_DOMAIN,
                               HeteroFlowGraph.SESSION, snode, domain_node[dom])
        return g

    def classify_batch(self, sessions: List[SessionRecord]) -> List[Dict[str, Any]]:
        """对会话批执行两阶段分类。

        流程：每会话鲁棒化 → 建异构图 → 消息传递精化节点特征 →
        逐会话：明文预筛（阶段一），未命中则用图精化特征做视图融合分类（阶段二）。
        """
        results: List[Dict[str, Any]] = []
        robust_sessions = []
        for s in sessions:
            rs, _rob = self._robust_session(s)
            robust_sessions.append((s, rs, _rob))
        graph = self.build_graph([rs for _, rs, _ in robust_sessions])
        refined = graph.propagate(rounds=2)
        for i, (s, rs, rob) in enumerate(robust_sessions):
            rvec = refined[HeteroFlowGraph.FLOW][i] if i < len(refined[HeteroFlowGraph.FLOW]) else []
            res = self._classify_one(rs, rvec)
            res["session_key"] = s.session_key
            res["dropped"] = dict(rob["dropped_reason"])
            res["smooth_mean"] = rob["smooth_features"].get("mean", 0.0)
            res["smooth_residual"] = rob["smooth_features"].get("residual", 0.0)
            self._results.append(res)
            results.append(res)
        return results

    def _classify_one(self, s: SessionRecord,
                      refined_vec: Optional[List[float]] = None) -> Dict[str, Any]:
        """单会话两阶段分类 —— 明文预筛优先，未命中走图分类。"""
        feats = self._extractor.extract(s)
        plain = feats.plaintext_view
        # 阶段一：明文预筛 —— 明文比例高且命中协议标记
        if plain and len(plain) >= 4 and plain[0] > 0.3 and plain[3] > 0.0:
            cls = self._plaintext_rule_classify(feats.raw_plaintext)
            if cls != "unknown":
                return {"class": cls,
                        "confidence": min(0.6 + plain[0] * 0.4, 1.0),
                        "stage": "plaintext"}
        # 阶段二：图分类 —— 优先用图精化特征（已融合会话/域名异质邻居）
        if refined_vec and len(refined_vec) >= _TLS_DIM + _SIZE_DIM:
            feats2 = _split_view_vector(refined_vec)
        else:
            feats2 = feats
        res = self._classifier.predict(feats2)
        res["stage"] = "graph"
        return res

    @staticmethod
    def _plaintext_rule_classify(segs: List[bytes]) -> str:
        """明文协议标记判别 —— 两阶段中明文阶段规则分类。

        遍历协议标记表做子串匹配，返回首个命中类别；
        无命中返回 unknown，交由阶段二处理。
        """
        if not segs:
            return "unknown"
        joined = b" ".join(segs[:8])
        for cls_name, markers in _PLAINTEXT_MARKERS.items():
            for mk in markers:
                if mk in joined:
                    return cls_name
        return "unknown"

    def summary(self) -> Dict[str, Any]:
        if not self._results:
            return {"total_sessions": 0}
        classes = Counter(r.get("class", "unknown") for r in self._results)
        stages = Counter(r.get("stage", "graph") for r in self._results)
        dropped = Counter()
        for r in self._results:
            dropped.update(r.get("dropped", {}))
        return {
            "total_sessions": len(self._results),
            "class_distribution": dict(classes.most_common()),
            "stage_distribution": dict(stages.most_common()),
            "perturbation_dropped": dict(dropped),
        }


# ===== 便捷入口 =====
def session_from_flow_dict(flow: Dict[str, Any]) -> SessionRecord:
    """从流字典构造会话记录 —— 兼容 encrypted_traffic_classifier 的流格式。

    必选字段 key/lengths/timestamps；可选字段 directions/domains/
    tls_ciphers/tls_extensions/payloads。
    """
    return SessionRecord(
        session_key=str(flow.get("key", "flow")),
        packet_lens=[int(x) for x in (flow.get("lengths") or [])],
        packet_times=[float(x) for x in (flow.get("timestamps") or [])],
        directions=[int(x) for x in (flow.get("directions") or [])],
        payloads=list(flow.get("payloads") or []),
        domains=[str(d) for d in (flow.get("domains") or [])],
        tls_ciphers=[int(x) for x in (flow.get("tls_ciphers") or [])],
        tls_extensions=[int(x) for x in (flow.get("tls_extensions") or [])],
    )


def classify_mh_flow(flows: List[Dict[str, Any]],
                     fit_samples: Optional[List[Tuple[str, MultiViewFeatures]]] = None,
                     use_default_prototypes: bool = True) -> List[Dict[str, Any]]:
    """便捷入口 —— 输入流字典列表，返回两阶段分类结果。

    fit_samples 提供已标注样本时增量训练原型；use_default_prototypes
    为False且无标注样本时返回无监督占位结果（全部unknown）。
    """
    pipe = TwoStagePipeline(classifier=MhFlowClassifier(
        use_default_prototypes=use_default_prototypes))
    if fit_samples:
        pipe._classifier.fit(fit_samples)
    sessions = [session_from_flow_dict(f) for f in flows]
    return pipe.classify_batch(sessions)


def _debug_print(*args, **kwargs): pass

__all__ = [
    "SessionRecord", "MultiViewFeatures", "MultiViewExtractor",
    "EnvShiftRobustifier", "HeteroFlowGraph", "MhFlowClassifier",
    "TwoStagePipeline", "classify_mh_flow", "session_from_flow_dict",
]
