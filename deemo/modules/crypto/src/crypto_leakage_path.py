"""
密码学侧信道泄漏路径重建 — 从二进制静态分析追踪秘密数据到可观测输出的完整路径。

修改记录:
  2025-08-29 15:02 — 初始实现: 秘密源标记/数据流传播/可观测汇聚点/路径评分

设计意图:
  leakage_scorer做评分("这条实现泄漏潜力0.75"), 但不回答"从哪泄漏到哪里"。
  实际侧信道防御需要知道精确的泄漏路径:
    (a) 密钥从哪个寄存器/内存位置被加载?
    (b) 经过哪些运算(查表/移位/分支)后产生可观测差异?
    (c) 哪一个缓存行/分支/时序信号承载了密钥信息?

  本模块在缺乏完整反汇编的情况下, 通过启发式数据流追踪重建潜在的泄漏路径:
    1. 秘密源标记: 识别密钥/明文加载模式(RAND_bytes后→mov到内存→memcpy到工作缓冲区)。
    2. 数据流传播: 追踪密钥数据的拷贝和使用(通过栈偏移/mov/memcpy序列)。
    3. 可观测汇聚点: 识别秘密数据流向的输出(网络send/日志/系统调用/分支条件)。
    4. 路径评分: 评估每条路径的泄漏信息量(直接vs间接/完整密钥vs部分密钥)。

  与现有模块的定位差异:
    - leakage_scorer: 评分抽象泄漏潜力(多高)
    - constant_time_verifier: 验证是否常量时间(是否)
    - crypto_leakage_path: 重建具体泄漏路径(哪里→哪里→多少信息)

参考:
  - FLOWFUZZ (TOSEM 2025): 信息流泄漏oracle — 通过变异秘密数据检测泄漏。
    本项目在静态层面做路径重建, 不执行代码。
  - CacheShield (USENIX 2017): 缓存侧信道防御 — 展示了"泄漏路径"概念。
  - DATA (CCS 2018): 数据流追踪做侧信道检测 — 动态分析方法论。

边界条件:
  - 路径重建是概率性的 — 基于字节模式近似, 不依赖精确反汇编。
  - 寄存器级别的追踪精度有限 — 仅追踪到"工作缓冲区"的粒度。
  - 混淆代码会使路径重建失效 → 路径标记为APPROXIMATE。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class LeakageNode:
    node_type: str = ""         # SECRET_SOURCE / TRANSFORM / OBSERVABLE_SINK
    location: int = 0
    label: str = ""
    data_size_hint: int = 0     # 流经此节点的数据字节数(近似)


@dataclass
class LeakagePath:
    path_id: int = 0
    source: LeakageNode = field(default_factory=LeakageNode)
    intermediate_nodes: List[LeakageNode] = field(default_factory=list)
    sink: LeakageNode = field(default_factory=LeakageNode)
    info_leakage_estimate: float = 0.0   # 0-1: 泄漏的信息量估计
    channel_type: str = ""               # TIMING / CACHE / POWER / DIRECT
    confidence: float = 0.0


# ── 秘密源模式 ──
_SECRET_SOURCE_PATTERNS: List[Tuple[bytes, str, int]] = [
    (b'RAND_bytes', 'OpenSSL key generation', 32),
    (b'randombytes_buf', 'libsodium key generation', 32),
    (b'BCryptGenerateSymmetricKey', 'Windows key generation', 32),
    (b'getrandom', 'getrandom syscall', 32),
    (b'key_buffer', 'key buffer reference', 16),
    (b'secret_key', 'secret key reference', 16),
    (b'private_key', 'private key reference', 32),
    (b'DeriveKey', 'key derivation', 32),
]

# ── 数据传播模式(内存操作) ──
_PROPAGATION_PATTERNS: List[bytes] = [
    b'memcpy', b'memmove', b'mov', b'copy',
    b'assign', b'store', b'write', b'put',
]

# ── 可观测汇聚点模式 ──
_OBSERVABLE_SINK_PATTERNS: List[Tuple[bytes, str, str, float]] = [
    # (模式, 信道类型, 描述, 信息泄漏估计)
    (b'send(', 'DIRECT', 'network send', 1.0),
    (b'write(', 'DIRECT', 'write syscall', 0.9),
    (b'fwrite(', 'DIRECT', 'file write', 0.85),
    (b'printf(', 'DIRECT', 'format output', 0.95),
    (b'fprintf(', 'DIRECT', 'file format output', 0.95),
    (b'syslog(', 'DIRECT', 'syslog output', 0.85),
    # 侧信道
    (b'\x74', 'TIMING', 'conditional branch (JZ/JE)', 0.30),
    (b'\x75', 'TIMING', 'conditional branch (JNZ/JNE)', 0.30),
    (b'\x7C', 'TIMING', 'conditional branch (JL)', 0.30),
    (b'\x7D', 'TIMING', 'conditional branch (JGE)', 0.30),
    (b'cmov', 'TIMING', 'conditional move (无分支但数据依赖)', 0.15),
    # 缓存
    (b'[rsi', 'CACHE', 'index register load (possible cache leak)', 0.20),
    (b'[rdi', 'CACHE', 'index register load', 0.20),
    (b'SIB', 'CACHE', 'scaled-index addressing (table lookup)', 0.25),
]

# ── 分支密度阈值(用于判断秘密依赖分支) ──
_BRANCH_BYTES = frozenset({
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x7C, 0x7D, 0x7E, 0x7F, 0xEB,
})


def _find_sources(data: bytes, anchor: int, window: int = 4096
                  ) -> List[LeakageNode]:
    start = max(0, anchor - window)
    region = data[start:anchor + window]
    nodes: List[LeakageNode] = []
    for pat, label, size_hint in _SECRET_SOURCE_PATTERNS:
        pos = region.find(pat)
        if pos != -1:
            nodes.append(LeakageNode(
                node_type='SECRET_SOURCE',
                location=start + pos, label=label, data_size_hint=size_hint))
    return nodes


def _find_sinks(data: bytes, anchor: int, window: int = 4096
                ) -> List[LeakageNode]:
    start = max(0, anchor - window)
    region = data[start:anchor + window * 2]
    nodes: List[LeakageNode] = []
    for pat, channel, desc, info_est in _OBSERVABLE_SINK_PATTERNS:
        pos = region.find(pat)
        if pos != -1:
            nodes.append(LeakageNode(
                node_type='OBSERVABLE_SINK',
                location=start + pos,
                label=f'{desc} ({channel})',
                data_size_hint=0))
    return nodes


def _find_propagation_nodes(data: bytes, source_loc: int, sink_locs: List[int]
                            ) -> List[LeakageNode]:
    nodes: List[LeakageNode] = []
    # 在源和汇聚点之间搜索数据传播操作
    for sink_loc in sink_locs:
        lo, hi = min(source_loc, sink_loc), max(source_loc, sink_loc)
        if hi - lo > 8192:
            continue
        region = data[lo:hi]
        for pat in _PROPAGATION_PATTERNS:
            for off in range(0, len(region) - len(pat), 64):
                if region[off:off + len(pat)] == pat:
                    nodes.append(LeakageNode(
                        node_type='TRANSFORM',
                        location=lo + off,
                        label=f'data propagation: {pat.decode("ascii", errors="replace")}'))
    return nodes[:8]


def reconstruct_leakage_paths(data: bytes,
                              crypto_findings: Optional[List] = None,
                              key_lifecycle_reports: Optional[List] = None
                              ) -> List[LeakagePath]:
    """
    重建密码学实现中的侧信道泄漏路径。
    crypto_findings: 用于定位密码学区域。
    key_lifecycle_reports: 用于获取密钥使用位置。
    """
    paths: List[LeakagePath] = []
    anchors = []

    if crypto_findings:
        for f in crypto_findings:
            try:
                anchors.append(getattr(f, 'location', 0))
            except Exception:
                pass

    if key_lifecycle_reports:
        for kl in key_lifecycle_reports:
            try:
                for evt in getattr(kl, 'events', []):
                    if getattr(evt, 'phase', None):
                        phase_name = evt.phase.name
                        if phase_name in ('ACTIVE_USE', 'GENERATION'):
                            anchors.append(getattr(evt, 'location', 0))
            except Exception:
                pass

    if not anchors:
        anchors = [0]

    path_id = 0
    for anchor in anchors[:15]:
        sources = _find_sources(data, anchor)
        sinks = _find_sinks(data, anchor)

        for src in sources:
            sink_locs = [s.location for s in sinks]
            intermediates = _find_propagation_nodes(data, src.location, sink_locs)

            for snk in sinks:
                # 计算信息泄漏估计
                info_est = 0.0
                channel = 'UNKNOWN'
                for pat, ch, _, ie in _OBSERVABLE_SINK_PATTERNS:
                    if pat in snk.label.encode('ascii', errors='replace'):
                        channel = ch
                        info_est = ie
                        break

                # 路径置信度: 中间节点越多 → 路径越可能完整
                conf = min(0.85, 0.35 + len(intermediates) * 0.10)

                # 分支密度加权: 源代码区域分支多 → 时序泄漏风险高
                region_start = max(0, anchor - 256)
                region = data[region_start:anchor + 256]
                branch_count = sum(1 for b in region if b in _BRANCH_BYTES)
                if branch_count > 4 and channel == 'TIMING':
                    info_est = min(1.0, info_est + 0.25)

                path_id += 1
                paths.append(LeakagePath(
                    path_id=path_id,
                    source=src,
                    intermediate_nodes=intermediates[:5],
                    sink=snk,
                    info_leakage_estimate=round(info_est, 3),
                    channel_type=channel,
                    confidence=round(conf, 3)))

    paths.sort(key=lambda p: (-p.info_leakage_estimate, -p.confidence))
    return paths[:20]
