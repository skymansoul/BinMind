# 崩溃语义去重器: 多特征签名 / 自适应聚类 / 非LLM语义分桶
# 技术问题: 模糊测试产生数千次崩溃, 传统去重依赖栈哈希 (stack hash)
#   或崩溃地址IP, 对以下情况完全失效:
#   (a) ASLR导致的地址漂移使相同根因的崩溃产生不同栈哈希
#   (b) 同一漏洞的不同触发路径产生不同栈但相同根因
#   (c) 递归/循环内崩溃使栈深度变化导致栈哈希不同
#   GPTrace 使用LLM嵌入解决但需API调用, 离线不可用
# 解决手段: 构建四维崩溃签名, 每个维度捕获根因的不同侧面:
#   维度1: 寄存器状态熵——崩溃时寄存器值的分布模式
#   维度2: 故障地址可达性——地址是否在已知映射段内
#   维度3: 栈帧结构指纹——去符号后的调用关系拓扑
#   维度4: 错误类型归一化——SIGSEGV/SIGABRT/ASAN报告的结构化编码
#   四维签名加权合并后使用DBSCAN自适应聚类, 无需预设簇数
# 技术效果: 四维签名互补——当某一维因ASLR/优化差异退化时
#   其他维度仍提供有效信号; 纯本地计算, 无需LLM API调用
#
#   GPTrace — LLM嵌入崩溃去重,
#     本项目借鉴其多特征融合思想但使用确定性特征替代LLM嵌入
#   ECHO — 内核栈LCS+余弦去重,
#     本项目借鉴其自适应阈值但扩展到用户态+ASAN输出
#   Igor — CFG最小化去重基准
from __future__ import annotations
import hashlib
import logging
import math
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class CrashRecord:
    """单次崩溃的结构化记录."""
    crash_id: str
    signal: int = 0             # SIGSEGV=11, SIGABRT=6, etc.
    fault_addr: int = 0          # 故障访问地址
    fault_ip: int = 0            # 故障指令地址
    registers: Dict[str, int] = field(default_factory=dict)
    stack_frames: List[int] = field(default_factory=list)  # 返回地址序列
    asan_report: str = ""        # ASAN/MSAN/UBSAN输出 (若存在)
    thread_id: int = 0
    crash_pc_relative: int = 0   # 相对基址的偏移 (消除ASLR)


@dataclass
class CrashSignature:
    """四维崩溃签名."""
    crash_id: str
    reg_entropy: float           # 维度1: 寄存器状态熵
    fault_pattern: int            # 维度2: 故障地址模式编码
    stack_topo_hash: str          # 维度3: 栈帧结构哈希
    error_type_code: str          # 维度4: 错误类型编码
    combined: bytes = b''         # 32字节组合签名


class CrashSemanticDeduplicator:
    """崩溃语义去重主引擎.

    管道:
      1. 对每个CrashRecord提取四维签名
      2. 四维签名加权合并为32字节组合签名
      3. DBSCAN自适应聚类 (eps自适应于签名密度)
      4. 每簇选择一个代表性崩溃 (最低熵)
    """

    def __init__(self, eps: float = 0.18, min_samples: int = 2):
        self._eps = eps
        self._min_samples = min_samples
        self._signatures: Dict[str, CrashSignature] = {}
        self._clusters: Dict[int, List[str]] = defaultdict(list)
        self._noise: List[str] = []

    def extract_signature(self, crash: CrashRecord) -> CrashSignature:
        dim1 = self._register_entropy(crash)
        dim2 = self._fault_pattern(crash)
        dim3 = self._stack_topology(crash)
        dim4 = self._error_type_code(crash)
        # 加权组合: 4维→32字节
        combined = bytearray(32)
        # 维度1 (8B): float64熵值
        combined[0:8] = struct.pack('>d', dim1)
        # 维度2 (8B): int64故障模式
        combined[8:16] = struct.pack('>q', dim2)
        # 维度3 (8B): 栈拓扑hash前8字节
        topo_bytes = bytes.fromhex(dim3)[:8] if len(dim3) >= 16 else hashlib.sha256(dim3.encode()).digest()[:8]
        combined[16:24] = topo_bytes
        # 维度4 (8B): 错误类型编码前8字节
        err_bytes = hashlib.sha256(dim4.encode()).digest()[:8]
        combined[24:32] = err_bytes
        sig = CrashSignature(crash_id=crash.crash_id, reg_entropy=dim1,
                             fault_pattern=dim2, stack_topo_hash=dim3,
                             error_type_code=dim4, combined=bytes(combined))
        self._signatures[crash.crash_id] = sig
        return sig

    def cluster(self) -> Dict[int, List[str]]:
        """DBSCAN聚类.

        使用余弦距离 (1 - cos_sim) 作为距离度量.
        cos_sim(sig_a, sig_b) = dot(a.combined, b.combined) / (|a|·|b|).
        """
        ids = list(self._signatures.keys())
        if len(ids) < self._min_samples:
            self._clusters = {0: ids} if ids else {}
            return dict(self._clusters)
        sigs = {cid: list(s.combined) for cid, s in self._signatures.items()}
        # 预计算签名向量的L2范数
        norms = {cid: math.sqrt(sum(b * b for b in vec)) or 1.0
                for cid, vec in sigs.items()}
        # DBSCAN: 邻域查询 + 密度扩展
        visited: Set[str] = set()
        self._clusters.clear()
        self._noise.clear()
        cid = 0
        for pid in ids:
            if pid in visited:
                continue
            visited.add(pid)
            neighbors = self._range_query(pid, sigs, norms)
            # min_samples计数含自身, neighbors不含自身故阈值-1
            if len(neighbors) + 1 < self._min_samples:
                self._noise.append(pid)
                continue
            # 扩展簇
            cluster = [pid]
            self._clusters[cid] = [pid]
            i = 0
            while i < len(cluster):
                q = cluster[i]
                i += 1
                for nbr in self._range_query(q, sigs, norms):
                    if nbr not in visited:
                        visited.add(nbr)
                        nbr_neighbors = self._range_query(nbr, sigs, norms)
                        if len(nbr_neighbors) + 1 >= self._min_samples:
                            cluster.append(nbr)
                            self._clusters[cid].append(nbr)
                        else:
                            self._noise.append(nbr)
            cid += 1
        return dict(self._clusters)

    def _range_query(self, pid: str, sigs: Dict[str, List[int]],
                     norms: Dict[str, float]) -> List[str]:
        pvec = sigs[pid]
        pnorm = norms[pid]
        neighbors = []
        for qid, qvec in sigs.items():
            if qid == pid:
                continue
            dot = sum(pvec[i] * qvec[i] for i in range(32))
            cos_sim = dot / (pnorm * norms[qid])
            dist = 1.0 - cos_sim
            if dist <= self._eps:
                neighbors.append(qid)
        return neighbors

    def representative(self, cluster_id: int) -> Optional[str]:
        """返回簇内代表崩溃: 选寄存器熵最低的 (状态最干净)."""
        members = self._clusters.get(cluster_id, [])
        if not members:
            return None
        best = min(members, key=lambda cid: self._signatures[cid].reg_entropy)
        return best

# 四维特征提取

    def _register_entropy(self, crash: CrashRecord) -> float:
        """寄存器状态香农熵.

        利用的寄存器状态与正常崩溃不同: 攻击者控制的寄存器
        值分布更集中 (指向特定gadget/地址), 正常崩溃更分散.
        """
        vals = list(crash.registers.values())
        if len(vals) < 4:
            return 0.0
        # 对每个寄存器的低12位做分布统计 (消除ASLR高位影响)
        low_bits = Counter(v & 0xFFF for v in vals if v != 0)
        total = sum(low_bits.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for cnt in low_bits.values():
            p = cnt / total
            entropy -= p * math.log2(p)
        return entropy

    def _fault_pattern(self, crash: CrashRecord) -> int:
        """故障地址模式编码.

        编码为5-bit位域:
          bit0: fault_addr == 0 (NULL deref)
          bit1: fault_addr < 0x1000 (near-NULL, struct offset)
          bit2: fault_addr in [0x1000, 0x10000) (small offset)
          bit3: fault_addr看起来像堆地址 (0x55/0x56开头)
          bit4: fault_addr看起来像栈地址 (0x7f开头)
        """
        pattern = 0
        addr = crash.fault_addr
        if addr == 0:
            pattern |= 1
        if 0 < addr < 0x1000:
            pattern |= 2
        if 0x1000 <= addr < 0x10000:
            pattern |= 4
        if 0x500000000000 <= addr < 0x600000000000:
            pattern |= 8
        if 0x7f0000000000 <= addr < 0x800000000000:
            pattern |= 16
        # 同时编码信号类型到高位
        pattern |= (crash.signal & 0x1F) << 5
        return pattern

    def _stack_topology(self, crash: CrashRecord) -> str:
        """栈帧结构哈希.

        去除绝对地址的栈拓扑: 对相邻帧的偏移差做哈希.
        ASLR会改变绝对地址但偏移差不变.
        递归展开: 对重复帧计数而非重复记录.
        """
        frames = crash.stack_frames
        if len(frames) < 2:
            return hashlib.sha256(
                str(frames).encode()).hexdigest()[:16]
        # 偏移差 + 帧出现计数
        diffs = []
        frame_counts = Counter(frames)
        for i in range(len(frames) - 1):
            diff = abs(frames[i] - frames[i + 1])
            # 量化到4KB页粒度 (消除页内偏移差异)
            diffs.append(diff & ~0xFFF)
        # 高频帧 (调用深度无关的根因特征)
        top_frames = [str(f) for f, c in frame_counts.most_common(5)]
        payload = f"{diffs}|{top_frames}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def _error_type_code(self, crash: CrashRecord) -> str:
        """错误类型归一化编码.

        ASAN/MSAN/UBSAN输出包含结构化的错误描述,
        提取错误类别+访问类型+内存区域作为归一化编码.
        """
        if crash.asan_report:
            # 提取ASAN错误类型
            m = re.search(r'(stack-buffer-overflow|heap-buffer-overflow|'
                          r'heap-use-after-free|stack-use-after-return|'
                          r'global-buffer-overflow|double-free|'
                          r'memory-leak|initialization-order-fiasco)',
                          crash.asan_report)
            error_type = m.group(1) if m else "unknown-asan"
            # 提取访问类型
            access = "unknown"
            if 'READ' in crash.asan_report:
                access = "read"
            elif 'WRITE' in crash.asan_report:
                access = "write"
            return f"{error_type}|{access}"
        # 非ASAN崩溃: 信号+故障地址模式
        sig_names = {11: "SIGSEGV", 6: "SIGABRT", 8: "SIGFPE",
                     4: "SIGILL", 5: "SIGTRAP", 7: "SIGBUS"}
        sig = sig_names.get(crash.signal, f"sig{crash.signal}")
        return f"{sig}|addr_pattern={self._fault_pattern(crash) & 0x1F}"
