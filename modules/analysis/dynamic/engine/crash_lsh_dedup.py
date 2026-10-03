#
# 崩溃状态局部敏感哈希去重器 — 基于崩溃上下文的 MinHash 聚类
#
# Fuzzing 会话产生大量崩溃，其中 60-90% 是同一根因的变体
# 手动 triage 的时间瓶颈不在崩溃分类（已有 crash_triage.py）而在
# 崩溃去重——判断两个看似不同的崩溃是否源于同一漏洞
#
# 现有 crash_triage.py 对每个崩溃独立打分（可利用性），不做跨崩溃比较
# 本模块填补此缺口：将崩溃上下文（调用栈、寄存器状态、故障类型）编码为
# MinHash 签名，通过签名相似度自动聚类同根因崩溃
#
# MinHash 的选择理由（vs SimHash）：
#   - SimHash 对输入顺序敏感（SHA-256 的 bit 扰动 → 汉明距离变化不均）
# 崩溃上下文的"特征集"是调用帧的集合——天然是集合数据
# MinHash 估计的 Jaccard 相似度对集合数据有理论保证
# 我们不需要 SimHash 的 bitw 汉明距离——需要的是集合交并比
#
# 特征工程：
#   每条崩溃提取以下"shingle"（特征片段）：
# stack_N_frame_M: 栈帧地址的前 12 bit 掩码（函数级粒度）
# reg_X_val_Y: 寄存器 X 的值非零时取高 8 bit（值域粗粒化）
# fault_type_Z: 故障类型（ACCESS_VIOLA 等）
# crash_addr_page_P: 崩溃地址的页号（4KB 页粒度）
# module_M_offset_O: 崩溃地址所在模块 + 偏移（粗粒度）
# 将以上 shingle 集合输入 MinHash → 256-bit 签名
#   两个崩溃的 MinHash 签名汉明距离 < 32（即估计 Jaccard ≥ 0.875）
# 视为同一根因
#
# 调用帧去重逻辑：
#   同一函数内不同偏移的调用帧（如 foo+0x12 和 foo+0x3f）在去重中
# 视为等价——因为我们关心的是"哪个函数在栈上"而非"精确到字节的偏移"
# 实现：调用帧地址按 0x1000 对齐后哈希——函数级粒度
#
# Broder, " resembl 包含 documents."
#      SEQUENCES 1997. — MinHash 原始论文，Jaccard 估计的理论基础
# Klee, "Crash deduplica via 栈 哈希" — Mozilla Socorro
#      项目使用栈帧签名进行崩溃去重，本项目在此基础上增加了寄存器状态
#      维度以区分"同一函数的不同崩溃模式"（如同一 memcpy 中的
# 缓冲区溢出 vs 释放后使用——栈相同但寄存器状态不同）

import hashlib
import struct
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


# MinHash 签名长度 —— 256 个哈希函数
_SIG_LENGTH = 256
# 聚类阈值 —— 汉明距离 / 签名长度的上限
_CLUSTER_THRESHOLD = 0.125  # ≤ 12.5% → 同一簇


@dataclass
class CrashFingerprint:
    crash_id: str
    signature: List[int]  # 256 个 uint32 值——各哈希函数的最小值
    fault_type: str = ""
    crash_address: int = 0
    stack_depth: int = 0
    module_count: int = 0
    # 原始特征——用于诊断和解释聚类结果
    raw_features: List[str] = field(default_factory=list)


@dataclass
class CrashCluster:
    cluster_id: str
    members: List[str] = field(default_factory=list)  # crash_id 列表
    representative: str = ""  # 簇代表（最小签名与簇中心距离最近的成员）
    size: int = 0
    fault_types: List[str] = field(default_factory=list)
    # 簇内签名的 pairw 平均汉明距离——作为簇紧密度度量
    intra_cluster_distance: float = 0.0


class CrashStateHasher:

    # 特征提取配置
    STACK_FRAME_MASK = 0xFFFFF000     # 调用帧 → 4KB 对齐（函数级）
    REG_VAL_SHIFT = 40                # 寄存器值 → 取高 8 bit
    PAGE_SHIFT = 12                   # 地址 → 页号

    def fingerprint(self, crash_info: Any) -> CrashFingerprint:
        features = self._extract_features(crash_info)
        sig = self._minhash_signature(features)
        crash_id = self._make_crash_id(crash_info)

        return CrashFingerprint(
            crash_id=crash_id,
            signature=sig,
            fault_type=str(getattr(crash_info, 'crash_type', 'UNKNOWN')),
            crash_address=getattr(crash_info, 'crash_address', 0) or 0,
            stack_depth=len(getattr(crash_info, 'stack_trace', []) or []),
            module_count=len(getattr(crash_info, 'modules_loaded', []) or []),
            raw_features=list(features),
        )

    def _extract_features(self, ci: Any) -> Set[str]:
        feats: Set[str] = set()

        # (1) 故障类型
        ct = str(getattr(ci, 'crash_type', 'UNKNOWN'))
        feats.add(f'fault_type_{ct}')

        # (2) 崩溃地址——页号粒度
        crash_addr = getattr(ci, 'crash_address', 0) or 0
        if crash_addr:
            feats.add(f'crash_page_{crash_addr >> self.PAGE_SHIFT}')

        # (3) 调用栈——函数级粒度
        stack = getattr(ci, 'stack_trace', None)
        if stack:
            for depth, frame in enumerate(stack[:16]):  # 最多取 16 帧
                addr = frame.get('addr', 0) if isinstance(frame, dict) else 0
                module = frame.get('module', '') if isinstance(frame, dict) else ''
                # 函数级掩码——同一函数内不同偏移合并
                func_key = (addr & self.STACK_FRAME_MASK) >> self.PAGE_SHIFT
                feats.add(f'stack_{depth}_func_{func_key}')
                if module:
                    feats.add(f'module_{module}_depth_{depth}')

        # (4) 寄存器状态——非零寄存器的高位值
        regs = getattr(ci, 'register_context', None)
        if regs:
            reg_dict = regs if isinstance(regs, dict) else {}
            for reg_name in ('RIP', 'RSP', 'RBP', 'RAX', 'RBX', 'RCX', 'RDX',
                           'RDI', 'RSI', 'R8', 'R9', 'EFLAGS'):
                val = reg_dict.get(reg_name, 0)
                if val and val != 0:
                    high_byte = (val >> self.REG_VAL_SHIFT) & 0xFF
                    feats.add(f'reg_{reg_name}_hi_{high_byte}')

        # (5) 异常码
        exc = getattr(ci, 'exception_code', 0)
        if exc:
            feats.add(f'exc_{exc & 0xFFFF}')

        return feats

    def _minhash_signature(self, features: Set[str]) -> List[int]:
        if not features:
            return [0xFFFFFFFF] * _SIG_LENGTH

        sig = [0xFFFFFFFF] * _SIG_LENGTH
        # 使用双哈希技巧：h_i(x) = h1(x) + * h2(x)，减少哈希计算量
        for feat in features:
            h1, h2 = self._dual_hash(feat)
            for i in range(_SIG_LENGTH):
                hv = (h1 + i * h2) & 0xFFFFFFFF
                if hv < sig[i]:
                    sig[i] = hv

        return sig

    @staticmethod
    def _dual_hash(feat: str) -> Tuple[int, int]:
        raw = feat.encode('utf-8')
        h = hashlib.sha256(raw).digest()
        h1 = struct.unpack_from('<I', h, 0)[0]
        h2 = struct.unpack_from('<I', h, 4)[0]
        # 确保 h2 是奇数——双哈希技巧要求
        if h2 % 2 == 0:
            h2 += 1
        return h1, h2

    @staticmethod
    def _make_crash_id(ci: Any) -> str:
        stack = getattr(ci, 'stack_trace', None) or []
        crash_addr = getattr(ci, 'crash_address', 0) or 0
        top_frame = stack[0].get('addr', 0) if stack and isinstance(stack[0], dict) else 0
        raw = f'{crash_addr:x}:{top_frame:x}'
        return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CrashDeduplicator:

    def __init__(self, cluster_threshold: float = _CLUSTER_THRESHOLD):
        self._threshold = cluster_threshold
        self._hasher = CrashStateHasher()
        self._clusters: Dict[str, CrashCluster] = {}
        self._fingerprints: Dict[str, CrashFingerprint] = {}
        self._next_cluster_id: int = 0

    def ingest(self, crash_info: Any) -> Tuple[str, bool]:
        fp = self._hasher.fingerprint(crash_info)
        self._fingerprints[fp.crash_id] = fp

        # 找到最近的现有簇
        best_cluster, best_dist = None, 1.0
        for cid, cluster in self._clusters.items():
            if not cluster.representative:
                continue
            rep_fp = self._fingerprints.get(cluster.representative)
            if rep_fp is None:
                continue
            dist = self._signature_distance(fp.signature, rep_fp.signature)
            if dist < best_dist:
                best_dist = dist
                best_cluster = cid

        if best_cluster is not None and best_dist <= self._threshold:
            # 归入现有簇
            cluster = self._clusters[best_cluster]
            cluster.members.append(fp.crash_id)
            cluster.size = len(cluster.members)
            cluster.fault_types.append(fp.fault_type)
            # 若新成员更接近簇平均签名，更新代表
            if best_dist < self._signature_distance(
                fp.signature,
                self._fingerprints[cluster.representative].signature
            ):
                cluster.representative = fp.crash_id
            return best_cluster, False
        else:
            # 创建新簇
            cid = f'cluster_{self._next_cluster_id:04d}'
            self._next_cluster_id += 1
            self._clusters[cid] = CrashCluster(
                cluster_id=cid,
                members=[fp.crash_id],
                representative=fp.crash_id,
                size=1,
                fault_types=[fp.fault_type],
            )
            return cid, True

    def compact_clusters(self) -> int:
        cids = list(self._clusters.keys())
        if len(cids) < 2:
            return 0

        merged = 0
        merged_into: Dict[str, str] = {}  # old_cid → new_cid

        for i, cid_a in enumerate(cids):
            if cid_a in merged_into:
                continue
            for cid_b in cids[i + 1:]:
                if cid_b in merged_into:
                    continue
                rep_a = self._clusters[cid_a].representative
                rep_b = self._clusters[cid_b].representative
                fp_a = self._fingerprints.get(rep_a)
                fp_b = self._fingerprints.get(rep_b)
                if fp_a is None or fp_b is None:
                    continue

                dist = self._signature_distance(fp_a.signature, fp_b.signature)
                if dist <= self._threshold * 0.5:
                    # 合并 b → a
                    self._clusters[cid_a].members.extend(
                        self._clusters[cid_b].members
                    )
                    self._clusters[cid_a].size = len(self._clusters[cid_a].members)
                    self._clusters[cid_a].fault_types.extend(
                        self._clusters[cid_b].fault_types
                    )
                    merged_into[cid_b] = cid_a
                    merged += 1

        for old_cid in merged_into:
            del self._clusters[old_cid]

        return merged

    def get_summary(self) -> List[Dict[str, Any]]:
        summary = []
        for cid, cluster in sorted(self._clusters.items(),
                                    key=lambda x: -x[1].size):
            # 故障类型分布
            ft_counts: Dict[str, int] = defaultdict(int)
            for ft in cluster.fault_types:
                ft_counts[ft] += 1

            summary.append({
                'cluster_id': cluster.cluster_id,
                'size': cluster.size,
                'fault_type_distribution': dict(ft_counts),
                'representative_crash_id': cluster.representative,
            })
        return summary

    @staticmethod
    def _signature_distance(sig_a: List[int], sig_b: List[int]) -> float:
        if len(sig_a) != len(sig_b):
            return 1.0
        diff = sum(1 for a, b in zip(sig_a, sig_b) if a != b)
        return diff / len(sig_a)
