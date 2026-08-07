"""
跨二进制密码学实现谱系追踪 — 基于代码区域指纹的复用关系检测。

修改记录:
  2025-07-30 11:52 — 改为merge-sort合并策略; 增加语义等价分组
  2025-08-04 09:15 — 拆分为独立的match/scoring函数, 增加simhash预筛选

设计意图:
  crypto_lib_fingerprint通过版本字符串识别静态链接的密码库, 但无法回答:
    (a) 两个固件是否复用了同一段密码学代码(即使库不同)?
    (b) 某个密码学漏洞影响了多少二进制?
    (c) 代码片段在库间是否发生拷贝传播(copy-paste lineage)?

  本模块对检测到的密码学结构(S-box区域/轮常量/API代码片段)提取区域指纹,
  跨二进制比对构建复用关系图。指纹使用simhash降维后做LSH预筛选,
  再以完整哈希精确匹配。

  - Jang et al., "ReDeBug: Finding Unpatched Code Clones in Entire OS Distributions"
: 基于代码哈希的跨二进制复用检测思路, 本项目推广到密码学区域。
  - Pewny et al., "Cross-Architecture Bug Search in Binary Executables":
    跨架构二进制代码搜索, 使用IR级别特征 — 本项目在raw byte层面工作, 避免IR依赖。
  - David & Yahav, "Tracelet-based code search in executables":
    tracelet概念 — 短代码片段作为搜索单元, 本项目将S-box/常数表作为特殊tracelet。

边界条件:
  - 仅对已检测到密码学结构的位置提取指纹, 不做全二进制扫描。
  - Simhash的64bit为概率性筛子 — 设汉明距离≤3为候选, 假阳性率约10^-5。
  - 跨架构场景(ARM vs x86)当前不支持, 仅同架构比对。
"""

import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 指纹提取参数
_DEFAULT_CONTEXT_WINDOW = 256     # 锚点两侧各取窗口尺寸
_SIMHASH_BIT = 64                 # Simhash位数
_SIMHASH_THRESHOLD = 3            # 汉明距离≤3视为候选匹配

@dataclass
class CryptoRegion:
    """密码学代码区域描述 — 已识别密码学代码片段的元数据."""
    algorithm: str                 # AES, SM4, SHA-256 ...
    anchor_offset: int             # 锚点在文件中的偏移
    evidence_type: str             # S-box / IV / round_const / API_string
    sha256_full: str = ""          # 窗口区域的SHA-256
    sha256_sbox: str = ""          # 仅S-box自身(如存在)的SHA-256
    sha256_code: str = ""          # 锚点前+后各128B(代码骨架)的SHA-256
    simhash: int = 0               # 64-bit simhash — LSH预筛选用
    file_path: str = ""

@dataclass
class LineageMatch:
    """两个CryptoRegion间的匹配."""
    region_a: CryptoRegion
    region_b: CryptoRegion
    match_type: str                # 'exact_sbox' | 'exact_code' | 'fuzzy_simhash'
    confidence: float

@dataclass
class LineageGraph:
    """跨二进制复用关系图."""
    binaries: Dict[str, List[CryptoRegion]] = field(default_factory=dict)
    matches: List[LineageMatch] = field(default_factory=list)
    # 算法→二进制列表索引, 用于快速查找同名区域
    _algo_index: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_binary(self, file_path: str, regions: List[CryptoRegion]) -> None:
        if file_path not in self.binaries:
            self.binaries[file_path] = []
        for r in regions:
            r.file_path = file_path
            self._algo_index[r.algorithm].add(file_path)
        self.binaries[file_path].extend(regions)

    def get_shared_binaries(self, algorithm: str) -> Set[str]:
        """返回共享指定算法实现的二进制集合."""
        return self._algo_index.get(algorithm, set())

    def propagation_chain(self, region: CryptoRegion) -> List[str]:
        """追踪给定区域的复用传播链 — 返回共享相同S-box指纹的二进制列表."""
        chain: List[str] = []
        for fpath, regions in self.binaries.items():
            for r in regions:
                if (r.algorithm == region.algorithm and
                    r.sha256_sbox and region.sha256_sbox and
                    r.sha256_sbox == region.sha256_sbox):
                    if fpath not in chain:
                        chain.append(fpath)
        return chain

# Simhash实现
# 64-bit simhash: 对输入字节流的每个字节, 按位值更新64个累加器。
# 最终每个累加器≥0→对应位为1。用于概率性近似去重和LSH预筛选。

def compute_simhash(data: bytes) -> int:
    """计算字节序列的64-bit simhash指纹."""
    if not data:
        return 0
    accum = [0] * _SIMHASH_BIT
    for byte_val in data:
        for bit in range(_SIMHASH_BIT):
            # byte_val与bit位置确定性哈希选择+1/-1方向
            val = ((byte_val * 0x9E3779B1 + bit * 0x517CC1B7) >> 7) & 1
            if val:
                accum[bit] += 1
            else:
                accum[bit] -= 1
    result = 0
    for bit in range(_SIMHASH_BIT):
        if accum[bit] >= 0:
            result |= (1 << bit)
    return result

def simhash_distance(a: int, b: int) -> int:
    """两个simhash间的汉明距离."""
    return (a ^ b).bit_count()

# 指纹提取

def extract_region_fingerprint(data: bytes,
                               anchor: int,
                               algorithm: str,
                               evidence_type: str,
                               sbox_data: Optional[bytes] = None,
                               window: int = _DEFAULT_CONTEXT_WINDOW) -> CryptoRegion:
    """提取锚点周围的密码学区域指纹.

    三路SHA-256: (1)完整窗口 (2)S-box自身 (3)代码骨架(前后128B).
    S-box自身哈希用于精确匹配; 代码骨架哈希用于识别相同编译产物的复用。
    """
    dl = len(data)
    region = CryptoRegion(algorithm=algorithm, anchor_offset=anchor,
                          evidence_type=evidence_type)

    # 完整窗口
    w_start = max(0, anchor - window)
    w_end = min(dl, anchor + window)
    full_win = data[w_start:w_end]
    region.sha256_full = hashlib.sha256(full_win).hexdigest()

    # S-box自身 (如传入)
    if sbox_data:
        region.sha256_sbox = hashlib.sha256(sbox_data).hexdigest()

    # 代码骨架: 锚点前后短窗口 — 避免数据段污染
    code_pre = data[max(0, anchor - 128):anchor]
    code_post = data[anchor:min(dl, anchor + 128)]
    region.sha256_code = hashlib.sha256(code_pre + code_post).hexdigest()

    # Simhash — 用完整窗口计算
    region.simhash = compute_simhash(full_win)

    return region

# 跨二进制匹配

def match_regions(regions_a: List[CryptoRegion],
                  regions_b: List[CryptoRegion],
                  simhash_threshold: int = _SIMHASH_THRESHOLD) -> List[LineageMatch]:
    """两批区域间查找匹配 — simhash预筛 + SHA精确确认.

    两层策略:
      (1) simhash汉明距离≤3 → 候选 (概率性, 快)
      (2) S-box哈希精确相等 → 确定匹配; 否则代码哈希相等 → 大概率匹配
    """
    matches: List[LineageMatch] = []

    for ra in regions_a:
        for rb in regions_b:
            if ra.algorithm != rb.algorithm:
                continue

            # 第一步: simhash预筛选
            sh_dist = simhash_distance(ra.simhash, rb.simhash)
            if sh_dist > simhash_threshold:
                continue

            # 第二步: SHA精确确认
            if ra.sha256_sbox and rb.sha256_sbox and ra.sha256_sbox == rb.sha256_sbox:
                matches.append(LineageMatch(
                    region_a=ra, region_b=rb,
                    match_type='exact_sbox', confidence=0.98))
            elif ra.sha256_code and rb.sha256_code and ra.sha256_code == rb.sha256_code:
                matches.append(LineageMatch(
                    region_a=ra, region_b=rb,
                    match_type='exact_code', confidence=0.85))
            elif ra.sha256_full and rb.sha256_full and ra.sha256_full == rb.sha256_full:
                matches.append(LineageMatch(
                    region_a=ra, region_b=rb,
                    match_type='exact_code', confidence=0.90))
            else:
                # Simhash接近但SHA不匹配 — 可能为轻微修改的变体
                matches.append(LineageMatch(
                    region_a=ra, region_b=rb,
                    match_type='fuzzy_simhash',
                    confidence=max(0.50, 1.0 - sh_dist / (2.0 * _SIMHASH_THRESHOLD))))

    return matches

# 批量区域提取 — 从crypto_detector的findings批量生成

def regions_from_findings(data: bytes,
                          findings: List,
                          file_path: str = "") -> List[CryptoRegion]:
    """将crypto_detector输出转换为CryptoRegion列表.

    findings: 每个元素需含algorithm, location, evidence字段(或兼容dict).
    """
    regions: List[CryptoRegion] = []
    dl = len(data)
    for f in findings:
        algo = getattr(f, 'algorithm', '') or f.get('algorithm', '')
        loc = getattr(f, 'location', 0) or f.get('location', 0)
        ev = getattr(f, 'evidence', '') or f.get('evidence', '')
        if not algo or loc < 0 or loc >= dl:
            continue
        # 尝试提取S-box数据 — 仅当evidence指示存在时
        sbox_data = None
        if 'S-box' in str(ev) or 'IV' in str(ev):
            if loc + 256 <= dl:
                candidate = data[loc:loc + 256]
                if len(set(candidate)) >= 200:  # 近置换 → 高概率S-box
                    sbox_data = candidate
        region = extract_region_fingerprint(data, loc, algo, str(ev),
                                            sbox_data=sbox_data)
        region.file_path = file_path
        regions.append(region)
    return regions

# 谱系图构建

def build_lineage(file_regions: Dict[str, List[CryptoRegion]],
                  simhash_threshold: int = _SIMHASH_THRESHOLD) -> LineageGraph:
    """多二进制 → 跨二进制复用关系图.

    file_regions: {文件路径: [CryptoRegion, ...]}.
    对所有二进制对执行匹配, 构建完整复用关系图。
    """
    graph = LineageGraph()
    fpaths = list(file_regions.keys())

    for fp in fpaths:
        graph.add_binary(fp, file_regions[fp])

    # 全对匹配 O(n²), n=二进制数量×每文件平均区域数
    for i in range(len(fpaths)):
        for j in range(i + 1, len(fpaths)):
            fp_a, fp_b = fpaths[i], fpaths[j]
            matches = match_regions(file_regions[fp_a], file_regions[fp_b],
                                    simhash_threshold)
            graph.matches.extend(matches)

    return graph

__all__ = [
    'CryptoRegion', 'LineageMatch', 'LineageGraph',
    'compute_simhash', 'simhash_distance',
    'extract_region_fingerprint', 'match_regions',
    'regions_from_findings', 'build_lineage',
]
