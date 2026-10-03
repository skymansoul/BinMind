# 初始实现：补丁近接度 + 约束边界距离的复合适应度
# 引入多样性奖励，防止搜索早熟收敛到同一局部最优

"""Bypass Fitness Landscape — 补丁绕过搜索的适应度地形。

问题形式化：
  给定已修补 binary B_patched，构造输入 x 使得 B_patched(x) 的行为
  偏离预期修补行为——即补丁未能阻止原漏洞的利用。

  这不等同于传统 fuzzing：传统 fuzzing 追求 crash coverage，
  本模块追求 patch boundary violation —— 输入到达补丁位置但绕过其安全检查。

适应度函数设计：
  F(x) = α · patch_proximity(x) + β · constraint_boundary_dist(x) + γ · diversity_bonus(x)

  其中：
    patch_proximity: 执行迹与补丁地址的接近程度（0..1）
    constraint_boundary_dist: 输入值距补丁检查边界的距离（0..1，越近越好）
    diversity_bonus: 与已发现 bypass 群体中其他输入的差异度

// 设计依据：
//   - AFL/AFL++ 的 edge coverage bitmap 提供覆盖率反馈但不理解补丁语义
//   - 本模块在 coverage bitmap 之上叠加补丁感知的 fitness features
//   - 类比 GAN 的对抗训练：generator = mutator, discriminator = patch checker
//   - 但避免 GAN 的训练不稳定性，改用直接梯度估计（SPSA 式扰动）
"""

import math
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict


@dataclass
class PatchSite:
    """补丁位置的结构化描述。"""
    address: int                     # 补丁字节在 binary 中的偏移
    size: int                        # 补丁字节数
    strategy: str = ""               # 修补策略描述
    check_kind: str = ""             # 安全检查类型：size_check | null_check | canary | sanitize
    check_param: int = 0             # 检查参数（如 size_check 的阈值大小）
    surrounding_instrs: List[str] = field(default_factory=list)
    # 补丁前后的汇编指令（用于约束提取）


@dataclass
class ExecutionTrace:
    """轻量执行迹 —— 仅记录对补丁近接度计算必要的部分。"""
    basic_blocks_hit: Set[int] = field(default_factory=set)
    instructions_hit: Set[int] = field(default_factory=set)
    syscall_sequence: List[str] = field(default_factory=list)
    exit_code: int = 0
    signal_num: int = 0
    coverage_bitmap_hash: str = ""
    # 是否在补丁附近（补丁前后 64 bytes 内）触发了基本块
    patch_vicinity_hit: Set[int] = field(default_factory=set)


# 补丁近接度

def patch_proximity(trace: ExecutionTrace, patch_sites: List[PatchSite],
                    total_binary_size: int = 0) -> float:
    """计算执行迹与补丁地址的接近程度。

    算法：
      对每个补丁位置，检查 trace 中最近的基本块地址。
      距离越近 → 分数越高。使用指数衰减：exp(-distance / bandwidth)。

    bandwidth 自动标定：补丁的预期影响范围（64/256/1024 bytes）。
    """
    if not patch_sites or not trace.basic_blocks_hit:
        return 0.0

    total_score = 0.0
    for site in patch_sites:
        best_dist = float('inf')
        for bb_addr in trace.basic_blocks_hit:
            dist = abs(bb_addr - site.address)
            if dist < best_dist:
                best_dist = dist
        if best_dist == float('inf'):
            continue
        # bandwidth: 补丁大小的 4 倍，至少 64
        bw = max(site.size * 4, 64)
        site_score = math.exp(-best_dist / bw)
        total_score += site_score

    return min(total_score / max(len(patch_sites), 1), 1.0)


# 约束边界距离

def constraint_boundary_distance(input_data: bytes,
                                 patch_sites: List[PatchSite]) -> float:
    """计算输入数据距补丁安全检查边界的距离。

    对每种检查类型有专用的距离度量：
      - size_check: 输入大小 vs 阈值 → |size - threshold| / threshold
      - null_check: 是否有零字节在指针关键位置
      - canary: 对 canary 值的逐字节匹配度
      - sanitize: 输入中非法字符的比例

    返回 0..1，越接近边界（越可能绕过检查）分值越高。
    此分值用于引导输入变异方向 —— 使输入刚好擦过检查的边界。
    """
    if not patch_sites or not input_data:
        return 0.0

    scores = []
    data_len = len(input_data)

    for site in patch_sites:
        if site.check_kind == 'size_check' and site.check_param > 0:
            # 越接近阈值越危险（可能触发 off-by-one）
            dist = abs(data_len - site.check_param)
            norm_dist = dist / max(site.check_param, 1)
            # 在阈值附近（±10%）得分高
            if norm_dist <= 0.10:
                scores.append(0.9)
            elif norm_dist <= 0.25:
                scores.append(0.6)
            elif norm_dist <= 0.50:
                scores.append(0.3)
            else:
                scores.append(0.05)

        elif site.check_kind == 'null_check':
            # 指针字段接近零 → 边界风险
            if data_len >= 8:
                # 取前 8 字节模拟指针值
                ptr_val = int.from_bytes(input_data[:8], 'little')
                if ptr_val == 0:
                    scores.append(0.2)  # 已被 null check 捕获
                elif ptr_val < 256:
                    scores.append(0.8)  # 接近零但不为零 — 可能绕过
                elif ptr_val < 4096:
                    scores.append(0.5)
                else:
                    scores.append(0.1)

        elif site.check_kind == 'canary':
            # canary 值猜测 — 对已知 canary 模式的匹配度
            canary_bytes = input_data[:8] if data_len >= 8 else input_data
            # 典型 Linux canary 低字节为 0x00
            if canary_bytes and canary_bytes[0] == 0x00:
                scores.append(0.7)
            elif canary_bytes and canary_bytes[0] == 0x0a:
                scores.append(0.5)
            else:
                scores.append(0.1)

        elif site.check_kind == 'sanitize':
            # 非法字符比例
            if data_len > 0:
                bad = sum(1 for b in input_data
                         if b in (0x00, 0x0a, 0x0d, 0x27, 0x22, 0x3b, 0x7c, 0x26))
                ratio = bad / data_len
                # 完全干净 → 低分（被 sanitize），含恶意字符 → 高分
                scores.append(ratio)

    return sum(scores) / max(len(scores), 1)


# 多样性奖励

def diversity_bonus(input_data: bytes,
                    seen_inputs: List[bytes],
                    n_bands: int = 8) -> float:
    """计算输入与已有 bypass 种群的结构多样性。

    方法：
      将输入分成 n_bands 个频段，每段计算字节熵。
      与 seen_inputs 中最近邻的 Jensen-Shannon 散度作为多样性分数。

    如果 seen_inputs 为空，返回 1.0（完全新颖）。
    """
    if not seen_inputs:
        return 1.0

    candidate_hist = _byte_entropy_bands(input_data, n_bands)
    min_jsd = float('inf')
    for seen in seen_inputs[-50:]:  # 最多比较 50 个历史输入
        seen_hist = _byte_entropy_bands(seen, n_bands)
        jsd = _jensen_shannon_divergence(candidate_hist, seen_hist)
        if jsd < min_jsd:
            min_jsd = jsd

    # JSD ∈ [0, ln(2)]，归一化
    return min_jsd / math.log(2) if math.log(2) > 0 else 0.0


def _byte_entropy_bands(data: bytes, n: int = 8) -> List[float]:
    """将数据切分为 n 个频段，每段计算字节值分布的香农熵。"""
    if not data:
        return [0.0] * n
    band_size = max(len(data) // n, 1)
    entropies = []
    for i in range(n):
        start = i * band_size
        end = min(start + band_size, len(data))
        if start >= len(data):
            entropies.append(0.0)
            continue
        chunk = data[start:end]
        freq = defaultdict(int)
        for b in chunk:
            freq[b] += 1
        total = len(chunk)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log(p)
        entropies.append(entropy)
    return entropies


def _jensen_shannon_divergence(p: List[float], q: List[float]) -> float:
    """两分布的 Jensen-Shannon 散度。"""
    if len(p) != len(q):
        return float('inf')
    m = [(a + b) / 2.0 for a, b in zip(p, q)]
    kl_pm = sum(a * math.log(a / c) if a > 0 and c > 0 else 0.0
                for a, c in zip(p, m))
    kl_qm = sum(b * math.log(b / c) if b > 0 and c > 0 else 0.0
                for b, c in zip(q, m))
    return (kl_pm + kl_qm) / 2.0


# 复合适应度

@dataclass
class BypassFitness:
    """复合适应度评分。"""
    proximity: float = 0.0
    boundary: float = 0.0
    diversity: float = 0.0
    composite: float = 0.0
    input_label: str = ""
    input_hash: str = ""

    def to_dict(self) -> Dict:
        return {
            'proximity': round(self.proximity, 4),
            'boundary': round(self.boundary, 4),
            'diversity': round(self.diversity, 4),
            'composite': round(self.composite, 4),
            'label': self.input_label,
        }


class BypassFitnessEvaluator:
    """适应度评估器 — 缓存迹信息，避免重复执行。

    对相同 input_hash 的重复查询返回缓存值。
    """

    def __init__(self, alpha: float = 0.45, beta: float = 0.40,
                 gamma: float = 0.15):
        self.alpha = alpha      # patch_proximity 权重
        self.beta = beta        # constraint_boundary 权重
        self.gamma = gamma      # diversity 权重
        self._cache: Dict[str, BypassFitness] = {}
        self._seen_inputs: List[bytes] = []

    def evaluate(self, input_data: bytes, label: str,
                 trace: ExecutionTrace,
                 patch_sites: List[PatchSite]) -> BypassFitness:
        """计算完整适应度。"""
        input_hash = hashlib.sha256(input_data).hexdigest()[:12]

        cached = self._cache.get(input_hash)
        if cached:
            return cached

        prox = patch_proximity(trace, patch_sites)
        bnd = constraint_boundary_distance(input_data, patch_sites)
        div = diversity_bonus(input_data, self._seen_inputs)

        composite = (self.alpha * prox + self.beta * bnd +
                     self.gamma * div)

        fitness = BypassFitness(
            proximity=prox, boundary=bnd, diversity=div,
            composite=composite, input_label=label, input_hash=input_hash,
        )
        self._cache[input_hash] = fitness
        self._seen_inputs.append(input_data)
        return fitness

    def top_k(self, k: int = 5) -> List[BypassFitness]:
        """返回适应度最高的 k 个输入。"""
        sorted_fits = sorted(
            self._cache.values(),
            key=lambda f: f.composite, reverse=True)
        return sorted_fits[:k]
