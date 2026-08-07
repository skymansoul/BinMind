"""
密码学侧信道泄漏潜力评分 — 从二进制静态特征量化实现的信息泄漏风险。

修改记录:
  2025-08-02 10:15 — 初始实现: 5维评分框架, 内存访问模式+分支分布+指令混合+时序+缓存
  2025-08-04 13:38 — 拆分各维度为独立评分函数; 增加加权融合策略和置信度输出

设计意图:
  constant_time_verifier判定"是否常量时间" — 二元结论, 无中间地带。
  现实中的密码学实现介于完全常量时间和明显可观测泄漏之间; 需要量化尺度来:
    (a) 在多个实现中选出泄漏风险最低的编译产物。
    (b) 标记"接近不安全"的实现以便优先加固。
    (c) 跨时间追踪同一代码库的泄漏风险变化趋势。

  本模块将侧信道泄漏潜力分解为5个正交维度, 各输出0-1归一化分值,
  加权融合为复合泄漏评分。评分基于静态二进制分析, 不需要实际功率/时序测量。

  5维度选择依据:
    D1 (Memory Access): 缓存攻击最核心的观测通道 — 秘密相关地址位→不同缓存组→可观测。
    D2 (Branch): 条件分支的执行时间差是可观测信号 — 简单功率分析(SIMP)的基础。
    D3 (Instruction Mix): 指令分布偏斜 → 功率特征可区分 — 差分功率分析(DPA)的前提。
    D4 (Timing Variance): 操作延时差异 → 最直观的侧信道 — 无需物理接触。
    D5 (Cache Footprint): 缓存行占用稳定性 → Spectre/Meltdown类攻击的前提。

  - Adjonyo et al.:
    NIST PQDSS候选系统性时序泄漏分析 — 展示了评分框架在跨实现比较中的实用性。
  - SILENT:
    非参数时序测量算法 — 本项目的静态近似可作为其预筛选阶段。

边界条件:
  - 静态分析无法精确判定运行时的秘密传播 — 评分代表"潜力"而非"确认泄漏"。
    输出明确标注为LEAKAGE_POTENTIAL, 不声称检测到实际泄漏。
  - 仅分析已检测到的密码学区域(需锚点偏移) — 不做全二进制扫描。
  - 混淆代码的评分可信度降低 — 通过confidence字段传达。
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple

# 评分常数
# 各维度权重 — 基于密码学侧信道攻击的实证研究
# D1(内存访问)和D2(分支)的权重最高, 因缓存时序和分支预测是当前最实用的攻击向量
_W1 = 0.30   # Memory Access — Prime+Probe/Flush+Reload类攻击的首要观测通道
_W2 = 0.25   # Branch — 条件分支执行时间差; 对嵌入式设备权重应上调
_W3 = 0.15   # Instruction Mix — 功率分析次级特征; 对智能卡关键, 对服务器较弱
_W4 = 0.15   # Timing Variance — 粗粒度时序差; 远程攻击者可观测
_W5 = 0.15   # Cache Footprint — Spectre类投机执行攻击; 现代CPU的关键维度

# 简单ALU操作码 — 单周期或接近单周期, 无秘密依赖差异
# 周期参考: Agner Fog instruction tables, Intel Optimization Reference Manual
_SIMPLE_ALU = frozenset({0x31, 0x33, 0x35, 0x01, 0x03, 0x05, 0x29, 0x2B, 0x2D,
                          0x21, 0x23, 0x25, 0x09, 0x0B, 0x0D, 0x39, 0x3B, 0x3D,
                          0x85, 0x84, 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3})

# 分支操作码
_BRANCHES = frozenset({0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x7C,
                        0x7D, 0x7E, 0x7F, 0xEB, 0xE8, 0xE9, 0xC3, 0xC2, 0xE3})

# REX前缀集合
_REX = frozenset({0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                   0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F})

@dataclass
class LeakageReport:
    """五维侧信道泄漏潜力评分报告."""
    algorithm: str = ""
    file_path: str = ""
    anchor_offset: int = 0
    region_size: int = 0
    # 各维度 0-1 分值 (0=无泄漏潜力, 1=极高泄漏潜力)
    d1_memory_access: float = 0.0
    d2_branch: float = 0.0
    d3_instruction_mix: float = 0.0
    d4_timing_variance: float = 0.0
    d5_cache_footprint: float = 0.0
    # 加权复合评分
    composite_score: float = 0.0
    # 风险等级
    risk_level: str = "UNKNOWN"   # NEGLIGIBLE / LOW / MEDIUM / HIGH / CRITICAL
    # 评分可信度 — 受代码混淆/数据不足等影响
    confidence: float = 0.0
    # 各维度异常标记
    flags: List[str] = field(default_factory=list)

# 维度1: 内存访问模式熵
# 统计包含ModRM+SIB/displacement的指令比例作为秘密相关地址的代理。
# 高分→大量内存操作数的指令→缓存侧信道观测面大。

def _score_memory_access(data: bytes, start: int, size: int) -> Tuple[float, float]:
    """
    返回 (score, confidence)。
    统计[base+index*scale+disp]寻址的占比; 高占比→更多地址相关指令→更多泄漏面。
    """
    end = min(start + size, len(data))
    region = data[start:end]
    n = len(region)
    if n < 16:
        return 0.5, 0.2

    mem_ops = 0
    total_insns = 0
    i = 0
    while i < n:
        b = region[i]
        if b in _REX:
            i += 1
            if i >= n:
                break
            b = region[i]

        total_insns += 1
        # ModRM字节存在: 多数双操作数指令(0x00-0x3F, 0x80-0xBF范围)
        if (0x00 <= b <= 0x3F) or (0x80 <= b <= 0xBF):
            if i + 1 < n:
                modrm = region[i + 1]
                mod_field = (modrm >> 6) & 0x3
                rm_field = modrm & 0x7
                # mod!=3 → 内存操作数; mod=3 → 寄存器操作数
                if mod_field != 3:
                    mem_ops += 1
                # mod==0且rm==5 → RIP相对寻址 (x64典型全局变量访问)
                if mod_field == 0 and rm_field == 5:
                    mem_ops += 1  # 额外加权: 全局变量访问更可能承载秘密
                i += 2
                continue
        elif b in _BRANCHES:
            i += 1 if b in (0xEB, 0xC3) else (2 if b == 0xC2 else (5 if b == 0xE8 or b == 0xE9 else 2))
            continue
        i += 1

    if total_insns < 4:
        return 0.5, 0.2

    ratio = mem_ops / total_insns
    # 密码学实现中内存操作占比的典型范围: 0.15-0.35
    # ratio偏低(<0.1)→寄存器为主(好); 偏高(>0.4)→内存密集(差)
    if ratio < 0.10:
        score = 0.10  # 近乎纯寄存器—优秀
    elif ratio < 0.20:
        score = 0.25
    elif ratio < 0.30:
        score = 0.50
    elif ratio < 0.40:
        score = 0.75
    else:
        score = 0.90

    conf = min(0.95, 0.4 + total_insns / 200.0)
    return score, conf

# 维度2: 分支分布
# 条件分支是可观测时序差的最直接来源。

def _score_branch(data: bytes, start: int, size: int) -> Tuple[float, float]:
    """
    统计条件分支密度和分支间距方差。
    密集+规则→循环结构(轮函数固有, 可接受)
    稀疏+不规则→数据依赖分支(密钥/明文条件→危险)
    """
    end = min(start + size, len(data))
    region = data[start:end]
    n = len(region)
    if n < 16:
        return 0.5, 0.2

    branch_positions = []
    i = 0
    while i < n:
        b = region[i]
        if b in _REX:
            i += 1
            if i >= n:
                break
            b = region[i]
        if b in _BRANCHES:
            # 仅条件分支(Jcc)与秘密依赖相关; JMP/CALL/RET的数据依赖性弱得多
            if 0x70 <= b <= 0x7F:
                branch_positions.append(i)
        # 跳过操作数
        if (0x00 <= b <= 0x3F) or (0x80 <= b <= 0xBF):
            i += 2 if i + 1 < n else 1
        elif b in _BRANCHES:
            i += 1 if b in (0xEB, 0xC3) else (2 if b == 0xC2 else (5 if b in (0xE8, 0xE9) else 2))
        else:
            i += 1

    if len(branch_positions) < 2:
        # 条件分支太少→无分支泄漏面; 但也可能是代码被混淆
        return 0.05, 0.5

    # 分支密度
    branch_density = len(branch_positions) / n

    # 间距方差: 规则间距→循环; 不规则→数据依赖
    if len(branch_positions) >= 3:
        gaps = [branch_positions[j + 1] - branch_positions[j]
                for j in range(len(branch_positions) - 1)]
        mean_gap = sum(gaps) / len(gaps)
        gap_variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        cv = math.sqrt(gap_variance) / mean_gap if mean_gap > 0 else 0
    else:
        cv = 1.0  # 数据不足, 保守估计高方差

    # 分支密度高+间距规则→密码学轮函数(泄漏潜力低)
    # 分支密度低+间距不规则→数据依赖分支(泄漏潜力高)
    if branch_density > 0.03 and cv < 0.3:
        score = 0.15  # 规则轮函数
    elif branch_density > 0.03 and cv < 0.6:
        score = 0.40
    elif branch_density > 0.01:
        score = 0.65
    else:
        score = 0.85  # 稀疏不规则分支—可能的数据依赖

    conf = min(0.9, 0.3 + len(branch_positions) / 40.0)
    return score, conf

# 维度3: 指令混合偏斜
# 均匀的指令混合 → 功率特征平坦 → DPA困难。
# 偏斜的指令混合 → 操作特征可区分 → DPA可行。

def _score_instruction_mix(data: bytes, start: int, size: int) -> Tuple[float, float]:
    """统计指令类型分布的熵; 低熵→偏斜→功率特征可区分→高分(差)。"""
    end = min(start + size, len(data))
    region = data[start:end]
    n = len(region)
    if n < 32:
        return 0.5, 0.3

    type_counts = Counter()
    total = 0
    i = 0
    while i < n:
        b = region[i]
        if b in _REX:
            i += 1
            if i >= n:
                break
            b = region[i]

        total += 1
        if b in _SIMPLE_ALU:
            type_counts['alu'] += 1
        elif b in _BRANCHES:
            type_counts['branch'] += 1
        elif (0x00 <= b <= 0x3F) or (0x80 <= b <= 0xBF):
            type_counts['mem'] += 1
        elif b in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                   0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):
            type_counts['stack'] += 1
        else:
            type_counts['other'] += 1

        # 跳过操作数
        if (0x00 <= b <= 0x3F) or (0x80 <= b <= 0xBF):
            i += 2 if i + 1 < n else 1
        elif b in _BRANCHES:
            i += 1 if b in (0xEB, 0xC3) else (2 if b == 0xC2 else (5 if b in (0xE8, 0xE9) else 2))
        else:
            i += 1

    if total < 8:
        return 0.5, 0.2

    # 指令类型分布熵→归一化得分
    total_float = float(total)
    entropy = 0.0
    for count in type_counts.values():
        p = count / total_float
        if p > 0:
            entropy -= p * math.log2(p)

    max_entropy = math.log2(min(len(type_counts), 5))
    norm_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

    # 高熵→均匀→低泄漏; 低熵→偏斜→高泄漏
    score = 1.0 - norm_entropy
    conf = min(0.9, 0.3 + total / 100.0)
    return score, conf

# 维度4: 操作时序方差
# 保守的静态估计 — 指令延时差异的简单统计。

def _score_timing_variance(data: bytes, start: int, size: int) -> Tuple[float, float]:
    """统计区域内操作延时分布方差; 高方差→不同路径延时差异大→可观察。"""
    end = min(start + size, len(data))
    region = data[start:end]
    n = len(region)
    if n < 16:
        return 0.5, 0.2

    cycles = []
    i = 0
    while i < n:
        b = region[i]
        if b in _REX and i + 1 < n:
            i += 1
            b = region[i]

        if b in _SIMPLE_ALU:
            cycles.append(1)
        elif b in _BRANCHES:
            # 条件分支: 取2(可能命中), 无条件1; 估值取平均
            if 0x70 <= b <= 0x7F:
                cycles.append(2)
            elif b in (0xE8, 0xE9, 0xC3, 0xC2):
                cycles.append(3)
            else:
                cycles.append(1)
        elif b in (0xF6, 0xF7):
            cycles.append(5)
        elif b in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                   0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):
            cycles.append(1)
        else:
            cycles.append(2)
        i += 1

    if len(cycles) < 4:
        return 0.5, 0.2

    mean_c = sum(cycles) / len(cycles)
    if mean_c < 0.5:
        return 0.2, 0.5

    variance = sum((c - mean_c) ** 2 for c in cycles) / len(cycles)
    cv = math.sqrt(variance) / mean_c if mean_c > 0 else 0

    # 变异系数→得分: CV<0.3→低(好), CV>1.0→高(差)
    if cv < 0.3:
        score = 0.10
    elif cv < 0.5:
        score = 0.30
    elif cv < 0.8:
        score = 0.55
    elif cv < 1.2:
        score = 0.75
    else:
        score = 0.95

    conf = min(0.9, 0.3 + len(cycles) / 80.0)
    return score, conf

# 维度5: 缓存占用稳定性
# 基于缓存行对齐和访问密度的静态近似。

def _score_cache_footprint(data: bytes, start: int, size: int) -> Tuple[float, float]:
    """
    估计缓存行占用模式。
    若大量不同偏移的内存访问分布在对齐的缓存行内→占用模式随数据变化→可观察。
    缓存行 = 64字节 (x86/ARM通用)。
    """
    CACHE_LINE = 64
    end = min(start + size, len(data))
    region = data[start:end]
    n = len(region)
    if n < CACHE_LINE:
        return 0.5, 0.2

    # 取区域内每64字节块的熵分布 — 模拟缓存行内容变化
    cache_line_entropies = []
    for cl_start in range(0, n, CACHE_LINE):
        cl_data = region[cl_start:cl_start + CACHE_LINE]
        if len(cl_data) < 32:
            continue
        # 简化: 字节值分布熵作为缓存行内容的代理
        byte_counts = Counter(cl_data)
        ent = 0.0
        cl_len = float(len(cl_data))
        for cnt in byte_counts.values():
            p = cnt / cl_len
            ent -= p * math.log2(p)
        max_ent = math.log2(min(len(byte_counts), 256))
        cache_line_entropies.append(ent / max_ent if max_ent > 0 else 0.0)

    if len(cache_line_entropies) < 2:
        return 0.5, 0.3

    # 缓存行间熵方差: 稳定→低泄漏; 波动→数据依赖缓存占用
    mean_ent = sum(cache_line_entropies) / len(cache_line_entropies)
    variance = sum((e - mean_ent) ** 2 for e in cache_line_entropies) / len(cache_line_entropies)

    # 高方差→不同缓存行内容差异大→缓存占用与数据相关
    if variance < 0.005:
        score = 0.10   # 非常稳定→缓存占用与数据无关
    elif variance < 0.015:
        score = 0.35
    elif variance < 0.04:
        score = 0.60
    elif variance < 0.08:
        score = 0.80
    else:
        score = 0.95

    conf = min(0.85, 0.3 + len(cache_line_entropies) / 30.0)
    return score, conf

# 主评分函数

def score_leakage_potential(data: bytes, anchor_offset: int = 0,
                            region_size: int = 512,
                            algorithm: str = "",
                            file_path: str = "") -> LeakageReport:
    """
    对密码学区域进行五维侧信道泄漏潜力评分。
    返回LeakageReport — 复合评分0-1, 0=无泄漏潜力, 1=极高泄漏潜力。
    """
    start = max(0, anchor_offset)
    end = min(start + region_size, len(data))

    d1, c1 = _score_memory_access(data, start, region_size)
    d2, c2 = _score_branch(data, start, region_size)
    d3, c3 = _score_instruction_mix(data, start, region_size)
    d4, c4 = _score_timing_variance(data, start, region_size)
    d5, c5 = _score_cache_footprint(data, start, region_size)

    composite = (_W1 * d1 + _W2 * d2 + _W3 * d3 + _W4 * d4 + _W5 * d5)
    avg_confidence = (c1 + c2 + c3 + c4 + c5) / 5.0

    # 风险等级映射
    if composite < 0.20:
        risk = "NEGLIGIBLE"
    elif composite < 0.35:
        risk = "LOW"
    elif composite < 0.55:
        risk = "MEDIUM"
    elif composite < 0.75:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    # 异常标记
    flags = []
    if d1 > 0.7:
        flags.append("high_memory_access_complexity")
    if d2 > 0.7:
        flags.append("irregular_branch_pattern_data_dependent")
    if d3 > 0.7:
        flags.append("skewed_instruction_mix_dpa_concern")
    if d4 > 0.7:
        flags.append("high_timing_variance")
    if d5 > 0.7:
        flags.append("unstable_cache_footprint")
    if avg_confidence < 0.5:
        flags.append("low_confidence_insufficient_data_or_obfuscation")

    return LeakageReport(
        algorithm=algorithm,
        file_path=file_path,
        anchor_offset=anchor_offset,
        region_size=region_size,
        d1_memory_access=round(d1, 4),
        d2_branch=round(d2, 4),
        d3_instruction_mix=round(d3, 4),
        d4_timing_variance=round(d4, 4),
        d5_cache_footprint=round(d5, 4),
        composite_score=round(composite, 4),
        risk_level=risk,
        confidence=round(avg_confidence, 4),
        flags=flags,
    )

def compare_implementations(reports: List[LeakageReport]) -> List[Tuple[str, float]]:
    """对多个密码学实现的泄漏评分排序 — 返回(算法标识, 复合评分)按风险升序。"""
    labeled = [(r.algorithm or f"@{r.anchor_offset:#x}", r.composite_score)
               for r in reports]
    labeled.sort(key=lambda x: x[1])
    return labeled

def batch_score_from_findings(data: bytes,
                              findings: List,  # List[CryptoFinding]
                              region_size: int = 512) -> List[LeakageReport]:
    """
    对crypto_detector的检测结果批量评分。
    与crypto_semantic_hash的批量接口保持一致。
    """
    reports = []
    for f in findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            loc = getattr(f, 'location', 0)
            report = score_leakage_potential(data, anchor_offset=loc,
                                             region_size=region_size,
                                             algorithm=algo)
            reports.append(report)
        except Exception:
            continue
    return reports
