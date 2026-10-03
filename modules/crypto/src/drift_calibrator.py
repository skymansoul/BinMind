"""
密码学实现偏移校准器 — 检测已识别密码实现与已知参考基线的结构偏移。

设计意图:
  crypto_detector识别"这是AES", 但无法判断"这个AES实现与OpenSSL 3.2.1的标准编译
  产物有多接近"。在以下场景中, 结构偏移是关键信号:
    (a) 固件更新后, 密码实现是否被替换/回退/修改?
    (b) 供应商声称使用"标准OpenSSL", 但二进制中的AES是否与OpenSSL编译产物匹配?
    (c) 检测通过打补丁插入的后门 — 后门代码会改变指令比例和基本块分布。

  本模块提取检测到的密码区域的6维结构特征向量, 与参考基线库比对,
  输出偏移评分和分类(无偏移/编译偏移/轻度修改/重度修改/未知变种)。

  - Jang et al., "ReDeBug": 代码克隆检测的N-gram方法 —
    指令级N-gram频率向量在跨编译器场景下保持稳定, 本项目基于此思想建立指令混合比特征。
  - Pewny et al., "Cross-Architecture Bug Search":
    结构特征(基本块数/边数/调用数)跨编译器具有稳健性 → 落入"编译偏移"类。
  - David et al., "FirmUp": 固件漏洞检测中跨版本代码匹配的方法,
    本项目将版本偏移概念从漏洞匹配推广到完整性验证。
  - US10445502B2: 通过指令直方图检测恶意代码注入 — 单指令频率变化是注入信号。

边界条件:
  - 参考基线需预建(已知库版本→特征向量), 当前交付重建和比对框架, 基线数据按需填充。
  - 重度混淆/加壳的二进制中指令混合比会大幅偏离 → 自动归入"重度修改"。
  - 仅对已检测到密码常量的区域提取特征, 不扫描未分类区域。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 核心数据结构

@dataclass
class DriftProfile:
    """密码区域的6维结构特征向量."""
    algorithm: str = ""
    file_path: str = ""
    anchor_offset: int = 0
    region_size: int = 0           # 分析区域大小 (字节)
    # 6维特征向量
    xor_ratio: float = 0.0         # XOR指令占比
    mov_ratio: float = 0.0         # MOV/LEA指令占比
    branch_ratio: float = 0.0      # JMP/Jcc/CALL/RET占比
    shift_ratio: float = 0.0       # SHL/SHR/ROR/ROL占比
    bb_count: int = 0              # 基本块数 (以ret/jmp为界)
    const_offset: int = 0          # 常量表距区域起始的偏移

    def to_vector(self) -> Tuple[float, ...]:
        return (self.xor_ratio, self.mov_ratio, self.branch_ratio,
                self.shift_ratio, float(self.bb_count) / 100.0,
                float(self.const_offset) / 4096.0)

@dataclass
class DriftReport:
    """偏移分析报告."""
    profile: Optional[DriftProfile] = None
    best_match: str = ""           # 最接近的参考基线名称
    drift_score: float = 0.0       # 余弦距离, [0,2]; 0=完全相同
    classification: str = ""       # none/compiler_drift/minor_patch/major_mod/unknown
    anomaly_flags: List[str] = field(default_factory=list)

# 特征提取
# 统计区域内的指令分布。不去做完整反汇编 — 仅用单字节操作码前缀做粗略分类。
# 精确度足够区分编译器产出的特征差异; 无需Capstone依赖。

# x86操作码分类 (单字节, 粗略)
_OPCODE_CLASS = {
    'xor': frozenset({0x31, 0x33, 0x81, 0x83}),  # xor r,r; xor r,imm
    'mov': frozenset({0x88, 0x89, 0x8A, 0x8B, 0xB0, 0xB8, 0xC6, 0xC7,
                       0x48, 0x49}),  # mov (含REX前缀)
    'branch': frozenset({0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                          0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,  # Jcc short
                          0xE8, 0xE9, 0xEB, 0xFF, 0xC2, 0xC3, 0xCA, 0xCB}),  # CALL/JMP/RET
    'shift': frozenset({0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3}),  # SHL/SHR/ROL/ROR
}

def _classify_opcode(byte_val: int) -> Optional[str]:
    for cls_name, opcodes in _OPCODE_CLASS.items():
        if byte_val in opcodes:
            return cls_name
    return None

def extract_drift_profile(data: bytes, anchor: int,
                          algorithm: str = "",
                          region_radius: int = 1024,
                          table_known_offset: int = 0) -> DriftProfile:
    """从密码区域提取结构特征向量.

    table_known_offset: 若已知常量表相对锚点的偏移 (如S-box在anchor+0x100),
    则传入以辅助偏移计算; 0表示与锚点重合。
    """
    dl = len(data)
    start = max(0, anchor - region_radius)
    end = min(dl, anchor + region_radius)
    region = data[start:end]
    region_size = end - start

    if region_size < 64:
        return DriftProfile(algorithm=algorithm, anchor_offset=anchor)

    counts = {'xor': 0, 'mov': 0, 'branch': 0, 'shift': 0, 'other': 0}
    bb_count = 1  # 至少1个基本块

    for i, b in enumerate(region):
        cls = _classify_opcode(b)
        if cls:
            counts[cls] += 1
        else:
            counts['other'] += 1
        # 基本块边界: RET(0xC3) / JMP(0xE9,0xEB) 作为块结束标志
        if b in (0xC3, 0xCB, 0xE9, 0xEB):
            if i + 1 < region_size:
                bb_count += 1

    total = sum(counts.values()) or 1
    profile = DriftProfile(
        algorithm=algorithm,
        anchor_offset=anchor,
        region_size=region_size,
        xor_ratio=counts['xor'] / total,
        mov_ratio=counts['mov'] / total,
        branch_ratio=counts['branch'] / total,
        shift_ratio=counts['shift'] / total,
        bb_count=bb_count,
        const_offset=table_known_offset,
    )
    return profile

# 基线库
# 键: "算法/库/版本" 描述字符串
# 值: DriftProfile预计算向量

_REFERENCE_BASELINES: Dict[str, DriftProfile] = {}

def register_baseline(name: str, profile: DriftProfile) -> None:
    """注册一个已知参考基线."""
    _REFERENCE_BASELINES[name] = profile

def list_baselines() -> List[str]:
    return list(_REFERENCE_BASELINES.keys())

# 偏移计算

def _cosine_similarity(v1: Tuple[float, ...],
                       v2: Tuple[float, ...]) -> float:
    """两特征向量的余弦相似度 — 不受向量长度影响, 仅比较方向."""
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 < 1e-9 or norm2 < 1e-9:
        return 0.0
    return dot / (norm1 * norm2)

def calibrate(profile: DriftProfile) -> DriftReport:
    """将目标DriftProfile与所有参考基线比对, 返回分类报告."""
    v_target = profile.to_vector()
    report = DriftReport(profile=profile)

    if not _REFERENCE_BASELINES:
        report.best_match = "no baselines registered"
        report.drift_score = 1.0
        report.classification = "unknown"
        return report

    best_name = ""
    best_sim = -1.0
    for name, bp in _REFERENCE_BASELINES.items():
        if bp.algorithm and profile.algorithm and bp.algorithm != profile.algorithm:
            continue  # 算法不匹配 → 跳过
        sim = _cosine_similarity(v_target, bp.to_vector())
        if sim > best_sim:
            best_sim = sim
            best_name = name

    report.best_match = best_name
    drift = 1.0 - best_sim   # 余弦距离: 0(同向) ~ 2(反向)
    report.drift_score = round(drift, 4)

    # 分类 [
    if drift <= 0.03:
        report.classification = "none"          # 几乎无偏移 — 同一编译产物
    elif drift <= 0.10:
        report.classification = "compiler_drift" # 同源码不同编译器/标志
    elif drift <= 0.25:
        report.classification = "minor_patch"    # 补丁级修改
    elif drift <= 0.50:
        report.classification = "major_mod"      # 大幅修改或不同实现
    else:
        report.classification = "unknown"        # 与所有基线均不匹配

    # 异常标志
    if profile.xor_ratio < 0.05 and profile.algorithm.startswith('AES'):
        report.anomaly_flags.append(
            f"XOR ratio={profile.xor_ratio:.3f} 过低 — AES MixColumns/XOR链缺失")
    if profile.branch_ratio > 0.30:
        report.anomaly_flags.append(
            f"分支比例={profile.branch_ratio:.3f} 过高 — 可能存在非标准控制流(注入/混淆)")
    if profile.bb_count > 50 and profile.region_size < 2048:
        report.anomaly_flags.append(
            f"基本块密度异常: {profile.bb_count}BB in {profile.region_size}B — "
            "可能的代码注入或JIT痕迹")

    return report

__all__ = [
    'DriftProfile', 'DriftReport',
    'extract_drift_profile', 'calibrate',
    'register_baseline', 'list_baselines',
]
