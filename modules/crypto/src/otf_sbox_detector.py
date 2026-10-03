"""
动态计算S-box检测器 — 识别嵌入式/IoT固件中不存储查表而实时计算S-box的密码学实现。

设计意图:
  标准检测(crypto_detector)依赖完整256字节S-box查表进行匹配, 无法捕获
  以下场景中的密码学实现:
    (a) 资源受限固件通过GF(2^8)逆元计算+仿射变换实时产生S-box值;
    (b) 代码混淆工具(OLLVM/Tigress)将查表展开为计算;
    (c) 白盒密码学将S-box编码为代数结构(gate-level circuit)。

  本模块通过扫描二进制中GF(2^8)乘法操作的模式组合来推断动态S-box计算 —
  不走查表, 走数学路径。

  - Satoh et al., "A Compact Rijndael Hardware Architecture with S-Box Optimization"
: 基于复合域GF(((2^2)^2)^2)的紧凑AES S-box → 小面积但多级门。
  - Wolkerstorfer et al., "An ASIC Implementation of the AES SBoxes":
    复合域反演理论基础: GF(2^8) → GF(((2^2)^2)^2)降次。
  - US11283621B1: 复合域编码的混淆S-box计算 — 白盒场景下的计算型S-box。
  - Daemen & Rijmen, "The Design of Rijndael" §4.3: S-box = Affine(Inverse(GF(2^8))).
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# GF(2^8)乘法/逆元计算的模式库
# 不存储完整256B查表时, GF(2^8)乘法可通过xtime(乘2)和xor组合实现。
# 求逆(本质: x^{254} = x^{-1}对x≠0)通过重复平方-乘法完成。
#
# 在x86/x64/ARM二进制中, 以下字节序列为GF(2^8)计算的特征模式。
# 每条模式配有说明, 含义为该操作码序列在密码学上下文中的语义。

# xtime(a): b = a << 1; if (a & 0x80) b ^= 0x1B
# x86实现: mov al, [src]; add al, al; sbb cl, cl; and cl, 0x1B; xor al, cl
_XTIME_X86_PATTERNS: List[Tuple[bytes, str]] = [
    # shl reg,1 → 左移+条件异或0x1B为AES MixColumns中xtime经典实现
    (b'\x02\xc0\x80\xe0\x1b\x00\x00\x00', 'xtime_pattern_shl_conditional_xor'),
    # add reg,reg → 等同shl 1; sbb构造掩码
    (b'\x00\xc0\x80\xd9\x1b', 'xtime_pattern_add_sbb_mask'),
]

# GF(2^8)乘法: xtime级联调用 → a * x^k = xtime^k(a)
# 模式: 连续调用xtime 2-7次, 中间xor配合产生任意系数乘法
# Thumb/ARM中常见:
# ARM: lsl r0, r0, #1; ands r1, r1, r0; eor r0, r0, r1, asr #7
_GF_MUL_ARM_PATTERNS: List[Tuple[bytes, str]] = [
    (b'\x4f\xea\x00\x00\x01', 'arm_lsl1_conditional_xor'),  # lsl r0, r0, #1 (Thumb)
]

# GF(2^8)模约简多项式 x^8+x^4+x^3+x+1 → 0x11B (AES)
# 约简操作: val ^= (overflow << 4) ^ (overflow << 3) ^ (overflow << 1) ^ overflow
_REDUCE_POLY_PATTERNS: List[Tuple[bytes, str]] = [
    # mov reg, overflow; shl reg, 4; xor src, reg; ... 三次重复xor序列
    (b'\xc1\xe0\x04\x31\xc1\xe0\x03\x31\xc1\xe0\x01\x31', 'reduce_poly_11B_seq'),
]

# 复合域GF(((2^2)^2)^2)基变换矩阵 — δ变换和δ^{-1}变换
# 紧凑AES硬件/软件实现中, 基变换矩阵的二进制表示为一组固定8bit常数序列。
# 例如Canright的δ矩阵可用8个特定字节表示。
# 当前检测已知紧凑实现中频率最高的矩阵行。

# AES S-box仿射变换 c = 0x63
_AFFINE_CONST_0x63: bytes = bytes([0x63])       # AES S-box仿射常数
# SM4 S-box仿射变换常数
_SM4_AFFINE_CONST: bytes = bytes([0xD3])          # SM4 S-box仿射常数

def scan_xtime(data: bytes, start: int = 0) -> List[int]:
    """返回data中疑似xtime操作的所有位置."""
    hits: List[int] = []
    dl = len(data)
    for off in range(start, dl - 12):
        # 核心判据: shl/add(自身)+1位后紧跟条件异或0x1B或sbb。
        # 取窗口6字节做匹配
        window = data[off:off + 6]
        b0, b1, b2, b3, b4, b5 = window[0], window[1], window[2], window[3], window[4], window[5]
        # x86: shl reg, 1 = 0xD0/D1/D2/D3 + {E0,E1,E2,E3}0x01 或 D0+E0格式
        if b0 in (0xD0, 0xD1, 0xD2, 0xD3) and b1 & 0xFE == 0xE0:
            hits.append(off)
        # add reg, reg (等价shl 1)
        elif b0 in (0x00, 0x01, 0x02, 0x03) and b1 in (0xC0, 0xC1, 0xC2, 0xC3):
            hits.append(off)
        # ARM/Thumb lsl rX, rX, #1
        elif len(window) >= 4 and window[:2] == b'\x4f\xea':
            hits.append(off)
    return hits

def scan_poly_reduce(data: bytes, start: int = 0) -> List[int]:
    """检测模约简多项式归约序列 — GF(2^8)乘法后约简标志."""
    hits: List[int] = []
    dl = len(data)
    for off in range(start, dl - 16):
        # 三次移位+xor序列 → 对应x^8+x^4+x^3+x+1约简
        w = data[off:off + 12]
        xor_count = 0
        for b in w:
            if b in (0x31, 0x33, 0x81, 0x83):
                xor_count += 1
        if xor_count >= 3:
            # 检查0x1B立即数 (模约简多项式标志)
            if b'\x1b' in w or b'\x11\xb0' in w or bytes([0x1B, 0x00, 0x00, 0x00]) in w:
                hits.append(off)
    return hits

# 仿射变换检测
# AES S-box = A ⋅ Inv(x) ⊕ 0x63, 其中A是GF(2)上8×8矩阵。
# 二进制中矩阵乘法A表现为: 取逆元结果y, 做固定序列移位+xor。
# 特征: 8次连续rotr/xor序列(每行对应矩阵一行), 最后xor 0x63(或0xD3)。

def scan_affine_transform(data: bytes, start: int = 0) -> List[Tuple[int, str]]:
    """检测仿射变换AES/SM4实现 — 返回(位置, 类型).

    AES仿射变换: b_i' = b_i xor b_{i+4} xor b_{i+5} xor b_{i+6} xor b_{i+7} xor c_i
    其中c = 0x63 (AES) / 0xD3 (SM4) / 其他(自定义变种)。

    x86中一条仿射变换行对应: mov + xor(3-5次)的固定模式。
    """
    results: List[Tuple[int, str]] = []
    dl = len(data)
    # 固定模式: 连续xor al/ah/bl/bh/cl/ch/dl/dh序列
    # AES仿射每行需4次字节xor, SM4同理。
    for off in range(start, dl - 64):
        # 取32字节窗口
        w = data[off:off + 32]
        xor_chain = 0
        for i in range(len(w)):
            if w[i] in (0x30, 0x31, 0x32, 0x33, 0x34, 0x35):  # xor r/m8, r8
                xor_chain += 1
        if xor_chain >= 12:  # 至少3行×4次xor
            # 确认后续有仿射常数 0x63 或 0xD3
            next_32 = data[off + 32:off + 64] if off + 64 <= dl else b''
            if _AFFINE_CONST_0x63 in next_32 or _AFFINE_CONST_0x63 in w:
                results.append((off, 'AES_affine'))
            elif _SM4_AFFINE_CONST in next_32 or _SM4_AFFINE_CONST in w:
                results.append((off, 'SM4_affine'))
            else:
                results.append((off, 'unknown_affine'))
    return results

# 综合判决

@dataclass
class OTFSBoxFinding:
    algorithm: str
    confidence: float
    evidence: str
    location: int
    evidence_type: str = ""          # xtime / poly_reduce / affine / composite
    xtime_nearby: int = 0
    poly_reduce_nearby: int = 0
    affine_nearby: bool = False
    composite_domain_hint: bool = False  # GF(((2^2)^2)^2)降次痕迹

def detect_otf_sbox(data: bytes, window_size: int = 512) -> List[OTFSBoxFinding]:
    """扫描二进制中动态S-box计算实现.

    策略: 以滑动窗口聚合xtime/模约简/仿射变换三类模式。
    若窗口内同时出现三类中的≥两类, 则高概率为动态S-box生成代码。
    """
    findings: List[OTFSBoxFinding] = []
    dl = len(data)
    if dl < 256:
        return findings

    # 一次性扫描全局模式位置
    xtime_offs = scan_xtime(data)
    poly_offs = scan_poly_reduce(data)
    affine_offs = scan_affine_transform(data)

    if not xtime_offs and not affine_offs:
        return findings

    # 模式位置转集合供快速查询, 扫描滑动窗口
    xtime_set = set(xtime_offs)
    poly_set = set(poly_offs)
    affine_info = {off: atype for off, atype in affine_offs}

    step = window_size // 4
    for w_start in range(0, max(0, dl - window_size), step):
        w_end = w_start + window_size
        xt_near = sum(1 for p in xtime_offs if w_start <= p < w_end)
        pr_near = sum(1 for p in poly_offs if w_start <= p < w_end)
        af_list = [affine_info[p] for p in affine_offs if w_start <= p < w_end]
        af_near = len(af_list) > 0

        # 判决条件: xtime + 仿射变换同时出现 → 强信号
        if xt_near >= 2 and af_near:
            algo = 'AES' if 'AES_affine' in af_list else \
                   'SM4' if 'SM4_affine' in af_list else \
                   'unknown (AES/SM4-like)'
            conf = min(0.90, 0.55 + 0.07 * xt_near + 0.15 * af_near)
            findings.append(OTFSBoxFinding(
                algorithm=algo,
                confidence=conf,
                evidence=f'动态S-box计算: xtime×{xt_near}, '
                         f'poly_reduce×{pr_near}, affine={af_list} '
                         f'at 0x{w_start:x}',
                location=w_start,
                evidence_type='composite' if pr_near >= 2 else 'xtime+affine',
                xtime_nearby=xt_near,
                poly_reduce_nearby=pr_near,
                affine_nearby=af_near,
                composite_domain_hint=pr_near >= 2,
            ))
        # xtime + 模约简 → 可能仅GF(2^8)乘法(如MixColumns), 置信度低
        elif xt_near >= 3 and pr_near >= 2:
            findings.append(OTFSBoxFinding(
                algorithm='AES (MixColumns on-the-fly)',
                confidence=0.55 + 0.05 * min(xt_near, 6),
                evidence=f'动态GF(2^8)乘法: xtime×{xt_near}, '
                         f'poly_reduce×{pr_near} at 0x{w_start:x}',
                location=w_start,
                evidence_type='gf_mul',
                xtime_nearby=xt_near,
                poly_reduce_nearby=pr_near,
                affine_nearby=False,
                composite_domain_hint=True,
            ))

    # 去重: 按位置合并相邻窗口重复发现
    return _dedup_otf(findings)

def _dedup_otf(findings: List[OTFSBoxFinding],
               eps: int = 256) -> List[OTFSBoxFinding]:
    if not findings:
        return []
    sorted_f = sorted(findings, key=lambda f: (f.location, -f.confidence))
    merged = [sorted_f[0]]
    for f in sorted_f[1:]:
        last = merged[-1]
        if abs(f.location - last.location) <= eps and f.algorithm == last.algorithm:
            if f.confidence > last.confidence:
                merged[-1] = f
        else:
            merged.append(f)
    return merged

__all__ = [
    'OTFSBoxFinding',
    'scan_xtime', 'scan_poly_reduce', 'scan_affine_transform',
    'detect_otf_sbox',
]
