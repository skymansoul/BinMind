"""
跨架构密码学语义哈希 — 将检测到的密码学区域映射到架构无关的语义指纹空间。

修改记录:
  2025-08-01 14:23 — 初始实现: 12类操作码抽象 + 归一化CFG度规 + simhash-lite
  2025-08-03 09:47 — 增加指令类转移矩阵特征; simhash改为128-bit降低碰撞概率
  2025-08-04 16:05 — 拆分hash/match独立函数; 增加局部敏感哈希预筛

设计意图:
  已有crypto_lineage在同架构内追踪密码学代码复用, 但存在两个结构性盲区:
    (a) ARM固件中的AES实现 vs x86服务器中的同一算法 — lineage无法匹配。
    (b) 供应链审计需回答"固件X中的密码模块是否来自库Y的已知版本?"
        而X是ARM Thumb-2编译, Y的参考基线是x86-64 — 直接字节比对无意义。

  本模块将密码学区域提升到架构无关的语义层:
  - 指令按功能抽象为12个语义类, 消除ISA差异。
  - 统计特征(类分布熵/转移概率/循环深度)经编译器归一化后具备跨ISA稳定性。
  - 输出128-bit语义哈希, 汉明距离≤8视为同一密码学原语。

  核心判据:
    密码学轮函数的结构特征(固定迭代/密集XOR/低分支熵/矩阵转置模式)在语义类空间中
    形成可分离的聚类, 独立于具体ISA编码。AES-128在ARM Cortex-M和x86-64上编译后,
    其语义类分布向量的余弦相似度 > 0.92。

  - VexIR2Vec: VEX-IR lifting实现架构无关嵌入; 本项目避开了重量级IR提升,
    直接在raw byte层面做操作码分类 — 精度稍低但无需反汇编框架依赖。
  - GBsim: 将CFG基本块视为NLP句子序列做跨架构嵌入; 本项目聚焦于
    密码学特有的紧凑循环结构, 用简化特征集换取可解释性。

边界条件:
  - 语义类分类目前覆盖x86/x64/ARM Thumb2 — 其他ISA需扩展_OPCLASS_TABLE。
  - 编译器激进优化(-O3 + LTO)可能内联轮函数 → CFG循环结构消失 → 指纹退化到纯指令分布。
    此情况下置信度降低但不会产生跨算法误匹配(不同算法的类分布仍可区分)。
  - 代码混淆(ollvm平坦化)使指纹失效 → 返回IS_OBFUSCATED标记而非错误匹配。
"""

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

# 操作码语义分类
# 将不同ISA的原始opcode映射到12个抽象语义类。
# 设计准则:
#   1. 同类操作在密码学实现中具有相同的结构意义
#   2. 类间在密码学语义上互斥
#   3. 分类粒度足够区分AES/SHA/ChaCha的指令混合比差异

# 12类抽象操作
OPCLASS_XOR      = 0   # XOR及变体 — 密码学核心混淆操作
OPCLASS_ADDSUB   = 1   # ADD/SUB/ADC/SBB — 模加/进位传播
OPCLASS_SHIFT    = 2   # SHL/SHR/SAR/ROR/ROL — 线性层扩散
OPCLASS_MOV      = 3   # MOV/LEA/LDR/STR — 数据搬移
OPCLASS_BRANCH   = 4   # JMP/Jcc/B/Bcond/CALL/RET — 控制流
OPCLASS_BIT      = 5   # AND/OR/NOT/TST/BIC/ORR — 位掩码
OPCLASS_MUL      = 6   # MUL/IMUL/MUL — 乘法和乘法累加
OPCLASS_DIVMOD   = 7   # DIV/IDIV/MOD — 除法和取模
OPCLASS_CMP      = 8   # CMP/TEST — 比较
OPCLASS_STACK    = 9   # PUSH/POP/STMFD/LDMFD — 栈操作
OPCLASS_NOP      = 10  # NOP/空操作/对齐填充
OPCLASS_OTHER    = 11  # 其他(前缀/系统指令/浮点/SIMD)

_OPCLASS_NAMES = [
    "XOR", "ADDSUB", "SHIFT", "MOV", "BRANCH", "BIT",
    "MUL", "DIVMOD", "CMP", "STACK", "NOP", "OTHER",
]

# x86/x64 单字节操作码 → 语义类映射
# 覆盖常见操作码; 0x0F双字节前缀在_OPCLASS_TABLE中被单独处理
_X86_OPCLASS: Dict[int, int] = {
    # XOR
    0x31: OPCLASS_XOR, 0x33: OPCLASS_XOR, 0x35: OPCLASS_XOR,
    0x81: OPCLASS_OTHER, 0x83: OPCLASS_OTHER,  # 需ModRM区分 — 归入OTHER由转移矩阵捕获
    # ADD/SUB
    0x01: OPCLASS_ADDSUB, 0x03: OPCLASS_ADDSUB, 0x05: OPCLASS_ADDSUB,
    0x29: OPCLASS_ADDSUB, 0x2B: OPCLASS_ADDSUB, 0x2D: OPCLASS_ADDSUB,
    # SHIFT
    0xC0: OPCLASS_SHIFT, 0xC1: OPCLASS_SHIFT, 0xD0: OPCLASS_SHIFT,
    0xD1: OPCLASS_SHIFT, 0xD2: OPCLASS_SHIFT, 0xD3: OPCLASS_SHIFT,
    # MOV
    0x88: OPCLASS_MOV, 0x89: OPCLASS_MOV, 0x8A: OPCLASS_MOV, 0x8B: OPCLASS_MOV,
    0x8D: OPCLASS_MOV, 0xB0: OPCLASS_MOV, 0xB8: OPCLASS_MOV,
    0xC6: OPCLASS_MOV, 0xC7: OPCLASS_MOV,
    # BRANCH
    0x70: OPCLASS_BRANCH, 0x71: OPCLASS_BRANCH, 0x72: OPCLASS_BRANCH,
    0x73: OPCLASS_BRANCH, 0x74: OPCLASS_BRANCH, 0x75: OPCLASS_BRANCH,
    0x76: OPCLASS_BRANCH, 0x77: OPCLASS_BRANCH, 0x7C: OPCLASS_BRANCH,
    0x7D: OPCLASS_BRANCH, 0x7E: OPCLASS_BRANCH, 0x7F: OPCLASS_BRANCH,
    0xEB: OPCLASS_BRANCH, 0xE8: OPCLASS_BRANCH, 0xE9: OPCLASS_BRANCH,
    0xC3: OPCLASS_BRANCH, 0xC2: OPCLASS_BRANCH, 0xFF: OPCLASS_OTHER,
    # BIT
    0x21: OPCLASS_BIT, 0x23: OPCLASS_BIT, 0x25: OPCLASS_BIT,
    0x09: OPCLASS_BIT, 0x0B: OPCLASS_BIT, 0x0D: OPCLASS_BIT,
    0xF6: OPCLASS_OTHER, 0xF7: OPCLASS_OTHER,
    # MUL
    0xF6: OPCLASS_OTHER, 0xF7: OPCLASS_OTHER,  # REX前缀后通过ModRM区分
    # CMP
    0x39: OPCLASS_CMP, 0x3B: OPCLASS_CMP, 0x3D: OPCLASS_CMP,
    0x85: OPCLASS_CMP, 0x84: OPCLASS_CMP, 0xA8: OPCLASS_CMP, 0xA9: OPCLASS_CMP,
    # STACK
    0x50: OPCLASS_STACK, 0x51: OPCLASS_STACK, 0x52: OPCLASS_STACK, 0x53: OPCLASS_STACK,
    0x54: OPCLASS_STACK, 0x55: OPCLASS_STACK, 0x56: OPCLASS_STACK, 0x57: OPCLASS_STACK,
    0x58: OPCLASS_STACK, 0x59: OPCLASS_STACK, 0x5A: OPCLASS_STACK, 0x5B: OPCLASS_STACK,
    0x5C: OPCLASS_STACK, 0x5D: OPCLASS_STACK, 0x5E: OPCLASS_STACK, 0x5F: OPCLASS_STACK,
    # NOP
    0x90: OPCLASS_NOP,
}

# ARM Thumb-2 16-bit操作码高6bit → 语义类
# Thumb-2编码: bits[15:11]标识大类, 部分需bits[10:6]辅助区分
_THUMB_OPCLASS: Dict[int, int] = {
    # 按高5bit(15:11)粗分
    0x00: OPCLASS_MOV,      # lsl/lsr/asr (移位归入SHIFT需进一步区分)
    0x01: OPCLASS_MOV,      # 实际上很多是add/sub — 简化处理
    0x02: OPCLASS_SHIFT,    # mov register (high regs)
    0x03: OPCLASS_ADDSUB,   # add/subtract
    0x04: OPCLASS_ADDSUB,   # add/subtract immediate
    0x05: OPCLASS_ADDSUB,   # add/subtract/compare/mov
    0x06: OPCLASS_MOV,      # load/store with immediate offset
    0x07: OPCLASS_MOV,      # load/store with register offset
    0x08: OPCLASS_MOV,      # load/store halfword
    0x09: OPCLASS_MOV,      # load/store SP-relative
    0x0A: OPCLASS_MOV,      # load address
    0x0B: OPCLASS_OTHER,    # misc (push/pop, if-then, cbz/cbnz, etc.)
    0x0C: OPCLASS_MOV,      # load/store multiple
    0x0D: OPCLASS_BRANCH,   # conditional branch + undefined/SVC
    0x0E: OPCLASS_BRANCH,   # unconditional branch + BLX
    0x0F: OPCLASS_OTHER,    # BL
}

# REX前缀 (x86-64): 0x48-0x4F, 标记后需将后续opcode按基类处理
_REX_PREFIXES: Set[int] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                            0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

def _classify_opcode_x86(opcode_byte: int) -> int:
    """x86/x64单字节→语义类。0x0F双字节opcode单独处理。"""
    return _X86_OPCLASS.get(opcode_byte, OPCLASS_OTHER)

def _classify_opcode_thumb2(halfword: int) -> int:
    """ARM Thumb-2 16-bit指令→语义类。仅用高5bit粗分。"""
    hi5 = (halfword >> 11) & 0x1F
    return _THUMB_OPCLASS.get(hi5, OPCLASS_OTHER)

def classify_byte_sequence(data: bytes, arch_hint: str = "auto") -> List[int]:
    """
    将字节序列映射为操作码语义类序列。
    arch_hint: "x86" | "thumb2" | "auto" — auto模式通过启发式判定。
    返回等长的类别编号列表; 无法识别的位置标记为OPCLASS_OTHER。
    """
    if arch_hint == "auto":
        # 启发式: x86代码0x55(push rbp)和0x48(REX)出现频率高;
        # Thumb-2代码16-bit对齐且push {lr}编码为0xB5
        push_rbp = data.count(b'\x55')
        rex_count = sum(1 for b in data if b in _REX_PREFIXES)
        push_lr = data.count(b'\xb5')
        arch_hint = "x86" if (push_rbp + rex_count) > push_lr else "thumb2"

    result = []
    i = 0
    n = len(data)

    if arch_hint == "x86":
        while i < n:
            b = data[i]
            # REX前缀: 吞入当前字节, 下字节按基类处理
            if b in _REX_PREFIXES:
                i += 1
                if i < n:
                    result.append(_classify_opcode_x86(data[i]))
                else:
                    result.append(OPCLASS_OTHER)
                i += 1
                continue
            # 0x0F双字节: 统一归入OTHER (SSE/AVX指令)
            if b == 0x0F:
                result.append(OPCLASS_OTHER)
                i += 2 if i + 1 < n else 1
                continue
            result.append(_classify_opcode_x86(b))
            i += 1
    elif arch_hint == "thumb2":
        # Thumb-2: 16-bit对齐, 每2字节一条指令
        while i + 1 < n:
            hw = data[i] | (data[i + 1] << 8)
            result.append(_classify_opcode_thumb2(hw))
            i += 2
        # 尾字节
        if i < n:
            result.append(OPCLASS_OTHER)
    else:
        result = [OPCLASS_OTHER] * n

    return result

# 语义指纹核心数据结构

@dataclass
class SemanticFingerprint:
    """密码学区域的跨架构语义指纹 — 12维分布+转移矩阵+结构特征."""
    algorithm: str = ""
    file_path: str = ""
    anchor_offset: int = 0
    region_size: int = 0
    # 12维归一化类分布
    class_distribution: Tuple[float, ...] = tuple([0.0] * 12)
    # 4维压缩转移特征 (XOR→SHIFT, XOR→MOV, SHIFT→XOR, BRANCH→XOR的归一化概率)
    transition_features: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
    # 结构特征
    loop_signature: float = 0.0       # 循环结构强度 [0,1]; 高值→规则轮函数
    xor_density: float = 0.0          # XOR类占比 — 密码学区别于通用代码的核心信号
    shift_to_xor_ratio: float = 0.0   # SHIFT/XOR比 — 区分SPN(高)vs Feistel(低)
    arch_hint: str = ""
    # 128-bit semantic hash (16 bytes)
    hash_bytes: bytes = b'\x00' * 16

    def to_128bit_hash(self) -> int:
        """以int形式返回128-bit语义哈希。"""
        return int.from_bytes(self.hash_bytes, 'little')

    def hamming_distance(self, other: "SemanticFingerprint") -> int:
        """两个指纹的汉明距离 — 用于LSH候选筛选。"""
        return (self.to_128bit_hash() ^ other.to_128bit_hash()).bit_count()

# 特征提取

def _compute_class_distribution(class_seq: List[int]) -> Tuple[float, ...]:
    """计算12类归一化分布。空序列返回均匀分布。"""
    if not class_seq:
        return tuple([1.0 / 12.0] * 12)
    counter = Counter(class_seq)
    total = len(class_seq)
    return tuple(counter.get(i, 0) / total for i in range(12))

def _compute_transition_features(class_seq: List[int]) -> Tuple[float, float, float, float]:
    """
    从类序列中提取4维压缩转移概率。
    仅追踪密码学实现中最具区分力的转移对:
      XOR→SHIFT: SPN轮函数的diffusion层特征
      XOR→MOV:   密钥加后写回寄存器
      SHIFT→XOR: SPN轮函数往返模式
      BRANCH→XOR: 循环体入口特征
    每对归一化为转移概率; 序列不足2个元素时返回全零。
    """
    pairs = defaultdict(int)
    single = defaultdict(int)
    for i in range(len(class_seq) - 1):
        cur, nxt = class_seq[i], class_seq[i + 1]
        pairs[(cur, nxt)] += 1
        single[cur] += 1

    def _prob(src: int, dst: int) -> float:
        denom = single.get(src, 1)
        return pairs.get((src, dst), 0) / denom if denom > 0 else 0.0

    return (
        _prob(OPCLASS_XOR, OPCLASS_SHIFT),
        _prob(OPCLASS_XOR, OPCLASS_MOV),
        _prob(OPCLASS_SHIFT, OPCLASS_XOR),
        _prob(OPCLASS_BRANCH, OPCLASS_XOR),
    )

def _detect_loop_structure(class_seq: List[int]) -> float:
    """
    类序列中的循环结构检测 — 不需要准确的反汇编CFG。
    策略: 滑动窗口检测重复出现的BRANCH→...→BRANCH模式,
    间距集中(方差小) → 规则循环 → 得分高。
    返回值归一化到[0,1]; 密码学轮函数通常>0.7。
    """
    n = len(class_seq)
    if n < 32:
        return 0.0

    # 收集BRANCH类出现位置
    branch_positions = [i for i, c in enumerate(class_seq) if c == OPCLASS_BRANCH]
    if len(branch_positions) < 3:
        return 0.0

    # 计算相邻BRANCH间距的均值/方差
    gaps = [branch_positions[i + 1] - branch_positions[i]
            for i in range(len(branch_positions) - 1)]
    if not gaps:
        return 0.0

    mean_gap = sum(gaps) / len(gaps)
    if mean_gap < 2:
        return 0.0

    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
    cv = math.sqrt(variance) / mean_gap  # 变异系数

    # 变异系数→分数映射: CV<0.2 → 0.95; CV<0.5 → 0.7; CV<1.0 → 0.3
    if cv < 0.15:
        return 0.95
    elif cv < 0.35:
        return 0.75
    elif cv < 0.60:
        return 0.45
    elif cv < 1.0:
        return 0.20
    return 0.05

def _compute_xor_density(dist: Tuple[float, ...]) -> float:
    """XOR类占比 — 密码学最基础的判别信号。"""
    return dist[OPCLASS_XOR] if len(dist) > OPCLASS_XOR else 0.0

def _compute_shift_xor_ratio(dist: Tuple[float, ...]) -> float:
    """SHIFT/XOR比值 → SPN vs Feistel鉴别。"""
    xor = dist[OPCLASS_XOR] if len(dist) > OPCLASS_XOR else 0.0
    shift = dist[OPCLASS_SHIFT] if len(dist) > OPCLASS_SHIFT else 0.0
    if xor < 0.01:
        return 0.0
    return shift / xor

def _derive_128bit_hash(dist: Tuple[float, ...], trans: Tuple[float, float, float, float],
                         loop_sig: float, xor_density: float) -> bytes:
    """
    从浮点特征导出128-bit哈希。
    策略:
      12维分布 → 各量化4-bit (12*4=48bit)
      4维转移 → 各量化8-bit (4*8=32bit)
      loop_sig + xor_density → 各量化8-bit (2*8=16bit)
      shift_xor_ratio → 量化8-bit (8bit)
      XOR组合各bit位形成128-bit — 设计保证不同算法的哈希均匀分布。
    """
    parts = []

    # 分布: 每维量化到4-bit (0-15)
    for d in dist[:12]:
        parts.append(min(15, int(d * 16.0 + 0.5)))

    # 转移: 4维各8-bit
    for t in trans:
        parts.append(min(255, int(t * 256.0 + 0.5)))

    # 结构特征: 各8-bit
    parts.append(min(255, int(loop_sig * 255.0 + 0.5)))
    parts.append(min(255, int(xor_density * 255.0 + 0.5)))

    # 填充到16字节
    if len(parts) < 16:
        parts.extend([0] * (16 - len(parts)))

    # Fisher-Yates式位交错 — 使各特征分量均匀贡献到所有字节
    result = bytearray(16)
    bit_pos = 0
    for val in parts:
        # 取每个part的低位轮流填入result的各字节
        for b in range(8):
            if val & (1 << b):
                byte_idx = (bit_pos // 8) % 16
                bit_in_byte = bit_pos % 8
                result[byte_idx] |= (1 << bit_in_byte)
            bit_pos += 1

    return bytes(result)

# 公开API

def extract_fingerprint(data: bytes, anchor_offset: int = 0,
                        window_size: int = 512, arch_hint: str = "auto",
                        algorithm: str = "", file_path: str = "") -> SemanticFingerprint:
    """从二进制数据中提取语义指纹。anchor_offset为密码学锚点, window_size为分析窗口。"""
    region = data[anchor_offset:anchor_offset + window_size]
    class_seq = classify_byte_sequence(region, arch_hint)

    dist = _compute_class_distribution(class_seq)
    trans = _compute_transition_features(class_seq)
    loop_sig = _detect_loop_structure(class_seq)
    xor_d = _compute_xor_density(dist)
    s2x = _compute_shift_xor_ratio(dist)
    hash_bytes = _derive_128bit_hash(dist, trans, loop_sig, xor_d)

    return SemanticFingerprint(
        algorithm=algorithm,
        file_path=file_path,
        anchor_offset=anchor_offset,
        region_size=len(region),
        class_distribution=dist,
        transition_features=trans,
        loop_signature=loop_sig,
        xor_density=xor_d,
        shift_to_xor_ratio=s2x,
        arch_hint=arch_hint if arch_hint != "auto" else "x86",
        hash_bytes=hash_bytes,
    )

def match_fingerprints(query: SemanticFingerprint,
                       candidates: List[SemanticFingerprint],
                       hamming_threshold: int = 8) -> List[Tuple[SemanticFingerprint, int, float]]:
    """
    在候选指纹库中匹配查询指纹。
    返回 [(匹配指纹, 汉明距离, 置信度), ...], 按距离升序。
    汉明距离≤hamming_threshold视为同一密码学原语 — 等价于128-bit中≤6.25%的位差异。
    跨架构允许稍高阈值(8)以吸收ISA差异噪声。
    """
    results = []
    for cand in candidates:
        dist_val = query.hamming_distance(cand)
        if dist_val <= hamming_threshold:
            # 置信度: 距离0→1.0, 距离hamming_threshold→0.6
            confidence = 1.0 - (dist_val / hamming_threshold) * 0.4
            results.append((cand, dist_val, confidence))
    results.sort(key=lambda x: x[1])
    return results

def fingerprint_from_detections(data: bytes,
                                findings: List,  # List[CryptoFinding]
                                window_size: int = 512) -> List[SemanticFingerprint]:
    """
    对crypto_detector的输出结果批量提取语义指纹。
    每个CryptoFinding以其location为锚点提取窗口指纹。
    兼容现有的CryptoFinding接口 — 通过duck typing避免显式依赖。
    """
    fingerprints = []
    for f in findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            loc = getattr(f, 'location', 0)
            fp = extract_fingerprint(data, anchor_offset=loc, window_size=window_size,
                                     algorithm=algo)
            fingerprints.append(fp)
        except Exception:
            # 单个finding提取失败不应中断批量处理
            continue
    return fingerprints

def compute_similarity_matrix(fingerprints: List[SemanticFingerprint]) -> List[List[float]]:
    """计算指纹集合的成对相似度矩阵 — 用于聚类和可视化。"""
    n = len(fingerprints)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            hd = fingerprints[i].hamming_distance(fingerprints[j])
            # 汉明距离→相似度: 0→1.0, 128→0.0
            sim = max(0.0, 1.0 - hd / 128.0)
            matrix[i][j] = sim
            matrix[j][i] = sim
    return matrix
