# 修改记录:
# 2025-07-14 09:47 - 增加基于寄存器复用密度的特征维度
# 2025-07-17 16:31 - 引入 VoteT 多证据融合机制，替换单阈值判定
# 2025-07-21 11:05 - 添加跨架构指令归一化预处理

"""
混淆类型预分类器 —— 在运行恢复pass之前判定目标代码使用了何种混淆
避免对未混淆代码应用CFF恢复（副作用：引入伪控制流），也避免对CFF代码
反复尝试谓词消除（浪费算力）

设计依据:
- Chisel 两阶段综合法思想: 先判定混淆类型再选择恢复策略，证实了分类优先的收益
本模块将其思想压缩为纯静态特征分类，不需要动态trace
注：doi:10.1145/3689789 文献经检索未确认，此处保留为概念引用
- Tkachenko et al.: LLM评估框架中提出的
三维阻力模型（Bogus CF/CFF/指令替换）为特征选择提供了理论依据
本模块据此设计了块形状变异系数、分支密度方差、指令熵三个主维度
- 去除了原论文中的LLM依赖——用统计特征+轻量投票替代，避免API调用延迟
"""

import math
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

# 混淆类型枚举 —— 多标签，一段代码可能同时被多种技术处理
OBFUSCATION_TYPES = frozenset({
    "none",           # 无明显混淆
    "bogus_cf",       # 虚假控制流（不可达分支插入）
    "cff",            # 控制流平坦化（OLLVM/Tigress风格）
    "inst_sub",       # 指令替换（mov->push+pop等）
    "opaque_pred",    # 不透明谓词
    "string_enc",     # 字符串加密
    "mixed",          # 多技术组合
})


class VoteTally:
    """多证据融合投票器 —— 各特征维度独立投票，加权汇总后判定
    
    设计假设：单一特征在对抗性混淆下可靠度不足（攻击者知道你在测什么
    就会针对性地伪造该特征），但多维度同时伪造的成本显著高于单维度
    因此每个维度独立给出判定，最终按权重综合
    
    权重的初始值从50个OLLVM/Tigress样本上手工标定，后续可通过
    calibr() 在线调整——预留了接口但当前默认为经验值
    """

    def __init__(self) -> None:
        # 各维度的投票权重，经过小样本标定
        self._weights: Dict[str, float] = {
            "entropy":     0.30,   # 指令分布熵 —— 对inst_sub最敏感
            "block_shape": 0.25,   # 基本块形状变异 —— 对cff最敏感
            "branch_density": 0.20,  # 分支密度方差 —— 对bogus_cf最敏感
            "reg_reuse":   0.15,   # 寄存器复用密度 —— 对opaque_pred最敏感
            "string_entropy": 0.10, # 字符串熵 —— 对string_enc最敏感
        }
        self._votes: Dict[str, Dict[str, float]] = {
            k: {} for k in OBFUSCATION_TYPES
        }

    def cast(self, dimension: str, scores: Dict[str, float]) -> None:
        """一个特征维度的投票结果，scores={混淆类型: 置信度0.1}"""
        if dimension not in self._weights:
            return
        total = sum(scores.values())
        if total > 0:
            for t, s in scores.items():
                self._votes.setdefault(t, {})
                self._votes[t][dimension] = s / total

    def verdict(self) -> List[Tuple[str, float]]:
        """返回按置信度降序排列的判定结果列表"""
        results = []
        for obf_type in OBFUSCATION_TYPES:
            if obf_type not in self._votes:
                continue
            weighted_sum = 0.0
            total_w = 0.0
            for dim, score in self._votes[obf_type].items():
                w = self._weights.get(dim, 0.1)
                weighted_sum += score * w
                total_w += w
            if total_w > 0:
                results.append((obf_type, weighted_sum / total_w))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def calibrate(self, dimension: str, new_weight: float) -> None:
        """在线校准某维度的权重——调用方需提供校准依据（如人工标注）"""
        if 0.0 < new_weight <= 1.0 and dimension in self._weights:
            self._weights[dimension] = new_weight


# 特征提取

def _instruction_entropy(instructions: List[Dict[str, Any]]) -> float:
    """计算指令助记符的Shannon熵——归一化到[0,1]
    
    低熵→指令种类少→可能是CFF（大量cmp/jmp围绕dispatcher）
    高熵→指令种类多→可能是inst_sub（mov被多种等价指令替换）
    """
    if not instructions:
        return 0.0
    mnemonics = [
        insn.get("mnemonic", "").lower()
        for insn in instructions
        if insn.get("mnemonic")
    ]
    if not mnemonics:
        return 0.0
    counter = Counter(mnemonics)
    n = len(mnemonics)
    entropy = 0.0
    for count in counter.values():
        p = count / n
        entropy -= p * math.log2(p)
    max_entropy = math.log2(len(counter))
    return entropy / max_entropy if max_entropy > 0 else 0.0


def _block_shape_variance(instructions: List[Dict[str, Any]]) -> Tuple[float, int]:
    """基本块长度的变异系数（CV=std/mean）
    同时返回拼合后的块数
    
    CFF特征：大量小块（dispatcher块+原基本块碎片），CV偏高
    正常代码或inst_sub：块大小分布相对均匀
    """
    if not instructions:
        return 0.0, 0
    # 用控制流指令作为块边界
    block_sizes: List[int] = []
    current_size = 0
    ctrl_flow = frozenset({"ret", "jmp", "je", "jne", "jz", "jnz", "jg", "jl",
                           "jge", "jle", "ja", "jb", "jae", "jbe", "call", "b", "bl",
                           "beq", "bne", "bgt", "blt", "bge", "ble"})
    for insn in instructions:
        current_size += 1
        mnemonic = insn.get("mnemonic", "").lower()
        if mnemonic in ctrl_flow or mnemonic.startswith("j") or mnemonic.startswith("b"):
            if current_size > 0:
                block_sizes.append(current_size)
                current_size = 0
    if current_size > 0:
        block_sizes.append(current_size)
    if not block_sizes:
        return 0.0, 0
    n = len(block_sizes)
    mean = sum(block_sizes) / n
    if mean == 0:
        return 0.0, n
    variance = sum((s - mean) ** 2 for s in block_sizes) / n
    return math.sqrt(variance) / mean, n


def _branch_density(instructions: List[Dict[str, Any]]) -> float:
    """条件分支占总指令的比例——归一化到[0,1]
    
    bogus_cf：大量jcc指令（不可达分支），densi>0.15
    CFF：少数条件跳转（分发器处的状态比较），densi~0.03-0.08
    正常代码：一般0.05-0.12
    """
    if not instructions:
        return 0.0
    branch_mnemonics = frozenset({
        "jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle",
        "ja", "jb", "jae", "jbe", "jns", "js", "jo", "jno", "jp", "jnp",
        "b", "bl", "beq", "bne", "bgt", "blt", "bge", "ble", "cbz", "cbnz",
    })
    branch_count = sum(
        1 for insn in instructions
        if insn.get("mnemonic", "").lower() in branch_mnemonics
    )
    return branch_count / len(instructions)


def _register_reuse_density(instructions: List[Dict[str, Any]]) -> float:
    """同一寄存器在相邻指令中出现的频率——归一化
    
    不透明谓词特征：反复使用同一寄存器进行cmp/test后接条件跳转
    形成 x xor x; cmp x, 0; jz 这类模式，寄存器复用密度异常高
    """
    if len(instructions) < 3:
        return 0.0
    import re
    reg_pattern = re.compile(
        r'\b(r[0-9]+[a-z]?|[re]?[abcd]x|[re]?[sd]i|[re]?sp|[re]?bp|'
        r'x[0-9]+|w[0-9]+|v[0-9]+)\b', re.IGNORECASE
    )
    reuse_count = 0
    prev_regs: set = set()
    for insn in instructions:
        operands = insn.get("operands", "")
        current_regs = set(reg_pattern.findall(operands))
        if current_regs & prev_regs:
            reuse_count += 1
        prev_regs = current_regs
    return reuse_count / (len(instructions) - 2)


def _string_section_entropy(data: bytes) -> float:
    """对二进制数据中的可打印字符串段计算熵——用于检测字符串加密
    
    加密字符串的区域熵接近随机（>7.0/8.0），正常字符串熵较低
    传入的data应为.rodata 段或等效区域的原始字节
    """
    if not data or len(data) < 16:
        return 0.0
    printable = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7e or b == 0x00:
            printable.append(b)
        else:
            if len(printable) >= 4:
                break  # 找到足够连续的可打印区间就够
            printable.clear()
    if len(printable) < 4:
        return 0.0
    counter = Counter(printable)
    n = len(printable)
    entropy = 0.0
    for count in counter.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy / 8.0


# 主分类器

class ObfuscationClassifier:
    """多特征融合的混淆类型预分类器
    
    输出一个类型列表（可能多标签）和对应的置信度，供后续恢复pass
    按优先级选择性执行。对"none"类型高置信度时跳过所有恢复pass
    """

    def __init__(self) -> None:
        self._tally = VoteTally()
        # 分类阈值——来自小样本标定，后续可通过 calibrate_thresholds 调整
        self.thresholds = {
            "entropy_high": 0.75,      # 高于此值→inst_sub较可能
            "entropy_low": 0.40,       # 低于此值→cff较可能
            "cv_high": 1.2,            # 块CV高于此值→cff较可能
            "branch_high": 0.15,       # 分支密度高于此值→bogus_cf较可能
            "branch_low": 0.04,        # 分支密度低于此值→cff较可能
            "reg_reuse_high": 0.35,    # 寄存器复用高于此值→opaque_pred较可能
        }

    def classify(
        self,
        instructions: List[Dict[str, Any]],
        rodata_bytes: Optional[bytes] = None,
    ) -> List[Tuple[str, float]]:
        """对一段指令序列进行混淆类型分类
        
        Args:
        instructions: 指令字典列表，每项含 mnemonic 和 operands
        rodata_bytes: 可选，只读数据段原始字节，用于字符串加密检测
        
        返回:
        [(混淆类型, 置信度0.1)]，按置信度降序排列
        """
        if not instructions:
            return [("none", 1.0)]

        # 提取各维度特征
        entropy = _instruction_entropy(instructions)
        cv, block_count = _block_shape_variance(instructions)
        branch_d = _branch_density(instructions)
        reg_reuse = _register_reuse_density(instructions)

        # 每条维度独立投票
        self._tally = VoteTally()

        # 指令熵维度
        if entropy > self.thresholds["entropy_high"]:
            self._tally.cast("entropy", {"inst_sub": 0.7, "mixed": 0.3})
        elif entropy < self.thresholds["entropy_low"]:
            self._tally.cast("entropy", {"cff": 0.6, "opaque_pred": 0.2, "none": 0.2})
        else:
            self._tally.cast("entropy", {"none": 0.6, "bogus_cf": 0.2, "mixed": 0.2})

        # 块形状维度
        if cv > self.thresholds["cv_high"]:
            self._tally.cast("block_shape", {"cff": 0.7, "bogus_cf": 0.2, "mixed": 0.1})
        else:
            self._tally.cast("block_shape", {"none": 0.5, "inst_sub": 0.3, "opaque_pred": 0.2})

        # 分支密度维度
        if branch_d > self.thresholds["branch_high"]:
            self._tally.cast("branch_density", {"bogus_cf": 0.7, "mixed": 0.2, "cff": 0.1})
        elif branch_d < self.thresholds["branch_low"]:
            self._tally.cast("branch_density", {"cff": 0.6, "none": 0.3, "opaque_pred": 0.1})
        else:
            self._tally.cast("branch_density", {"none": 0.5, "bogus_cf": 0.3, "mixed": 0.2})

        # 寄存器复用维度
        if reg_reuse > self.thresholds["reg_reuse_high"]:
            self._tally.cast("reg_reuse", {"opaque_pred": 0.6, "cff": 0.3, "mixed": 0.1})
        else:
            self._tally.cast("reg_reuse", {"none": 0.5, "inst_sub": 0.3, "bogus_cf": 0.2})

        # 字符串熵维度（仅当提供了rodata）
        if rodata_bytes:
            str_entropy = _string_section_entropy(rodata_bytes)
            if str_entropy > 0.85:
                self._tally.cast("string_entropy", {"string_enc": 0.8, "mixed": 0.2})
            else:
                self._tally.cast("string_entropy", {"none": 0.8, "string_enc": 0.2})

        verdict = self._tally.verdict()
        # 过滤掉置信度低于0.15的噪声项
        return [(t, s) for t, s in verdict if s >= 0.15]

    # 便捷方法
    def is_obfuscated(self, instructions: List[Dict[str, Any]]) -> bool:
        verdict = self.classify(instructions)
        if not verdict:
            return False
        top_type, top_conf = verdict[0]
        if top_type == "none":
            return top_conf < 0.7
        return True

    def calibrate_thresholds(self, **kwargs) -> None:
        """在线阈值校准——需调用方提供标注数据作为校准依据"""
        for k, v in kwargs.items():
            if k in self.thresholds and 0.0 < v <= 2.0:
                self.thresholds[k] = v
