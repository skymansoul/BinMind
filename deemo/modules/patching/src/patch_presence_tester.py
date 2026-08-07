# 修改记录:
# 2025-07-22 09:18 — 增加自适应阈值标定，避免小函数误匹配
# 2025-07-25 17:33 — 寄存器写入签名改用归一化哈希，降低编译器差异干扰
# 2025-07-28 08:51 — 与 CVE KB 集成：用已知 CVE patch 作为参考签名源

"""Patch Presence Tester (PPT) — 语义签名提取与匹配。

给定一个目标 binary 和一个已知的参考 patch（来自 CVE KB 或直接提供），
判断目标 binary 中是否已包含该 patch。不要求源码，不要求编译。

方法路径:
    binary → 函数级语义签名提取 → 多粒度匹配 → 置信度评分

多粒度: 指令级 → 基本块 → 函数，原始匹配后取加权综合。

// ref: PS3 使用四种语义签名进行 patch presence test，
// 本实现借鉴其签名分类思路（寄存器写/内存写/条件/调用），
// 但不要求 SMT solver 也不依赖源码编译。
// 与 PS3 的关键区别：PS3 需要符号模拟 + SMT 等值检查，
// 本项目走轻量 concrete signature matching 路线，
// 代价是反编译器优化差异可能导致误判，收益是无外部依赖。
// ref: REACT 在 IR 级提取特征，本项目直接在汇编级完成类似操作。
// ref: Lares 基于代码理解的不需编译的 PPT，
// 本项目签名为 deterministic 的静态提取，外部理解引擎作为可选增强（预留接口）。
"""

import re
import os
import struct
import logging
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set

_log = logging.getLogger(__name__)

# 语义签名标签
# 四种签名类型对应 PS3 的分类法，这里做了工程化适配

class SigKind:
    REG_WRITE = "reg_write"       # 寄存器写入（目标寄存器 + 写入源模式）
    MEM_STORE = "mem_store"       # 内存存储（基址寄存器 + 偏移量模式）
    CONDITION = "condition"       # 条件分支（条件类型 + 比较操作数）
    CALL_TARGET = "call_target"   # 函数调用目标（被调用者签名）
    LOAD_CONST = "load_const"     # 常量加载（立即数值，可选忽略低 12 位）


@dataclass(frozen=True)
class SemanticSignature:
    """不可变语义签名 — 用 frozen 以支持 hash(set)。"""
    kind: str
    content: str       # 规范化字符串表示
    weight: float = 1.0  # 签名权重: condition > reg_write > mem_store ≈ call_target

    def __hash__(self):
        return hash((self.kind, self.content))

    def __eq__(self, other):
        if not isinstance(other, SemanticSignature):
            return False
        return self.kind == other.kind and self.content == other.content


@dataclass
class FunctionSignatureProfile:
    """单个函数的完整语义签名画像。"""
    function_name: str
    address: int = 0
    signatures: Set[SemanticSignature] = field(default_factory=set)
    basic_block_count: int = 0
    instruction_count: int = 0
    complexity_class: str = "medium"  # "tiny"|"small"|"medium"|"large" → 影响匹配阈值


@dataclass
class MatchResult:
    """patch presence 匹配结果。"""
    target_function: str
    reference_function: str
    match_score: float         # 0..1 综合匹配分
    threshold: float           # 本次判定阈值
    present: bool              # 是否判定为 patch 存在
    granularity_scores: Dict[str, float] = field(default_factory=dict)
    matched_signatures: List[Tuple[str, str]] = field(default_factory=list)
    confidence: float = 0.0


# 汇编级语义签名提取器

class SemanticSignatureExtractor:
    """从反汇编文本中提取语义签名。

    输入: radare2/Ghidra/objdump 风格的反汇编行列表。
    输出: 去重的 SemanticSignature 集合。

    设计约束:
      - 不依赖反编译器输出质量（伪代码 vs 汇编均可）
      - 对寄存器重命名有基本容错（通过归一化）
      - 对编译器优化差异做宽松匹配（如常量折叠后仍可匹配）
    """

    # 寄存器分类 — x86_64 为主，ARM64 扩展见 _normalize_register
    _X86_CALLER_SAVED = {'rax','rcx','rdx','r8','r9','r10','r11',
                         'eax','ecx','edx','r8d','r9d','r10d','r11d'}
    _X86_CALLEE_SAVED = {'rbx','rsi','rdi','r12','r13','r14','r15','rbp','rsp',
                         'ebx','esi','edi','r12d','r13d','r14d','r15d'}
    _ARM64_REGS = {'x0','x1','x2','x3','x4','x5','x6','x7','x8',
                   'x9','x10','x11','x12','x13','x14','x15',
                   'x16','x17','x18','x19','x20','x21','x22','x23',
                   'x24','x25','x26','x27','x28','x29','x30','sp','lr','pc',
                   'w0','w1','w2','w3','w4','w5','w6','w7','w8',
                   'w9','w10','w11','w12','w13','w14','w15',
                   'w16','w17','w18','w19','w20','w21','w22','w23',
                   'w24','w25','w26','w27','w28','w29','w30'}

    def extract(self, asm_lines: List[str], function_name: str = "",
                address: int = 0) -> FunctionSignatureProfile:
        """主入口: 汇编行 → 签名画像。"""
        sigs: Set[SemanticSignature] = set()
        bb_count = 0
        inst_count = 0
        for line in asm_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(';'):
                continue
            # 基本块标记
            if re.match(r'(loc_|\.L|LAB_)', stripped) or ':' in stripped.split()[0]:
                bb_count += 1
                continue
            inst_count += 1
            sigs.update(self._extract_from_instruction(stripped))

        profile = FunctionSignatureProfile(
            function_name=function_name,
            address=address,
            signatures=sigs,
            basic_block_count=max(bb_count, 1),
            instruction_count=max(inst_count, 1),
            complexity_class=self._classify_complexity(inst_count, bb_count)
        )
        return profile

    def _extract_from_instruction(self, inst: str) -> Set[SemanticSignature]:
        """单条指令 → 签名集合（一条指令可能产出多个签名）。"""
        sigs: Set[SemanticSignature] = set()
        norm = inst.lower().replace(',', ' ').replace('[', ' [').strip()
        parts = norm.split()
        if not parts:
            return sigs
        mnemonic = parts[0]

        # 寄存器写入检测
        if self._is_write_mnemonic(mnemonic):
            reg = self._extract_dest_register(parts, mnemonic)
            if reg:
                src_pattern = ' '.join(parts[1:]) if len(parts) > 1 else ''
                sigs.add(SemanticSignature(
                    kind=SigKind.REG_WRITE,
                    content=f"w→{self._normalize_register(reg)}|{self._hash_operands(src_pattern)}",
                    weight=0.8))

        # 内存存储
        if mnemonic in ('mov', 'movq', 'movl', 'movw', 'movb', 'str', 'stp', 'stur',
                        'fstp', 'fst', 'movups', 'movaps', 'vmovdqu', 'vmovdqa'):
            mem_op = self._find_memory_operand(parts)
            if mem_op:
                sigs.add(SemanticSignature(
                    kind=SigKind.MEM_STORE,
                    content=f"st→{mem_op}",
                    weight=0.6))

        # 条件分支
        if self._is_conditional_branch(mnemonic):
            cond = self._extract_condition(inst)
            if cond:
                sigs.add(SemanticSignature(
                    kind=SigKind.CONDITION,
                    content=f"br?{cond}",
                    weight=1.2))  # 条件分支权重最高 — 补丁通常在条件判断处

        # 函数调用
        if mnemonic in ('call', 'bl', 'blr', 'jal', 'jalr'):
            target = self._extract_call_target(parts)
            if target:
                sigs.add(SemanticSignature(
                    kind=SigKind.CALL_TARGET,
                    content=f"call→{target}",
                    weight=0.7))

        # 立即数（常量加载）
        imm = self._extract_immediate(norm)
        if imm is not None:
            # 大立即数可能为地址/常量，≤ 128 的忽略（太高频）
            if abs(imm) > 128:
                sigs.add(SemanticSignature(
                    kind=SigKind.LOAD_CONST,
                    content=f"imm≔{imm}",
                    weight=0.4))

        return sigs

# helpers

    @staticmethod
    def _is_write_mnemonic(m: str) -> bool:
        return m in ('mov', 'movq', 'movl', 'movw', 'movb', 'lea', 'xor', 'add', 'sub',
                     'mul', 'imul', 'and', 'or', 'shl', 'shr', 'sar', 'pop', 'ldr', 'ldp',
                     'adrp', 'adr', 'movz', 'movk', 'sxtw', 'uxtw', 'neg', 'not', 'inc', 'dec')

    @staticmethod
    def _is_conditional_branch(m: str) -> bool:
        return m in ('je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae',
                     'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jcxz',
                     'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge', 'b.hs', 'b.lo',
                     'b.mi', 'b.pl', 'b.vs', 'b.vc', 'cbnz', 'cbz', 'tbnz', 'tbz')

    @staticmethod
    def _extract_dest_register(parts: list, mnemonic: str) -> Optional[str]:
        if mnemonic == 'pop' and len(parts) >= 2:
            return parts[1].rstrip(']').lstrip('[')
        if mnemonic in ('ldr', 'ldp') and len(parts) >= 2:
            return parts[1]
        if mnemonic in ('adrp', 'adr', 'movz', 'movk') and len(parts) >= 2:
            return parts[1]
        if len(parts) >= 2:
            # 常规: mnemonic dst, src
            return parts[1]
        return None

    @staticmethod
    def _find_memory_operand(parts: list) -> Optional[str]:
        text = ' '.join(parts)
        m = re.search(r'\[([^\]]+)\]', text)
        if m:
            return m.group(1).strip()
        return None

    @staticmethod
    def _extract_condition(inst: str) -> Optional[str]:
        m = re.search(r'(?:cmp|test|tst|subs|adds)\s+([^;]+)', inst, re.I)
        if m:
            return m.group(1).strip()[:40]
        # ARM64 cbz/cbnz/tbnz/tbz
        m = re.search(r'(?:cbz|cbnz|tbnz|tbz)\s+([^;]+)', inst, re.I)
        if m:
            return m.group(1).strip()[:40]
        return None

    @staticmethod
    def _extract_call_target(parts: list) -> Optional[str]:
        if len(parts) < 2:
            return None
        target = parts[-1]
        target = target.rstrip(';')
        # 去 plt 后缀
        target = re.sub(r'@plt$', '', target)
        # 去 * 前缀（间接调用）
        target = target.lstrip('*')
        # 保留已命名符号，忽略裸地址
        if re.match(r'0x[0-9a-f]+$', target, re.I) or target.isdigit():
            # 匿名地址调用 — 保留为特征但不标记具体名
            return f"<indirect:{target[:8]}>"
        return target

    @staticmethod
    def _extract_immediate(text: str) -> Optional[int]:
        # 优先匹配明确的立即数标记如 #0x1234 / $0x10
        m = re.search(r'[#$](0x[0-9a-f]+|\d+)', text, re.I)
        if m:
            val = m.group(1)
            return int(val, 16) if val.startswith('0x') or val.startswith('0X') else int(val)
        # 匹配独立数字（保守）
        m = re.search(r'\b(\d{4,})\b', text)
        if m:
            return int(m.group(1))
        return None

    @staticmethod
    def _normalize_register(reg: str) -> str:
        """寄存器归一化: eax→rax, w0→x0 (宽度归一到 64 位等价类)。
        // 编译器可能在 32-bit 和 64-bit 版本间切换子寄存器，
        // 归一化降低这种差异对签名匹配的影响。
        """
        r = reg.lower().strip()
        # ARM64 32-bit → 64-bit
        if r.startswith('w') and r[1:].isdigit():
            return 'x' + r[1:]
        # x86 32-bit → 64-bit
        for a32, a64 in [('eax','rax'),('ebx','rbx'),('ecx','rcx'),('edx','rdx'),
                          ('esi','rsi'),('edi','rdi'),('ebp','rbp'),('esp','rsp')]:
            if r == a32:
                return a64
        return r

    @staticmethod
    def _hash_operands(ops: str) -> str:
        """操作数模式哈希 — 短，稳定，不依赖具体常量值。
        // 使用 sha256 截断 8 字符：碰撞概率在实际使用中可忽略。
        """
        # 替换立即数为占位符
        norm = re.sub(r'0x[0-9a-f]+', 'IMM', ops, flags=re.I)
        norm = re.sub(r'\b\d+\b', 'NUM', norm)
        return hashlib.sha256(norm.strip().encode()).hexdigest()[:8]

    @staticmethod
    def _classify_complexity(inst_count: int, bb_count: int) -> str:
        if inst_count <= 5:
            return "tiny"
        elif inst_count <= 20:
            return "small"
        elif inst_count <= 80:
            return "medium"
        return "large"


# 匹配引擎

class PatchPresenceTester:
    """基于语义签名的 patch presence 判定器。

    用法:
        tester = PatchPresenceTester(extractor=SemanticSignatureExtractor())
        result = tester.test(target_asm, reference_asm, target_name, ref_name)
    """

    # 不同复杂度的基线阈值 — tiny 函数签名太少，高阈值避免误匹配
    _BASE_THRESHOLDS = {"tiny": 0.85, "small": 0.75, "medium": 0.60, "large": 0.50}

    # 各签名类型在匹配中的权重
    _KIND_WEIGHTS = {
        SigKind.CONDITION: 1.2,
        SigKind.REG_WRITE: 0.8,
        SigKind.MEM_STORE: 0.6,
        SigKind.CALL_TARGET: 0.7,
        SigKind.LOAD_CONST: 0.3,  # 常量容易被编译器优化改变
    }

    def __init__(self, extractor=None):
        self.extractor = extractor or SemanticSignatureExtractor()

    def test(self, target_asm: List[str], reference_asm: List[str],
             target_name: str = "", reference_name: str = "") -> MatchResult:
        """执行 patch presence test。"""
        tp = self.extractor.extract(target_asm, target_name)
        rp = self.extractor.extract(reference_asm, reference_name)

        # 多粒度得分
        inst_score = self._instruction_level_match(tp, rp)
        bb_penalty = self._basic_block_delta_penalty(tp, rp)
        func_score = self._function_level_match(tp, rp)

        # 综合: 指令级 0.5 + 函数级 0.5，再减去基本块差异惩罚
        raw = inst_score * 0.5 + func_score * 0.5 - bb_penalty
        combined = max(0.0, min(1.0, raw))

        threshold = self._calibrate_threshold(tp, rp)
        present = combined >= threshold

        result = MatchResult(
            target_function=target_name,
            reference_function=reference_name,
            match_score=combined,
            threshold=threshold,
            present=present,
            granularity_scores={"instruction": inst_score, "function": func_score,
                                "bb_penalty": bb_penalty},
            matched_signatures=list(self._matched_sig_pairs(tp, rp))[:20],
            confidence=self._compute_confidence(combined, threshold, tp.instruction_count)
        )
        return result

    def test_with_profile(self, target_asm: List[str],
                          reference_profile: FunctionSignatureProfile,
                          target_name: str = "") -> MatchResult:
        """使用已提取的参考画像进行匹配——避免重复提取，批量场景适用。"""
        tp = self.extractor.extract(target_asm, target_name)
        inst_score = self._instruction_level_match(tp, reference_profile)
        bb_penalty = self._basic_block_delta_penalty(tp, reference_profile)
        func_score = self._function_level_match(tp, reference_profile)
        raw = inst_score * 0.5 + func_score * 0.5 - bb_penalty
        combined = max(0.0, min(1.0, raw))
        threshold = self._calibrate_threshold(tp, reference_profile)
        present = combined >= threshold
        return MatchResult(
            target_function=target_name,
            reference_function=reference_profile.function_name,
            match_score=combined,
            threshold=threshold,
            present=present,
            granularity_scores={"instruction": inst_score, "function": func_score,
                                "bb_penalty": bb_penalty},
            confidence=self._compute_confidence(combined, threshold, tp.instruction_count)
        )

# 多粒度匹配

    def _instruction_level_match(self, tp: FunctionSignatureProfile,
                                  rp: FunctionSignatureProfile) -> float:
        """指令级: 基于签名集合的加权 Jaccard 相似度。"""
        if not tp.signatures or not rp.signatures:
            return 0.0
        return self._weighted_jaccard(tp.signatures, rp.signatures)

    def _function_level_match(self, tp: FunctionSignatureProfile,
                               rp: FunctionSignatureProfile) -> float:
        """函数级: 签名分布相似度（各类签名占比的比较）。
        // 两个不同大小的函数可能在签名集合上差异大，
        // 但签名的 type distribution 相似则函数结构相近。
        """
        def _kind_dist(p: FunctionSignatureProfile) -> Dict[str, float]:
            dist: Dict[str, int] = {}
            for sig in p.signatures:
                dist[sig.kind] = dist.get(sig.kind, 0) + 1
            total = max(len(p.signatures), 1)
            return {k: v / total for k, v in dist.items()}
        td = _kind_dist(tp)
        rd = _kind_dist(rp)
        all_kinds = set(td.keys()) | set(rd.keys())
        if not all_kinds:
            return 0.0
        diffs = [abs(td.get(k, 0) - rd.get(k, 0)) for k in all_kinds]
        return 1.0 - (sum(diffs) / len(all_kinds))

    def _basic_block_delta_penalty(self, tp: FunctionSignatureProfile,
                                    rp: FunctionSignatureProfile) -> float:
        """基本块数量差异惩罚 — 0 到 0.3。
        // 块数差异过大说明控制流结构被重构（内联/优化），
        // 这时不应仅从签名判定 patch 存在。
        """
        a, b = tp.basic_block_count, rp.basic_block_count
        if a == 0 and b == 0:
            return 0.0
        ratio = min(a, b) / max(a, b) if max(a, b) > 0 else 0.0
        return (1.0 - ratio) * 0.3

# 自适应阈值

    def _calibrate_threshold(self, tp: FunctionSignatureProfile,
                              rp: FunctionSignatureProfile) -> float:
        """基于双方复杂度的自适应阈值。
        // 小函数签名少 → 随机碰撞概率高 → 提高阈值。
        // 大函数有足够信息量 → 可适当降低。
        """
        base = self._BASE_THRESHOLDS.get(tp.complexity_class, 0.65)
        # 签名总数差距过大时加 0.05–0.10 的保守偏移
        a, b = len(tp.signatures), len(rp.signatures)
        if max(a, b) > 0:
            size_ratio = min(a, b) / max(a, b)
            if size_ratio < 0.5:
                base += 0.08
        return min(base, 0.95)

    def _compute_confidence(self, score: float, threshold: float,
                            inst_count: int) -> float:
        """置信度估算 — 基于 score 与 threshold 的差距 + 函数规模。
        // 分数远超阈值且函数足够大 → 高置信。
        // 分数刚好过线且函数很小 → 低置信（建议人工复核）。
        """
        margin = score - threshold
        # sigmoid-ish 标准化
        norm = 1.0 / (1.0 + max(1e-6, (-margin * 8)))
        size_bonus = min(inst_count / 60.0, 1.0) * 0.2
        return min(round(norm + size_bonus, 3), 1.0)

# 加权 Jaccard

    def _weighted_jaccard(self, a: Set[SemanticSignature],
                           b: Set[SemanticSignature]) -> float:
        """带权重的 Jaccard — 不同类型签名贡献不同。"""
        inter = a & b
        if not inter:
            return 0.0
        w_inter = sum(self._KIND_WEIGHTS.get(s.kind, 0.5) * s.weight for s in inter)
        # 取 a, b 签名集权重和的均值做分母
        w_total_a = sum(self._KIND_WEIGHTS.get(s.kind, 0.5) * s.weight for s in a)
        w_total_b = sum(self._KIND_WEIGHTS.get(s.kind, 0.5) * s.weight for s in b)
        if w_total_a + w_total_b == 0:
            return 0.0
        return w_inter / ((w_total_a + w_total_b) / 2.0)

    @staticmethod
    def _matched_sig_pairs(tp, rp):
        """返回匹配上的签名对，供报告输出。"""
        inter = tp.signatures & rp.signatures
        for s in sorted(inter, key=lambda x: (x.kind, x.content)):
            yield (s.kind, s.content)


# CVE KB 集成
# 将 CVEKnowledgeBase 中的参考 patch 函数预先提取为签名画像，
# 批量匹配时复用画像，避免对每个 target 重复提取参考侧。

def build_reference_profiles(cve_kb, cve_id: str,
                              extractor=None) -> Dict[str, FunctionSignatureProfile]:
    """从 CVE KB 中提取指定 CVE 的参考函数签名画像。

    返回 {function_name: FunctionSignatureProfile}，可直接传入
    PatchPresenceTester.test_with_profile()。
    """
    ext = extractor or SemanticSignatureExtractor()
    profiles: Dict[str, FunctionSignatureProfile] = {}
    entry = cve_kb.lookup(cve_id)
    if not entry:
        _log.warning("PPT: CVE %s not found in knowledge base", cve_id)
        return profiles
    # entry 可能包含 patched_function_asm (dict: fn_name → asm_lines)
    patched_asm = getattr(entry, 'patched_function_asm', None)
    if not patched_asm:
        _log.info("PPT: CVE %s has no patched_function_asm — skipping", cve_id)
        return profiles
    for fn_name, asm_lines in patched_asm.items():
        profile = ext.extract(asm_lines, fn_name)
        profiles[fn_name] = profile
    _log.info("PPT: built %d reference profiles for CVE %s", len(profiles), cve_id)
    return profiles
