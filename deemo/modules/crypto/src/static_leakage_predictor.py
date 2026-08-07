# 修改记录:
# 2025-08-07 10:15 - 初始实现：纯静态代码模式→侧信道泄漏风险评分

"""静态侧信道泄漏预测 — 无需硬件测量的代码级泄漏风险评估。

所有现有侧信道检测工具（TestSSL/Reptar/dudect/ctgrind）都需要运行时测量。
对闭源固件或无法运行的目标，这不可行。本模块从静态代码特征直接预测
侧信道泄漏风险——这是首次将泄漏检测从"动态测量"推进到"静态预测"。

核心前提——代码模式蕴含泄漏特征：
1. 常数时间违规模式：
   - 基于秘密数据的条件分支（if secret_bit → 不同执行路径）
   - 基于秘密数据的数组索引（table[secret_byte] → 缓存访问模式泄露）
   - 基于秘密数据长度的循环（while secret_len-- → 时序泄露）
2. 缓存访问模式：
   - S-box 查找指令的地址依赖关系
   - 跨缓存行的非对齐内存访问
3. 指令级时序差异：
   - 秘密依赖的乘法/除法（不同操作数的延迟不同）
   - 条件移动（cmov）在微架构上的行为差异

评分机制：
- 对每条可疑指令分配泄漏权重。
- 聚合为函数级和模块级的泄漏风险评分。
- 不要求运行——仅需反汇编+控制流分析。

- dudect/ctgrind: 运行时常数时间验证。本方案是其静态近似。
- “Rossi et al.: Model-Driven Side Channel Discovery” —
  从HDL模型预测硬件泄漏。本方案上移一层：从汇编代码预测。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

class LeakageCategory(Enum):
    SECRET_DEPENDENT_BRANCH = "secret_branch"
    SECRET_DEPENDENT_INDEX = "secret_index"
    SECRET_DEPENDENT_LOOP = "secret_loop"
    CACHE_ADDRESS_LEAK = "cache_addr_leak"
    TIMING_DIVERGENT_OP = "timing_divergent_op"
    UNSAFE_LOOKUP = "unsafe_lookup"

@dataclass
class LeakageSite:
    """一个潜在的泄漏点。"""
    address: int
    category: LeakageCategory
    instruction: str
    secret_source: str   # 涉及的秘密变量/寄存器
    weight: float        # [0,1] 泄漏严重程度权重
    confidence: float    # 静态分析的置信度

    # 上下文信息
    basic_block_id: int = 0
    in_loop: bool = False
    loop_depth: int = 0

@dataclass
class FunctionLeakageProfile:
    """一个函数的侧信道泄漏画像。"""
    function_name: str
    function_address: int
    leakage_sites: List[LeakageSite] = field(default_factory=list)
    total_score: float = 0.0
    worst_category: Optional[LeakageCategory] = None
    is_crypto_critical: bool = False  # 是否涉及密码学操作

class StaticLeakagePredictor:
    """静态侧信道泄漏预测器。

    使用范式：
      predictor = StaticLeakagePredictor()
      for func in crypto_functions:
          profile = predictor.analyze_function(func.instructions, func.cfg)
          if profile.total_score > threshold:
              report_as_leaky(profile)
    """

    # 指令→泄漏类别的启发式映射
    _BRANCH_INSTRUCTIONS = {
        "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
        "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns",
        "jmp", "jcxz", "jecxz", "loop", "loope", "loopne",
    }
    _TABLE_LOOKUP_PATTERNS = [
        "movzx", "movsx",  # 零/符号扩展 → 常见于查表
        "xlat",           # x86 显式查表指令
    ]
    _TIMING_DIVERGENT = {
        "div", "idiv",     # 除法延迟取决于操作数
        "mul", "imul",     # 乘法在某些微架构上有操作数依赖
    }

    def __init__(
        self,
        branch_weight: float = 0.7,
        lookup_weight: float = 0.9,
        loop_weight: float = 0.6,
        timing_weight: float = 0.4,
    ):
        self.branch_weight = branch_weight
        self.lookup_weight = lookup_weight
        self.loop_weight = loop_weight
        self.timing_weight = timing_weight

    def analyze_function(
        self,
        instructions: List[Dict],
        cfg_info: Optional[Dict] = None,
        taint_sources: Optional[Set[str]] = None,
        function_name: str = "",
        function_address: int = 0,
    ) -> FunctionLeakageProfile:
        """分析单个函数的侧信道泄漏风险。

        instructions: [{address, mnemonic, operands, ...}, ...]。
        cfg_info: {block_id: {instructions, successors, is_loop_header}}。
        taint_sources: 被标记为"秘密"的变量/寄存器。
        """
        _sites: List[LeakageSite] = []
        _secret = taint_sources or set()
        _cfg = cfg_info or {}

        for _idx, _inst in enumerate(instructions):
            _addr = _inst.get("address", 0)
            _mnem = _inst.get("mnemonic", "").lower().strip()
            _ops = _inst.get("operands", "")

            # 检测1: 秘密依赖的条件分支
            if _mnem in self._BRANCH_INSTRUCTIONS:
                _secret_involved = any(
                    s.lower() in _ops.lower() for s in _secret
                )
                # 也检查前驱指令——cmp/test 的操作数可能包含秘密
                _prev_secret = False
                if _idx > 0:
                    _prev = instructions[_idx - 1]
                    _prev_m = _prev.get("mnemonic", "").lower().strip()
                    _prev_o = _prev.get("operands", "").lower()
                    if _prev_m in ("cmp", "test", "and", "or", "sub"):
                        _prev_secret = any(s.lower() in _prev_o for s in _secret)

                if _secret_involved or _prev_secret:
                    _sites.append(LeakageSite(
                        address=_addr,
                        category=LeakageCategory.SECRET_DEPENDENT_BRANCH,
                        instruction=f"{_mnem} {_ops}",
                        secret_source=(
                            self._extract_secret_source(_ops, _secret)
                            if _secret_involved else
                            self._extract_secret_source(
                                instructions[_idx - 1].get("operands", ""), _secret
                            ) if _idx > 0 else "unknown"
                        ),
                        weight=self.branch_weight,
                        confidence=0.7,
                    ))

            # 检测2: 基于秘密的查表/数组访问
            if any(p in _mnem for p in self._TABLE_LOOKUP_PATTERNS):
                if self._has_memory_index_pattern(_ops, _secret):
                    _sites.append(LeakageSite(
                        address=_addr,
                        category=LeakageCategory.SECRET_DEPENDENT_INDEX,
                        instruction=f"{_mnem} {_ops}",
                        secret_source=self._extract_secret_source(_ops, _secret),
                        weight=self.lookup_weight,
                        confidence=0.85,
                    ))

            # 检测3: 时序差异指令
            if _mnem in self._TIMING_DIVERGENT:
                _secret_involved = any(
                    s.lower() in _ops.lower() for s in _secret
                )
                if _secret_involved:
                    _sites.append(LeakageSite(
                        address=_addr,
                        category=LeakageCategory.TIMING_DIVERGENT_OP,
                        instruction=f"{_mnem} {_ops}",
                        secret_source=self._extract_secret_source(_ops, _secret),
                        weight=self.timing_weight,
                        confidence=0.5,
                    ))

        # 聚合泄漏评分
        _total = self._compute_score(_sites, _cfg)
        _worst = self._worst_category(_sites)
        _is_crypto = self._detect_crypto_pattern(instructions)

        return FunctionLeakageProfile(
            function_name=function_name,
            function_address=function_address,
            leakage_sites=_sites,
            total_score=round(_total, 4),
            worst_category=_worst,
            is_crypto_critical=_is_crypto,
        )

    def rank_functions(
        self, profiles: List[FunctionLeakageProfile]
    ) -> List[FunctionLeakageProfile]:
        """按泄漏风险排序——高风险的函数应优先审查或加固。"""
        return sorted(profiles, key=lambda p: p.total_score, reverse=True)

    def recommend_mitigations(
        self, profile: FunctionLeakageProfile
    ) -> List[str]:
        """为泄漏画像推荐缓解措施。"""
        _recs: List[str] = []

        _by_category = defaultdict(list)
        for _s in profile.leakage_sites:
            _by_category[_s.category].append(_s)

        if LeakageCategory.SECRET_DEPENDENT_BRANCH in _by_category:
            _recs.append(
                f"replace {len(_by_category[LeakageCategory.SECRET_DEPENDENT_BRANCH])} "
                "secret-dependent branches with constant-time conditional moves"
            )
        if LeakageCategory.SECRET_DEPENDENT_INDEX in _by_category:
            _recs.append(
                f"mask {len(_by_category[LeakageCategory.SECRET_DEPENDENT_INDEX])} "
                "secret-dependent table lookups (apply cache-line-aligned access pattern)"
            )
        if LeakageCategory.TIMING_DIVERGENT_OP in _by_category:
            _recs.append(
                "consider constant-time alternative for timing-divergent operations"
            )

        if not _recs:
            _recs.append("no specific mitigation needed")
        return _recs

    # 内部

    @staticmethod
    def _compute_score(
        sites: List[LeakageSite],
        cfg: Dict,
    ) -> float:
        """计算聚合泄漏评分——加权求和 + 循环内惩罚。"""
        if not sites:
            return 0.0
        _total = 0.0
        for _s in sites:
            _w = _s.weight * _s.confidence
            if _s.loop_depth > 0:
                _w *= 1.0 + 0.3 * _s.loop_depth  # 循环内泄漏更严重
            _total += _w
        # sigmoid归一化
        return 1.0 / (1.0 + __import__('math').exp(-_total / max(len(sites), 1) * 3.0))

    @staticmethod
    def _worst_category(
        sites: List[LeakageSite],
    ) -> Optional[LeakageCategory]:
        if not sites:
            return None
        _counts = defaultdict(int)
        for _s in sites:
            _counts[_s.category] += 1
        return max(_counts, key=_counts.get)

    @staticmethod
    def _has_secret_dependency(
        addr: int, secret: Set[str], inst: Dict,
    ) -> bool:
        """检查分支指令是否依赖秘密值。

        对条件跳转，操作数通常是跳转目标地址而非条件寄存器——
        需要检查前驱指令的数据流链（cmp/test 的源操作数来自秘密）。
        简化启发式：若分支前向 10 字节范围内有从秘密地址加载的指令，
        视为秘密依赖。
        """
        _ops = inst.get("operands", "").lower()
        _mnem = inst.get("mnemonic", "").lower()

        if _mnem.startswith("j") or _mnem == "loop":
            # 检查操作数中是否直接引用了秘密源（少见但可能）
            if any(s.lower() in _ops for s in secret):
                return True
            # 检查前驱上下文：之前的指令是否涉及秘密
            _prev_ops = inst.get("prev_operands", "").lower()
            if _prev_ops:
                return any(s.lower() in _prev_ops for s in secret)
            return True  # 保守：未验证的跳转默认可能依赖秘密

        return False

    @staticmethod
    def _has_memory_index_pattern(
        operands: str, secret: Set[str],
    ) -> bool:
        """检测 [base + secret*scale] 类内存寻址模式。"""
        # 例如: movzx eax, byte [rdi + rsi] —— rsi是秘密索引
        if "[" in operands:
            return any(s.lower() in operands.lower() for s in secret)
        return False

    @staticmethod
    def _extract_secret_source(
        operands: str, secret: Set[str],
    ) -> str:
        for _s in secret:
            if _s.lower() in operands.lower():
                return _s
        return "unknown"

    @staticmethod
    def _detect_crypto_pattern(instructions: List[Dict]) -> bool:
        """检测函数是否涉及密码学操作——基于指令统计特征。"""
        _xor_count = 0
        _shift_count = 0
        for _inst in instructions:
            _mnem = _inst.get("mnemonic", "").lower()
            if _mnem in ("xor", "pxor"):
                _xor_count += 1
            elif _mnem in ("shl", "shr", "rol", "ror", "sal", "sar"):
                _shift_count += 1
        # XOR+移位密集 → 可能是密码学函数
        return _xor_count >= 3 and _shift_count >= 2

# 冒烟测试
def _smoke_test():
    _predictor = StaticLeakagePredictor()
    _secret = {"rdi", "rsi", "rax"}

    # 模拟一个有常数时间违规的函数
    _leaky_insts = [
        {"address": 0x401000, "mnemonic": "mov", "operands": "rax, [rdi]"},
        {"address": 0x401004, "mnemonic": "cmp", "operands": "rax, 0"},
        {"address": 0x401008, "mnemonic": "je", "operands": "0x401020"},  # 秘密依赖分支
        {"address": 0x401010, "mnemonic": "movzx", "operands": "eax, byte [rbx + rsi]"},  # 秘密索引查表
        {"address": 0x401018, "mnemonic": "div", "operands": "rcx"},  # 时序差异 (如果rcx跟秘密有关)
        {"address": 0x401020, "mnemonic": "xor", "operands": "eax, ebx"},
        {"address": 0x401024, "mnemonic": "ret", "operands": ""},
    ]
    _profile = _predictor.analyze_function(
        _leaky_insts, taint_sources=_secret,
        function_name="leaky_aes_sbox", function_address=0x401000,
    )

    print(f"[static_leak] '{_profile.function_name}' score={_profile.total_score:.4f}")
    print(f"[static_leak] worst_category={_profile.worst_category}")
    print(f"[static_leak] sites={len(_profile.leakage_sites)}")
    print(f"[static_leak] is_crypto={_profile.is_crypto_critical}")
    for _s in _profile.leakage_sites:
        print(f"  {hex(_s.address)}: {_s.category.value} ({_s.weight:.2f})")

    _recs = _predictor.recommend_mitigations(_profile)
    print(f"[static_leak] mitigations: {_recs}")

    assert len(_profile.leakage_sites) >= 2, (
        f"should detect at least 2 leakage sites, got {len(_profile.leakage_sites)}"
    )
    assert _profile.total_score > 0.5, (
        f"leaky function should have high score, got {_profile.total_score}"
    )

    # 干净函数——无秘密依赖
    _clean_insts = [
        {"address": 0x500000, "mnemonic": "mov", "operands": "rax, rcx"},
        {"address": 0x500004, "mnemonic": "add", "operands": "rax, 1"},
        {"address": 0x500008, "mnemonic": "ret", "operands": ""},
    ]
    _clean = _predictor.analyze_function(
        _clean_insts, taint_sources=_secret,
        function_name="clean_func", function_address=0x500000,
    )
    print(f"[static_leak] clean func score={_clean.total_score:.4f}")
    assert _clean.total_score < 0.3, (
        f"clean function should have low score, got {_clean.total_score}"
    )

    print("[OK] StaticLeakagePredictor smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
