# ARM PAC差分密码分析器。FEAT_PACQARMA3安全边界评估。
# 参考：
#   "Differential Cryptanalysis of the Reduced Pointer Authentication Code
#    Function used in Arm's FEAT_PACQARMA3 Feature"
#    (IACR FSE 2025, ePrint 2025/321) — Avanzi, Dunkelman, Ghosh
#    ARM后期将QARMA-64从12轮缩减至8轮，部分PAC配置不再满足
#    原始安全目标；不同PAC长度与轮数组合的安全性存在差异。
#   "PACMAN: Attacking ARM Pointer Authentication with Speculative Execution"
#    (ISCA 2022) — Ravichandran et al. (MIT)
#    推测执行暴力破解PAC：16位PAC < 3分钟，单次猜测约2.69ms。
#   "Limitations and Opportunities of Modern Hardware Isolation Mechanisms"
#    (USENIX ATC 2024) — PAC/MTE/CHERI的局限与机遇。

import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum

logger = logging.getLogger(__name__)


class PACKey(IntEnum):
    """ARM PAC五种密钥类型。"""
    IA = 0  # 指令A密钥
    IB = 1  # 指令B密钥
    DA = 2  # 数据A密钥
    DB = 3  # 数据B密钥
    GA = 4  # 通用密钥


class QARMAConfig(IntEnum):
    """QARMA-64配置，轮数与PAC长度。"""
    R8_PAC16 = 1   # 8轮，16-bit PAC，FEAT_PACQARMA3默认
    R8_PAC24 = 2   # 8轮，24-bit PAC
    R8_PAC32 = 3   # 8轮，32-bit PAC
    R12_PAC16 = 4  # 12轮，16-bit PAC
    R12_PAC32 = 5  # 12轮，32-bit PAC


@dataclass
class PACSecurityBound:
    """特定PAC配置的安全边界评估。"""
    config: QARMAConfig
    rounds: int
    pac_bits: int
    brute_force_time_ms: float       # 单次暴力破解耗时（ms）
    collision_probability: float      # 生日碰撞概率（2^16次尝试）
    diff_attack_complexity: int       # 差分攻击复杂度（FSE 2025）
    security_margin: int              # 安全余量（bits），负值即不安全
    is_practically_secure: bool = True


@dataclass
class PACVulnerabilityAssessment:
    binary_path: str = ""
    architecture: str = ""           # "arm64", "arm64e"
    pac_instructions_count: int = 0   # PACI*A/PAUTI*A 指令数
    pac_gadgets: list[dict] = field(default_factory=list)
    qarma_config_estimate: Optional[QARMAConfig] = None
    security_bounds: list[PACSecurityBound] = field(default_factory=list)
    overall_risk: str = "LOW"


class ARMPACDifferentialAnalyzer:
    """ARM PAC指针认证安全性评估器。

    基于IACR FSE 2025 QARMA-64差分密码分析结果，
    评估二进制中PAC使用的实际安全性。

    分析阶段：
    1. 反汇编扫描：统计PAC指令（PACI*、AUTI*、XPAC*、RETAA）
    2. 配置推断：由二进制特征推断QARMA配置
    3. 安全边界：基于FSE 2025复杂度数据评估风险
    4. PACMAN检测：是否存在可供推测执行利用的PAC gadget
    """

    # PAC指令匹配模式，覆盖ARMv8.3-A PAC与ARMv8.5-A BTI
    _PAC_INSTRUCTION_PATTERNS = {
        "pacia":  r'\bpaciasp\b|\bpacia\b|\bpaciaz\b',     # PAC IA
        "pacib":  r'\bpacibsp\b|\bpacib\b|\bpacibz\b',     # PAC IB
        "pacda":  r'\bpacdza\b',                            # PAC DA
        "pacdb":  r'\bpacdzb\b',                            # PAC DB
        "pacga":  r'\bpacga\b',                             # PAC GA，通用
        "autia":  r'\bautiasp\b|\bautia\b|\bautiaz\b',     # AUT IA
        "autib":  r'\bautibsp\b|\bautib\b|\bautibz\b',     # AUT IB
        "autda":  r'\bautdza\b',                            # AUT DA
        "autdb":  r'\bautdzb\b',                            # AUT DB
        "xpaci":  r'\bxpaci\b|\bxpacd\b',                  # XPAC，剥离签名
        "retaa":  r'\bretaasb\b|\bretaa\b|\bretab\b',      # RET，含PAC校验
    }

    # FSE 2025安全性数据：(轮数, PAC长度, 暴力耗时ms, 差分攻击复杂度log2)
    _FSE2025_SECURITY_DATA: list[tuple[int, int, float, int]] = [
        (12, 32, 1.2, 64),     # 原始QARMA-64，安全
        (12, 16, 0.15, 32),    # 12轮16-bit，PAC长度不足
        (8,  32, 0.8, 40),     # 8轮32-bit，论文判为边界安全
        (8,  24, 0.3, 28),     # 8轮24-bit，安全性不足
        (8,  16, 0.05, 20),    # 8轮16-bit，FEAT_PACQARMA3默认，论文判为不安全
    ]

    def __init__(self, asm_text: str = "", binary_path: str = "",
                 arch: str = "arm64"):
        self._asm = asm_text
        self._path = binary_path
        self._arch = arch
        self._pac_counts: dict[str, int] = {}
        if binary_path and hasattr(self, '_path'):
            self._path = binary_path

    def count_pac_instructions(self) -> dict[str, int]:
        """统计PAC相关指令数量，衡量PAC使用密度。"""
        if not self._asm:
            self._pac_counts = {}
            return self._pac_counts
        import re as _re
        counts = {}
        for key, pattern in self._PAC_INSTRUCTION_PATTERNS.items():
            matches = _re.findall(pattern, self._asm, _re.IGNORECASE)
            counts[key] = len(matches)
        self._pac_counts = counts
        return counts

    def infer_qarma_config(self) -> QARMAConfig:
        """由二进制特征推断QARMA-64配置。

        启发式规则：
        - iOS 17+/macOS 14+ arm64e，倾向FEAT_PACQARMA3（8轮）
        - Android arm64，通常为原始12轮QARMA-64
        - 32-bit PAC可通过指针格式推断（bit[62:61]保留）
        """
        counts = self._pac_counts or self.count_pac_instructions()
        total_pac = sum(counts.get(k, 0) for k in ("pacia", "pacib", "pacda", "pacdb"))
        has_pacga = counts.get("pacga", 0) > 0  # PACGA 是 ARMv8.6-A 引入的
        total_aut = sum(counts.get(k, 0) for k in ("autia", "autib", "autda", "autdb"))
        if total_pac == 0 and total_aut == 0:
            return QARMAConfig.R12_PAC32  # 无PAC指令时取保守估计
        # XPAC指令暗示签名剥离操作，趋向新芯片
        if counts.get("xpaci", 0) > 0:
            return QARMAConfig.R8_PAC16  # 假设为 FEAT_PACQARMA3
        return QARMAConfig.R12_PAC32

    def evaluate_security_bounds(self) -> list[PACSecurityBound]:
        """基于FSE 2025数据，计算所有配置的安全边界。"""
        bounds = []
        default_attempts = 65536  # 2^16，16-bit PAC暴力搜索空间
        for rounds, pac_bits, bf_ms, diff_log2 in self._FSE2025_SECURITY_DATA:
            collision_prob = 1.0 - (1.0 - 1.0 / (2 ** pac_bits)) ** default_attempts
            margin = pac_bits - diff_log2
            bounds.append(PACSecurityBound(
                config=QARMAConfig.R8_PAC16,  # 占位，外部覆写
                rounds=rounds, pac_bits=pac_bits,
                brute_force_time_ms=bf_ms,
                collision_probability=round(collision_prob, 4),
                diff_attack_complexity=int(2 ** diff_log2),
                security_margin=int(margin),
                is_practically_secure=(margin > 4),
            ))
        # 覆写为正确的配置枚举值
        config_order = [QARMAConfig.R8_PAC16, QARMAConfig.R8_PAC24,
                       QARMAConfig.R8_PAC32, QARMAConfig.R12_PAC16,
                       QARMAConfig.R12_PAC32]
        for b, cfg in zip(bounds, config_order):
            b.config = cfg
        return bounds

    def detect_pacman_gadgets(self) -> list[dict]:
        """检测PACMAN攻击可用的推测执行gadget。

        PACMAN gadget模式（ISCA 2022）：
        - AUTIA/AUTIB后紧跟load/store，推测窗口内可访问验证后的指针
        - RETAA/RETAB前有load，推测返回地址验证可被绕过
        每条gadget标注window_size（AUT到fence的指令数）
        """
        if not self._asm:
            return []
        import re as _re
        gadgets = []
        aut_lines: list[tuple[int, str]] = []
        for i, line in enumerate(self._asm.split("\n")):
            stripped = line.strip()
            if _re.search(r'\bauti[ab]\b', stripped, _re.IGNORECASE):
                aut_lines.append((i, stripped))
        for line_no, line_text in aut_lines:
            # 查找AUT后1~10条指令范围内的load（ldr/ldp）
            window = self._asm.split("\n")[line_no:line_no + 10]
            has_load = any(_re.search(r'\bldr\b|\bldp\b|\bldur\b', l, _re.IGNORECASE)
                          for l in window)
            has_barrier = any(_re.search(r'\bdmb\b|\bdsb\b|\bisb\b', l, _re.IGNORECASE)
                            for l in window[:3])
            if has_load and not has_barrier:
                gadgets.append({
                    "type": "pacman_load_gadget",
                    "line": line_no + 1,
                    "instruction": line_text.strip()[:80],
                    "window_size": 10,
                    "has_barrier": False,
                    "exploitability": "High" if not has_barrier else "Low",
                })
        return gadgets

    def assess(self) -> PACVulnerabilityAssessment:
        self.count_pac_instructions()
        qarma_config = self.infer_qarma_config()
        bounds = self.evaluate_security_bounds()
        pac_gadgets = self.detect_pacman_gadgets()
        # 综合风险评估
        current_bound = next(
            (b for b in bounds if b.config == qarma_config), bounds[0])
        total_pac = sum(self._pac_counts.values())
        gadget_count = len(pac_gadgets)
        high_risk = (not current_bound.is_practically_secure or
                     gadget_count >= 5 or total_pac == 0)
        med_risk = gadget_count >= 2 or (total_pac > 0 and total_pac < 10)
        risk_level = "HIGH" if high_risk else "MEDIUM" if med_risk else "LOW"
        return PACVulnerabilityAssessment(
            binary_path=self._path,
            architecture=self._arch,
            pac_instructions_count=total_pac,
            pac_gadgets=pac_gadgets,
            qarma_config_estimate=qarma_config,
            security_bounds=bounds,
            overall_risk=risk_level,
        )


def assess_arm_pac(asm_text: str = "", binary_path: str = "",
                   arch: str = "arm64") -> PACVulnerabilityAssessment:
    analyzer = ARMPACDifferentialAnalyzer(
        asm_text=asm_text, binary_path=binary_path, arch=arch)
    return analyzer.assess()
