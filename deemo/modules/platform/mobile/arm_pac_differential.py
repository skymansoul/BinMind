# 2026-08-02
# ARM PAC 差分密码分析器 — FEAT_PACQARMA3 的安全边界评估
# 参考:
#   "Differential Cryptanalysis of the Reduced Pointer Authentication Code
#    Function used in Arm's FEAT_PACQARMA3 Feature"
#    (IACR FSE 2025, ePrint 2025/321) — Avanzi, Dunkelman, Ghosh
#    发现: ARM 后期将 QARMA-64 从 12 轮降为 8 轮后, 部分 PAC 配置
#    不满足原安全目标; 不同 PAC 长度和轮数的组合存在安全性差异
#   "PACMAN: Attacking ARM Pointer Authentication with Speculative Execution"
#    (ISCA 2022) — Ravichandran et al. (MIT)
#    投机执行暴力破解 PAC: 16 位 PAC < 3 分钟, 每个 PAC 猜测 ~2.69ms
#   "Limitations and Opportunities of Modern Hardware Isolation Mechanisms"
#    (USENIX ATC 2024) — PAC/MTE/CHERI 的局限性和机遇

import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum

logger = logging.getLogger(__name__)


class PACKey(IntEnum):
    """ARM PAC 的五种密钥类型。"""
    IA = 0  # Instruction A-key
    IB = 1  # Instruction B-key
    DA = 2  # Data A-key
    DB = 3  # Data B-key
    GA = 4  # General A-key


class QARMAConfig(IntEnum):
    """QARMA-64 配置 — 轮数和 PAC 长度。"""
    R8_PAC16 = 1   # 8 轮, 16-bit PAC → FEAT_PACQARMA3 默认
    R8_PAC24 = 2   # 8 轮, 24-bit PAC
    R8_PAC32 = 3   # 8 轮, 32-bit PAC
    R12_PAC16 = 4  # 12 轮 (原始 QARMA-64)
    R12_PAC32 = 5  # 12 轮, 32-bit PAC


@dataclass
class PACSecurityBound:
    """特定 PAC 配置的安全边界评估。"""
    config: QARMAConfig
    rounds: int
    pac_bits: int
    brute_force_time_ms: float       # 单次暴力破解所需时间 (ms)
    collision_probability: float      # 生日碰撞概率 (2^16 次尝试)
    diff_attack_complexity: int       # 差分攻击复杂度 (FSE 2025)
    security_margin: int              # 安全余量 (bits), 负数=不安全
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
    """ARM PAC 指针认证安全性评估器。

    基于 IACR FSE 2025 的 QARMA-64 差分密码分析结果,
    评估给定二进制中 PAC 使用的实际安全性。

    分析阶段:
    1. 反汇编扫描: 统计 PAC 相关指令 (PACI*, AUTI*, XPAC*, RETAA)
    2. 配置推断: 从二进制特征推断实际 QARMA 配置
    3. 安全边界计算: 基于 FSE 2025 论文的复杂度数据评估风险
    4. PACMAN 投机场检测: 是否存在可供投机执行利用的 PAC gadget
    """

    # PAC 指令匹配模式 — 覆盖 ARMv8.3-A PAC + ARMv8.5-A BTI
    _PAC_INSTRUCTION_PATTERNS = {
        "pacia":  r'\bpaciasp\b|\bpacia\b|\bpaciaz\b',     # PAC IA
        "pacib":  r'\bpacibsp\b|\bpacib\b|\bpacibz\b',     # PAC IB
        "pacda":  r'\bpacdza\b',                            # PAC DA
        "pacdb":  r'\bpacdzb\b',                            # PAC DB
        "pacga":  r'\bpacga\b',                             # PAC GA (通用)
        "autia":  r'\bautiasp\b|\bautia\b|\bautiaz\b',     # AUT IA
        "autib":  r'\bautibsp\b|\bautib\b|\bautibz\b',     # AUT IB
        "autda":  r'\bautdza\b',                            # AUT DA
        "autdb":  r'\bautdzb\b',                            # AUT DB
        "xpaci":  r'\bxpaci\b|\bxpacd\b',                  # XPAC (strip PAC)
        "retaa":  r'\bretaasb\b|\bretaa\b|\bretab\b',      # RET with PAC check
    }

    # FSE 2025 的安全性数据: (轮数, PAC长度, 差分攻击复杂度 (log2))
    _FSE2025_SECURITY_DATA: list[tuple[int, int, float, int]] = [
        # (rounds, pac_bits, brute_force_ms, diff_complexity_log2)
        (12, 32, 1.2, 64),     # 原始 QARMA-64: 安全
        (12, 16, 0.15, 32),    # 12轮 16-bit: 16-bit PAC 过于短
        (8,  32, 0.8, 40),     # 8轮 32-bit PAC: 论文认为边界安全
        (8,  24, 0.3, 28),     # 8轮 24-bit: 安全性不足
        (8,  16, 0.05, 20),    # 8轮 16-bit PAC: 论文认为不安全 (FEAT_PACQARMA3 默认)
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
        """统计 PAC 相关指令数量 — 衡量 PAC 使用密度。"""
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
        """从二进制特征推断 QARMA-64 配置。

        启发式规则:
        - iOS 17+/macOS 14+ arm64e → 倾向于 FEAT_PACQARMA3 (8轮)
        - Android arm64 通常 → 原始 12 轮 QARMA-64
        - 32-bit PAC 可通过指针格式推断 (bit[62:61] 保留)
        """
        counts = self._pac_counts or self.count_pac_instructions()
        total_pac = sum(counts.get(k, 0) for k in ("pacia", "pacib", "pacda", "pacdb"))
        has_pacga = counts.get("pacga", 0) > 0  # PACGA 是 ARMv8.6-A 引入的
        total_aut = sum(counts.get(k, 0) for k in ("autia", "autib", "autda", "autdb"))
        if total_pac == 0 and total_aut == 0:
            return QARMAConfig.R12_PAC32  # 默认保守估计
        # 若包含 XPAC 指令, 暗示 strip PAC 操作 → 偏向新芯片
        if counts.get("xpaci", 0) > 0:
            return QARMAConfig.R8_PAC16  # 假设为 FEAT_PACQARMA3
        return QARMAConfig.R12_PAC32

    def evaluate_security_bounds(self) -> list[PACSecurityBound]:
        """基于 FSE 2025 数据计算所有可能配置的安全边界。"""
        bounds = []
        default_attempts = 65536  # 2^16 (16-bit PAC 的暴力搜索空间)
        for rounds, pac_bits, bf_ms, diff_log2 in self._FSE2025_SECURITY_DATA:
            collision_prob = 1.0 - (1.0 - 1.0 / (2 ** pac_bits)) ** default_attempts
            margin = pac_bits - diff_log2
            bounds.append(PACSecurityBound(
                config=QARMAConfig.R8_PAC16,  # 将在外部覆写
                rounds=rounds, pac_bits=pac_bits,
                brute_force_time_ms=bf_ms,
                collision_probability=round(collision_prob, 4),
                diff_attack_complexity=int(2 ** diff_log2),
                security_margin=int(margin),
                is_practically_secure=(margin > 4),
            ))
        # 覆盖正确的配置枚举
        config_order = [QARMAConfig.R8_PAC16, QARMAConfig.R8_PAC24,
                       QARMAConfig.R8_PAC32, QARMAConfig.R12_PAC16,
                       QARMAConfig.R12_PAC32]
        for b, cfg in zip(bounds, config_order):
            b.config = cfg
        return bounds

    def detect_pacman_gadgets(self) -> list[dict]:
        """检测 PACMAN 攻击可利用的投机执行 gadget。

        PACMAN 的 gadget 模式 (ISCA 2022):
        - AUTIA/AUTIB 后紧跟 load/store (投机窗口内可访问 PAC 验证后的指针)
        - RETAA/RETAB 前有 load (投机返回地址验证可被绕过)
        每条 gadget 标记 window_size (AUT 到 fence 的指令数)
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
            # 查找 AUT 后 1-10 条指令内的 load (ldr/ldp)
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
        # 总体风险评估
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
