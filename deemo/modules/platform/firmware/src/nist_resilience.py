# 2026-08-02
# NIST SP 800-193 固件平台弹性评估 — 独立于 UEFI analyzer 的增强版
# 覆盖三个维度 (保护/检测/恢复) 的完整指标矩阵
# 参考:
#   NIST SP 800-193 "Platform Firmware Resiliency Guidelines" (2018, updated 2024)
#   "Bringing Forensic Readiness to Modern Computer Firmware" (arXiv 2505.05697, 2025)
#     提出的取证就绪性评估包含 firmware recovery readiness 维度
#   TCG Cyber Resilient Technology (CyRes) 工作组草案

import re
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ResilienceDimension(Enum):
    PROTECTION = "protection"
    DETECTION = "detection"
    RECOVERY = "recovery"


class MaturityLevel(Enum):
    """NIST 800-193 成熟度级别 — 从无措施到全自动化恢复。"""
    NONE = 0       # 无可检测措施
    BASIC = 1      # 基础保护存在，但无自动恢复
    ADEQUATE = 2   # 满足最低合规要求
    ENHANCED = 3   # 超出合规要求，含主动监控
    RESILIENT = 4  # 全自动检测 + 恢复 + 取证审计


@dataclass
class ResilienceIndicator:
    name: str
    dimension: ResilienceDimension
    description: str = ""
    detected: bool = False
    evidence: str = ""
    maturity_contribution: int = 0  # 0-4, 本指标对成熟度的加分


@dataclass
class ResilienceAssessment:
    firmware_path: str = ""
    protection_score: float = 0.0     # 0.0-1.0
    detection_score: float = 0.0
    recovery_score: float = 0.0
    overall_maturity: MaturityLevel = MaturityLevel.NONE
    indicators: list = field(default_factory=list)
    missing_critical: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    nist_800_193_compliant: bool = False


# ── 保护维度指标 ──
# 基于 NIST 800-193 Section 4.1: 固件应保护关键平台固件组件
_PROTECTION_INDICATORS: list[dict] = [
    {"sig": rb"SmmLockSmram|SMM_LOCK", "name": "SMRAM Lock", "weight": 4,
     "desc": "SMRAM 在 DXE 阶段结束后被锁定，防止 ring0 代码篡改 SMM"},
    {"sig": rb"BiosLock|BIOS_LOCK", "name": "BIOS Lock", "weight": 3,
     "desc": "BIOS Write Enable (BIOSWE) 在 Boot 后被置位禁止"},
    {"sig": rb"BiosWriteEnable|BiosWriteDisable", "name": "BIOS Write Disable", "weight": 3,
     "desc": "SPI flash 写保护已激活"},
    {"sig": rb"TsegLock|TSEG_LOCK", "name": "TSEG Lock", "weight": 3,
     "desc": "Top of Memory Segment 已锁定，保护 SMRAM 区域"},
    {"sig": rb"SmmRstLock|SMM_RESET", "name": "SMM Reset Lock", "weight": 2,
     "desc": "SMM 重启向量被锁定，阻止恶意 SMM 代码劫持启动流程"},
    {"sig": rb"SecureBoot|SECURE_BOOT|PKDefault", "name": "Secure Boot", "weight": 4,
     "desc": "UEFI Secure Boot 已配置并启用"},
    {"sig": rb"FvbReadLock|FvbWriteLock|VarLock", "name": "Firmware Volume Lock", "weight": 2,
     "desc": "固件卷的读写锁定机制存在"},
    {"sig": rb"PlatformFirmwareProtection", "name": "Platform Firmware Protection", "weight": 2,
     "desc": "平台固件保护寄存器已配置"},
]

# ── 检测维度指标 ──
_DETECTION_INDICATORS: list[dict] = [
    {"sig": rb"ValidateFv|VerifyFv|FvCheckSum", "name": "Firmware Volume Validation", "weight": 4,
     "desc": "固件卷在加载前进行完整性校验"},
    {"sig": rb"Hash2Extend|Tpm2PcrExtend|MeasurePcr", "name": "TPM PCR Extension", "weight": 3,
     "desc": "关键固件组件被度量至 TPM PCR"},
    {"sig": rb"Hash2|SHA256|SHA384", "name": "Cryptographic Hashing", "weight": 2,
     "desc": "固件使用 SHA-256 或更强度量"},
    {"sig": rb"FvbAuthentication|FvbSigned|FvAuth", "name": "FV Authentication", "weight": 4,
     "desc": "固件卷在加载前进行数字签名验证"},
    {"sig": rb"CapsuleHash|CapsuleVerify|VerifyCapsule", "name": "Capsule Verification", "weight": 3,
     "desc": "固件更新胶囊的完整性/签名校验"},
    {"sig": rb"BootGuard|BPM|BootPolicyManifest", "name": "Intel Boot Guard", "weight": 4,
     "desc": "Intel Boot Guard 启动策略清单验证"},
    {"sig": rb"ImageVerification|DxeImageVerification", "name": "DXE Image Verification", "weight": 3,
     "desc": "DXE 驱动的镜像签名验证"},
]

# ── 恢复维度指标 ──
_RECOVERY_INDICATORS: list[dict] = [
    {"sig": rb"RecoveryMode|RecoveryFv", "name": "Recovery Mode", "weight": 4,
     "desc": "检测到固件恢复模式入口"},
    {"sig": rb"SelfTest|Bist|PowerOnSelfTest", "name": "Firmware Self-Test", "weight": 2,
     "desc": "固件自检机制存在"},
    {"sig": rb"BootIntegrityCheck|BootGuardStartup", "name": "Boot Integrity Check", "weight": 3,
     "desc": "启动完整性检查在每次启动时执行"},
    {"sig": rb"A/BUpdate|A_B_UPDATE", "name": "A/B Update Scheme", "weight": 4,
     "desc": "双重固件分区 (A/B) 回滚方案"},
    {"sig": rb"FirmwareBackup|FwBackup|RecoveryBackup", "name": "Firmware Backup", "weight": 3,
     "desc": "固件的已知良好备份存在"},
    {"sig": rb"ImageRollback|RollbackProtect", "name": "Rollback Protection", "weight": 4,
     "desc": "固件回滚保护已启用 (SVN/anti-rollback counter)"},
    {"sig": rb"CapsuleRecovery|RecoveryCapsule", "name": "Capsule Recovery", "weight": 3,
     "desc": "可通过 UEFI Capsule 进行固件恢复"},
]


class NIST800193Assessor:
    """NIST SP 800-193 固件弹性评估器 — 独立于 UEFI analyzer 的专用模块。

    对固件二进制执行三阶段评估：
    1. 静态扫描 → 发现弹性指标 (签名匹配)
    2. 加权计分 → 每个维度的覆盖率
    3. 成熟度映射 → NONE→BASIC→ADEQUATE→ENHANCED→RESILIENT

    与 uefi_runtime_security_analyzer 中 _assess_nist_800_193 的区别：
    该函数在 UEFI 模块级别运行且依赖 PE 导入分析；
    NIST800193Assessor 直接对固件二进制做字节级扫描，不依赖 PE 解析，
    因此可应用于非 UEFI 固件 (如 U-Boot, coreboot, LinuxBoot)。
    """

    def __init__(self, firmware_data: bytes, firmware_path: str = ""):
        self._data = firmware_data
        self._path = firmware_path
        self._indicators: list[ResilienceIndicator] = []
        self._build_indicator_list()

    def _build_indicator_list(self):
        for dim, indicator_list in [
            (ResilienceDimension.PROTECTION, _PROTECTION_INDICATORS),
            (ResilienceDimension.DETECTION, _DETECTION_INDICATORS),
            (ResilienceDimension.RECOVERY, _RECOVERY_INDICATORS),
        ]:
            for item in indicator_list:
                self._indicators.append(ResilienceIndicator(
                    name=item["name"], dimension=dim,
                    description=item["desc"],
                    maturity_contribution=item["weight"]
                ))

    def assess(self) -> ResilienceAssessment:
        for ind in self._indicators:
            self._scan_indicator(ind)
        return self._compute_assessment()

    # 扫描单个指标: 在所有固件数据中查找对应签名
    def _scan_indicator(self, ind: ResilienceIndicator):
        # 反向查找: 从 indicator 列表中找匹配的签名
        for dim_list, sig_source in [
            (ResilienceDimension.PROTECTION, _PROTECTION_INDICATORS),
            (ResilienceDimension.DETECTION, _DETECTION_INDICATORS),
            (ResilienceDimension.RECOVERY, _RECOVERY_INDICATORS),
        ]:
            if ind.dimension != dim_list:
                continue
            for item in sig_source:
                if item["name"] == ind.name:
                    sig: bytes = item["sig"]
                    matches = list(re.finditer(sig, self._data, re.IGNORECASE))
                    if matches:
                        ind.detected = True
                        # 取第一个匹配点附近的上下文
                        start = max(0, matches[0].start() - 16)
                        end = min(len(self._data), matches[0].end() + 16)
                        ind.evidence = self._data[start:end].hex()
                    break

    def _compute_assessment(self) -> ResilienceAssessment:
        dims = {d: [] for d in ResilienceDimension}
        for ind in self._indicators:
            dims[ind.dimension].append(ind)
        p_score = self._dim_score(dims[ResilienceDimension.PROTECTION])
        d_score = self._dim_score(dims[ResilienceDimension.DETECTION])
        r_score = self._dim_score(dims[ResilienceDimension.RECOVERY])
        missing = [i.name for i in self._indicators
                   if not i.detected and i.maturity_contribution >= 3]
        overall = (p_score + d_score + r_score) / 3.0
        recs = []
        if p_score < 0.6:
            recs.append("保护维度不足: 考虑启用 SMRAM Lock + Secure Boot + SPI Write Protect")
        if d_score < 0.6:
            recs.append("检测维度不足: 考虑集成 TPM PCR 扩展 + FV Authentication")
        if r_score < 0.6:
            recs.append("恢复维度不足: 考虑实现 A/B Update + Rollback Protection")
        level = MaturityLevel.NONE
        if overall >= 0.9:
            level = MaturityLevel.RESILIENT
        elif overall >= 0.7:
            level = MaturityLevel.ENHANCED
        elif overall >= 0.5:
            level = MaturityLevel.ADEQUATE
        elif overall >= 0.25:
            level = MaturityLevel.BASIC
        return ResilienceAssessment(
            firmware_path=self._path,
            protection_score=round(p_score, 2),
            detection_score=round(d_score, 2),
            recovery_score=round(r_score, 2),
            overall_maturity=level,
            indicators=self._indicators,
            missing_critical=missing,
            recommendations=recs,
            nist_800_193_compliant=(level.value >= MaturityLevel.ADEQUATE.value),
        )

    def _dim_score(self, indicators: list[ResilienceIndicator]) -> float:
        total_weight = sum(i.maturity_contribution for i in indicators)
        detected_weight = sum(i.maturity_contribution for i in indicators if i.detected)
        if total_weight == 0:
            return 0.0
        return detected_weight / total_weight


def assess_firmware_resilience(data: bytes, path: str = "") -> ResilienceAssessment:
    return NIST800193Assessor(data, path).assess()
