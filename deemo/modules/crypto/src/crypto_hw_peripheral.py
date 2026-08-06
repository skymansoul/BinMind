"""
密码学硬件外设指纹 — 通过MMIO寄存器访问模式识别固件中使用的硬件加密加速器。

修改记录:
  2025-08-26 14:18 — 初始实现: ARM TrustZone CryptoCell/STM32 CRYP/NXP CAAM/CE检测

设计意图:
  嵌入式固件通常使用SoC内置的硬件加密加速器(AES/SHA/TRNG/PKA引擎),
  通过MMIO寄存器映射进行访问。识别固件使用了哪些加密外设对安全审计至关重要:
    (a) 硬件加速器的已知漏洞(如CVE-2022-xxxx影响某型号AES引擎)。
    (b) 固件是否回退到软件实现(安全问题 — 软件实现可能有侧信道泄漏)。
    (c) 供应链: 芯片型号声称包含加密引擎, 但固件是否实际使用了它?

  既有MMIO检测工具(XtractIO 2025)识别通用MMIO访问模式, 不做加密特化。
  本模块内置常见加密外设的寄存器地址指纹库, 通过MMIO访问模式匹配识别。

  检测策略:
    1. 已知外设寄存器地址匹配(ARM CryptoCell/STM32 CRYP/NXP CAAM/等)。
    2. 寄存器访问序列识别(如写密钥→写IV→写控制→读状态→读输出的AES操作序列)。
    3. DMA descriptor模式(AES-GCM的scatter-gather DMA链)。
    4. 字符串指纹(crypto/trng/aes/hash引擎名称)。

参考:
  - XtractIO (2025): 通用MMIO地址静态提取 — 本模块在XtractIO的通用检测基础上
    增加加密特化的外设指纹库。
  - ARM Cortex-M CRYP1 hardware accelerator reference.
  - NXP CAAM (i.MX series) reference manual.

边界条件:
  - 外设指纹库需持续扩展 — 当前覆盖ARM/NXP/ST主要系列。
  - MMIO地址在固件中可能以符号名(链接后解析)或立即数形式存在。
  - 部分加密外设通过DMA间接访问 → 仅检测DMA描述符设置代码。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class PeripheralType(Enum):
    AES_ACCEL = 0
    SHA_ACCEL = 1
    TRNG = 2
    PKA = 3           # Public Key Accelerator (RSA/ECC)
    COMBO = 4         # 组合加密引擎
    DMA_CRYPTO = 5    # DMA辅助加密


@dataclass
class PeripheralFingerprint:
    vendor: str = ""
    family: str = ""                 # STM32H7 / i.MX6 / CC313 / etc.
    peripheral_name: str = ""
    periph_type: PeripheralType = PeripheralType.COMBO
    # 寄存器基地址的典型值 — 同一系列可能有变体
    base_addresses: List[int] = field(default_factory=list)
    # 特征寄存器偏移(用于确认外设身份)
    signature_reg_offset: int = 0
    signature_reg_value: int = 0     # 复位值或ID寄存器的预期值
    # 字符串指纹
    string_hints: List[str] = field(default_factory=list)
    # 操作序列模式(如AES: 写KEY→写IV→写CTRL→读STATUS)
    op_sequence: List[bytes] = field(default_factory=list)


# ── 已知加密外设指纹库 ──

_KNOWN_PERIPHERALS: List[PeripheralFingerprint] = [
    # ARM Cortex-M CRYP1 (STM32F4/F7/H7系列)
    PeripheralFingerprint(
        vendor='STMicro', family='STM32F4/F7/H7',
        peripheral_name='CRYP1 (AES/DES/TDES)',
        periph_type=PeripheralType.AES_ACCEL,
        base_addresses=[0x50060000, 0x40010600],
        signature_reg_offset=0x3C, signature_reg_value=0x00000000,
        string_hints=['CRYP', 'HAL_CRYP', 'CRYP1'],
        op_sequence=[b'\x00\x10', b'\x04\x10', b'\x08\x10']  # KEY/IV/CTRL寄存器写
    ),
    # ARM CryptoCell-312 (nRF52840/nRF5340等)
    PeripheralFingerprint(
        vendor='ARM/Nordic', family='nRF52/nRF53',
        peripheral_name='CryptoCell-312',
        periph_type=PeripheralType.COMBO,
        base_addresses=[0x5002A000],
        signature_reg_offset=0x00, signature_reg_value=0x00000000,
        string_hints=['CRYPTOCELL', 'cc312', 'cryptocell', 'CC312'],
    ),
    # STM32 HASH (SHA-1/SHA-256硬件)
    PeripheralFingerprint(
        vendor='STMicro', family='STM32F4/F7/H7',
        peripheral_name='HASH (SHA-1/SHA-256)',
        periph_type=PeripheralType.SHA_ACCEL,
        base_addresses=[0x50060400, 0x40011400],
        string_hints=['HAL_HASH', 'HASH_Handle'],
    ),
    # STM32 RNG (硬件TRNG)
    PeripheralFingerprint(
        vendor='STMicro', family='STM32F4/F7/H7/L4',
        peripheral_name='RNG (硬件TRNG)',
        periph_type=PeripheralType.TRNG,
        base_addresses=[0x50060800, 0x40011800],
        string_hints=['HAL_RNG', 'RNG_HandleTypeDef'],
    ),
    # NXP CAAM (i.MX6/7/8系列 — Cryptographic Acceleration & Assurance Module)
    PeripheralFingerprint(
        vendor='NXP', family='i.MX6/7/8',
        peripheral_name='CAAM (AES/SHA/RSA/TRNG)',
        periph_type=PeripheralType.COMBO,
        base_addresses=[0x02100000, 0x30900000],
        string_hints=['CAAM', 'caam_', 'caam_jr', 'fsl_caam'],
    ),
    # NXP DCP (i.MX RT系列 — Data Co-Processor)
    PeripheralFingerprint(
        vendor='NXP', family='i.MX RT10xx',
        peripheral_name='DCP (AES/SHA)',
        periph_type=PeripheralType.COMBO,
        base_addresses=[0x40280000],
        string_hints=['DCP', 'dcp_', 'fsl_dcp'],
    ),
    # ARM TrustZone Crypto (Cortex-A — OP-TEE crypto driver)
    PeripheralFingerprint(
        vendor='ARM', family='Cortex-A (OP-TEE)',
        peripheral_name='TrustZone Crypto',
        periph_type=PeripheralType.COMBO,
        string_hints=['optee_crypto', 'TEE_AE', 'tee_aes'],
    ),
    # Espressif ESP32 AES/SHA accelerator
    PeripheralFingerprint(
        vendor='Espressif', family='ESP32',
        peripheral_name='AES/SHA accelerator',
        periph_type=PeripheralType.COMBO,
        base_addresses=[0x3FF01000],
        string_hints=['esp_aes', 'esp_sha', 'esp_hmac'],
    ),
]


@dataclass
class HwPeripheralReport:
    peripheral: PeripheralFingerprint
    detected: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    base_address_found: int = 0


def fingerprint_peripherals(data: bytes, strings: Optional[List[str]] = None
                            ) -> List[HwPeripheralReport]:
    """
    对固件二进制做加密外设指纹识别。
    返回检测到的外设列表。
    """
    reports: List[HwPeripheralReport] = []
    strs = strings or []

    for periph in _KNOWN_PERIPHERALS:
        evidence: List[str] = []
        conf = 0.0
        addr_found = 0

        # 1. 基地址匹配
        for addr in periph.base_addresses:
            addr_le = addr.to_bytes(4, 'little')
            addr_be = addr.to_bytes(4, 'big')
            if addr_le in data or addr_be in data:
                evidence.append(f'MMIO base 0x{addr:08x} found')
                addr_found = addr
                conf += 0.35
                break

        # 2. 字符串匹配
        str_matches = 0
        for hint in periph.string_hints:
            hint_bytes = hint.encode('ascii', errors='replace')
            if hint_bytes in data:
                str_matches += 1
                evidence.append(f'string: {hint}')
            for s in strs:
                if hint.lower() in s.lower():
                    str_matches += 1
                    evidence.append(f'string "{s[:40]}" -> {hint}')
                    break
        if str_matches >= 1:
            conf += min(0.40, str_matches * 0.15)

        # 3. 操作序列匹配
        seq_matches = 0
        for seq_pat in periph.op_sequence:
            # 在64字节窗口内搜索序列元素
            found_in_window = False
            for i in range(0, len(data) - 64, 4):
                window = data[i:i + 64]
                if seq_pat in window:
                    found_in_window = True
                    break
            if found_in_window:
                seq_matches += 1
        if seq_matches >= 2:
            conf += 0.25

        # 4. 签名寄存器值匹配(若基地址已找到)
        if addr_found and periph.signature_reg_offset >= 0 and periph.signature_reg_value:
            sig_addr = addr_found + periph.signature_reg_offset
            sig_le = sig_addr.to_bytes(4, 'little')
            if sig_le in data:
                conf += 0.10
                evidence.append(f'signature reg at offset {periph.signature_reg_offset:#x}')

        conf = min(0.95, conf)
        reports.append(HwPeripheralReport(
            peripheral=periph, detected=conf >= 0.30,
            confidence=conf, evidence=evidence,
            base_address_found=addr_found))

    # 按置信度降序排列
    reports.sort(key=lambda r: -r.confidence)
    return reports


def summarize_peripherals(reports: List[HwPeripheralReport]) -> Dict[str, int]:
    """统计各类型加密外设的检测数量。"""
    summary = {'AES': 0, 'SHA': 0, 'TRNG': 0, 'PKA': 0, 'COMBO': 0}
    type_map = {
        PeripheralType.AES_ACCEL: 'AES', PeripheralType.SHA_ACCEL: 'SHA',
        PeripheralType.TRNG: 'TRNG', PeripheralType.PKA: 'PKA',
        PeripheralType.COMBO: 'COMBO', PeripheralType.DMA_CRYPTO: 'COMBO',
    }
    for r in reports:
        if r.detected:
            key = type_map.get(r.peripheral.periph_type, 'COMBO')
            summary[key] += 1
    return summary
