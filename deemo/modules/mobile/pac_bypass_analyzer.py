SignedGadgetFinder=None
from typing import Dict, List, Optional, Any, Tuple, Set
"""
ARM PAC bypass surface analysis.
Maps signing/verification gadgets, strip chains, signing oracles, brute-force viability.
ARM64e (v8.3-A+) target.
"""

import struct
import re
from dataclasses import dataclass

# ARM64 PAC指令集编码（hint-space）
PAC_OPCODES = {
    0xDAC123E0: "PACIA",    # 通用指针认证，A-key，双寄存器操作数
    0xDAC12BE0: "PACIASP",  # 栈指针认证，A-key，隐式SP操作数
    0xDAC143E0: "PACIB",
    0xDAC14BE0: "PACIBSP",
    0xDAC163E0: "PACDA",
    0xDAC16BE0: "PACDASP",
    0xDAC183E0: "PACDB",
    0xDAC18BE0: "PACDBSP",
    0xDAC103E0: "PACGA",   # 通用PAC生成，三寄存器，输出至Xd
}

AUTH_OPCODES = {
    0xDAC123C0: "AUTIA",
    0xDAC12BC0: "AUTIASP",
    0xDAC143C0: "AUTIB",
    0xDAC14BC0: "AUTIBSP",
    0xDAC163C0: "AUTDA",
    0xDAC16BC0: "AUTDASP",
    0xDAC183C0: "AUTDB",
    0xDAC18BC0: "AUTDBSP",
    0xDAC103C0: "AUTGA",
}

XPAC_OPCODES = {
    0xDAC143E0: "XPACI",
    0xDAC147E0: "XPACD",
    0xDAC14FE0: "XPACLRI",  # 返回地址剥离，清除PAC签名
}

RETAA = 0xD65F0BFF  # 返回并A-key认证
RETAB = 0xD65F0FFF  # 返回并B-key认证
BRAA  = 0xD61F0800  # 分支至A-key认证指针
BRAB  = 0xD61F0C00  # 分支至B-key认证指针
BLRAA = 0xD63F0800  # 带链接分支至A-key认证指针
BLRAB = 0xD63F0C00  # 带链接分支至B-key认证指针

# 无签名返回编码
RET_UNSIGNED = 0xD65F0BFF  # RET原始编码，后续mask校验与RETAA区分


@dataclass
class PACGadget:
    address: int
    kind: str           # gadget分类标签：sign/auth/strip/branch_auth
    mnemonic: str
    regs: str           # 操作寄存器描述，如"x0, sp"


@dataclass
class PACLeak:
    address: int
    kind: str           # 泄露类型标签：signing_oracle/forged_pointer/strip_gadget
    description: str


@dataclass
class AnalysisResult:
    signing_gadgets: list[PACGadget]
    auth_gadgets: list[PACGadget]
    strip_gadgets: list[PACGadget]
    branch_auth_gadgets: list[PACGadget]
    leaks: list[PACLeak]
    entropy_assessment: str


def _decode_arm64_insn(word: int) -> tuple[str, str]:
    """解析32-bit指令字，匹配已知PAC操作码。"""
    # 掩除寄存器域以提取基操作码
    base = word & 0xFFFFFFE0
    if base in PAC_OPCODES:
        rd = word & 0x1F
        rn = (word >> 5) & 0x1F
        return PAC_OPCODES[base], f"x{rd}, x{rn}"
    if base in AUTH_OPCODES:
        rd = word & 0x1F
        rn = (word >> 5) & 0x1F
        return AUTH_OPCODES[base], f"x{rd}, x{rn}"
    if base in XPAC_OPCODES:
        rd = word & 0x1F
        return XPAC_OPCODES[base], f"x{rd}"
    if base == (RETAA & 0xFFFFFFE0):
        return "RETAA", ""
    if base == (RETAB & 0xFFFFFFE0):
        return "RETAB", ""
    if base == (BRAA & 0xFFE0FFE0):
        rn = (word >> 5) & 0x1F
        return "BRAA", f"x{rn}"
    if base == (BRAB & 0xFFE0FFE0):
        rn = (word >> 5) & 0x1F
        return "BRAB", f"x{rn}"
    if base == (BLRAA & 0xFFE0FFE0):
        rn = (word >> 5) & 0x1F
        return "BLRAA", f"x{rn}"
    if base == (BLRAB & 0xFFE0FFE0):
        rn = (word >> 5) & 0x1F
        return "BLRAB", f"x{rn}"
    return "", ""


def _entropy_assessment(n_sign: int, n_auth: int, n_strip: int) -> str:
    """估算PAC暴力绕过所需搜索代价。"""
    # PAC宽度16-bit，理论搜索空间2^16
    # 每发现一个签名神谕，有效搜索空间对应收缩
    effective_entropy = 16
    if n_strip > 0:
        # strip gadget可构造未认证指针，降低有效熵
        effective_entropy -= min(n_strip * 2, 14)

    if n_sign > 0 and n_auth == 0:
        return (f"~{2**effective_entropy} attempts needed. "
                f"Signing gadgets found ({n_sign}) without verification: "
                f"signing oracle may enable brute-force bypass (PACGA collision in ~{2**(effective_entropy//2)} tries).")

    if n_auth < n_sign:
        return (f"~{2**effective_entropy} brute-force attempts. "
                f"Fewer auth gadgets ({n_auth}) than sign ({n_sign}): "
                f"some pointers never verified. Partial bypass feasible.")

    return (f"~{2**effective_entropy} brute-force attempts. "
            f"Balanced sign/auth coverage ({n_sign}/{n_auth}). "
            f"Brute-force unlikely without additional oracle.")


class PACBypassAnalyzer:
    """ARM64e二进制PAC绕过可行性评估。"""

    def __init__(self):
        self._signing: list[PACGadget] = []
        self._auth: list[PACGadget] = []
        self._strip: list[PACGadget] = []
        self._branch_auth: list[PACGadget] = []
        self._leaks: list[PACLeak] = []

    def analyze(self, binary: bytes) -> list[PACLeak]:
        """全量扫描PAC相关gadget，输出绕过可行性判定。"""
        self._signing.clear()
        self._auth.clear()
        self._strip.clear()
        self._branch_auth.clear()
        self._leaks.clear()

        for i in range(0, len(binary) - 3, 4):
            word = struct.unpack_from("<I", binary, i)[0]
            mnem, regs = _decode_arm64_insn(word)
            if not mnem:
                continue

            if "PAC" in mnem and "AUTH" not in mnem and "XPAC" not in mnem:
                g = PACGadget(address=i, kind="sign", mnemonic=mnem, regs=regs)
                self._signing.append(g)
                # PACGA配合用户可控修饰符构成签名神谕
                if "PACGA" in mnem:
                    self._leaks.append(PACLeak(
                        address=i, kind="signing_oracle",
                        description=f"PACGA at {i:#x} allows arbitrary PAC generation"))

            elif "AUTH" in mnem:
                g = PACGadget(address=i, kind="auth", mnemonic=mnem, regs=regs)
                self._auth.append(g)

            elif "XPAC" in mnem:
                g = PACGadget(address=i, kind="strip", mnemonic=mnem, regs=regs)
                self._strip.append(g)
                self._leaks.append(PACLeak(
                    address=i, kind="strip_gadget",
                    description=f"XPAC at {i:#x}: pointer stripping gadget"))

            elif mnem in ("BRAA", "BRAB", "BLRAA", "BLRAB", "RETAA", "RETAB"):
                g = PACGadget(address=i, kind="branch_auth", mnemonic=mnem, regs=regs)
                self._branch_auth.append(g)

        return self._leaks

    @property
    def result(self) -> AnalysisResult:
        return AnalysisResult(
            signing_gadgets=self._signing,
            auth_gadgets=self._auth,
            strip_gadgets=self._strip,
            branch_auth_gadgets=self._branch_auth,
            leaks=self._leaks,
            entropy_assessment=_entropy_assessment(
                len(self._signing), len(self._auth), len(self._strip)))


def create_pac_bypass_analyzer() -> PACBypassAnalyzer:
    return PACBypassAnalyzer()
PACBypassPath=None
PACSignatureDetector=None
