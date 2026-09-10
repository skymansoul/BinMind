"""
密码学伪装检测 — 检测被故意伪装为普通代码的密码学实现(或反之)。

设计意图:
  恶意软件常伪装其密码学实现以逃避检测:
    (a) S-box不是以静态表存储, 而是在运行时通过数学公式动态计算。
    (b) 轮常量不是以立即数形式, 而是从π/e/sqrt(2)逐位计算。
    (c) 密码学代码被打乱并隐藏在看似合法的UI/日志/配置代码中。

  另一方面, 非密码学代码也可能被误报为密码学:
    (d) 大查找表(如字体/Unicode映射/图形调色板)可能被误认为S-box。
    (e) JPEG压缩的DCT矩阵看起来像密码学常量。

  本模块识别两类伪装:
    TYPE_A (隐蔽密码学): 密码学被隐藏 — 动态S-box/OTF常量/代码混淆。
    TYPE_B (假阳性排除): 非密码学被误报 — 字体表/校验和/压缩表。

  检测策略(4个信号):
    S1 (OTF S-box): 在代码段检测到GF(2^8)乘法+仿射变换序列→动态S-box计算。
    S2 (常量导出): π/e/sqrt(2)的逐位展开代码→运行时轮常量导出。
    S3 (代码结构异常): 密码学代码被拆散+填充NOP/垃圾指令→混淆伪装。
    S4 (假阳性排除): 高频字节值+低熵→字体表; 重复数据→校验和表。

  - otf_sbox_detector (本模块): 在线S-box生成检测 — 本模块扩展为更广义的伪装检测。
  - Collberg et al.: 代码混淆分类 — 控制流/数据/布局混淆。
  - Obfuscator-LLVM: 常见混淆pass — 指令替换/虚假控制流/控制流平坦化。

边界条件:
  - 伪装检测是高假阳性率任务 — 需要多信号共存才能做出可靠判定。
  - TYPE_B假阳性排除需要理解上下文 — 仅凭字节模式难以区分S-box和字体表。
  - 高级伪装(如全同态加密混淆)超出当前检测能力。
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class CamouflageSignal:
    signal_type: str = ""          # HIDDEN_CRYPTO / FALSE_POSITIVE / OBFUSCATION
    description: str = ""
    location: int = 0
    confidence: float = 0.0
    evidence: str = ""

@dataclass
class CamouflageReport:
    binary_name: str = ""
    signals: List[CamouflageSignal] = field(default_factory=list)
    hidden_crypto_count: int = 0
    false_positive_count: int = 0
    obfuscation_count: int = 0
    overall_assessment: str = ""

# S1: OTF S-box检测(动态生成)

def _detect_otf_sbox_generation(data: bytes) -> List[CamouflageSignal]:
    """
    检测动态S-box生成: GF(2^8)乘法+仿射变换。
    表现为: 循环中mul(0xF7+ModRM)+xor(0x31/0x33)+移位(0xC0-0xD3)。
    """
    signals: List[CamouflageSignal] = []
    # 在256字节窗口内搜索: 至少5次mul + 5次xor + 2次shift → GF(2^8)运算
    for start in range(0, len(data) - 512, 64):
        window = data[start:start + 512]
        mul_count = window.count(b'\xF7') + window.count(b'\x0F\xAF')
        xor_count = sum(1 for i in range(len(window) - 1)
                        if window[i] in (0x31, 0x33, 0x35))
        shift_count = sum(1 for i in range(len(window) - 1)
                          if 0xC0 <= window[i] <= 0xD3)
        if mul_count >= 3 and xor_count >= 5 and shift_count >= 2:
            signals.append(CamouflageSignal(
                signal_type='HIDDEN_CRYPTO',
                description=f'疑似动态S-box生成: {mul_count}mul + {xor_count}xor + {shift_count}shift',
                location=start,
                confidence=min(0.80, 0.40 + (mul_count + xor_count) * 0.03),
                evidence=f'GF(2^8)操作密集区域 @0x{start:x}'))

    return signals[:5]

# S2: 常量导出检测

_CONSTANT_DERIVATION_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'3.1415926535', 'π literal → possible NUMS constant derivation', 0.60),
    (b'2.7182818284', 'e literal → possible NUMS constant derivation', 0.60),
    (b'1.4142135623', '√2 literal → possible NUMS constant derivation', 0.60),
    (b'1.6180339887', 'φ (golden ratio) → possible NUMS constant derivation', 0.60),
    (b'nothing_up_my_sleeve', 'NUMS keyword → explicit intent', 0.85),
    (b'nothing-up-my-sleeve', 'NUMS keyword → explicit intent', 0.85),
]

def _detect_constant_derivation(data: bytes) -> List[CamouflageSignal]:
    signals: List[CamouflageSignal] = []
    for pat, desc, conf in _CONSTANT_DERIVATION_PATTERNS:
        pos = data.find(pat)
        if pos != -1:
            signals.append(CamouflageSignal(
                signal_type='HIDDEN_CRYPTO',
                description=f'NUMS常量导出代码: {desc}',
                location=pos, confidence=conf,
                evidence=f'字符串 @0x{pos:x}: {pat.decode("ascii", errors="replace")}'))
    return signals

# S3: 混淆检测

def _detect_code_obfuscation(data: bytes) -> List[CamouflageSignal]:
    """
    检测代码混淆伪装: 异常的NOP密度/jmp链/垃圾指令插入模式。
    """
    signals: List[CamouflageSignal] = []
    window = data[:min(len(data), 0x10000)]

    # NOP sled检测: 连续NOP(0x90)>16字节 → 典型的缓冲区溢出或混淆填充
    nop_runs = []
    run_start = -1
    for i, b in enumerate(window):
        if b == 0x90:
            if run_start == -1:
                run_start = i
        else:
            if run_start != -1 and i - run_start >= 16:
                nop_runs.append((run_start, i - run_start))
            run_start = -1

    for start, length in nop_runs[:3]:
        signals.append(CamouflageSignal(
            signal_type='OBFUSCATION',
            description=f'NOP sled: {length}字节连续0x90',
            location=start, confidence=0.78,
            evidence=f'{length}B NOP sled @0x{start:x}'))

    # JMP链检测: 连续无条件跳转→控制流平坦化
    jmp_chain = 0
    for i in range(len(window) - 5):
        if window[i] in (0xEB, 0xE9) and i + 1 < len(window):
            rel = window[i + 1]
            if 0 <= rel <= 16:  # 短跳转(16字节内)
                jmp_chain += 1
    if jmp_chain >= 10:
        signals.append(CamouflageSignal(
            signal_type='OBFUSCATION',
            description=f'控制流平坦化嫌疑: {jmp_chain}次短跳转',
            location=0, confidence=0.72,
            evidence=f'{jmp_chain} short jumps → possible control-flow flattening'))

    return signals[:5]

# S4: 假阳性排除

def _detect_false_positive_tables(data: bytes) -> List[CamouflageSignal]:
    """
    检测可能被误报为密码学的非密码学结构。
    特征: 高频重复字节(字体表)/连续递增数值(校验和表)/低熵大表。
    """
    signals: List[CamouflageSignal] = []
    window = data[:min(len(data), 0x100000)]

    # 高频字节检测: 某字节出现>40% → 可能是字体/图像数据
    for start in range(0, len(window) - 512, 256):
        chunk = window[start:start + 256]
        cnt = Counter(chunk)
        most_common_freq = cnt.most_common(1)[0][1] / 256.0 if cnt else 0
        if most_common_freq > 0.40:
            signals.append(CamouflageSignal(
                signal_type='FALSE_POSITIVE',
                description=f'单一字节频率{most_common_freq*100:.0f}%→可能为字体/图形数据而非S-box',
                location=start, confidence=0.68,
                evidence=f'byte 0x{cnt.most_common(1)[0][0]:02x} appears {cnt.most_common(1)[0][1]}x/256'))
            break

    # 连续递增序列检测: 0x00,0x01,0x02...→校验和表而非S-box
    for start in range(0, len(window) - 64, 128):
        chunk = window[start:start + 64]
        sequential = sum(1 for i in range(len(chunk) - 1)
                         if chunk[i + 1] == (chunk[i] + 1) & 0xFF)
        if sequential >= 50:
            signals.append(CamouflageSignal(
                signal_type='FALSE_POSITIVE',
                description=f'连续递增序列({sequential}/63字节)→校验和/映射表',
                location=start, confidence=0.75,
                evidence=f'sequential bytes @0x{start:x}'))
            break

    return signals[:3]

# 主检测器

class CamouflageDetector:
    """密码学伪装检测器 — 组合四类信号。"""

    def __init__(self, data: bytes):
        self._data = data

    def run_all(self) -> CamouflageReport:
        signals: List[CamouflageSignal] = []
        signals.extend(_detect_otf_sbox_generation(self._data))
        signals.extend(_detect_constant_derivation(self._data))
        signals.extend(_detect_code_obfuscation(self._data))
        signals.extend(_detect_false_positive_tables(self._data))

        signals.sort(key=lambda s: -s.confidence)
        hidden = sum(1 for s in signals if s.signal_type == 'HIDDEN_CRYPTO')
        fp = sum(1 for s in signals if s.signal_type == 'FALSE_POSITIVE')
        obf = sum(1 for s in signals if s.signal_type == 'OBFUSCATION')

        if hidden >= 3:
            assessment = '高度可疑 — 存在多处隐蔽密码学实现迹象; 建议深度逆向'
        elif hidden >= 1:
            assessment = '可疑 — 检测到隐蔽密码学信号; 验证是否为合法OTF实现'
        elif obf >= 2 or fp >= 2:
            assessment = '需进一步分析 — 存在混淆或误报信号'
        else:
            assessment = '未检测到显著伪装信号'

        return CamouflageReport(
            binary_name='', signals=signals,
            hidden_crypto_count=hidden,
            false_positive_count=fp,
            obfuscation_count=obf,
            overall_assessment=assessment)
