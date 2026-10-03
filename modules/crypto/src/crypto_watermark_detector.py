"""
密码学实现水印检测 — 识别二进制加密实现中的有意或无意指纹/水印。

设计意图:
  密码学实现中常嵌入了可识别来源的水印/指纹:
    (a) 有意水印: 供应商在S-box或轮常量中微调特定bit, 作为版权标记。
        如某DRM库的AES S-box将字节0x63改为0x62(不影响密码学安全性但可追踪)。
    (b) 无意指纹: 编译器/优化级别/库版本在二进制中留下独特的代码布局签名。
        如GCC -O2的AES循环展开模式 vs Clang -O2的向量化模式。
    (c) 调试残留: 开发者姓名/项目代号/构建路径在二进制字符串中。
    (d) 陷阱门参数: 非标准椭圆曲线参数 → 可能是只有设计者知道的弱曲线。

  水印检测对供应链验证至关重要:
    (a) 固件声称"使用OpenSSL官方的AES", 但S-box有1字节差异 →
        可能使用修改过的库, 或被植入了后门。
    (b) 二进制中的构建路径字符串"/home/attacker/malware_crypto" →
        暴露了恶意代码的开发者身份。
    (c) 非标准曲线参数但使用NIST推荐的安全级别 → 可能是供应商版权水印。

  检测策略(5个互补维度):
    D1: S-box/常量表的已知标准值偏差
    D2: 非标准但密码学安全的参数替换
    D3: 开发者身份残留(路径/用户名/邮件/IDE元数据)
    D4: 时间戳/构建号/版本字符串的不一致性
    D5: 已知水印库的API签名

  - Qu & Potkonjak: "Fingerprinting intellectual property" —
    硬件IP水印的早期工作, 本项目将概念移植到二进制软件。
  - Nagaraja et al.: "Stegobot" — 隐写通道用于机器人通信,
    密码学常数的微调作为隐写载体。

边界条件:
  - 1字节偏差可能是编译器的对齐padding而非水印 → 需多信号印证。
  - 某些水印非常微妙(单个bit翻转) → 静态检测灵敏度受限。
  - 合法定制(SM4→ARIA S-box替换)与水印的界限模糊 → 标记为ANOMALY供人工裁决。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .constants import AES_SBOX, SM4_SBOX, GOST_SBOX, CAMELLIA_SBOX

@dataclass
class WatermarkFinding:
    category: str = ""             # CONSTANT_DEVIATION / ARTIFACT / PATH_LEAK / TIMESTAMP / API_SIGNATURE
    description: str = ""
    location: int = 0
    confidence: float = 0.0
    severity: str = ""             # INFO / SUSPICIOUS / ANOMALY / MALICIOUS_INDICATOR
    reference_value: str = ""      # 参考标准值
    detected_value: str = ""       # 检测到的异常值
    hypothesis: str = ""           # 最有说服力的解释

# D1: 常量偏差检测

def _check_constant_deviation(data: bytes, reference: bytes,
                               algo_name: str, offset: int,
                               max_deviations: int = 3) -> Optional[WatermarkFinding]:
    """检测256字节区域与参考S-box的逐字节差异。"""
    if offset + 256 > len(data):
        return None
    region = data[offset:offset + 256]
    deviations = []
    for i in range(256):
        if region[i] != reference[i]:
            deviations.append((i, reference[i], region[i]))

    if not deviations:
        return None

    n_dev = len(deviations)
    if n_dev == 0:
        return None
    if n_dev > max_deviations:
        # 偏差太多 → 可能是完全不同的S-box, 不是水印
        return None

    # 少量精确偏差 → 水印嫌疑
    detail_parts = [f'{algo_name} S-box: {n_dev} byte(s) differ from reference']
    for idx, ref_val, det_val in deviations[:3]:
        detail_parts.append(f'   byte[{idx}]: ref=0x{ref_val:02x} detected=0x{det_val:02x}')

    severity = 'ANOMALY'
    if n_dev == 1:
        severity = 'SUSPICIOUS'  # 单个字节差异 → 可能是故意的

    return WatermarkFinding(
        category='CONSTANT_DEVIATION',
        description='; '.join(detail_parts),
        location=offset,
        confidence=0.72 if n_dev <= 2 else 0.55,
        severity=severity,
        reference_value=f'{algo_name} standard S-box',
        detected_value=f'{n_dev} byte(s) deviating',
        hypothesis='可能是供应商水印(微调1-2字节不影响安全性)或非标准实现')

# D2-D4: 其他水印维度

_DEV_ARTIFACT_PATTERNS: List[Tuple[bytes, str, float, str]] = [
    (b'/home/', 'Unix home directory path', 0.65, 'PATH_LEAK'),
    (b'/Users/', 'macOS home directory path', 0.65, 'PATH_LEAK'),
    (b'C:\\Users\\', 'Windows user path', 0.65, 'PATH_LEAK'),
    (b'build_', 'build directory reference', 0.55, 'ARTIFACT'),
    (b'jenkins', 'Jenkins CI artifact', 0.60, 'ARTIFACT'),
    (b'Dockerfile', 'Docker build artifact', 0.55, 'ARTIFACT'),
    (b'__DATE__', 'compile-time date macro', 0.78, 'TIMESTAMP'),
    (b'__TIME__', 'compile-time time macro', 0.78, 'TIMESTAMP'),
    (b'__TIMESTAMP__', 'compile-time timestamp macro', 0.82, 'TIMESTAMP'),
    (b'@(#)', 'SCCS version string (Solaris heritage)', 0.75, 'ARTIFACT'),
]

# 已知密码学水印方案 — 不应出现在合法二进制中的字符串
_KNOWN_WATERMARK_SCHEMES: List[Tuple[bytes, str, float]] = [
    (b'watermark', 'watermark keyword', 0.55),
    (b'fingerprinted', 'fingerprinted keyword', 0.60),
    (b'copyright_protection', 'copyright protection keyword', 0.65),
    (b'drm_protected', 'DRM protection keyword', 0.60),
    (b'tamper_detect', 'tamper detection keyword', 0.55),
    (b'integrity_check', 'integrity check presence', 0.40),
]

def detect_watermarks(data: bytes,
                      crypto_findings: Optional[List] = None,
                      strings: Optional[List[str]] = None
                      ) -> List[WatermarkFinding]:
    findings: List[WatermarkFinding] = []

    # D1: S-box偏差
    sbox_checks = [
        ('AES', AES_SBOX), ('SM4', SM4_SBOX),
        ('GOST', GOST_SBOX), ('Camellia', CAMELLIA_SBOX),
    ]
    for algo_name, ref_sbox in sbox_checks:
        ref_bytes = bytes(ref_sbox)
        pref = ref_bytes[:8]  # 使用8字节前缀作为探针
        pos = 0
        while True:
            pos = data.find(pref, pos)
            if pos == -1:
                break
            result = _check_constant_deviation(data, ref_bytes, algo_name, pos)
            if result:
                findings.append(result)
            pos += 8  # 跳过探针长度避免重叠

    # D2: 开发者残留
    for pat, desc, conf, cat in _DEV_ARTIFACT_PATTERNS:
        for off in range(0, min(len(data), 0x100000), 64):
            if data[off:off + len(pat)] == pat:
                # 提取上下文
                end = min(off + 200, len(data))
                context = data[off:end].split(b'\x00')[0]
                try:
                    ctx_str = context.decode('ascii', errors='replace')
                except Exception:
                    ctx_str = repr(context[:60])

                findings.append(WatermarkFinding(
                    category=cat, description=f'{desc}: {ctx_str[:80]}',
                    location=off, confidence=conf,
                    severity='INFO' if cat in ('ARTIFACT', 'PATH_LEAK', 'TIMESTAMP') else 'SUSPICIOUS',
                    reference_value='', detected_value=ctx_str[:60],
                    hypothesis='构建环境残留 — 可追踪二进制构建来源'))
                break

    # D3: 水印关键词
    for pat, desc, conf in _KNOWN_WATERMARK_SCHEMES:
        if pat in data:
            findings.append(WatermarkFinding(
                category='API_SIGNATURE',
                description=f'{desc} keyword found',
                location=data.find(pat), confidence=conf,
                severity='SUSPICIOUS',
                hypothesis='二进制可能包含有意添加的版权保护水印代码'))

    # D4: 字符串检查
    if strings:
        for s in strings:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            for pat, desc, conf, _cat in _DEV_ARTIFACT_PATTERNS:
                if pat in sb:
                    findings.append(WatermarkFinding(
                        category='ARTIFACT',
                        description=f'{desc} in string: "{s[:60]}"',
                        location=0, confidence=conf * 0.85,
                        severity='INFO',
                        hypothesis='构建环境字符串残留'))

    findings.sort(key=lambda f: -f.confidence)
    return findings[:20]
