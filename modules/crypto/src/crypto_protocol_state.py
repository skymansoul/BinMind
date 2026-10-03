"""
密码协议状态机重建 — 从二进制中的密码学API调用序列推断协议握手状态机。

设计意图:
  既有signal_protocol分析Signal协议的特定实现模式, crypto_traffic_decrypt处理流量解密。
  但两者都不回答"此二进制实现了什么加密协议, 其状态机是否标准?"。
  这一信息缺口在以下场景中至关重要:
    (a) 固件声称"支持TLS 1.2", 但二进制中的状态转移路径与标准TLS 1.2不同 —
        是否存在安全降级路径或跳步漏洞?
    (b) 未文档化的加密协议实现 — 可能是合法的内部协议, 也可能是隐蔽C2通道。
    (c) 协议实现中的缺失状态 — 例如没有证书验证步骤的TLS → 中间人攻击可行。

  本模块从静态二进制分析推断协议状态机:
    1. 在检测到的密码学API调用点周围提取上下文。
    2. 将每个API调用分类到协议阶段: INIT / HELLO / KEY_EXCHANGE / AUTH / DATA / CLOSE。
    3. 构建状态转移图并匹配已知协议指纹。

  与既有研究的本质区别:
    -: 从网络流量推断协议状态机 — 需要抓包, 有网络依赖。
    - ProtocolGPT: 从源码用LLM推断状态机 — 需要源码访问。
    本模块直接从二进制推断 — 无需流量/源码/运行时, 纯静态。

  - Beurdouche et al.: "A Messy State of the Union" — TLS实现
    状态机缺陷的系统分析, 本项目将其概念从源码审查移植到二进制静态分析。
  - de Ruiter & Poll: "Protocol State Fuzzing of TLS" —
    状态机推断用于协议Fuzzing, 本项目以API序列分类替代主动探测。
  - ESORICS 2022: TLS栈指纹识别 — 通过状态机行为差异区分实现。

边界条件:
  - API调用分类依赖字符串匹配 — 加壳/混淆的二进制中分类精度降低。
  - 当前覆盖TLS/SSH/IPSec/WireGuard/Noise — 自定义协议仅能做通用分类。
  - 状态转移图是静态近似 — 实际的运行时状态转移可能因条件分支而异。
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

class ProtoPhase(Enum):
    INIT = auto()           # 库初始化 / 上下文创建
    HELLO = auto()          # ClientHello / ServerHello / 参数协商
    KEY_EXCHANGE = auto()   # DH / ECDH / 密钥协商
    AUTH = auto()           # 证书验证 / 签名验证 / 身份认证
    DERIVE = auto()         # 密钥派生 (HKDF / PRF)
    DATA = auto()           # 加密数据传输
    CLOSE = auto()          # 会话关闭 / 告警 / 清理
    UNKNOWN = auto()        # 未分类

# API调用→协议阶段分类规则
_PHASE_PATTERNS: List[Tuple[bytes, ProtoPhase, float]] = [
    (b'SSL_CTX_new', ProtoPhase.INIT, 0.95),
    (b'SSL_new', ProtoPhase.INIT, 0.90),
    (b'tls_init', ProtoPhase.INIT, 0.90),
    (b'ssh_init', ProtoPhase.INIT, 0.90),
    (b'wolfSSL_Init', ProtoPhase.INIT, 0.90),
    (b'gnutls_init', ProtoPhase.INIT, 0.90),
    (b'InitializeSecurityContext', ProtoPhase.INIT, 0.85),
    # HELLO
    (b'SSL_connect', ProtoPhase.HELLO, 0.90),
    (b'SSL_accept', ProtoPhase.HELLO, 0.90),
    (b'SSL_do_handshake', ProtoPhase.HELLO, 0.85),
    (b'ClientHello', ProtoPhase.HELLO, 0.95),
    (b'ServerHello', ProtoPhase.HELLO, 0.95),
    (b'gnutls_handshake', ProtoPhase.HELLO, 0.85),
    # KEY_EXCHANGE
    (b'SSL_CTX_set_ecdh', ProtoPhase.KEY_EXCHANGE, 0.85),
    (b'DH_generate_key', ProtoPhase.KEY_EXCHANGE, 0.90),
    (b'DH_compute_key', ProtoPhase.KEY_EXCHANGE, 0.90),
    (b'ECDH_compute_key', ProtoPhase.KEY_EXCHANGE, 0.92),
    (b'EVP_PKEY_derive', ProtoPhase.KEY_EXCHANGE, 0.88),
    (b'X25519', ProtoPhase.KEY_EXCHANGE, 0.82),
    (b'ecdh_', ProtoPhase.KEY_EXCHANGE, 0.88),
    # AUTH
    (b'SSL_CTX_use_certificate', ProtoPhase.AUTH, 0.90),
    (b'SSL_get_verify_result', ProtoPhase.AUTH, 0.92),
    (b'X509_verify', ProtoPhase.AUTH, 0.92),
    (b'verify_signature', ProtoPhase.AUTH, 0.88),
    (b'certificate_verify', ProtoPhase.AUTH, 0.90),
    (b'CertVerify', ProtoPhase.AUTH, 0.90),
    # DERIVE
    (b'SSL_export_keying_material', ProtoPhase.DERIVE, 0.88),
    (b'HKDF', ProtoPhase.DERIVE, 0.85),
    (b'hkdf_', ProtoPhase.DERIVE, 0.85),
    (b'derive_secret', ProtoPhase.DERIVE, 0.82),
    (b'tls13_derive', ProtoPhase.DERIVE, 0.90),
    # DATA
    (b'SSL_read', ProtoPhase.DATA, 0.90),
    (b'SSL_write', ProtoPhase.DATA, 0.90),
    (b'EncryptMessage', ProtoPhase.DATA, 0.82),
    (b'DecryptMessage', ProtoPhase.DATA, 0.82),
    (b'aead_encrypt', ProtoPhase.DATA, 0.85),
    (b'aead_decrypt', ProtoPhase.DATA, 0.85),
    # CLOSE
    (b'SSL_shutdown', ProtoPhase.CLOSE, 0.95),
    (b'SSL_free', ProtoPhase.CLOSE, 0.88),
    (b'gnutls_bye', ProtoPhase.CLOSE, 0.90),
]

# 已知协议指纹 — 标准状态转移序列
# 用于匹配重建的状态机到已知协议
_PROTOCOL_FINGERPRINTS: Dict[str, List[ProtoPhase]] = {
    'TLS 1.2 (full handshake)': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.AUTH, ProtoPhase.DERIVE, ProtoPhase.DATA, ProtoPhase.CLOSE,
    ],
    'TLS 1.3 (full handshake)': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.DERIVE, ProtoPhase.AUTH, ProtoPhase.DATA, ProtoPhase.CLOSE,
    ],
    'TLS 1.2 (PSK resumption)': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.DERIVE,
        ProtoPhase.DATA, ProtoPhase.CLOSE,
    ],
    'SSH (full handshake)': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.AUTH, ProtoPhase.DERIVE, ProtoPhase.DATA, ProtoPhase.CLOSE,
    ],
    'IPSec IKEv2': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.AUTH, ProtoPhase.DERIVE, ProtoPhase.DATA,
    ],
    'WireGuard': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.DERIVE, ProtoPhase.DATA,
    ],
    'Noise (IK pattern)': [
        ProtoPhase.INIT, ProtoPhase.HELLO, ProtoPhase.KEY_EXCHANGE,
        ProtoPhase.AUTH, ProtoPhase.DERIVE, ProtoPhase.DATA,
    ],
}

@dataclass
class ProtoStateTransition:
    from_phase: ProtoPhase
    to_phase: ProtoPhase
    evidence: str = ""
    location: int = 0

@dataclass
class ProtocolStateMachine:
    protocol_name: str = ""              # 匹配的已知协议名, 或 "Custom"
    phases_detected: Set[ProtoPhase] = field(default_factory=set)
    transitions: List[ProtoStateTransition] = field(default_factory=list)
    best_match: str = ""                 # 最接近的已知协议
    match_confidence: float = 0.0
    missing_phases: List[str] = field(default_factory=list)
    extra_phases: List[str] = field(default_factory=list)
    anomaly_flags: List[str] = field(default_factory=list)

def _classify_api_call(api_string: str) -> Tuple[ProtoPhase, float]:
    """将API字符串分类到协议阶段。返回(阶段, 置信度)。"""
    sb = api_string.encode('ascii', errors='replace')
    best_phase = ProtoPhase.UNKNOWN
    best_weight = 0.0

    for pattern, phase, weight in _PHASE_PATTERNS:
        if pattern in sb:
            if weight > best_weight:
                best_weight = weight
                best_phase = phase

    return best_phase, best_weight

def _extract_api_calls(data: bytes, anchor: int, window: int = 256) -> List[Tuple[str, int]]:
    """在锚点附近提取可打印的API调用字符串。返回(字符串, 相对偏移)列表。"""
    region = data[max(0, anchor - window):anchor + window]
    calls = []
    for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{4,}', region):
        s = m.group().decode('ascii', errors='replace')
        if any(c.isupper() for c in s) or '_' in s:
            calls.append((s, m.start()))
    return calls

def reconstruct_state_machine(data: bytes,
                              crypto_findings: Optional[List] = None,
                              strings: Optional[List[str]] = None
                              ) -> ProtocolStateMachine:
    """
    从二进制和密码学检测结果重建协议状态机。
    crypto_findings: crypto_detector的输出, 用于定位密码学区域。
    strings: 从二进制提取的字符串列表。
    """
    phases: Dict[ProtoPhase, int] = defaultdict(int)
    transitions: List[ProtoStateTransition] = []
    phase_sequence: List[Tuple[ProtoPhase, int]] = []

    # 从密码学锚点周围提取API调用
    anchors = []
    if crypto_findings:
        for f in crypto_findings:
            try:
                anchors.append(getattr(f, 'location', 0))
            except Exception:
                pass

    if not anchors:
        anchors = [0]

    for anchor in anchors[:20]:  # 限制数量
        api_calls = _extract_api_calls(data, anchor)
        for call_str, rel_off in api_calls:
            phase, conf = _classify_api_call(call_str)
            if conf > 0.7:
                phases[phase] += 1
                abs_off = anchor + rel_off
                if phase_sequence:
                    prev_phase, prev_off = phase_sequence[-1]
                    if prev_phase != phase and abs_off > prev_off:
                        transitions.append(ProtoStateTransition(
                            from_phase=prev_phase, to_phase=phase,
                            evidence=call_str, location=abs_off))
                phase_sequence.append((phase, abs_off))

    # 从字符串列表补充
    if strings:
        for s in strings:
            phase, conf = _classify_api_call(s)
            if conf > 0.7:
                phases[phase] += 1

    detected = set(phases.keys())
    detected.discard(ProtoPhase.UNKNOWN)

    # 匹配已知协议指纹
    best_match = ""
    best_score = 0.0
    detected_seq = [p for p, _ in phase_sequence if p != ProtoPhase.UNKNOWN]

    for proto_name, ref_seq in _PROTOCOL_FINGERPRINTS.items():
        ref_set = set(ref_seq)
        if not ref_set:
            continue
        overlap = len(detected & ref_set)
        expected = len(ref_set) if ref_set else 1
        score = overlap / expected
        if score > best_score:
            best_score = score
            best_match = proto_name

    # 缺失/额外阶段分析
    expected_phases = set()
    if best_match:
        expected_phases = set(_PROTOCOL_FINGERPRINTS.get(best_match, []))
    missing = [p.name for p in expected_phases - detected if p != ProtoPhase.UNKNOWN]
    extra = [p.name for p in detected - expected_phases if p != ProtoPhase.UNKNOWN]

    # 异常标记
    anomalies = []
    if ProtoPhase.AUTH not in detected and ProtoPhase.DATA in detected:
        anomalies.append("DATA_without_AUTH — possible authentication bypass")
    if ProtoPhase.KEY_EXCHANGE not in detected and ProtoPhase.DATA in detected:
        anomalies.append("DATA_without_KEY_EXCHANGE — static key or missing PFS")
    if ProtoPhase.HELLO not in detected and len(detected) >= 2:
        anomalies.append("missing_HELLO_phase — non-standard initiation")

    return ProtocolStateMachine(
        protocol_name=best_match if best_score >= 0.6 else "Custom",
        phases_detected=detected,
        transitions=transitions[:50],
        best_match=best_match,
        match_confidence=round(best_score, 3),
        missing_phases=missing,
        extra_phases=extra,
        anomaly_flags=anomalies,
    )
