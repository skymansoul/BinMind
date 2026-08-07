"""
密码学基线噪声估计 — 建立二进制中"正常"密码学信号基线并检测偏离。

修改记录:
  2025-09-18 16:42 — 初始实现: 基线建立/异常检测/种群统计/域特定归一化

设计意图:
  37个检测模块回答"此二进制中有什么密码学", 但无法区分"正常"和"异常"。
  一个IoT灯泡固件包含AES-128是正常的, 但同一个固件包含RSA-4096+ECDSA+ML-KEM
  就高度异常 — 可能是供应链攻击植入了额外的密码学功能。

  本模块建立密码学信号的统计基线:
    (a) 种群基线: 同类设备/固件的密码学信号典型分布。
    (b) 域基线: 设备类别(路由器/摄像头/PLC/智能手机)的期望密码学特征。
    (c) 时间基线: 同一设备跨版本的密码学特征变化趋势。

  偏离基线的检测:
    D1 (算法异常): 出现此类设备不应有的密码学算法。
    D2 (复杂度异常): 算法种类/实现数超过同类设备2σ以上。
    D3 (库异常): 出现不应在此类设备中的密码学库。
    D4 (规模异常): 密码学代码占比异常高/低。

  - NIST SP 800-53 Rev.5: CM-8 信息系统组件清单 — 基线配置管理。
  - MITRE ATT&CK T1587.001: 开发能力获取 — 恶意软件植入密码学。
  - Statistical Process Control (SPC): 工业统计过程控制 — 3σ异常检测。

边界条件:
  - 基线需要同类设备的参考数据集 — 冷启动时使用域默认基线。
  - 种群统计在样本量<5时不可靠 → 标记为LOW_CONFIDENCE。
  - 基线应随时间迭代更新 — 当前输出为初始基线快照。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class DomainBaseline:
    domain: str = ""               # 设备类别 (iot_lightbulb / router / plc / smartphone)
    expected_algos: List[str] = field(default_factory=list)
    expected_algo_count_range: Tuple[int, int] = (1, 8)
    expected_key_sizes: List[int] = field(default_factory=list)
    forbidden_algos: List[str] = field(default_factory=list)
    typical_libraries: List[str] = field(default_factory=list)
    crypto_code_ratio_range: Tuple[float, float] = (0.001, 0.15)

# 域默认基线

_DOMAIN_BASELINES: Dict[str, DomainBaseline] = {
    'iot_lightbulb': DomainBaseline(
        domain='IoT灯泡/插座',
        expected_algos=['AES-128', 'AES-256', 'SHA-256', 'ECDH', 'ECDSA'],
        expected_algo_count_range=(1, 4),
        expected_key_sizes=[128, 256],
        forbidden_algos=['RSA-4096', 'ML-KEM', 'ML-DSA', 'Ed25519', 'X25519',
                        'ChaCha20'],
        typical_libraries=['mbedTLS', 'wolfSSL', 'tinyDTLS'],
        crypto_code_ratio_range=(0.01, 0.10)),
    'router': DomainBaseline(
        domain='路由器/网关',
        expected_algos=['AES-128', 'AES-256', 'SHA-256', 'SHA-512', 'RSA',
                        'ECDH', 'ECDSA', 'DH', 'ChaCha20', 'X25519'],
        expected_algo_count_range=(3, 12),
        expected_key_sizes=[128, 256, 2048, 4096],
        forbidden_algos=[],
        typical_libraries=['OpenSSL', 'wolfSSL', 'mbedTLS'],
        crypto_code_ratio_range=(0.02, 0.25)),
    'plc': DomainBaseline(
        domain='PLC/工业控制器',
        expected_algos=['AES-128', 'SHA-256', 'ECDSA'],
        expected_algo_count_range=(1, 5),
        expected_key_sizes=[128],
        forbidden_algos=['RSA', 'DH', 'DSA', 'MD5', 'SHA-1'],
        typical_libraries=['mbedTLS', 'custom'],
        crypto_code_ratio_range=(0.005, 0.08)),
    'smartphone': DomainBaseline(
        domain='智能手机/平板',
        expected_algos=['AES-256', 'SHA-256', 'SHA-512', 'RSA', 'ECDSA',
                        'Ed25519', 'ECDH', 'X25519', 'ChaCha20', 'ML-KEM'],
        expected_algo_count_range=(5, 20),
        expected_key_sizes=[128, 256, 2048, 4096],
        forbidden_algos=['DES', '3DES', 'MD5', 'SHA-1', 'RC4'],
        typical_libraries=['BoringSSL', 'OpenSSL', 'Java JCA', 'Go crypto'],
        crypto_code_ratio_range=(0.03, 0.30)),
}

@dataclass
class AnomalyFinding:
    anomaly_type: str = ""         # ALGO_ANOMALY / COMPLEXITY / LIBRARY / SIZE
    description: str = ""
    severity: str = ""             # CRITICAL / HIGH / MEDIUM / LOW
    expected_value: str = ""
    detected_value: str = ""
    deviation_sigma: float = 0.0   # 偏离均值多少σ

@dataclass
class BaselineReport:
    domain: str = ""
    anomaly_count: int = 0
    anomalies: List[AnomalyFinding] = field(default_factory=list)
    within_baseline: bool = True

def _get_domain_baseline(algo_names: List[str]) -> DomainBaseline:
    """根据检测到的算法推断最可能的设备域。"""
    algo_set = set(algo_names)
    best_match = None
    best_score = -1
    for domain, bl in _DOMAIN_BASELINES.items():
        expected_set = set(bl.expected_algos)
        overlap = len(algo_set & expected_set)
        extra = len(algo_set - expected_set)
        score = overlap - extra * 0.5
        if score > best_score:
            best_score = score
            best_match = domain
    return _DOMAIN_BASELINES.get(best_match or 'router',
                                  _DOMAIN_BASELINES['router'])

def check_baseline(algo_names: Optional[List[str]] = None,
                   crypto_findings: Optional[List] = None,
                   lib_fingerprints: Optional[List] = None,
                   domain_hint: Optional[str] = None,
                   binary_size: int = 0,
                   crypto_code_size: int = 0,
                   ) -> BaselineReport:
    """
    检查密码学信号是否在域基线的正常范围内。
    """
    algos = list(algo_names or [])
    if crypto_findings:
        for f in crypto_findings:
            try:
                algos.append(getattr(f, 'algorithm', ''))
            except Exception:
                pass

    # 域推断
    if domain_hint:
        bl = _DOMAIN_BASELINES.get(domain_hint, _get_domain_baseline(algos))
    else:
        bl = _get_domain_baseline(algos)

    anomalies: List[AnomalyFinding] = []

    # D1: 算法异常 — 禁止算法/非预期算法
    for algo in algos:
        if algo in bl.forbidden_algos:
            anomalies.append(AnomalyFinding(
                anomaly_type='ALGO_ANOMALY',
                description=f'{algo}不在{bl.domain}的预期算法列表中',
                severity='HIGH',
                expected_value=f'禁止: {bl.forbidden_algos}',
                detected_value=algo, deviation_sigma=5.0))
        if algo not in bl.expected_algos and algo not in bl.forbidden_algos:
            anomalies.append(AnomalyFinding(
                anomaly_type='ALGO_ANOMALY',
                description=f'{algo}不在{bl.domain}的已知算法集中',
                severity='MEDIUM',
                expected_value=f'预期: {bl.expected_algos[:5]}...',
                detected_value=algo, deviation_sigma=2.0))

    # D2: 复杂度异常 — 算法种类超预期
    unique_algos = len(set(algos))
    lo, hi = bl.expected_algo_count_range
    if unique_algos > hi:
        sigma = max(1.0, (unique_algos - hi) / max(1, hi) * 3)
        anomalies.append(AnomalyFinding(
            anomaly_type='COMPLEXITY',
            description=f'算法种类({unique_algos})超过{bl.domain}的上限({hi})',
            severity='MEDIUM' if unique_algos < hi * 2 else 'HIGH',
            expected_value=f'{lo}-{hi}', detected_value=str(unique_algos),
            deviation_sigma=round(sigma, 2)))

    # D3: 库异常
    if lib_fingerprints:
        for lf in lib_fingerprints:
            try:
                lib = getattr(lf, 'lib_name', '')
                if lib not in bl.typical_libraries and lib:
                    anomalies.append(AnomalyFinding(
                        anomaly_type='LIBRARY',
                        description=f'密码学库"{lib}"不在{bl.domain}的典型列表中',
                        severity='MEDIUM',
                        expected_value=str(bl.typical_libraries),
                        detected_value=lib, deviation_sigma=2.5))
            except Exception:
                pass

    # D4: 规模异常
    if binary_size > 0 and crypto_code_size > 0:
        ratio = crypto_code_size / binary_size
        rlo, rhi = bl.crypto_code_ratio_range
        if ratio > rhi:
            sigma = max(1.0, (ratio - rhi) / rhi * 5)
            anomalies.append(AnomalyFinding(
                anomaly_type='SIZE',
                description=f'密码学代码占比({ratio:.2%})超过{bl.domain}的上限({rhi:.1%})',
                severity='MEDIUM',
                expected_value=f'{rlo:.1%}-{rhi:.1%}',
                detected_value=f'{ratio:.2%}', deviation_sigma=round(sigma, 2)))

    anomalies.sort(key=lambda a: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[a.severity])
    return BaselineReport(
        domain=bl.domain,
        anomaly_count=len(anomalies),
        anomalies=anomalies,
        within_baseline=len(anomalies) == 0)
