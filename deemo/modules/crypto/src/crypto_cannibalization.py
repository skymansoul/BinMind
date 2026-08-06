"""
密码学代码蚕食检测 — 检测跨二进制密码学代码的非授权复用(蚕食)。

修改记录:
  2025-09-04 08:42 — 初始实现: 跨二进制指纹匹配/复用关系图/许可证冲突/供应链风险

设计意图:
  既有crypto_lineage在同二进制内追踪密码学代码复用, crypto_diversity检测
  同一二进制内的多实现冗余。但供应链中更隐蔽的风险是"蚕食(cannibalization)":
    固件A的密码学代码被固件B直接复制使用, 绕过许可证/供应链/安全审计。

  蚕食的典型场景:
    (a) GPL许可的OpenSSL代码被蚕食到闭源商用固件 → 许可证违规。
    (b) 已知含CVE的密码学代码被蚕食到新固件 → CVE传播但无人知晓。
    (c) 恶意固件蚕食受害者的合法密码学代码以伪装身份 → 供应链攻击。

  检测策略:
    1. 从多个二进制中提取密码学区域指纹(使用crypto_semantic_hash)。
    2. 构建跨二进制指纹相似度矩阵。
    3. 对高相似度(汉明距离≤阈值)的配对进行蚕食判定:
       - 确认为蚕食(EXACT_MATCH)
       - 疑似蚕食(HEURISTIC_MATCH, 可能是同库独立编译)
       - 共享来源(SHARED_ORIGIN, 二者均来自同一上游库)
    4. 检测许可证冲突(GPL→闭源 / MIT不兼容等)。

参考:
  - Jang et al. (S&P 2012): ReDeBug跨二进制漏洞检测 — 代码复用检测方法论。
  - Pewny et al. (S&P 2015): 跨架构二进制代码搜索。
  - German et al. (2010): 许可证兼容性分析 — 开源许可证冲突检测。

边界条件:
  - 跨二进制匹配需要多个二进制作为输入 — 至少2个。
  - 蚕食和"合法复用同一库"的区分是概率性的 — 输出置信度而非确定判定。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CannibalizationMatch:
    source_binary: str = ""          # 被蚕食的源二进制
    target_binary: str = ""          # 蚕食者二进制
    algorithm: str = ""
    source_offset: int = 0
    target_offset: int = 0
    hamming_distance: int = 128      # 语义指纹汉明距离(越小越相似)
    similarity: float = 0.0          # 0-1 相似度
    match_type: str = ""             # EXACT_MATCH / HEURISTIC_MATCH / SHARED_ORIGIN
    confidence: float = 0.0
    license_risk: str = ""           # LICENSE_CONFLICT / COMPATIBLE / UNKNOWN
    evidence: List[str] = field(default_factory=list)


# ── 许可证信息(简化) ──
_LICENSE_MAP: Dict[str, str] = {
    'GPL-2.0': 'COPYLEFT_STRONG',
    'GPL-3.0': 'COPYLEFT_STRONG',
    'LGPL-2.1': 'COPYLEFT_WEAK',
    'MIT': 'PERMISSIVE',
    'BSD-3': 'PERMISSIVE',
    'Apache-2.0': 'PERMISSIVE',
    'OpenSSL': 'OPENSSL_SPECIAL',  # OpenSSL License (BSD-like + advertising)
    'Proprietary': 'PROPRIETARY',
}

# 许可证兼容性矩阵 (行→列: 行许可证的代码被蚕食到列的二进制, 是否合规)
_LICENSE_COMPAT: Dict[Tuple[str, str], str] = {
    ('COPYLEFT_STRONG', 'PROPRIETARY'): 'LICENSE_CONFLICT',
    ('COPYLEFT_STRONG', 'PERMISSIVE'): 'LICENSE_CONFLICT',
    ('COPYLEFT_WEAK', 'PROPRIETARY'): 'LICENSE_CONFLICT',
    ('COPYLEFT_WEAK', 'PERMISSIVE'): 'COMPATIBLE (动态链接)',
    ('PERMISSIVE', 'PROPRIETARY'): 'COMPATIBLE',
    ('PERMISSIVE', 'PERMISSIVE'): 'COMPATIBLE',
    ('PERMISSIVE', 'COPYLEFT_STRONG'): 'COMPATIBLE',
    ('PROPRIETARY', 'ANY'): 'LICENSE_CONFLICT (未授权复用)',
}


# ── 跨二进制指纹匹配 ──

def _compute_cross_binary_similarity(
        fingerprints_a: List,
        fingerprints_b: List
) -> List[CannibalizationMatch]:
    """
    计算两个二进制密码学指纹集合的跨二进制相似度。
    指纹来自crypto_semantic_hash.extract_fingerprint()。
    """
    matches: List[CannibalizationMatch] = []
    if not fingerprints_a or not fingerprints_b:
        return matches

    for fa in fingerprints_a:
        for fb in fingerprints_b:
            try:
                hd = fa.hamming_distance(fb)
            except Exception:
                continue

            sim = max(0.0, 1.0 - hd / 128.0)

            # 判定蚕食类型
            if hd <= 4:
                mtype = 'EXACT_MATCH'
                conf = 0.92
            elif hd <= 8:
                mtype = 'HEURISTIC_MATCH'
                conf = 0.78
            elif hd <= 16:
                mtype = 'SHARED_ORIGIN'
                conf = 0.60
            else:
                continue

            algo_a = getattr(fa, 'algorithm', 'unknown')
            off_a = getattr(fa, 'anchor_offset', 0)
            off_b = getattr(fb, 'anchor_offset', 0)
            path_a = getattr(fa, 'file_path', 'binary_a')
            path_b = getattr(fb, 'file_path', 'binary_b')

            matches.append(CannibalizationMatch(
                source_binary=path_a, target_binary=path_b,
                algorithm=algo_a,
                source_offset=off_a, target_offset=off_b,
                hamming_distance=hd, similarity=round(sim, 4),
                match_type=mtype, confidence=conf,
                evidence=[f'{algo_a}: HD={hd}/128, sim={sim:.3f}']))

    matches.sort(key=lambda m: m.hamming_distance)
    return matches


def _check_license_conflict(source_license: str, target_license: str) -> str:
    """检测许可证冲突。"""
    src_type = _LICENSE_MAP.get(source_license, 'UNKNOWN')
    tgt_type = _LICENSE_MAP.get(target_license, 'UNKNOWN')
    if src_type == 'UNKNOWN' or tgt_type == 'UNKNOWN':
        return 'UNKNOWN'
    compat = _LICENSE_COMPAT.get((src_type, tgt_type))
    if compat:
        return compat
    return 'COMPATIBLE'


def detect_cannibalization(
        binary_fingerprints: Dict[str, List],
        binary_licenses: Optional[Dict[str, str]] = None
) -> List[CannibalizationMatch]:
    """
    跨二进制密码学代码蚕食检测。
    binary_fingerprints: {二进制路径: [SemanticFingerprint列表], ...}
    binary_licenses: {二进制路径: 许可证字符串, ...}
    """
    paths = list(binary_fingerprints.keys())
    licenses = binary_licenses or {}
    all_matches: List[CannibalizationMatch] = []

    for i in range(len(paths)):
        for j in range(i + 1, len(paths)):
            pa, pb = paths[i], paths[j]
            fps_a = binary_fingerprints[pa]
            fps_b = binary_fingerprints[pb]

            pair_matches = _compute_cross_binary_similarity(fps_a, fps_b)
            for m in pair_matches:
                # 检查许可证冲突
                lic_a = licenses.get(pa, '')
                lic_b = licenses.get(pb, '')
                if lic_a and lic_b:
                    m.license_risk = _check_license_conflict(lic_a, lic_b)

                # EXACT_MATCH且有许可证冲突 → 升级为LICENSE_VIOLATION
                if (m.match_type == 'EXACT_MATCH' and
                        'LICENSE_CONFLICT' in m.license_risk):
                    m.evidence.append(f'LICENSE VIOLATION: {lic_a}→{lic_b}')
                    m.confidence = min(0.98, m.confidence + 0.10)

            all_matches.extend(pair_matches)

    all_matches.sort(key=lambda m: (m.hamming_distance, -m.confidence))
    return all_matches[:50]


def summarize_cannibalization(matches: List[CannibalizationMatch]
                              ) -> Dict[str, int]:
    """汇总蚕食检测统计。"""
    s: Dict[str, int] = {}
    for m in matches:
        s[m.match_type] = s.get(m.match_type, 0) + 1
        if m.license_risk:
            key = f'license_{m.license_risk}'
            s[key] = s.get(key, 0) + 1
    return s
