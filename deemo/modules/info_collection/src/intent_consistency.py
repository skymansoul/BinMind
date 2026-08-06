"""
对抗性意图一致性校验器 (AICV)。

问题来源: API 导入注入攻击 (arXiv:2605.18624) 可在不改变恶意行为的前提下,
仅通过注入 ~20 个良性 API 导入就将检出率从 87.5% 降至 30%。
现有的单一信号源推断 (API 序列或 LLM 语义) 对此类攻击无感知。

解决: 从 API 导入画像、CFG 结构特征、代码模式三路独立信号中提取意图签名。
三路信号的协方差结构本身携带信息 —— 自然样本的信号分布趋于聚类,
对抗混淆会破坏这种聚类结构。不直接判定恶意/良性, 而是建模跨信号的不一致性。

本模块与行为单元扰动检测 (arXiv:2509.15756) 互补: 后者检测序列内扰动,
本模块检测跨信号不一致。
"""

# File: intent_consistency.py  |  2026-07-26 create AICV; 2026-08-04 audit: stray import fix

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class SignalSource(Enum):
    """独立信号源。"""
    API_IMPORTS = "api_imports"          # PE 导入表 / ELF 动态符号
    CFG_STRUCTURE = "cfg_structure"      # 控制流图拓扑特征
    CODE_PATTERNS = "code_patterns"      # 指令序列 n-gram 模式
    STRING_TABLE = "string_table"        # 可读字符串集合


class IntentSignal(Enum):
    """从各信号源提取的意图标签。"""
    NETWORK = "network"                  # 网络通信相关
    FILE_OPS = "file_operations"         # 文件系统操作
    PROCESS = "process_manipulation"     # 进程/线程操控
    MEMORY = "memory_manipulation"       # 内存操作
    REGISTRY = "registry_ops"            # 注册表/配置写入
    CRYPTO = "cryptographic"             # 加密/解密操作
    PERSISTENCE = "persistence"          # 持久化机制
    EVASION = "evasion"                  # 反检测/反调试
    EXFIL = "exfiltration"              # 数据外传
    UNKNOWN = "unknown"


@dataclass
class SignalProfile:
    """单信号源的意图画像。"""
    source: SignalSource
    intent_distribution: Dict[IntentSignal, float]  # 归一化分布, 总和 1.0
    confidence: float  # 该信号源本身的置信度 [0, 1]
    evidence_count: int  # 用于构建画像的原始证据条数
    top_intents: List[IntentSignal] = field(default_factory=list)

    def dominant_intent(self) -> IntentSignal:
        if not self.intent_distribution:
            return IntentSignal.UNKNOWN
        return max(self.intent_distribution, key=self.intent_distribution.get)


@dataclass
class ConsistencyReport:
    """多信号一致性校验报告。"""
    profiles: Dict[SignalSource, SignalProfile]
    overall_consistency: float   # 全局一致性评分 [0, 1]
    pairwise_scores: Dict[Tuple[SignalSource, SignalSource], float]
    likely_obfuscated: bool
    obfuscation_signals: List[str]  # 触发混淆检测的具体信号
    conflicting_pairs: List[Tuple[SignalSource, SignalSource, str]]


# ---------------------------------------------------------------------------
# API → Intent 映射表
# 仅包含具有强判别力的 API 子集, 避免噪声注入。
# 完整覆盖需结合 MITRE ATT&CK 技术映射, 此处为核心判别集。
# ---------------------------------------------------------------------------

_API_INTENT_MAP: Dict[str, IntentSignal] = {
    # 网络
    "socket": IntentSignal.NETWORK, "connect": IntentSignal.NETWORK,
    "send": IntentSignal.NETWORK, "recv": IntentSignal.NETWORK,
    "InternetOpen": IntentSignal.NETWORK, "InternetConnect": IntentSignal.NETWORK,
    "HttpOpenRequest": IntentSignal.NETWORK, "HttpSendRequest": IntentSignal.NETWORK,
    "URLDownloadToFile": IntentSignal.NETWORK, "WinHttpOpen": IntentSignal.NETWORK,
    "getaddrinfo": IntentSignal.NETWORK, "gethostbyname": IntentSignal.NETWORK,
    # 文件
    "CreateFile": IntentSignal.FILE_OPS, "ReadFile": IntentSignal.FILE_OPS,
    "WriteFile": IntentSignal.FILE_OPS, "DeleteFile": IntentSignal.FILE_OPS,
    "CopyFile": IntentSignal.FILE_OPS, "MoveFile": IntentSignal.FILE_OPS,
    "FindFirstFile": IntentSignal.FILE_OPS, "FindNextFile": IntentSignal.FILE_OPS,
    "open": IntentSignal.FILE_OPS, "fopen": IntentSignal.FILE_OPS,
    "fwrite": IntentSignal.FILE_OPS, "fread": IntentSignal.FILE_OPS,
    # 进程
    "CreateProcess": IntentSignal.PROCESS, "WinExec": IntentSignal.PROCESS,
    "CreateRemoteThread": IntentSignal.PROCESS, "OpenProcess": IntentSignal.PROCESS,
    "TerminateProcess": IntentSignal.PROCESS, "ShellExecute": IntentSignal.PROCESS,
    "system": IntentSignal.PROCESS, "popen": IntentSignal.PROCESS,
    "exec": IntentSignal.PROCESS, "fork": IntentSignal.PROCESS,
    # 内存
    "VirtualAlloc": IntentSignal.MEMORY, "VirtualProtect": IntentSignal.MEMORY,
    "WriteProcessMemory": IntentSignal.MEMORY, "ReadProcessMemory": IntentSignal.MEMORY,
    "HeapCreate": IntentSignal.MEMORY, "HeapAlloc": IntentSignal.MEMORY,
    "malloc": IntentSignal.MEMORY, "mmap": IntentSignal.MEMORY,
    "mprotect": IntentSignal.MEMORY,
    # 注册表/配置
    "RegCreateKey": IntentSignal.REGISTRY, "RegSetValue": IntentSignal.REGISTRY,
    "RegDeleteKey": IntentSignal.REGISTRY, "RegOpenKey": IntentSignal.REGISTRY,
    "RegQueryValue": IntentSignal.REGISTRY,
    # 加密
    "CryptEncrypt": IntentSignal.CRYPTO, "CryptDecrypt": IntentSignal.CRYPTO,
    "CryptAcquireContext": IntentSignal.CRYPTO, "CryptGenKey": IntentSignal.CRYPTO,
    "EVP_EncryptInit": IntentSignal.CRYPTO, "AES_": IntentSignal.CRYPTO,
    # 持久化
    "CreateService": IntentSignal.PERSISTENCE, "StartService": IntentSignal.PERSISTENCE,
    "RegisterServiceCtrlHandler": IntentSignal.PERSISTENCE,
    "SetFileAttributes": IntentSignal.PERSISTENCE,
    # 反检测
    "IsDebuggerPresent": IntentSignal.EVASION, "CheckRemoteDebuggerPresent": IntentSignal.EVASION,
    "GetTickCount": IntentSignal.EVASION, "rdtsc": IntentSignal.EVASION,
    "NtQueryInformationProcess": IntentSignal.EVASION,
    "VirtualProtectEx": IntentSignal.EVASION,
    # 数据外传
    "HttpSendRequest": IntentSignal.EXFIL, "FtpPutFile": IntentSignal.EXFIL,
    "InternetWriteFile": IntentSignal.EXFIL,
}


# CFG 拓扑特征 → 意图信号的映射
# 高扇出 / 多分支配 → 网络或进程操控; 线性流程 → 文件操作或加密;
# 循环密集 → 加密或持久化轮询
_CFG_INTENT_INDICATORS: Dict[str, IntentSignal] = {
    "high_fanout": IntentSignal.PROCESS,
    "loop_dense": IntentSignal.CRYPTO,
    "linear_chain": IntentSignal.FILE_OPS,
    "callback_rich": IntentSignal.NETWORK,
    "exception_handler_dense": IntentSignal.EVASION,
    "self_modifying_pattern": IntentSignal.EVASION,
    "syscall_dense": IntentSignal.MEMORY,
    "indirect_call_heavy": IntentSignal.EVASION,
}


class IntentConsistencyVerifier:
    """
    多信号意图一致性校验器。

    三条独立信号通路:
    1. API 导入表 → 意图分布
    2. CFG 结构特征 → 意图分布
    3. 代码指令模式 → 意图分布

    一致性评分算法:
    - 计算每对信号源之间的 Jensen-Shannon 散度
    - 取均值作为全局不一致性度量
    - 1 - 均值 = 一致性评分
    - 低于阈值 (默认 0.55) 触发混淆警报

    设计要点: 不直接将单一信号映射为恶意识别, 而是建模
    "信号间协方差" —— 自然样本的信号在高维分布中应聚类,
    对抗混淆破坏这种聚类结构。
    """

    _OBFUSCATION_THRESHOLD = 0.55

    def __init__(self, threshold: float = 0.55):
        self._threshold = threshold

    def profile_api_imports(self, api_calls: List[str]) -> SignalProfile:
        """从 API 调用列表构建意图画像。"""
        if not api_calls:
            return SignalProfile(
                source=SignalSource.API_IMPORTS,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        counter: Dict[IntentSignal, int] = Counter()
        unmatched = 0
        for api in api_calls:
            # 精确匹配 → 前缀匹配
            intent = _API_INTENT_MAP.get(api)
            if intent is None:
                for prefix, sig in _API_INTENT_MAP.items():
                    if api.startswith(prefix) or api.lower().startswith(prefix.lower()):
                        intent = sig
                        break
            if intent is not None:
                counter[intent] += 1
            else:
                unmatched += 1

        total = sum(counter.values()) + unmatched
        if total == 0:
            return SignalProfile(
                source=SignalSource.API_IMPORTS,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        dist = {k: v / total for k, v in counter.items()}
        # 未匹配比例作为置信度折扣
        confidence = 1.0 - (unmatched / total)
        ranked = sorted(dist, key=dist.get, reverse=True)  # noqa: F841
        return SignalProfile(
            source=SignalSource.API_IMPORTS,
            intent_distribution=dist,
            confidence=confidence,
            evidence_count=len(api_calls),
            top_intents=sorted(dist, key=dist.get, reverse=True)[:3],
        )

    def profile_cfg_features(self, cfg_features: Dict[str, float]) -> SignalProfile:
        """
        从 CFG 结构特征构建意图画像。

        cfg_features 键为 _CFG_INTENT_INDICATORS 中的特征名,
        值为该特征的归一化强度 [0, 1]。
        """
        if not cfg_features:
            return SignalProfile(
                source=SignalSource.CFG_STRUCTURE,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        scores: Dict[IntentSignal, float] = {}
        weight_sum = 0.0
        for feature, strength in cfg_features.items():
            intent = _CFG_INTENT_INDICATORS.get(feature)
            if intent is not None:
                clamped = max(0.0, min(1.0, strength))
                if intent not in scores:
                    scores[intent] = 0.0
                scores[intent] += clamped
                weight_sum += 1.0

        if weight_sum == 0:
            return SignalProfile(
                source=SignalSource.CFG_STRUCTURE,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        dist = {k: v / weight_sum for k, v in scores.items()}
        # CFG 特征的置信度受特征数量影响, 特征越多越可靠
        confidence = min(0.95, len(cfg_features) / 8.0)
        return SignalProfile(
            source=SignalSource.CFG_STRUCTURE,
            intent_distribution=dist,
            confidence=confidence,
            evidence_count=len(cfg_features),
            top_intents=sorted(dist, key=dist.get, reverse=True)[:3],
        )

    def profile_code_patterns(self, patterns: Dict[str, int]) -> SignalProfile:
        """
        从代码模式 n-gram 构建意图画像。

        patterns: 键为模式描述, 值为出现频次。
        例如: {"push_ret": 5, "indirect_call": 3, "tight_loop": 12}
        """
        if not patterns:
            return SignalProfile(
                source=SignalSource.CODE_PATTERNS,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        # 模式 → 意图的启发式映射
        _PATTERN_INTENT: Dict[str, IntentSignal] = {
            "tight_loop": IntentSignal.CRYPTO,
            "push_ret": IntentSignal.EVASION,
            "indirect_call": IntentSignal.EVASION,
            "syscall_pattern": IntentSignal.MEMORY,
            "callback_reg": IntentSignal.NETWORK,
            "file_enum_loop": IntentSignal.FILE_OPS,
            "process_walk": IntentSignal.PROCESS,
            "reg_key_iter": IntentSignal.REGISTRY,
            "sleep_call": IntentSignal.EVASION,
            "encrypt_loop": IntentSignal.CRYPTO,
        }
        scores: Dict[IntentSignal, float] = Counter()  # type: ignore[assignment]
        total = sum(patterns.values())
        for pat, count in patterns.items():
            intent = _PATTERN_INTENT.get(pat)
            if intent is not None:
                scores[intent] += count / max(1, total)

        if not scores:
            return SignalProfile(
                source=SignalSource.CODE_PATTERNS,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        # 归一化
        score_sum = sum(scores.values())  # type: ignore[arg-type]
        dist = {k: v / score_sum for k, v in scores.items()}  # type: ignore[union-attr]
        confidence = min(0.9, total / 20.0)
        return SignalProfile(
            source=SignalSource.CODE_PATTERNS,
            intent_distribution=dist,
            confidence=confidence,
            evidence_count=len(patterns),
            top_intents=sorted(dist, key=dist.get, reverse=True)[:3],
        )

    def profile_string_table(self, strings: List[str]) -> SignalProfile:
        """从可读字符串提取意图信号。"""
        if not strings:
            return SignalProfile(
                source=SignalSource.STRING_TABLE,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        _STRING_PATTERNS: Dict[str, IntentSignal] = {
            r"https?://": IntentSignal.NETWORK,
            r"\.(?:exe|dll|sys)$": IntentSignal.FILE_OPS,
            r"\\registry\\": IntentSignal.REGISTRY,
            r"cmd\.exe": IntentSignal.PROCESS,
            r"SELECT\s": IntentSignal.EXFIL,
            r"password": IntentSignal.EXFIL,
            r"encrypt": IntentSignal.CRYPTO,
            r"debug": IntentSignal.EVASION,
            r"vmware|virtualbox": IntentSignal.EVASION,
            r"task\s*scheduler": IntentSignal.PERSISTENCE,
        }
        scores: Dict[IntentSignal, float] = Counter()  # type: ignore[assignment]
        matched = 0
        for s in strings:
            for pattern, intent in _STRING_PATTERNS.items():
                if re.search(pattern, s, re.IGNORECASE):
                    scores[intent] += 1  # type: ignore[index]
                    matched += 1
                    break

        if matched == 0:
            return SignalProfile(
                source=SignalSource.STRING_TABLE,
                intent_distribution={},
                confidence=0.0,
                evidence_count=0,
            )
        total = sum(scores.values())  # type: ignore[arg-type]
        dist = {k: v / total for k, v in scores.items()}  # type: ignore[union-attr]
        confidence = min(0.85, matched / len(strings) + 0.2)
        return SignalProfile(
            source=SignalSource.STRING_TABLE,
            intent_distribution=dist,
            confidence=confidence,
            evidence_count=len(strings),
            top_intents=sorted(dist, key=dist.get, reverse=True)[:3],
        )

    def _js_divergence(
        self, dist_a: Dict[IntentSignal, float], dist_b: Dict[IntentSignal, float]
    ) -> float:
        """Jensen-Shannon 散度, 对称且有界 [0, ln(2)]。"""
        all_keys = set(dist_a.keys()) | set(dist_b.keys())
        if not all_keys:
            return 0.0
        js = 0.0
        for k in all_keys:
            p = dist_a.get(k, 0.0)
            q = dist_b.get(k, 0.0)
            m = (p + q) / 2.0
            if m > 0:
                if p > 0:
                    js += p * math.log(p / m)
                if q > 0:
                    js += q * math.log(q / m)
        return js / 2.0

    def verify(
        self,
        api_calls: List[str],
        cfg_features: Optional[Dict[str, float]] = None,
        code_patterns: Optional[Dict[str, int]] = None,
        strings: Optional[List[str]] = None,
    ) -> ConsistencyReport:
        """
        执行多信号一致性校验。

        返回 ConsistencyReport, 其中:
        - overall_consistency < 阈值 → likely_obfuscated = True
        - conflicting_pairs 包含具体的不一致信号对
        """
        profiles: Dict[SignalSource, SignalProfile] = {}

        p_api = self.profile_api_imports(api_calls)
        profiles[SignalSource.API_IMPORTS] = p_api

        p_cfg = self.profile_cfg_features(cfg_features or {})
        profiles[SignalSource.CFG_STRUCTURE] = p_cfg

        p_code = self.profile_code_patterns(code_patterns or {})
        profiles[SignalSource.CODE_PATTERNS] = p_code

        if strings:
            p_str = self.profile_string_table(strings)
            profiles[SignalSource.STRING_TABLE] = p_str

        # 计算两两 JS 散度
        active = [s for s, p in profiles.items() if p.evidence_count > 0 and p.confidence > 0.1]
        pairwise: Dict[Tuple[SignalSource, SignalSource], float] = {}
        js_values: List[float] = []

        for i in range(len(active)):
            for j in range(i + 1, len(active)):
                s_a, s_b = active[i], active[j]
                js = self._js_divergence(
                    profiles[s_a].intent_distribution,
                    profiles[s_b].intent_distribution,
                )
                pairwise[(s_a, s_b)] = js
                js_values.append(js)

        if not js_values:
            overall = 1.0
        else:
            # JS 散度均值 → 转换为一致性评分
            avg_js = sum(js_values) / len(js_values)
            # ln(2) ≈ 0.6931, 规范化到 [0, 1] 区间
            normalized = avg_js / 0.6931
            overall = 1.0 - min(1.0, normalized)

        # 检测冲突对: 任意一对的散度超过 0.4 bit 视为显著不一致
        conflicting: List[Tuple[SignalSource, SignalSource, str]] = []
        obfuscation_signals: List[str] = []
        for (a, b), js in pairwise.items():
            if js > 0.4:
                dom_a = profiles[a].dominant_intent().value
                dom_b = profiles[b].dominant_intent().value
                reason = f"{a.value}→{dom_a} vs {b.value}→{dom_b} (JS={js:.3f})"
                conflicting.append((a, b, reason))

        if overall < self._threshold:
            likely_obfuscated = True
            if conflicting:
                obfuscation_signals.append(
                    f"多信号意图不匹配 (一致性={overall:.3f}): "
                    + "; ".join(r for _, _, r in conflicting)
                )
            else:
                obfuscation_signals.append(
                    f"低置信度全局不一致 (一致性={overall:.3f}), 可能为样本稀疏导致"
                )
        else:
            likely_obfuscated = False

        # 额外检查: API 和 CFG 的主导意图截然不同
        if p_api.evidence_count > 0 and p_cfg.evidence_count > 0:
            dom_api = p_api.dominant_intent()
            dom_cfg = p_cfg.dominant_intent()
            if dom_api != dom_cfg and dom_api != IntentSignal.UNKNOWN and dom_cfg != IntentSignal.UNKNOWN:
                # 仅标记高置信度冲突
                api_conf = p_api.intent_distribution.get(dom_api, 0)
                cfg_conf = p_cfg.intent_distribution.get(dom_cfg, 0)
                if api_conf > 0.3 and cfg_conf > 0.3:
                    likely_obfuscated = True
                    msg = (
                        f"API 主导意图={dom_api.value}({api_conf:.2f}) "
                        f"vs CFG 主导意图={dom_cfg.value}({cfg_conf:.2f})"
                    )
                    if msg not in obfuscation_signals:
                        obfuscation_signals.append(msg)

        return ConsistencyReport(
            profiles=profiles,
            overall_consistency=overall,
            pairwise_scores=pairwise,
            likely_obfuscated=likely_obfuscated,
            obfuscation_signals=obfuscation_signals,
            conflicting_pairs=conflicting,
        )


__all__ = [
    "SignalSource",
    "IntentSignal",
    "SignalProfile",
    "ConsistencyReport",
    "IntentConsistencyVerifier",
]
