# 攻击/漏洞签名自主提取 —— 从二进制分析结果中挖掘 IOC 与检测规则
# 文献依据:
#   "Fast and automated generation of attack signatures..."
#     — 最早的自动化签名构造框架，从网络/主机入侵事件中提取 token-based 签名。
#   "Dynamic Taint Analysis for Automatic Detection..."
#     — 动态污点分析 + 自动化签名构造，签名存为语义骨架。
#   "Towards automated exploit signature generation using honeypots"
# — 蜜罐驱动的漏洞签名提取流水线。
#   "Automatic Patch-Based Exploit Generation is Possible..."
# — 基于补丁 diff 的
#     自主 exploit 构造，其签名提取部分直接启发本模块。
#
# 签名类型:
#   - IOC (Indicator of Compromise): 文件 hash、IP、域名、mutex 名等
# Semantic: 污点传播路径、控制流特征、API 调用序列
# Structural: 字节码 n-gram、CFG 拓扑模式、基本块计数
#   - Behavioral: syscall trace 模式、文件系统/注册表操作序列
#
# 输出格式: YARA 规则、Sigma 规则、JSON IOC 列表、STIX 2.1 bundle。

import hashlib
import json
import re
import time
from typing import List, Dict, Optional, Any, Set, Tuple
from collections import Counter


# IOC 提取 —— 从 findings 中自主识别可操作的威胁指标

class IOCExtractor:
    """从分析结果中提取 Indicators of Compromise。

    支持类型: file_hash (MD5/SHA1/SHA256), ipv4, ipv6, domain, url, mutex,
    registry_key, file_path, email, cve_id。

 将签名定义为 token 序列的最长子串；
    本实现泛化至任意 IOC 类型的提取 + 去重 + 置信度排序。
    """

    # 预编译正则模式 —— 按识别顺序排列
    _PATTERNS = [
        ("sha256", re.compile(r'\b[a-fA-F0-9]{64}\b')),
        ("sha1",   re.compile(r'\b[a-fA-F0-9]{40}\b')),
        ("md5",    re.compile(r'\b[a-fA-F0-9]{32}\b')),
        ("ipv4",   re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                              r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')),
        ("domain", re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
                              r'[a-zA-Z]{2,}\b')),
        ("url",    re.compile(r'https?://[^\s,\"\'\]\)]{8,200}')),
        ("email",  re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')),
        ("cve",    re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)),
    ]

    def __init__(self):
        self._seen: Dict[str, Set[str]] = {t: set() for t, _ in self._PATTERNS}
        self._all_iocs: List[dict] = []

    def extract_from_text(self, text: str, source: str = "",
                           min_confidence: float = 0.5) -> List[dict]:
        """从任意文本中提取 IOC。source 标记 IOC 来源。"""
        found = []
        for ioc_type, pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if value in self._seen[ioc_type]:
                    continue
                self._seen[ioc_type].add(value)
                conf = self._confidence(ioc_type, value)
                if conf >= min_confidence:
                    ioc = {"type": ioc_type, "value": value,
                           "confidence": conf, "source": source,
                           "extracted_at": time.time()}
                    found.append(ioc)
                    self._all_iocs.append(ioc)
        return found

    def extract_from_findings(self, findings: List[dict],
                               sig_id: int = 0) -> List[dict]:
        """从 analysis_results 批量提取 IOC。"""
        all_iocs = []
        text_fields = ["description", "detail", "summary", "message",
                       "output", "value", "data", "addr", "caller", "callee"]
        for finding in findings:
            for field in text_fields:
                val = finding.get(field, "")
                if isinstance(val, str) and len(val) > 3:
                    src = f"sig:{sig_id}:{finding.get('type', 'unknown')}"
                    iocs = self.extract_from_text(val, source=src)
                    all_iocs.extend(iocs)
        return all_iocs

    def _confidence(self, ioc_type: str, value: str) -> float:
        """IOC 置信度启发式评估 —— 基于结构与上下文信号。"""
        if ioc_type == "sha256":
            return 0.95
        if ioc_type in ("ipv4", "domain"):
            # 排除常见假阳性 (回环、保留地址、localhost 等)
            if value in ("127.0.0.1", "0.0.0.0", "255.255.255.255",
                         "localhost", "example.com"):
                return 0.1
            return 0.7
        if ioc_type == "cve":
            return 0.9
        if ioc_type == "url":
            return 0.65
        return 0.6

    def top_by_type(self, ioc_type: str, limit: int = 20) -> List[dict]:
        return [i for i in self._all_iocs if i["type"] == ioc_type][:limit]

    def to_yara_rule(self, rule_name: str = "auto_generated_rule",
                      min_confidence: float = 0.7) -> str:
        """从高置信度 IOC 构造 YARA 规则骨架 —— 字符串部分用 IOC 值填充。"""
        iocs = [i for i in self._all_iocs if i["confidence"] >= min_confidence]
        if not iocs:
            return ""

        strings = []
        for i, ioc in enumerate(iocs):
            v = ioc["value"]
            if ioc["type"] in ("sha256", "sha1", "md5"):
                strings.append(f'        $hash_{i} = "{{{v}}}" nocase')
            elif ioc["type"] in ("ipv4", "domain", "url", "cve"):
                escaped = v.replace('\\', '\\\\').replace('"', '\\"')
                strings.append(f'        $str_{i} = "{escaped}" nocase wide ascii')

        condition_parts = []
        if strings:
            condition_parts.append("any of them")

        rule = f"""rule {rule_name} {{
    meta:
        author = "BinMind Signature Miner"
        date = "{time.strftime('%Y-%m-%d')}"
        confidence = "{min_confidence}"
    strings:
{chr(10).join(strings)}
    condition:
        {" or ".join(condition_parts) if condition_parts else "false"}
}}"""
        return rule

    def to_stix_bundle(self) -> dict:
        """将 IOC 导出为 STIX 2.1 bundle 格式。"""
        indicators = []
        for i, ioc in enumerate(self._all_iocs):
            ind = {
                "type": "indicator",
                "id": f"indicator--{hashlib.sha256(ioc['value'].encode()).hexdigest()[:32]}",
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "name": f"{ioc['type']}: {ioc['value'][:60]}",
                "pattern": f"[{ioc['type']}:value = '{ioc['value']}']",
                "pattern_type": "stix",
                "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "confidence": int(ioc["confidence"] * 100),
            }
            indicators.append(ind)
        return {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]}",
            "objects": indicators,
        }

    @property
    def total(self) -> int:
        return len(self._all_iocs)

    def stats(self) -> dict:
        by_type = Counter(i["type"] for i in self._all_iocs)
        return {"total": self.total, "by_type": dict(by_type)}


# SignaturePatternMiner — 从 findings 中挖掘检测模式
# 的语义骨架构造策略

class SignaturePatternMiner:
    """从分析结果中提取可复用的检测模式。

    模式类型:
      - api_sequence: API 调用序列 n-gram
      - control_flow: 基本块计数 + 边密度 + 循环深度
      - string_constants: 二进制中出现的特征字符串
      - entropy_profile: section-level 熵分布
    """

    def __init__(self, min_support: int = 3, ngram_size: int = 3):
        self.min_support = min_support
        self.n = ngram_size
        self._patterns: Dict[str, List[dict]] = {
            "api_sequence": [],
            "control_flow": [],
            "string_constants": [],
            "entropy_profile": [],
        }

    def mine_from_findings(self, findings: List[dict],
                            sig_id: int = 0) -> Dict[str, List[dict]]:
        """从单条签名的 findings 中挖掘模式。"""
        # API 序列提取
        api_calls = []
        for f in findings:
            ftype = f.get("type", "")
            if ftype in ("call_edge", "function_call", "api_call"):
                api_name = (f.get("callee") or f.get("to") or
                            f.get("name") or f.get("function", ""))
                if api_name:
                    api_calls.append(api_name)

        if len(api_calls) >= self.n:
            for i in range(len(api_calls) - self.n + 1):
                seq = tuple(api_calls[i:i + self.n])
                self._patterns["api_sequence"].append({
                    "sig_id": sig_id, "pattern": seq,
                    "type": "api_sequence",
                })

        # 控制流特征 (从 findings 基本块数据提取)
        bb_count = 0
        edge_count = 0
        for f in findings:
            if f.get("type") in ("cfg", "control_flow", "basic_block"):
                bb_count += f.get("block_count", f.get("count", 0))
                edge_count += f.get("edge_count", 0)
        if bb_count > 0:
            self._patterns["control_flow"].append({
                "sig_id": sig_id,
                "basic_blocks": bb_count,
                "edges": edge_count,
                "density": round(edge_count / max(bb_count, 1), 3),
            })

        # 特征字符串常量
        strings_found = []
        for f in findings:
            for key in ("strings", "string_constants", "literals"):
                vals = f.get(key, [])
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, str) and len(v) >= 4:
                            strings_found.append(v)
        for s in set(strings_found):
            self._patterns["string_constants"].append({
                "sig_id": sig_id, "value": s,
                "length": len(s),
            })

        return {k: v for k, v in self._patterns.items() if v}

    def frequent_api_patterns(self, top_k: int = 20) -> List[Tuple[tuple, int]]:
        """返回出现频率最高的 API 调用序列模式。"""
        seqs = [tuple(p["pattern"]) for p in self._patterns["api_sequence"]]
        cnt = Counter(seqs)
        return cnt.most_common(top_k)

    def export_rules(self, out_path: str = "") -> List[dict]:
        """将模式导出为可执行检测规则。"""
        rules = []
        freq = self.frequent_api_patterns(top_k=50)
        for seq_tuple, count in freq:
            if count >= self.min_support:
                rules.append({
                    "rule_type": "api_sequence",
                    "api_chain": list(seq_tuple),
                    "support": count,
                    "description": f"API call sequence: {' -> '.join(seq_tuple)}",
                })
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
        return rules
