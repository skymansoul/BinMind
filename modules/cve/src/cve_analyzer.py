# CVE分析入口-串联各子模块的统一调度层。
# 双KB架构为已知技术债：CVEKnowledgeBase基于SQLite，另有一个CVEKB JSON版本。
# 分析器惰性加载可用者。长期应将两者合并为单一实现。
#
# semantic_search()每次调用新建CVESearchEngine-少量查询适用，批量场景需缓存。
# 此为待优化项，非缺陷。
#
# prioritize()逐个try/except各评分模块-单模块失败不影响其余环节。

import os
from typing import List, Dict, Optional, Any, Union

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase, get_kb


class CVEAnalyzer:
    """CVE分析主入口-文件/二进制/SBOM分发调度。"""

    def __init__(self, kb: Optional[CVEKnowledgeBase] = None):
        """初始化分析器。
        kb: 可选注入点。None时使用模块级单例。
        兼容双KB模式-按需传入CVEKB JSON实例。"""
        self._kb = kb if kb is not None else get_kb()

# 主分发
    def analyze(self, target: str) -> Dict[str, Any]:
        """主入口。接受文件路径、二进制路径或SBOM路径。
        按目标类型分发。
        返回分析管道结果字典。"""
        if not os.path.exists(target):
            return {"error": f"Target not found: {target}", "target": target}

        result: Dict[str, Any] = {
            "target": target,
            "type": self._detect_type(target),
        }

        target_type = result["type"]

        if target_type == "file":
            result["findings"] = self._analyze_file(target)
        elif target_type == "binary":
            result["findings"] = self._analyze_binary(target)
        elif target_type == "sbom":
            result["findings"] = self._analyze_sbom(target)
        else:
            result["error"] = f"Unknown target type: {target_type}"

        return result

    def _detect_type(self, target: str) -> str:
        """按路径/扩展名推断目标类型。"""
        target_lower = target.lower()
        if target_lower.endswith((".json", ".xml")) and any(
            kw in os.path.basename(target_lower) for kw in ["sbom", "cyclonedx", "spdx", "bom"]
        ):
            return "sbom"
        if target_lower.endswith((".exe", ".dll", ".so", ".elf", ".bin", ".app", ".sys", ".ko", ".o")):
            return "binary"
        return "file"

# 兼容方法
    def analyze_strings(self, strings: List[str]) -> List[CVEEntry]:
        """兼容方法-从提取的字符串中解析CVE ID并检索知识库。
        匹配CVE-YYYY-NNNNN格式。"""
        import re

        found: Dict[str, CVEEntry] = {}
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

        for s in strings:
            for match in cve_pattern.finditer(s):
                cve_id = match.group(0).upper()
                if cve_id not in found:
                    entry = self._kb.get(cve_id)
                    if entry:
                        found[cve_id] = entry

        return list(found.values())

# 知识库访问
    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """从知识库获取单个CVE条目。"""
        return self._kb.get(cve_id)

    def search_cves(self, query: str, limit: int = 50) -> List[CVEEntry]:
        """通过知识库内置搜索做关键词检索。"""
        entries, _ = self._kb.search(query=query, limit=limit)
        return entries

# 语义搜索
    def semantic_search(self, query: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
        """基于BM25的CVE描述语义检索。
        每次调用新建CVESearchEngine-引擎未缓存。
        少量查询适用，批量场景需优化：将引擎缓存到实例上。"""
        from .cve_search import CVESearchEngine

        engine = CVESearchEngine(self._kb)
        engine.build()
        return engine.search(query, top_n=top_n)

# 富化
    def enrich_with_epss(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """批量EPSS富化。返回 cve_id -> {score, percentile}。"""
        try:
            from .cve_epss import EPSSClient
            client = EPSSClient()
            return client.fetch_scores(cve_ids)
        except ImportError:
            # cve_epss不可用-返回空富化
            return {cve_id: {"epss_score": None, "epss_percentile": None} for cve_id in cve_ids}

# 优先级排序
    def prioritize(self, entries: List[CVEEntry]) -> List[CVEEntry]:
        """按严重度 + EPSS评分 + SSVC决策排序。
        各评分模块独立try/except-单模块失败不中断整个管道。"""
        enriched = list(entries)

        # 收集cve_id做批量富化
        cve_ids = [e.cve_id for e in enriched]

        # EPSS评分
        try:
            from .cve_epss import EPSSClient
            client = EPSSClient()
            epss_data = client.fetch_scores(cve_ids)
            for entry in enriched:
                data = epss_data.get(entry.cve_id, {})
                if data.get("epss_score") is not None:
                    entry.epss_score = data["epss_score"]
                if data.get("epss_percentile") is not None:
                    entry.epss_percentile = data["epss_percentile"]
        except ImportError:
            pass  # epss模块不可用

        # SSVC评分（尝试导入，缺失则跳过）
        try:
            from .cve_ssvc import evaluate_ssvc
            for entry in enriched:
                try:
                    decision = evaluate_ssvc(entry)
                    # 将决策暂存于entry上（临时方案-应作为正式字段）
                    entry.__dict__["_ssvc_decision"] = decision
                except Exception:
                    pass
        except ImportError:
            pass

        # 排序：CRITICAL > HIGH > MEDIUM > LOW > NONE > UNKNOWN，同级别按epss percentile降序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

        def sort_key(e: CVEEntry) -> Tuple[int, float]:
            sev = severity_order.get(e.severity, 99)
            epss = -(e.epss_percentile or 0.0)  # 取负使高percentile排前
            return (sev, epss)

        enriched.sort(key=sort_key)
        return enriched

# 内部分析器
    def _analyze_file(self, path: str) -> Dict[str, Any]:
        """分析文本文件-读取内容并搜索知识库。"""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            findings["error"] = f"Failed to read file: {e}"
            return findings

        # 正则提取CVE ID
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        cve_ids = list(set(m.group(0).upper() for m in cve_pattern.finditer(content)))

        entries = []
        for cve_id in cve_ids[:100]:  # 上限100，避免过度查询
            entry = self._kb.get(cve_id)
            if entry:
                entries.append(entry)

        findings["cves"] = [e.to_dict() for e in entries]
        findings["cve_count"] = len(entries)
        return findings

    def _analyze_binary(self, path: str) -> Dict[str, Any]:
        """分析二进制-提取字符串并搜索知识库中的CVE。"""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        # 简易二进制字符串提取（无pefile/elf依赖）
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            findings["error"] = f"Failed to read binary: {e}"
            return findings

        # 提取 >=4字符的可打印ASCII字符串
        strings = self._extract_strings(data)

        entries = self.analyze_strings(strings)
        findings["cves"] = [e.to_dict() for e in entries]
        findings["cve_count"] = len(entries)
        findings["strings_extracted"] = len(strings)
        return findings

    def _analyze_sbom(self, path: str) -> Dict[str, Any]:
        """分析SBOM文件-解析并匹配包到已知CVE。"""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        try:
            # 优先使用sbom匹配器
            from .cve_sbom_matcher import match_sbom
            result = match_sbom(path, self._kb)
            findings.update(result)
        except ImportError:
            # 回退：直接读取文件查找CVE ID
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                import re
                cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
                cve_ids = list(set(m.group(0).upper() for m in cve_pattern.finditer(content)))

                entries = []
                for cve_id in cve_ids[:100]:
                    entry = self._kb.get(cve_id)
                    if entry:
                        entries.append(entry)
                findings["cves"] = [e.to_dict() for e in entries]
                findings["cve_count"] = len(entries)
            except Exception as e:
                findings["error"] = f"SBOM analysis failed: {e}"

        return findings

    @staticmethod
    def _extract_strings(data: bytes, min_len: int = 4) -> List[str]:
        """从二进制数据提取可打印ASCII字符串。
        静态方法-不依赖实例状态。"""
        strings: List[str] = []
        current: List[int] = []

        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII
                current.append(byte)
            else:
                if len(current) >= min_len:
                    strings.append(bytes(current).decode("ascii", errors="replace"))
                current = []

        # 末尾残留处理
        if len(current) >= min_len:
            strings.append(bytes(current).decode("ascii", errors="replace"))

        return strings
