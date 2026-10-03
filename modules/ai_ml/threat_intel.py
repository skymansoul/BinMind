from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

MISP_AVAILABLE = False
try:
    from pymisp import PyMISP, MISPEvent
    MISP_AVAILABLE = True
except ImportError:
    # 占位类便于测试 patch，运行时不可用
    class PyMISP:
        pass
    class MISPEvent:
        pass

OTX_AVAILABLE = False
try:
    from OTXv2 import OTXv2
    OTX_AVAILABLE = True
except ImportError:
    # 占位类便于测试 patch，运行时不可用
    class OTXv2:
        def __init__(self, api_key):
            pass


class Config:
    """威胁情报配置，字段对齐历史 config.py 的 MISP/OTX 配置项。"""
    MISP_URL = os.environ.get('MISP_URL', '')
    MISP_API_KEY = os.environ.get('MISP_API_KEY', '')
    MISP_VERIFY_SSL = os.environ.get('MISP_VERIFY_SSL', 'true').lower() == 'true'
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    THREAT_INTEL_TIMEOUT = int(os.environ.get('THREAT_INTEL_TIMEOUT', '30'))


@dataclass
class ThreatIntelResult:
    """字段同时兼容旧版扁平结构与新版结构化结构，保证调用方可按任一接口访问。"""
    query: str = ""
    query_type: str = ""  # 哈希, cve, indicator, ip, domain
    source: str = ""  # misp, otx, local
    found: bool = False
    query_id: str = ""
    task_id: str = ""
    provider: str = ""
    query_value: str = ""
    is_malicious: bool = False
    malware_families: List[str] = field(default_factory=list)
    apt_groups: List[str] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)
    pulses: List[Dict[str, Any]] = field(default_factory=list)
    in_wild: bool = False
    first_seen: str = ""
    last_seen: str = ""
    summary: str = ""
    severity: str = "unknown"
    confidence: float = 0.0
    description: str = ""
    tags: List[str] = field(default_factory=list)
    related_indicators: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'query': self.query,
            'query_type': self.query_type,
            'source': self.source,
            'found': self.found,
            'query_id': self.query_id,
            'task_id': self.task_id,
            'provider': self.provider,
            'query_value': self.query_value,
            'is_malicious': self.is_malicious,
            'malware_families': self.malware_families,
            'apt_groups': self.apt_groups,
            'iocs': self.iocs,
            'pulses': self.pulses,
            'in_wild': self.in_wild,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'summary': self.summary,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'tags': self.tags,
            'related_indicators': self.related_indicators,
            'references': self.references,
            'raw_response': self.raw_response,
            'timestamp': self.timestamp,
        }


class ThreatIntelClient:

    def __init__(
        self,
        misp_url: Optional[str] = None,
        misp_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        db_path: Optional[str] = None,
        providers: Optional[List[str]] = None,
        **kwargs,
    ) -> None:
        self.providers = list(providers) if providers else ['misp', 'otx']
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.misp_client = None
        self.otx_client = None
        self.misp_url = misp_url or os.environ.get('MISP_URL', '')
        self.misp_key = misp_key or os.environ.get('MISP_KEY', '')
        self.otx_key = otx_key or os.environ.get('OTX_KEY', '')

        db_path = db_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'threat_intel_cache.sqlite3'
        )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

        self._cache_ttl = 86400  # 24 hours
        # 并发控制：限制同时请求数，避免触发API限流
        self._rate_semaphore = threading.BoundedSemaphore(5)
        self._init_clients()

    def _init_clients(self) -> None:
        """按 providers 初始化 MISP/OTX 客户端。"""
        if 'misp' in self.providers or 'all' in self.providers:
            self._init_misp()
        if 'otx' in self.providers or 'all' in self.providers:
            self._init_otx()

    @staticmethod
    def _ns() -> Dict[str, Any]:
        """取模块命名空间；外部 patch 通过 modules.threat_intel 生效时取其属性。"""
        try:
            import modules as _mp
            candidate = getattr(_mp, 'threat_intel', None)
        except Exception:
            candidate = None
        if candidate is None:
            candidate = sys.modules.get('modules.threat_intel')
        if candidate is not None:
            return vars(candidate)
        return globals()

    def _init_misp(self) -> None:
        """初始化 MISP 客户端，配置缺失或库缺失时保持为空。"""
        ns = self._ns()
        cfg = ns.get('Config', Config)
        if not ns.get('MISP_AVAILABLE'):
            _logger.warning("[ThreatIntel] PyMISP 未安装，跳过MISP初始化")
            return
        if not cfg.MISP_URL or not cfg.MISP_API_KEY:
            _logger.warning("[ThreatIntel] MISP配置未设置，跳过MISP初始化")
            return
        try:
            self.misp_client = ns['PyMISP'](
                url=cfg.MISP_URL,
                key=cfg.MISP_API_KEY,
                ssl=cfg.MISP_VERIFY_SSL,
                timeout=cfg.THREAT_INTEL_TIMEOUT,
            )
            _logger.info("[ThreatIntel] MISP客户端已初始化")
        except Exception as e:
            _logger.error(f"[ThreatIntel] MISP初始化失败: {e}")

    def _init_otx(self) -> None:
        """初始化 OTX 客户端，配置缺失或库缺失时保持为空。"""
        ns = self._ns()
        cfg = ns.get('Config', Config)
        if not ns.get('OTX_AVAILABLE'):
            _logger.warning("[ThreatIntel] OTXv2 未安装，跳过OTX初始化")
            return
        if not cfg.OTX_API_KEY:
            _logger.warning("[ThreatIntel] OTX API密钥未设置，跳过OTX初始化")
            return
        try:
            self.otx_client = ns['OTXv2'](cfg.OTX_API_KEY)
            _logger.info("[ThreatIntel] OTX客户端已初始化")
        except Exception as e:
            _logger.error(f"[ThreatIntel] OTX初始化失败: {e}")

    def _generate_query_id(self) -> str:
        """生成唯一查询ID（12位十六进制）。"""
        return hashlib.md5(
            f"{datetime.now().isoformat()}{os.urandom(16)}".encode()
        ).hexdigest()[:12]

    def _parse_misp_events(self, events: List, result: ThreatIntelResult) -> None:
        """解析 MISP 事件，聚合 pulse、IOC、恶意家族与 APT 组织。"""
        for event in events:
            if MISP_AVAILABLE and isinstance(event, MISPEvent):
                event_dict = event.to_dict()
            else:
                event_dict = event

            result.pulses.append({
                'name': event_dict.get('info', ''),
                'description': event_dict.get('description', ''),
                'tags': [tag.get('name', '') for tag in event_dict.get('Tag', [])],
                'created': event_dict.get('date', ''),
            })

            for attr in event_dict.get('Attribute', []):
                result.iocs.append({
                    'type': attr.get('type', ''),
                    'value': attr.get('value', ''),
                    'category': attr.get('category', ''),
                })
                if attr.get('type') in ['malware-type', 'target-machine']:
                    result.malware_families.append(attr.get('value', ''))

            tags = [tag.get('name', '') for tag in event_dict.get('Tag', [])]
            for tag in tags:
                if 'APT' in tag or 'apt' in tag.lower():
                    result.apt_groups.append(tag)

            result.is_malicious = True

        result.summary = f"从MISP获取到{len(result.pulses)} 个事件，{len(result.iocs)} 个IOC"
        result.confidence = min(0.5 + len(result.pulses) * 0.1, 1.0)

    def _parse_otx_pulses(self, pulses: List[Dict], result: ThreatIntelResult) -> None:
        """解析 OTX pulses，聚合 pulse、IOC、恶意家族与 APT 组织。"""
        for pulse in pulses:
            result.pulses.append({
                'name': pulse.get('name', ''),
                'description': pulse.get('description', ''),
                'tags': pulse.get('tags', []),
                'created': pulse.get('created', ''),
                'modified': pulse.get('modified', ''),
            })

            if pulse.get('is_malicious'):
                result.is_malicious = True
            if pulse.get('in_wild'):
                result.in_wild = True
            if pulse.get('first_seen'):
                result.first_seen = pulse['first_seen']
            if pulse.get('last_seen'):
                result.last_seen = pulse['last_seen']

            for family in pulse.get('malware_families', []):
                if family not in result.malware_families:
                    result.malware_families.append(family)

            for actor in pulse.get('actors', []):
                if actor not in result.apt_groups:
                    result.apt_groups.append(actor)

            for indicator in pulse.get('indicators', []):
                result.iocs.append({
                    'type': indicator.get('type', ''),
                    'value': indicator.get('indicator', ''),
                    'description': indicator.get('description', ''),
                })

        result.summary = f"从OTX获取到{len(result.pulses)} 个脉冲，{len(result.iocs)} 个IOC"
        result.confidence = min(0.5 + len(result.pulses) * 0.1, 1.0)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    # SQLite 初始化
    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_cache (
                    query_hash TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    query_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_type
                ON threat_cache(query_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_timestamp
                ON threat_cache(timestamp)
            """)

    # 缓存键生成
    def _cache_key(self, query: str, query_type: str) -> str:
        content = f"{query_type}:{query.lower()}"
        return hashlib.sha256(content.encode()).hexdigest()

    def _check_cache(
        self,
        query: str,
        query_type: str,
    ) -> Optional[ThreatIntelResult]:
        key = self._cache_key(query, query_type)
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT result_json, timestamp FROM threat_cache WHERE query_hash = ?",
                (key,),
            ).fetchone()

        if row:
            result_data = json.loads(row[0])
            cache_time = row[1]
            if time.time() - cache_time < self._cache_ttl:
                return ThreatIntelResult(**result_data)

        return None

    def _save_cache(self, result: ThreatIntelResult) -> None:
        key = self._cache_key(result.query, result.query_type)
        result_json = json.dumps(result.to_dict())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_cache
                   (query_hash, query, query_type, source, result_json, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (key, result.query, result.query_type, result.source,
                 result_json, result.timestamp),
            )

    def purge_stale_cache(self, older_than_seconds: Optional[int] = None) -> int:
        """定期清除超出TTL的记录，缓存表大时建议低负载时段执行。"""
        ttl = older_than_seconds if older_than_seconds is not None else self._cache_ttl
        cutoff = time.time() - ttl
        with self._lock, self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM threat_cache WHERE timestamp < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
            conn.execute("VACUUM")  # 回收磁盘空间
        _logger.info(f"Purged {deleted} stale cache entries (TTL={ttl}s)")
        return deleted

    def query_hash(self, file_hash: str) -> ThreatIntelResult:
        hash_len = len(file_hash)
        if hash_len == 32:
            query_type = "hash_md5"
        elif hash_len == 40:
            query_type = "hash_sha1"
        elif hash_len == 64:
            query_type = "hash_sha256"
        else:
            query_type = "hash"

        cached = self._check_cache(file_hash, query_type)
        if cached:
            return cached

        result = ThreatIntelResult(
            query=file_hash,
            query_type=query_type,
            source="unknown",
            found=False,
        )

        if self.otx_key:
            otx_result = self._query_otx_hash(file_hash)
            if otx_result.found:
                result = otx_result

        if self.misp_key and not result.found:
            misp_result = self._query_misp_hash(file_hash)
            if misp_result.found:
                result = misp_result

        self._save_cache(result)
        return result

    def query_cve(self, cve_id: str) -> ThreatIntelResult:
        cached = self._check_cache(cve_id, "cve")
        if cached:
            return cached

        result = ThreatIntelResult(
            query=cve_id,
            query_type="cve",
            source="unknown",
            found=False,
        )

        if self.misp_key:
            misp_result = self._query_misp_cve(cve_id)
            if misp_result.found:
                result = misp_result

        if self.otx_key and not result.found:
            otx_result = self._query_otx_cve(cve_id)
            if otx_result.found:
                result = otx_result

        self._save_cache(result)
        return result

    def query_indicator(
        self,
        indicator: str,
        indicator_type: str = "auto",
    ) -> ThreatIntelResult:
        if indicator_type == "auto":
            indicator_type = self._detect_indicator_type(indicator)

        cached = self._check_cache(indicator, indicator_type)
        if cached:
            return cached

        result = ThreatIntelResult(
            query=indicator,
            query_type=indicator_type,
            source="unknown",
            found=False,
        )

        if self.otx_key:
            otx_result = self._query_otx_indicator(indicator, indicator_type)
            if otx_result.found:
                result = otx_result

        if self.misp_key and not result.found:
            misp_result = self._query_misp_indicator(indicator, indicator_type)
            if misp_result.found:
                result = misp_result

        self._save_cache(result)
        return result

    def _query_otx_hash(self, file_hash: str) -> ThreatIntelResult:
        try:
            import requests
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                tags = list(set(
                    tag for pulse in pulses
                    for tag in pulse.get('tags', [])
                ))

                return ThreatIntelResult(
                    query=file_hash,
                    query_type="hash",
                    source="otx",
                    found=len(pulses) > 0,
                    severity="medium" if pulses else "unknown",
                    confidence=min(len(pulses) * 0.1, 0.9),
                    description=f"Found in {len(pulses)} OTX pulses",
                    tags=tags[:20],
                    references=[p.get('name', '') for p in pulses[:5]],
                    raw_response=data,
                )
        except ImportError:
            _logger.debug("requests not available for OTX query")
        except Exception as e:
            _logger.warning(f"OTX hash query failed: {e}")

        return ThreatIntelResult(
            query=file_hash,
            query_type="hash",
            source="otx",
            found=False,
        )

    def _query_misp_hash(self, file_hash: str) -> ThreatIntelResult:
        if not self.misp_url:
            return ThreatIntelResult(
                query=file_hash,
                query_type="hash",
                source="misp",
                found=False,
            )

        try:
            import requests
            url = f"{self.misp_url}/attributes/restSearch"
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json',
            }
            data = {
                'returnFormat': 'json',
                'value': file_hash,
            }
            resp = requests.post(url, headers=headers, json=data, timeout=15, verify=False)

            if resp.status_code == 200:
                result_data = resp.json()
                attributes = result_data.get('response', {}).get('Attribute', [])
                events = set(attr.get('event_id', '') for attr in attributes)

                tags: List[str] = []
                for attr in attributes:
                    for tag in attr.get('Tag', []):
                        tags.append(tag.get('name', ''))

                return ThreatIntelResult(
                    query=file_hash,
                    query_type="hash",
                    source="misp",
                    found=len(attributes) > 0,
                    severity="high" if len(events) > 1 else "medium",
                    confidence=min(len(attributes) * 0.1, 0.95),
                    description=f"Found in {len(events)} MISP events",
                    tags=list(set(tags))[:20],
                    references=[f"MISP Event {e}" for e in sorted(events)[:5]],
                    raw_response=result_data,
                )
        except ImportError:
            _logger.debug("requests not available for MISP query")
        except Exception as e:
            _logger.warning(f"MISP hash query failed: {e}")

        return ThreatIntelResult(
            query=file_hash,
            query_type="hash",
            source="misp",
            found=False,
        )

    def _query_misp_cve(self, cve_id: str) -> ThreatIntelResult:
        """搜索 type=cve 或 tag 中包含 CVE-ID 的属性，聚合关联事件和标签。"""
        if not self.misp_url:
            return ThreatIntelResult(
                query=cve_id,
                query_type="cve",
                source="misp",
                found=False,
            )

        try:
            import requests
            url = f"{self.misp_url}/attributes/restSearch"
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json',
            }
            data = {
                'returnFormat': 'json',
                'value': cve_id,
                'type': 'vulnerability',
            }
            resp = requests.post(url, headers=headers, json=data, timeout=15, verify=False)

            if resp.status_code == 200:
                result_data = resp.json()
                attributes = result_data.get('response', {}).get('Attribute', [])
                events = set(attr.get('event_id', '') for attr in attributes)

                tags: List[str] = []
                related: List[str] = []
                for attr in attributes:
                    for tag in attr.get('Tag', []):
                        tags.append(tag.get('name', ''))
                    # 收集关联的IOC
                    if attr.get('type') == 'vulnerability':
                        related.append(attr.get('value', ''))

                # 严重程度推断：关联事件越多 → 越高
                ecount = len(events)
                if ecount >= 5:
                    severity = "critical"
                elif ecount >= 2:
                    severity = "high"
                elif ecount >= 1:
                    severity = "medium"
                else:
                    severity = "unknown"

                return ThreatIntelResult(
                    query=cve_id,
                    query_type="cve",
                    source="misp",
                    found=ecount > 0,
                    severity=severity,
                    confidence=min(ecount * 0.08 + 0.15, 0.95),
                    description=f"Found in {ecount} MISP events" if ecount else "No MISP events",
                    tags=list(set(tags))[:20],
                    related_indicators=list(set(related))[:20],
                    references=[f"MISP Event {e}" for e in sorted(events)[:5]],
                    raw_response=result_data,
                )
        except ImportError:
            _logger.debug("requests not available for MISP CVE query")
        except Exception as e:
            _logger.warning(f"MISP CVE query failed: {e}")

        return ThreatIntelResult(
            query=cve_id,
            query_type="cve",
            source="misp",
            found=False,
        )

    def _query_otx_cve(self, cve_id: str) -> ThreatIntelResult:
        """通过搜索 CVE ID 获取关联 pulses。"""
        try:
            import requests
            url = "https://otx.alienvault.com/api/v1/search/pulses"
            headers = {'X-OTX-API-KEY': self.otx_key}
            params = {'q': cve_id, 'limit': 20}
            resp = requests.get(url, headers=headers, params=params, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get('results', [])
                tags = list(set(
                    tag for pulse in pulses
                    for tag in pulse.get('tags', [])
                ))

                pcount = len(pulses)
                if pcount >= 5:
                    severity = "critical"
                elif pcount >= 2:
                    severity = "high"
                elif pcount >= 1:
                    severity = "medium"
                else:
                    severity = "unknown"

                # 提取关联的 IOC indicators
                related: List[str] = []
                for pulse in pulses:
                    for ind in pulse.get('indicators', []):
                        related.append(ind.get('indicator', ''))

                return ThreatIntelResult(
                    query=cve_id,
                    query_type="cve",
                    source="otx",
                    found=pcount > 0,
                    severity=severity,
                    confidence=min(pcount * 0.08 + 0.15, 0.9),
                    description=f"Found in {pcount} OTX pulses" if pcount else "Not found in OTX",
                    tags=tags[:20],
                    related_indicators=list(set(related))[:20],
                    references=[p.get('name', '') or p.get('id', '') for p in pulses[:5]],
                    raw_response=data,
                )
        except ImportError:
            _logger.debug("requests not available for OTX CVE query")
        except Exception as e:
            _logger.warning(f"OTX CVE query failed: {e}")

        return ThreatIntelResult(
            query=cve_id,
            query_type="cve",
            source="otx",
            found=False,
        )

    def _query_otx_indicator(
        self, indicator: str, indicator_type: str
    ) -> ThreatIntelResult:
        """根据类型构造 OTX API endpoint，解析 general 和 malware 数据。"""
        try:
            import requests

            # OTX API v1 支持的类型映射
            type_map = {
                'ip': 'IPv4',
                'domain': 'domain',
                'hostname': 'hostname',
                'url': 'url',
                'email': 'email',
            }
            otx_type = type_map.get(indicator_type, indicator_type)
            url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
            headers = {'X-OTX-API-KEY': self.otx_key}
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                tags = list(set(
                    tag for pulse in pulses
                    for tag in pulse.get('tags', [])
                ))

                # 提取恶意软件家族关联
                malware_samples: List[str] = []
                for pulse in pulses:
                    for ms in pulse.get('malware_families', []):
                        malware_samples.append(ms)

                pcount = len(pulses)
                severity = "high" if pcount > 2 else ("medium" if pcount > 0 else "unknown")

                return ThreatIntelResult(
                    query=indicator,
                    query_type=indicator_type,
                    source="otx",
                    found=pcount > 0,
                    severity=severity,
                    confidence=min(pcount * 0.1, 0.9),
                    description=f"Found in {pcount} OTX pulses" if pcount else "Clean in OTX",
                    tags=tags[:20],
                    related_indicators=list(set(malware_samples))[:10],
                    references=[p.get('name', '') for p in pulses[:5]],
                    raw_response=data,
                )
        except ImportError:
            _logger.debug("requests not available for OTX indicator query")
        except Exception as e:
            _logger.warning(f"OTX indicator query failed: {e}")

        return ThreatIntelResult(
            query=indicator,
            query_type=indicator_type,
            source="otx",
            found=False,
        )

    def _query_misp_indicator(
        self, indicator: str, indicator_type: str
    ) -> ThreatIntelResult:
        """映射 indicator_type 到 MISP attribute type，搜索匹配 attribute 并聚合事件上下文。"""
        if not self.misp_url:
            return ThreatIntelResult(
                query=indicator,
                query_type=indicator_type,
                source="misp",
                found=False,
            )

        try:
            import requests

            # indicator_type → MISP attribute type 映射
            misp_type_map = {
                'ip': 'ip-src',
                'domain': 'domain',
                'hostname': 'hostname',
                'url': 'url',
                'email': 'email-src',
                'ipv6': 'ip-src',
            }
            misp_type = misp_type_map.get(indicator_type, indicator_type)

            url = f"{self.misp_url}/attributes/restSearch"
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json',
            }
            data = {
                'returnFormat': 'json',
                'value': indicator,
                'type': misp_type,
            }
            resp = requests.post(url, headers=headers, json=data, timeout=15, verify=False)

            if resp.status_code == 200:
                result_data = resp.json()
                attributes = result_data.get('response', {}).get('Attribute', [])
                events = set(attr.get('event_id', '') for attr in attributes)

                tags: List[str] = []
                related: List[str] = []
                for attr in attributes:
                    for tag in attr.get('Tag', []):
                        tags.append(tag.get('name', ''))
                    related.append(attr.get('value', ''))

                ecount = len(events)
                if ecount >= 5:
                    severity = "critical"
                elif ecount >= 2:
                    severity = "high"
                elif ecount >= 1:
                    severity = "medium"
                else:
                    severity = "unknown"

                return ThreatIntelResult(
                    query=indicator,
                    query_type=indicator_type,
                    source="misp",
                    found=ecount > 0,
                    severity=severity,
                    confidence=min(ecount * 0.08 + 0.1, 0.95),
                    description=f"Found in {ecount} MISP events" if ecount else "Clean in MISP",
                    tags=list(set(tags))[:20],
                    related_indicators=list(set(related))[:20],
                    references=[f"MISP Event {e}" for e in sorted(events)[:5]],
                    raw_response=result_data,
                )
        except ImportError:
            _logger.debug("requests not available for MISP indicator query")
        except Exception as e:
            _logger.warning(f"MISP indicator query failed: {e}")

        return ThreatIntelResult(
            query=indicator,
            query_type=indicator_type,
            source="misp",
            found=False,
        )

    @staticmethod
    def _detect_indicator_type(indicator: str) -> str:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return "ip"
        if re.match(r'^[a-fA-F0-9:]+$', indicator):
            return "ip"
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$', indicator):
            return "domain"
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', indicator):
            return "email"
        return "unknown"

    def batch_query_hashes(
        self,
        hashes: List[str],
        max_workers: int = 5,
    ) -> List[ThreatIntelResult]:
        """线程池并发查询，信号量控制并发度避免API限流，结果按输入顺序返回。"""
        results: Dict[int, ThreatIntelResult] = {}

        def _rate_limited_query(idx: int, h: str) -> Tuple[int, ThreatIntelResult]:
            with self._rate_semaphore:
                _logger.debug(f"Batch hash query [{idx}]: {h[:12]}...")
                return idx, self.query_hash(h)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_rate_limited_query, i, h): i
                for i, h in enumerate(hashes)
            }
            for future in as_completed(futures):
                try:
                    idx, result = future.result(timeout=60)
                    results[idx] = result
                except Exception as e:
                    _logger.error(f"Batch hash query failed at index {futures[future]}: {e}")

        return [results[i] for i in range(len(hashes))]

    def batch_query_cves(
        self,
        cves: List[str],
        max_workers: int = 5,
    ) -> List[ThreatIntelResult]:
        """每个 worker 持有信号量保证不超过 rate limit。"""
        results: Dict[int, ThreatIntelResult] = {}

        def _rate_limited_cve(idx: int, c: str) -> Tuple[int, ThreatIntelResult]:
            with self._rate_semaphore:
                _logger.debug(f"Batch CVE query [{idx}]: {c}")
                return idx, self.query_cve(c)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_rate_limited_cve, i, c): i
                for i, c in enumerate(cves)
            }
            for future in as_completed(futures):
                try:
                    idx, result = future.result(timeout=60)
                    results[idx] = result
                except Exception as e:
                    _logger.error(f"Batch CVE query failed at index {futures[future]}: {e}")

        return [results[i] for i in range(len(cves))]

    def batch_query_indicators(
        self,
        indicators: List[Tuple[str, str]],
        max_workers: int = 5,
    ) -> List[ThreatIntelResult]:
        """并发批量查询 IOC indicators。"""
        results: Dict[int, ThreatIntelResult] = {}

        def _rate_limited_indicator(
            idx: int, val: str, itype: str
        ) -> Tuple[int, ThreatIntelResult]:
            with self._rate_semaphore:
                _logger.debug(f"Batch indicator query [{idx}]: {val}")
                return idx, self.query_indicator(val, itype)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_rate_limited_indicator, i, v, t): i
                for i, (v, t) in enumerate(indicators)
            }
            for future in as_completed(futures):
                try:
                    idx, result = future.result(timeout=60)
                    results[idx] = result
                except Exception as e:
                    _logger.error(
                        f"Batch indicator query failed at index {futures[future]}: {e}"
                    )

        return [results[i] for i in range(len(indicators))]

    def save_to_db(self, result: ThreatIntelResult) -> None:
        self._save_cache(result)

    def load_from_db(
        self,
        query: str,
        query_type: str,
    ) -> Optional[ThreatIntelResult]:
        return self._check_cache(query, query_type)

    def format_report(
        self,
        results: List[ThreatIntelResult],
        format: str = "text",
    ) -> str:
        if format == "json":
            return json.dumps(
                {'results': [r.to_dict() for r in results]},
                indent=2,
            )

        if format == "markdown":
            lines = ["# Threat Intelligence Report\n"]
            lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            lines.append(f"**Total queries:** {len(results)}\n")

            found = [r for r in results if r.found]
            lines.append(f"**Threats found:** {len(found)}\n")

            lines.append("\n## Findings\n")
            for r in found:
                lines.append(f"### {r.query}")
                lines.append(f"- **Type:** {r.query_type}")
                lines.append(f"- **Source:** {r.source}")
                lines.append(f"- **Severity:** {r.severity}")
                lines.append(f"- **Confidence:** {r.confidence:.0%}")
                lines.append(f"- **Description:** {r.description}")
                if r.tags:
                    lines.append(f"- **Tags:** {', '.join(r.tags[:10])}")
                lines.append("")

            return '\n'.join(lines)

        lines = [
            "=" * 60,
            "THREAT INTELLIGENCE REPORT",
            "=" * 60,
            f"Total queries: {len(results)}",
            f"Threats found: {sum(1 for r in results if r.found)}",
            "",
        ]

        for r in results:
            if r.found:
                lines.append(f"[!] {r.query} ({r.query_type})")
                lines.append(f"    Source: {r.source}")
                lines.append(f"    Severity: {r.severity}")
                lines.append(f"    Confidence: {r.confidence:.0%}")
                lines.append(f"    {r.description}")
                lines.append("")

        lines.append("=" * 60)
        return '\n'.join(lines)

    def query_by_hash(self, sha256_hash: str, task_id: str = "", anonymize: bool = False) -> List[ThreatIntelResult]:
        """按 SHA256 哈希查询威胁情报，聚合 MISP 与 OTX 结果。"""
        results: List[ThreatIntelResult] = []

        if self.misp_client:
            result = self._query_misp_by_hash(sha256_hash)
            if result:
                result.task_id = task_id
                results.append(result)

        if self.otx_client:
            result = self._query_otx_by_hash(sha256_hash)
            if result:
                result.task_id = task_id
                results.append(result)

        return results

    def query_by_cve(self, cve_id: str, task_id: str = "") -> List[ThreatIntelResult]:
        """按 CVE 编号查询威胁情报，聚合 MISP 与 OTX 结果。"""
        results: List[ThreatIntelResult] = []

        if self.misp_client:
            result = self._query_misp_by_cve(cve_id)
            if result:
                result.task_id = task_id
                results.append(result)

        if self.otx_client:
            result = self._query_otx_by_cve(cve_id)
            if result:
                result.task_id = task_id
                results.append(result)

        return results

    def query_by_indicator(self, indicator: str, indicator_type: str = "IPv4", task_id: str = "") -> List[ThreatIntelResult]:
        """按威胁指标（IP/域名/URL等）查询威胁情报。"""
        results: List[ThreatIntelResult] = []

        if self.misp_client:
            result = self._query_misp_by_indicator(indicator, indicator_type)
            if result:
                result.task_id = task_id
                results.append(result)

        if self.otx_client:
            result = self._query_otx_by_indicator(indicator)
            if result:
                result.task_id = task_id
                results.append(result)

        return results

    def _query_misp_by_hash(self, sha256_hash: str) -> Optional[ThreatIntelResult]:
        """通过 MISP 按哈希查询。"""
        try:
            events = self.misp_client.search(
                value=sha256_hash,
                type_attribute='sha256',
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT,
            )
            if not events:
                return None

            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'misp'
            result.query_type = 'hash'
            result.query_value = sha256_hash
            self._parse_misp_events(events, result)
            return result
        except Exception as e:
            _logger.error(f"[ThreatIntel] MISP哈希查询失败: {e}")
            return None

    def _query_misp_by_cve(self, cve_id: str) -> Optional[ThreatIntelResult]:
        """通过 MISP 按 CVE 查询。"""
        try:
            events = self.misp_client.search(
                value=cve_id,
                type_attribute='vulnerability',
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT,
            )
            if not events:
                return None

            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'misp'
            result.query_type = 'cve'
            result.query_value = cve_id
            self._parse_misp_events(events, result)
            return result
        except Exception as e:
            _logger.error(f"[ThreatIntel] MISP CVE查询失败: {e}")
            return None

    def _query_misp_by_indicator(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        """通过 MISP 按指标查询，映射指标类型到 MISP attribute type。"""
        misp_types = {
            'IPv4': 'ip-dst',
            'IPv6': 'ip-dst',
            'domain': 'domain',
            'url': 'url',
        }
        misp_type = misp_types.get(indicator_type, 'ip-dst')

        try:
            events = self.misp_client.search(
                value=indicator,
                type_attribute=misp_type,
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT,
            )
            if not events:
                return None

            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'misp'
            result.query_type = indicator_type
            result.query_value = indicator
            self._parse_misp_events(events, result)
            return result
        except Exception as e:
            _logger.error(f"[ThreatIntel] MISP指标查询失败: {e}")
            return None

    def _query_otx_by_hash(self, sha256_hash: str) -> Optional[ThreatIntelResult]:
        """通过 OTX 按哈希查询。"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'hash'
            result.query_value = sha256_hash

            pulses = self.otx_client.get_indicator_details_by_section(
                'file_hash', sha256_hash, 'general'
            )
            if pulses and pulses.get('pulse_info'):
                self._parse_otx_pulses([pulses['pulse_info']], result)
                return result
            return None
        except Exception as e:
            _logger.error(f"[ThreatIntel] OTX哈希查询失败: {e}")
            return None

    def _query_otx_by_cve(self, cve_id: str) -> Optional[ThreatIntelResult]:
        """通过 OTX 按 CVE 查询。"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'cve'
            result.query_value = cve_id

            pulses = self.otx_client.get_pulses_for_cve(cve_id)
            if pulses:
                self._parse_otx_pulses(pulses, result)
                return result
            return None
        except Exception as e:
            _logger.error(f"[ThreatIntel] OTX CVE查询失败: {e}")
            return None

    def _query_otx_by_indicator(self, indicator: str) -> Optional[ThreatIntelResult]:
        """通过 OTX 按指标查询。"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'indicator'
            result.query_value = indicator

            pulses = self.otx_client.get_pulses_by_indicator(indicator)
            if pulses:
                self._parse_otx_pulses(pulses, result)
                return result
            return None
        except Exception as e:
            _logger.error(f"[ThreatIntel] OTX指标查询失败: {e}")
            return None

    def batch_query(
        self,
        hashes: List[str] = None,
        cves: List[str] = None,
        indicators: List[Dict[str, str]] = None,
        task_id: str = "",
        anonymize: bool = False,
    ) -> List[ThreatIntelResult]:
        """参数为空时直接返回空列表，避免无意义的初始化调用。"""
        results: List[ThreatIntelResult] = []

        if hashes:
            for h in hashes:
                results.extend(self.query_by_hash(h, task_id, anonymize))

        if cves:
            for cve in cves:
                results.extend(self.query_by_cve(cve, task_id))

        if indicators:
            for ind in indicators:
                results.extend(self.query_by_indicator(
                    ind.get('value', ''),
                    ind.get('type', 'IPv4'),
                    task_id))

        return results

    def format_results_for_report(self, results: List[ThreatIntelResult]) -> str:
        """格式化威胁情报结果用于报告输出。"""
        if not results:
            return "未找到相关威胁情报"

        lines = ["## 威胁情报关联结果"]

        for result in results:
            lines.append(f"\n### {result.provider.upper()} 查询结果")
            lines.append(f"**查询类型:** {result.query_type}")
            lines.append(f"**查询值:** {result.query_value}")
            lines.append(f"**是否恶意:** {'是' if result.is_malicious else '否'}")
            lines.append(f"**在野利用:** {'是' if result.in_wild else '否'}")
            lines.append(f"**置信度:** {result.confidence * 100:.1f}%")

            if result.malware_families:
                lines.append("\n**关联恶意软件家族:**")
                for family in result.malware_families:
                    lines.append(f"- {family}")

            if result.apt_groups:
                lines.append("\n**关联APT组织:**")
                for group in result.apt_groups:
                    lines.append(f"- {group}")

            if result.iocs:
                lines.append(f"\n**关联IOC ({len(result.iocs)}个):**")
                for ioc in result.iocs[:5]:
                    lines.append(f"- {ioc.get('type')}: {ioc.get('value')}")
                if len(result.iocs) > 5:
                    lines.append(f"- ... 还有 {len(result.iocs) - 5} 个")

            lines.append(f"\n**摘要:** {result.summary}")
            lines.append("\n---")

        return '\n'.join(lines)

    def is_provider_available(self, provider: str) -> bool:
        """检查指定提供商是否可用。"""
        if provider.lower() == 'misp':
            return self.misp_client is not None
        elif provider.lower() == 'otx':
            return self.otx_client is not None
        return False

    def get_available_providers(self) -> List[str]:
        """获取当前可用的提供商列表。"""
        available = []
        if self.misp_client:
            available.append('misp')
        if self.otx_client:
            available.append('otx')
        return available
