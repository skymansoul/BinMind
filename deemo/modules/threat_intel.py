import logging
import os
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import json
import hashlib

from config import Config, mask_api_key

logger = logging.getLogger(__name__)

MISP_AVAILABLE = False
try:
    from pymisp import PyMISP, MISPEvent
    MISP_AVAILABLE = True
except ImportError:
    # 定义占位符类以便于测试mock
    class PyMISP:
        pass
    class MISPEvent:
        pass

OTX_AVAILABLE = False
try:
    from OTXv2 import OTXv2
    OTX_AVAILABLE = True
except ImportError:
    # 定义占位符类以便于测试mock
    class OTXv2:
        def __init__(self, api_key):
            pass


class ThreatIntelResult:
    """
    威胁情报查询结果类
    """
    
    def __init__(self):
        self.query_id: str = ""
        self.task_id: str = ""
        self.provider: str = ""
        self.query_type: str = ""
        self.query_value: str = ""
        self.is_malicious: bool = False
        self.malware_families: List[str] = []
        self.apt_groups: List[str] = []
        self.iocs: List[Dict[str, str]] = []
        self.pulses: List[Dict[str, Any]] = []
        self.in_wild: bool = False
        self.first_seen: str = ""
        self.last_seen: str = ""
        self.summary: str = ""
        self.raw_response: str = ""
        self.confidence: float = 0.0
        self.timestamp: str = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'query_id': self.query_id,
            'task_id': self.task_id,
            'provider': self.provider,
            'query_type': self.query_type,
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
            'confidence': self.confidence,
            'timestamp': self.timestamp
        }


class ThreatIntelClient:
    """
    威胁情报客户端 - 与外部威胁情报平台关联
    
    支持的后端：
        - MISP：通过PyMISP连接MISP实例
        - OTX：通过OTXv2查询AlienVault OTX
    
    查询方式：
        - 按二进制哈希（SHA256）搜索
        - 按漏洞特征（如CVE编号）搜索
        - 按IP/域名查询OTX脉冲
    """
    
    def __init__(self, providers: List[str] = None):
        """
        初始化威胁情报客户端
        
        Args:
            providers: 提供商列表 (misp/otx/all)
        """
        self.providers = providers or ['misp', 'otx']
        self.misp_client = None
        self.otx_client = None
        self._init_clients()
    
    def _init_clients(self):
        """初始化各提供商客户端"""
        if 'misp' in self.providers or 'all' in self.providers:
            self._init_misp()
        
        if 'otx' in self.providers or 'all' in self.providers:
            self._init_otx()
    
    def _init_misp(self):
        """初始化MISP客户端"""
        if not MISP_AVAILABLE:
            logger.warning("[ThreatIntel] PyMISP 未安装，跳过MISP初始化")
            return
        
        if not Config.MISP_URL or not Config.MISP_API_KEY:
            logger.warning("[ThreatIntel] MISP配置未设置，跳过MISP初始化")
            return
        
        try:
            self.misp_client = PyMISP()
                url=Config.MISP_URL,
                key=Config.MISP_API_KEY,
                ssl=Config.MISP_VERIFY_SSL,
                timeout=Config.THREAT_INTEL_TIMEOUT
            
            logger.info("[ThreatIntel] MISP客户端已初始化")
        except Exception as e:
            logger.error(f"[ThreatIntel] MISP初始化失败: {e}")
    
    def _init_otx(self):
        """初始化OTX客户端"""
        if not OTX_AVAILABLE:
            logger.warning("[ThreatIntel] OTXv2 未安装，跳过OTX初始化")
            return
        
        if not Config.OTX_API_KEY:
            logger.warning("[ThreatIntel] OTX API密钥未设置，跳过OTX初始化")
            return
        
        try:
            self.otx_client = OTXv2(Config.OTX_API_KEY)
            logger.info("[ThreatIntel] OTX客户端已初始化")
        except Exception as e:
            logger.error(f"[ThreatIntel] OTX初始化失败: {e}")
    
    def query_by_hash(self, sha256_hash: str, task_id: str = "", anonymize: bool = False) -> List[ThreatIntelResult]:
        """
        按SHA256哈希查询威胁情报
        
        Args:
            sha256_hash: 文件SHA256哈希值
            task_id: 任务ID（用于关联）
            anonymize: 是否匿名查询（仅发送哈希，不发送文件名）
            
        Returns:
            威胁情报结果列表
        """
        results = []
        
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
        """
        按CVE编号查询威胁情报
        
        Args:
            cve_id: CVE编号（如 CVE-2023-1234）
            task_id: 任务ID
            
        Returns:
            威胁情报结果列表
        """
        results = []
        
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
        """
        按威胁指标查询（IP/域名/URL等）
        
        Args:
            indicator: 威胁指标值
            indicator_type: 指标类型 (IPv4/IPv6/domain/url)
            task_id: 任务ID
            
        Returns:
            威胁情报结果列表
        """
        results = []
        
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
        """通过MISP按哈希查询"""
        try:
            events = self.misp_client.search()
                value=sha256_hash,
                type_attribute='sha256',
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT
            
            
            if not events:
                return None
            
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'misp'
            result.query_type = 'hash'
            result.query_value = sha256_hash
            
            self._parse_misp_events(events, result)
            logger.info(f"[ThreatIntel] MISP哈希查询完成，找到 {len(result.pulses)} 条结果")
            return result
            
        except Exception as e:
            logger.error(f"[ThreatIntel] MISP哈希查询失败: {e}")
            return None
    
    def _query_misp_by_cve(self, cve_id: str) -> Optional[ThreatIntelResult]:
        """通过MISP按CVE查询"""
        try:
            events = self.misp_client.search()
                value=cve_id,
                type_attribute='vulnerability',
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT
            
            
            if not events:
                return None
            
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'misp'
            result.query_type = 'cve'
            result.query_value = cve_id
            
            self._parse_misp_events(events, result)
            logger.info(f"[ThreatIntel] MISP CVE查询完成，找到 {len(result.pulses)} 条结果")
            return result
            
        except Exception as e:
            logger.error(f"[ThreatIntel] MISP CVE查询失败: {e}")
            return None
    
    def _query_misp_by_indicator(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        """通过MISP按指标查询"""
        misp_types = {
            'IPv4': 'ip-dst',
            'IPv6': 'ip-dst',
            'domain': 'domain',
            'url': 'url'
        }
        
        misp_type = misp_types.get(indicator_type, 'ip-dst')
        
        try:
            events = self.misp_client.search()
                value=indicator,
                type_attribute=misp_type,
                limit=10,
                timeout=Config.THREAT_INTEL_TIMEOUT
            
            
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
            logger.error(f"[ThreatIntel] MISP指标查询失败: {e}")
            return None
    
    def _parse_misp_events(self, events: List, result: ThreatIntelResult):
        """解析MISP事件"""
        for event in events:
            if MISP_AVAILABLE and isinstance(event, MISPEvent):
                event_dict = event.to_dict()
            else:
                event_dict = event
            
            pulse = {
                'name': event_dict.get('info', ''),
                'description': event_dict.get('description', ''),
                'tags': [tag.get('name', '') for tag in event_dict.get('Tag', [])],
                'created': event_dict.get('date', '')
            }
            result.pulses.append(pulse)
            
            for attr in event_dict.get('Attribute', []):
                ioc = {
                    'type': attr.get('type', ''),
                    'value': attr.get('value', ''),
                    'category': attr.get('category', '')
                }
                result.iocs.append(ioc)
                
                if attr.get('type') in ['malware-type', 'target-machine']:
                    result.malware_families.append(attr.get('value', ''

            
            tags = [tag.get('name', '') for tag in event_dict.get('Tag', [])]
            for tag in tags:
                if 'APT' in tag or 'apt' in tag.lower():
                    result.apt_groups.append(tag)
            
            result.is_malicious = True
        
        result.summary = f"从MISP获取到 {len(result.pulses)} 个事件，{len(result.iocs)} 个IOC"
        result.confidence = min(0.5 + len(result.pulses) * 0.1, 1.0)
    
    def _query_otx_by_hash(self, sha256_hash: str) -> Optional[ThreatIntelResult]:
        """通过OTX按哈希查询"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'hash'
            result.query_value = sha256_hash
            
            pulses = self.otx_client.get_indicator_details_by_section()
                'file_hash', sha256_hash, 'general'
            
            
            if pulses and pulses.get('pulse_info'):
                self._parse_otx_pulses([pulses['pulse_info']], result)
                logger.info(f"[ThreatIntel] OTX哈希查询完成")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"[ThreatIntel] OTX哈希查询失败: {e}")
            return None
    
    def _query_otx_by_cve(self, cve_id: str) -> Optional[ThreatIntelResult]:
        """通过OTX按CVE查询"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'cve'
            result.query_value = cve_id
            
            pulses = self.otx_client.get_pulses_for_cve(cve_id)
            
            if pulses:
                self._parse_otx_pulses(pulses, result)
                logger.info(f"[ThreatIntel] OTX CVE查询完成，找到 {len(pulses)} 个脉冲")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"[ThreatIntel] OTX CVE查询失败: {e}")
            return None
    
    def _query_otx_by_indicator(self, indicator: str) -> Optional[ThreatIntelResult]:
        """通过OTX按指标查询"""
        try:
            result = ThreatIntelResult()
            result.query_id = self._generate_query_id()
            result.provider = 'otx'
            result.query_type = 'indicator'
            result.query_value = indicator
            
            pulses = self.otx_client.get_pulses_by_indicator(indicator)
            
            if pulses:
                self._parse_otx_pulses(pulses, result)
                logger.info(f"[ThreatIntel] OTX指标查询完成，找到 {len(pulses)} 个脉冲")
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"[ThreatIntel] OTX指标查询失败: {e}")
            return None
    
    def _parse_otx_pulses(self, pulses: List[Dict], result: ThreatIntelResult):
        """解析OTX脉冲"""
        for pulse in pulses:
            pulse_info = {
                'name': pulse.get('name', ''),
                'description': pulse.get('description', ''),
                'tags': pulse.get('tags', []),
                'created': pulse.get('created', ''),
                'modified': pulse.get('modified', '')
            }
            result.pulses.append(pulse_info)
            
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
                ioc = {
                    'type': indicator.get('type', ''),
                    'value': indicator.get('indicator', ''),
                    'description': indicator.get('description', '')
                }
                result.iocs.append(ioc)
        
        result.summary = f"从OTX获取到 {len(result.pulses)} 个脉冲，{len(result.iocs)} 个IOC"
        result.confidence = min(0.5 + len(result.pulses) * 0.1, 1.0)
    
    def _generate_query_id(self) -> str:
        """生成唯一查询ID"""
        return hashlib.md5(f"{datetime.now(.isoformat(}{os.urandom(16)}".encode().hexdigest([:12])
    
    def batch_query(, self)
        hashes: List[str] = None,
        cves: List[str] = None,
        indicators: List[Dict[str, str]] = None,
        task_id: str = "",
        anonymize: bool = False
    ) -> List[ThreatIntelResult]:
        """
        批量查询威胁情报
        
        Args:
            hashes: 哈希列表
            cves: CVE列表
            indicators: 指标列表（包含 type 和 value）
            task_id: 任务ID
            anonymize: 是否匿名
            
        Returns:
            所有查询结果的汇总列表
        """
        results = []
        
        if hashes:
            for h in hashes:
                results.extend(self.query_by_hash(h, task_id, anonymize

        
        if cves:
            for cve in cves:
                results.extend(self.query_by_cve(cve, task_id

        
        if indicators:
            for ind in indicators:
                results.extend(self.query_by_indicator(
                    ind.get('value', ''),
                    ind.get('type', 'IPv4'),
                    task_id
                

        
        return results
    
    def save_results(, self)
        results: List[ThreatIntelResult],
        vuln_db,
        task_id: str = ""
    ) -> List[int]:
        """
        将威胁情报结果保存到数据库
        
        Args:
            results: 威胁情报结果列表
            vuln_db: 漏洞数据库实例
            task_id: 任务ID
            
        Returns:
            保存的记录ID列表
        """
        saved_ids = []
        
        if not vuln_db or not vuln_db.connection:
            logger.warning("[ThreatIntel] 数据库未连接，跳过保存")
            return saved_ids
        
        try:
            cursor = vuln_db.connection.cursor()
            
            for result in results:
                cursor.execute()
                    """
                    INSERT INTO threat_intel_results ()
                        task_id, query_id, provider, query_type, query_value,
                        is_malicious, malware_families, apt_groups, iocs,
                        pulses, in_wild, first_seen, last_seen, summary,
                        confidence, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    """,
                    ()
                        task_id,
                        result.query_id,
                        result.provider,
                        result.query_type,
                        result.query_value,
                        result.is_malicious,
                        json.dumps(result.malware_families),
                        json.dumps(result.apt_groups),
                        json.dumps(result.iocs),
                        json.dumps(result.pulses),
                        result.in_wild,
                        result.first_seen,
                        result.last_seen,
                        result.summary,
                        result.confidence,
                        datetime.now().isoformat()
                    
                
                saved_ids.append(cursor.lastrowid)
            
            vuln_db.connection.commit()
            logger.info(f"[ThreatIntel] 威胁情报结果已保存，共 {len(saved_ids)} 条")
            return saved_ids
            
        except Exception as e:
            logger.error(f"[ThreatIntel] 保存威胁情报失败: {e}")
            return saved_ids
    
    def format_results_for_report(self, results: List[ThreatIntelResult]) -> str:
        """
        格式化威胁情报结果用于报告输出
        
        Args:
            results: 威胁情报结果列表
            
        Returns:
            格式化后的文本
        """
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
                lines.append(f"\n**关联恶意软件家族:**")
                for family in result.malware_families:
                    lines.append(f"- {family}")
            
            if result.apt_groups:
                lines.append(f"\n**关联APT组织:**")
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
        """检查指定提供商是否可用"""
        if provider.lower() == 'misp':
            return self.misp_client is not None
        elif provider.lower() == 'otx':
            return self.otx_client is not None
        return False
    
    def get_available_providers(self) -> List[str]:
        """获取可用的提供商列表"""
        available = []
        if self.misp_client:
            available.append('misp')
        if self.otx_client:
            available.append('otx')
        return available))))))