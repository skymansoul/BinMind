"""
Nuclei模板生成模块

根据发现的Web服务漏洞自动生成Nuclei模板，用于大规模快速验证漏洞存在性。
支持HTTP/TCP协议，自动填充CVE、严重等级、描述等元数据。
"""

import os
import re
import json
import hashlib
import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

import yaml

try:
    from config import Config
except ImportError:
    Config = None

# 允许独立运行时的基本配置
class NucleiConfig:
    NUCLEI_TEMPLATES_DIR = "data/nuclei_templates"
    LOG_LEVEL = "INFO"


# 配置日志
if Config is not None and hasattr(Config, 'LOG_LEVEL'):
    log_level_str = Config.LOG_LEVEL
else:
    log_level_str = NucleiConfig.LOG_LEVEL
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(level=log_level)
logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    PATH_TRAVERSAL = "path_traversal"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    RCE = "rce"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INFO_DISCLOSURE = "info_disclosure"
    AUTH_BYPASS = "auth_bypass"
    COMMAND_INJECTION = "command_injection"
    FILE_UPLOAD = "file_upload"
    XXE = "xxe"
    SSTI = "ssti"
    LFI = "lfi"
    RFI = "rfi"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    DESERIALIZATION = "deserialization"
    WEAK_AUTH = "weak_auth"
    IDOR = "idor"
    OTHER = "other"


class ProtocolType(Enum):
    """协议类型枚举"""
    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    FILE = "file"
    SSL = "ssl"
    WEBSOCKET = "websocket"
    HEADLESS = "headless"


class SeverityLevel(Enum):
    """严重等级枚举"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HttpRequest:
    """HTTP请求定义"""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    raw: Optional[str] = None  # 原始请求字符串
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "method": self.method,
            "path": self.path,
        }
        if self.headers:
            result["headers"] = self.headers
        if self.body:
            result["body"] = self.body
        return result


@dataclass
class MatchCondition:
    """匹配条件定义"""
    match_type: str  # status, body, header, regex, dsl, size, word
    condition: str   # 具体匹配内容
    part: str = "body"  # body, header, all, status_code
    negative: bool = False
    flags: str = ""  # 正则表达式标志，如 "i" 表示忽略大小写
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {self.match_type: self.condition}
        if self.part != "body":
            result["part"] = self.part
        if self.negative:
            result["negative"] = True
        if self.flags:
            result["flags"] = self.flags
        return result


@dataclass
class VulnerabilityInfo:
    """漏洞信息定义"""
    name: str                                    # 漏洞名称
    vulnerability_type: VulnerabilityType        # 漏洞类型
    protocol: ProtocolType                       # 协议类型
    severity: SeverityLevel                      # 严重等级
    description: str                             # 漏洞描述
    requests: List[HttpRequest]                  # 请求列表
    matches: List[MatchCondition]                # 匹配条件列表
    
    # 可选字段
    cve_id: Optional[str] = None                 # CVE编号
    cwe_id: Optional[str] = None                  # CWE编号
    cvss_score: Optional[float] = None            # CVSS分数
    affected_endpoint: Optional[str] = None      # 受影响端点
    affected_product: Optional[str] = None       # 受影响产品
    affected_version: Optional[str] = None       # 受影响版本
    reference_urls: List[str] = field(default_factory=list)  # 参考链接
    tags: List[str] = field(default_factory=list)            # 标签
    author: str = "LLM-Binary-Analyzer"          # 作者
    remediation: Optional[str] = None            # 修复建议
    
    # 高级选项
    stop_at_first_match: bool = False            # 首次匹配后停止
    matchers_condition: str = "or"               # and/or
    extractors: List[Dict[str, Any]] = field(default_factory=list)  # 提取器


@dataclass
class TemplateMetadata:
    """模板元数据"""
    id: str
    name: str
    author: str
    severity: str
    description: str
    reference: List[str]
    tags: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NucleiTemplate:
    """Nuclei模板定义"""
    id: str
    info: TemplateMetadata
    http: List[Dict[str, Any]] = field(default_factory=list)
    tcp: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_yaml(self) -> str:
        """转换为YAML格式"""
        template = {
            "id": self.id,
            "info": {
                "name": self.info.name,
                "author": self.info.author,
                "severity": self.info.severity,
                "description": self.info.description,
                "reference": self.info.reference,
                "tags": self.info.tags,
            }
        }
        
        # 添加额外元数据
        if self.info.metadata:
            template["info"]["metadata"] = self.info.metadata
        
        # 添加协议特定内容
        if self.http:
            template["http"] = self.http
        if self.tcp:
            template["tcp"] = self.tcp
        
        return yaml.dump(template, allow_unicode=True, default_flow_style=False, sort_keys=False)


class NucleiTemplateGenerator:
    """
    Nuclei模板生成器
    
    根据漏洞信息自动生成Nuclei模板，用于大规模漏洞验证。
    支持HTTP/TCP等多种协议，自动生成请求和匹配规则。
    """
    
    # 漏洞类型到标签的映射
    VULN_TYPE_TAGS = {
        VulnerabilityType.PATH_TRAVERSAL: ["lfi", "traversal", "rce"],
        VulnerabilityType.SQL_INJECTION: ["sqli", "injection", "rce"],
        VulnerabilityType.XSS: ["xss", "injection"],
        VulnerabilityType.SSRF: ["ssrf", "oast", "injection"],
        VulnerabilityType.RCE: ["rce", "injection", "oast"],
        VulnerabilityType.HARDCODED_CREDENTIALS: ["creds", "auth", "exposure"],
        VulnerabilityType.INFO_DISCLOSURE: ["exposure", "info", "config"],
        VulnerabilityType.AUTH_BYPASS: ["auth", "bypass"],
        VulnerabilityType.COMMAND_INJECTION: ["rce", "injection", "oast"],
        VulnerabilityType.FILE_UPLOAD: ["upload", "rce", "file"],
        VulnerabilityType.XXE: ["xxe", "rce", "oast"],
        VulnerabilityType.SSTI: ["ssti", "injection", "rce"],
        VulnerabilityType.LFI: ["lfi", "traversal", "rce"],
        VulnerabilityType.RFI: ["rfi", "rce", "oast"],
        VulnerabilityType.OPEN_REDIRECT: ["redirect", "header"],
        VulnerabilityType.CRLF_INJECTION: ["crlf", "header", "injection"],
        VulnerabilityType.DESERIALIZATION: ["deserialization", "rce", "injection"],
        VulnerabilityType.WEAK_AUTH: ["auth", "weak", "brute-force"],
        VulnerabilityType.IDOR: ["idor", "auth", "access"],
        VulnerabilityType.OTHER: ["vuln"],
    }
    
    # 漏洞类型到默认匹配规则的映射
    DEFAULT_MATCHERS = {
        VulnerabilityType.PATH_TRAVERSAL: [
            MatchCondition("regex", r"(root:|etc/passwd|boot\.ini|windows/system32)", "body"),
            MatchCondition("status", "200", "status_code"),
        ],
        VulnerabilityType.SQL_INJECTION: [
            MatchCondition("regex", r"(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR)", "body"),
            MatchCondition("status", "500", "status_code"),
        ],
        VulnerabilityType.XSS: [
            MatchCondition("regex", r"<script>alert\(['\"]?xss['\"]?\)</script>", "body"),
            MatchCondition("word", ["<script>", "alert(", "onerror="], "body"),
        ],
        VulnerabilityType.RCE: [
            MatchCondition("regex", r"(uid=\d+|gid=\d+|groups=|Windows IP Configuration)", "body"),
        ],
        VulnerabilityType.INFO_DISCLOSURE: [
            MatchCondition("regex", r"(password|secret|api_key|token|credential).{0,50}", "body", flags="i"),
        ],
        VulnerabilityType.HARDCODED_CREDENTIALS: [
            MatchCondition("regex", r"(password\s*=\s*['\"][^'\"]+['\"]|api_key\s*=\s*['\"][^'\"]+['\"])", "body"),
        ],
    }
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化模板生成器
        
        Args:
            output_dir: 模板输出目录，默认使用配置中的目录
        """
        self.output_dir = Path(output_dir or Config.NUCLEI_TEMPLATES_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Nuclei模板生成器初始化，输出目录: {self.output_dir}")
    
    def generate_template(self, vuln_info: VulnerabilityInfo) -> NucleiTemplate:
        """
        根据漏洞信息生成Nuclei模板
        
        Args:
            vuln_info: 漏洞信息对象
            
        Returns:
            生成的NucleiTemplate对象
        """
        # 生成模板ID
        template_id = self._generate_template_id(vuln_info)
        
        # 准备标签
        tags = list(vuln_info.tags)
        tags.extend(self.VULN_TYPE_TAGS.get(vuln_info.vulnerability_type, []))
        tags = list(set(tags))  # 去重
        
        # 准备参考链接
        references = list(vuln_info.reference_urls)
        if vuln_info.cve_id:
            references.insert(0, f"https://nvd.nist.gov/vuln/detail/{vuln_info.cve_id}")
        
        # 准备元数据
        metadata = {}
        if vuln_info.cve_id:
            metadata["cve"] = vuln_info.cve_id
        if vuln_info.cwe_id:
            metadata["cwe"] = vuln_info.cwe_id
        if vuln_info.cvss_score:
            metadata["cvss_score"] = vuln_info.cvss_score
        if vuln_info.affected_product:
            metadata["product"] = vuln_info.affected_product
        if vuln_info.affected_version:
            metadata["version"] = vuln_info.affected_version
        
        # 创建元数据对象
        template_metadata = TemplateMetadata(
            id=template_id,
            name=vuln_info.name,
            author=vuln_info.author,
            severity=vuln_info.severity.value,
            description=vuln_info.description,
            reference=references,
            tags=tags,
            metadata=metadata
        )
        
        # 构建请求
        requests = self._build_requests(vuln_info)
        
        # 构建匹配器
        matchers = self._build_matchers(vuln_info)
        
        # 创建模板
        template = NucleiTemplate(
            id=template_id,
            info=template_metadata
        )
        
        # 根据协议类型设置请求
        if vuln_info.protocol == ProtocolType.HTTP:
            http_requests = []
            for req in requests:
                http_req = req.copy()
                http_req["matchers"] = matchers
                if vuln_info.stop_at_first_match:
                    http_req["stop-at-first-match"] = True
                if vuln_info.matchers_condition != "or":
                    http_req["matchers-condition"] = vuln_info.matchers_condition
                if vuln_info.extractors:
                    http_req["extractors"] = vuln_info.extractors
                http_requests.append(http_req)
            template.http = http_requests
        elif vuln_info.protocol == ProtocolType.TCP:
            tcp_requests = []
            for req in requests:
                tcp_req = req.copy()
                tcp_req["matchers"] = matchers
                tcp_requests.append(tcp_req)
            template.tcp = tcp_requests
        
        logger.info(f"生成模板: {template_id}, 类型: {vuln_info.vulnerability_type.value}")
        return template
    
    def _generate_template_id(self, vuln_info: VulnerabilityInfo) -> str:
        """
        生成模板唯一ID
        
        Args:
            vuln_info: 漏洞信息
            
        Returns:
            模板ID字符串
        """
        if vuln_info.cve_id:
            # 使用CVE编号作为ID
            return vuln_info.cve_id.lower().replace("-", "-")
        
        # 基于漏洞信息生成唯一ID
        content = f"{vuln_info.name}_{vuln_info.vulnerability_type.value}_{vuln_info.affected_endpoint or ''}"
        hash_val = hashlib.md5(content.encode()).hexdigest()[:8]
        
        # 清理名称用于ID
        clean_name = re.sub(r'[^a-zA-Z0-9]', '-', vuln_info.name.lower())
        clean_name = re.sub(r'-+', '-', clean_name).strip('-')
        
        return f"{clean_name}-{hash_val}"
    
    def _build_requests(self, vuln_info: VulnerabilityInfo) -> List[Dict[str, Any]]:
        """
        构建请求列表
        
        Args:
            vuln_info: 漏洞信息
            
        Returns:
            请求字典列表
        """
        requests = []
        
        for http_req in vuln_info.requests:
            req_dict = http_req.to_dict()
            
            # 如果有原始请求，优先使用
            if http_req.raw:
                req_dict = {"raw": http_req.raw}
            
            requests.append(req_dict)
        
        # 如果没有请求，创建默认请求
        if not requests and vuln_info.affected_endpoint:
            default_req = HttpRequest(
                method="GET",
                path=vuln_info.affected_endpoint
            )
            requests.append(default_req.to_dict())
        
        return requests
    
    def _build_matchers(self, vuln_info: VulnerabilityInfo) -> List[Dict[str, Any]]:
        """
        构建匹配器列表
        
        Args:
            vuln_info: 漏洞信息
            
        Returns:
            匹配器字典列表
        """
        matchers = []
        
        # 使用提供的匹配条件
        if vuln_info.matches:
            for match in vuln_info.matches:
                matchers.append(match.to_dict())
        else:
            # 使用默认匹配规则
            default_matchers = self.DEFAULT_MATCHERS.get(vuln_info.vulnerability_type, [])
            for match in default_matchers:
                matchers.append(match.to_dict())
        
        return matchers
    
    def save_template(self, template: NucleiTemplate, filename: Optional[str] = None) -> str:
        """
        保存模板到文件
        
        Args:
            template: 模板对象
            filename: 文件名（不含扩展名），默认使用模板ID
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            filename = template.id
        
        # 确保文件名安全
        filename = self._sanitize_filename(filename)
        filepath = self.output_dir / f"{filename}.yaml"
        
        # 写入文件
        yaml_content = template.to_yaml()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        logger.info(f"模板已保存: {filepath}")
        return str(filepath)
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        清理文件名，防止路径注入
        
        Args:
            filename: 原始文件名
            
        Returns:
            安全的文件名
        """
        # 移除路径分隔符
        filename = filename.replace('/', '_').replace('\\', '_')
        # 移除危险字符
        filename = re.sub(r'[<>:"|?*]', '', filename)
        # 限制长度
        if len(filename) > 200:
            filename = filename[:200]
        return filename
    
    def generate_from_vulnerability_dict(self, vuln_dict: Dict[str, Any]) -> NucleiTemplate:
        """
        从漏洞字典生成模板
        
        Args:
            vuln_dict: 漏洞信息字典
            
        Returns:
            生成的NucleiTemplate对象
        """
        # 解析漏洞类型
        vuln_type_str = vuln_dict.get('vulnerability_type', 'other').lower()
        try:
            vuln_type = VulnerabilityType(vuln_type_str)
        except ValueError:
            vuln_type = VulnerabilityType.OTHER
        
        # 解析协议类型
        protocol_str = vuln_dict.get('protocol', 'http').lower()
        try:
            protocol = ProtocolType(protocol_str)
        except ValueError:
            protocol = ProtocolType.HTTP
        
        # 解析严重等级
        severity_str = vuln_dict.get('severity', 'medium').lower()
        try:
            severity = SeverityLevel(severity_str)
        except ValueError:
            severity = SeverityLevel.MEDIUM
        
        # 解析请求列表
        requests = []
        for req_dict in vuln_dict.get('requests', []):
            req = HttpRequest(
                method=req_dict.get('method', 'GET'),
                path=req_dict.get('path', '/'),
                headers=req_dict.get('headers', {}),
                body=req_dict.get('body'),
                raw=req_dict.get('raw')
            )
            requests.append(req)
        
        # 解析匹配条件
        matches = []
        for match_dict in vuln_dict.get('matches', []):
            match = MatchCondition(
                match_type=match_dict.get('type', 'word'),
                condition=match_dict.get('condition', ''),
                part=match_dict.get('part', 'body'),
                negative=match_dict.get('negative', False)
            )
            matches.append(match)
        
        # 创建漏洞信息对象
        vuln_info = VulnerabilityInfo(
            name=vuln_dict.get('name', 'Unknown Vulnerability'),
            vulnerability_type=vuln_type,
            protocol=protocol,
            severity=severity,
            description=vuln_dict.get('description', ''),
            requests=requests,
            matches=matches,
            cve_id=vuln_dict.get('cve_id'),
            cwe_id=vuln_dict.get('cwe_id'),
            cvss_score=vuln_dict.get('cvss_score'),
            affected_endpoint=vuln_dict.get('affected_endpoint'),
            affected_product=vuln_dict.get('affected_product'),
            affected_version=vuln_dict.get('affected_version'),
            reference_urls=vuln_dict.get('reference_urls', []),
            tags=vuln_dict.get('tags', []),
            author=vuln_dict.get('author', 'LLM-Binary-Analyzer'),
            remediation=vuln_dict.get('remediation'),
            stop_at_first_match=vuln_dict.get('stop_at_first_match', False),
            matchers_condition=vuln_dict.get('matchers_condition', 'or'),
            extractors=vuln_dict.get('extractors', [])
        )
        
        return self.generate_template(vuln_info)
    
    def generate_path_traversal_template(
        self,
        name: str,
        endpoint: str,
        traversal_path: str = "/etc/passwd",
        cve_id: Optional[str] = None,
        **kwargs
    ) -> NucleiTemplate:
        """
        生成路径遍历漏洞模板
        
        Args:
            name: 漏洞名称
            endpoint: 受影响端点
            traversal_path: 遍历路径
            cve_id: CVE编号
            **kwargs: 其他参数
            
        Returns:
            生成的模板
        """
        vuln_info = VulnerabilityInfo(
            name=name,
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.HIGH,
            description=f"Path traversal vulnerability in {endpoint} allowing access to {traversal_path}",
            requests=[
                HttpRequest(method="GET", path=endpoint)
            ],
            matches=[
                MatchCondition("regex", r"(root:|daemon:|bin:|sys:)", "body"),
            ],
            cve_id=cve_id,
            affected_endpoint=endpoint,
            tags=["lfi", "traversal"],
            **kwargs
        )
        return self.generate_template(vuln_info)
    
    def generate_hardcoded_creds_template(
        self,
        name: str,
        endpoint: str,
        credential_patterns: List[str],
        cve_id: Optional[str] = None,
        **kwargs
    ) -> NucleiTemplate:
        """
        生成硬编码凭证漏洞模板
        
        Args:
            name: 漏洞名称
            endpoint: 受影响端点
            credential_patterns: 凭证匹配模式列表
            cve_id: CVE编号
            **kwargs: 其他参数
            
        Returns:
            生成的模板
        """
        # 构建匹配模式
        patterns = "|".join(credential_patterns)
        
        vuln_info = VulnerabilityInfo(
            name=name,
            vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.HIGH,
            description=f"Hardcoded credentials exposed in {endpoint}",
            requests=[
                HttpRequest(method="GET", path=endpoint)
            ],
            matches=[
                MatchCondition("regex", patterns, "body"),
            ],
            cve_id=cve_id,
            affected_endpoint=endpoint,
            tags=["creds", "exposure", "auth"],
            **kwargs
        )
        return self.generate_template(vuln_info)
    
    def generate_rce_template(
        self,
        name: str,
        endpoint: str,
        method: str = "POST",
        body: Optional[str] = None,
        command: str = "id",
        cve_id: Optional[str] = None,
        **kwargs
    ) -> NucleiTemplate:
        """
        生成远程代码执行漏洞模板
        
        Args:
            name: 漏洞名称
            endpoint: 受影响端点
            method: HTTP方法
            body: 请求体
            command: 测试命令
            cve_id: CVE编号
            **kwargs: 其他参数
            
        Returns:
            生成的模板
        """
        # 根据命令生成匹配模式
        if command == "id":
            match_pattern = r"uid=\d+\(.*\)\s+gid=\d+\(.*\)"
        elif command == "whoami":
            match_pattern = r"(root|admin|www-data|apache|nobody)"
        else:
            match_pattern = r".*"  # 通用匹配
        
        vuln_info = VulnerabilityInfo(
            name=name,
            vulnerability_type=VulnerabilityType.RCE,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.CRITICAL,
            description=f"Remote code execution vulnerability in {endpoint}",
            requests=[
                HttpRequest(method=method, path=endpoint, body=body)
            ],
            matches=[
                MatchCondition("regex", match_pattern, "body"),
            ],
            cve_id=cve_id,
            affected_endpoint=endpoint,
            tags=["rce", "injection", "oast"],
            **kwargs
        )
        return self.generate_template(vuln_info)
    
    def generate_sqli_template(
        self,
        name: str,
        endpoint: str,
        method: str = "GET",
        param: str = "id",
        payload: str = "' OR '1'='1",
        cve_id: Optional[str] = None,
        **kwargs
    ) -> NucleiTemplate:
        """
        生成SQL注入漏洞模板
        
        Args:
            name: 漏洞名称
            endpoint: 受影响端点
            method: HTTP方法
            param: 注入参数名
            payload: 注入载荷
            cve_id: CVE编号
            **kwargs: 其他参数
            
        Returns:
            生成的模板
        """
        # 构建注入路径
        if method.upper() == "GET":
            path = f"{endpoint}?{param}={payload}"
            body = None
        else:
            path = endpoint
            body = f"{param}={payload}"
        
        vuln_info = VulnerabilityInfo(
            name=name,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.CRITICAL,
            description=f"SQL injection vulnerability in {endpoint} parameter {param}",
            requests=[
                HttpRequest(method=method, path=path, body=body)
            ],
            matches=[
                MatchCondition("regex", r"(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|Warning.*mysql_)", "body"),
                MatchCondition("status", "500", "status_code"),
            ],
            cve_id=cve_id,
            affected_endpoint=endpoint,
            tags=["sqli", "injection", "rce"],
            **kwargs
        )
        return self.generate_template(vuln_info)
    
    def generate_ssrf_template(
        self,
        name: str,
        endpoint: str,
        param: str,
        oast_domain: str = "{{interactsh-url}}",
        cve_id: Optional[str] = None,
        **kwargs
    ) -> NucleiTemplate:
        """
        生成SSRF漏洞模板
        
        Args:
            name: 漏洞名称
            endpoint: 受影响端点
            param: 注入参数名
            oast_domain: OAST域名（默认使用interactsh）
            cve_id: CVE编号
            **kwargs: 其他参数
            
        Returns:
            生成的模板
        """
        vuln_info = VulnerabilityInfo(
            name=name,
            vulnerability_type=VulnerabilityType.SSRF,
            protocol=ProtocolType.HTTP,
            severity=SeverityLevel.HIGH,
            description=f"Server-side request forgery vulnerability in {endpoint} parameter {param}",
            requests=[
                HttpRequest(
                    method="GET",
                    path=f"{endpoint}?{param}={oast_domain}"
                )
            ],
            matches=[
                MatchCondition("word", ["interactsh"], "body"),
            ],
            cve_id=cve_id,
            affected_endpoint=endpoint,
            tags=["ssrf", "oast", "injection"],
            stop_at_first_match=True,
            **kwargs
        )
        return self.generate_template(vuln_info)
    
    def validate_template(self, template: NucleiTemplate) -> Dict[str, Any]:
        """
        验证模板有效性
        
        Args:
            template: 模板对象
            
        Returns:
            验证结果字典
        """
        result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # 检查必需字段
        if not template.id:
            result["valid"] = False
            result["errors"].append("模板ID不能为空")
        
        if not template.info.name:
            result["valid"] = False
            result["errors"].append("模板名称不能为空")
        
        if not template.info.severity:
            result["valid"] = False
            result["errors"].append("严重等级不能为空")
        
        # 检查是否有请求定义
        if not template.http and not template.tcp:
            result["valid"] = False
            result["errors"].append("模板必须包含HTTP或TCP请求")
        
        # 检查请求是否有匹配器
        for req in template.http:
            if "matchers" not in req or not req["matchers"]:
                result["warnings"].append("请求缺少匹配器，可能产生误报")
        
        # 检查ID格式
        if template.id and not re.match(r'^[a-z0-9-]+$', template.id):
            result["warnings"].append(f"模板ID格式不规范: {template.id}")
        
        # 检查严重等级
        valid_severities = ["info", "low", "medium", "high", "critical"]
        if template.info.severity.lower() not in valid_severities:
            result["warnings"].append(f"无效的严重等级: {template.info.severity}")
        
        return result
    
    def generate_report(self, templates: List[NucleiTemplate]) -> str:
        """
        生成模板统计报告
        
        Args:
            templates: 模板列表
            
        Returns:
            Markdown格式的报告
        """
        report_lines = [
            "# Nuclei模板生成报告",
            "",
            f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**模板总数**: {len(templates)}",
            "",
            "## 模板列表",
            "",
        ]
        
        # 按严重等级分组
        severity_groups = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for template in templates:
            severity = template.info.severity.lower()
            if severity in severity_groups:
                severity_groups[severity].append(template)
        
        # 输出各等级模板
        for severity, temps in severity_groups.items():
            if temps:
                report_lines.append(f"### {severity.upper()} ({len(temps)})")
                report_lines.append("")
                for t in temps:
                    cve = t.info.metadata.get("cve", "N/A")
                    report_lines.append(f"- **{t.info.name}** (`{t.id}`)")
                    report_lines.append(f"  - CVE: {cve}")
                    report_lines.append(f"  - 描述: {t.info.description[:100]}...")
                    report_lines.append("")
        
        # 统计信息
        report_lines.extend([
            "## 统计信息",
            "",
            "| 严重等级 | 数量 |",
            "|----------|------|",
        ])
        
        for severity, temps in severity_groups.items():
            report_lines.append(f"| {severity.upper()} | {len(temps)} |")
        
        return "\n".join(report_lines)


# 向后兼容别名
NucleiGenerator = NucleiTemplateGenerator

# 便捷函数
def generate_nuclei_template(vuln_info: Union[VulnerabilityInfo, Dict[str, Any]], 
                            output_dir: Optional[str] = None) -> str:
    """
    便捷函数：生成并保存Nuclei模板
    
    Args:
        vuln_info: 漏洞信息对象或字典
        output_dir: 输出目录
        
    Returns:
        保存的文件路径
    """
    generator = NucleiTemplateGenerator(output_dir)
    
    if isinstance(vuln_info, dict):
        template = generator.generate_from_vulnerability_dict(vuln_info)
    else:
        template = generator.generate_template(vuln_info)
    
    return generator.save_template(template)


if __name__ == "__main__":
    # 示例用法
    generator = NucleiTemplateGenerator()
    
    # 示例1：路径遍历漏洞
    template1 = generator.generate_path_traversal_template(
        name="Example App Path Traversal",
        endpoint="/api/file?name=",
        cve_id="CVE-2024-12345"
    )
    print(f"生成模板: {template1.id}")
    generator.save_template(template1)
    
    # 示例2：SQL注入漏洞
    template2 = generator.generate_sqli_template(
        name="Example App SQL Injection",
        endpoint="/api/users",
        param="id",
        cve_id="CVE-2024-12346"
    )
    generator.save_template(template2)
    
    # 示例3：RCE漏洞
    template3 = generator.generate_rce_template(
        name="Example App RCE",
        endpoint="/api/exec",
        method="POST",
        body='{"cmd":"id"}',
        cve_id="CVE-2024-12347"
    )
    generator.save_template(template3)
    
    print(f"\n模板已保存到: {generator.output_dir}")