"""
漏洞至 MITRE ATT&CK 自动映射模块

功能:
    1. 将漏洞映射到 MITRE ATT&CK 框架的技术
    2. 描述攻击者可能如何利用漏洞实施攻击
    3. 丰富威胁上下文，便于安全运营团队响应
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ATTACKTechnique:
    """
    ATT&CK 技术信息
    """
    technique_id: str
    technique_name: str
    description: str = ""
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityMapping:
    """
    漏洞到 ATT&CK 的映射结果
    """
    vulnerability_type: str
    vulnerability_id: str = ""
    cve_id: str = ""
    mapped_techniques: List[ATTACKTechnique] = field(default_factory=list)
    primary_technique: Optional[ATTACKTechnique] = None
    confidence: float = 0.0
    reasoning: str = ""
    impact_type: str = ""  # RCE, Privilege Escalation, Info Leak, etc.
    target_type: str = ""  # Client, Server, Driver, etc.


@dataclass
class MappingResult:
    """
    映射结果
    """
    success: bool
    mappings: List[VulnerabilityMapping] = field(default_factory=list)
    unmapped_vulnerabilities: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# 漏洞类型到 ATT&CK 技术的默认映射规则
DEFAULT_VULN_TO_ATTACK_MAPPING = {
    # 远程代码执行类漏洞
    'rce': {
        'techniques': ['T1190', 'T1203'],
        'tactics': ['Initial Access', 'Execution'],
        'impact': 'Remote Code Execution',
        'reasoning': '远程代码执行漏洞允许攻击者通过漏洞直接在目标系统上执行代码'
    },
    'remote_code_execution': {
        'techniques': ['T1190', 'T1210'],
        'tactics': ['Initial Access', 'Execution'],
        'impact': 'Remote Code Execution',
        'reasoning': '远程代码执行漏洞可被用于初始访问或远程服务利用'
    },
    
    # 客户端漏洞
    'client_side': {
        'techniques': ['T1203'],
        'tactics': ['Execution'],
        'impact': 'Client Execution',
        'reasoning': '客户端漏洞（如浏览器解析器漏洞）可被用于客户端执行攻击'
    },
    'browser_vulnerability': {
        'techniques': ['T1203'],
        'tactics': ['Execution'],
        'impact': 'Client Execution',
        'reasoning': '浏览器漏洞可被用于 Exploit for Client Execution'
    },
    
    # 权限提升类漏洞
    'privilege_escalation': {
        'techniques': ['T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Privilege Escalation',
        'reasoning': '权限提升漏洞允许攻击者获得更高权限'
    },
    'kernel_eop': {
        'techniques': ['T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Privilege Escalation',
        'reasoning': '内核权限提升漏洞可被用于 Exploitation for Privilege Escalation'
    },
    'local_privilege_escalation': {
        'techniques': ['T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Privilege Escalation',
        'reasoning': '本地权限提升漏洞允许攻击者提升权限'
    },
    
    # 信息泄露类漏洞
    'information_disclosure': {
        'techniques': ['T1592'],
        'tactics': ['Reconnaissance'],
        'impact': 'Information Disclosure',
        'reasoning': '信息泄露漏洞可被用于收集受害者主机信息'
    },
    'info_leak': {
        'techniques': ['T1592', 'T1087'],
        'tactics': ['Reconnaissance', 'Discovery'],
        'impact': 'Information Disclosure',
        'reasoning': '信息泄露漏洞可被用于侦察或发现阶段'
    },
    
    # 内存破坏类漏洞（允许代码执行）
    'buffer_overflow': {
        'techniques': ['T1055', 'T1068'],
        'tactics': ['Privilege Escalation', 'Defense Evasion'],
        'impact': 'Code Execution',
        'reasoning': '缓冲区溢出漏洞可被用于进程注入或权限提升'
    },
    'stack_overflow': {
        'techniques': ['T1055', 'T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Code Execution',
        'reasoning': '栈溢出漏洞可被用于进程注入或权限提升'
    },
    'heap_overflow': {
        'techniques': ['T1055', 'T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Code Execution',
        'reasoning': '堆溢出漏洞可被用于进程注入或权限提升'
    },
    'use_after_free': {
        'techniques': ['T1055'],
        'tactics': ['Privilege Escalation', 'Defense Evasion'],
        'impact': 'Code Execution',
        'reasoning': 'UAF漏洞可被用于进程注入'
    },
    
    # 命令注入类漏洞
    'command_injection': {
        'techniques': ['T1059'],
        'tactics': ['Execution'],
        'impact': 'Command Execution',
        'reasoning': '命令注入漏洞允许攻击者执行任意命令'
    },
    'os_command_injection': {
        'techniques': ['T1059'],
        'tactics': ['Execution'],
        'impact': 'Command Execution',
        'reasoning': 'OS命令注入可被用于 Command and Scripting Interpreter'
    },
    
    # SQL注入类漏洞
    'sql_injection': {
        'techniques': ['T1190'],
        'tactics': ['Initial Access'],
        'impact': 'Data Access',
        'reasoning': 'SQL注入可被用于 Exploit Public-Facing Application'
    },
    
    # 文件操作类漏洞
    'path_traversal': {
        'techniques': ['T1083', 'T1005'],
        'tactics': ['Collection'],
        'impact': 'File Access',
        'reasoning': '路径遍历漏洞可被用于文件收集'
    },
    'arbitrary_file_read': {
        'techniques': ['T1005'],
        'tactics': ['Collection'],
        'impact': 'File Access',
        'reasoning': '任意文件读取漏洞可被用于数据收集'
    },
    'arbitrary_file_write': {
        'techniques': ['T1105'],
        'tactics': ['Command and Control'],
        'impact': 'File Modification',
        'reasoning': '任意文件写入可被用于 Ingress Tool Transfer'
    },
    
    # 拒绝服务类漏洞
    'denial_of_service': {
        'techniques': ['T1499'],
        'tactics': ['Impact'],
        'impact': 'Service Disruption',
        'reasoning': '拒绝服务漏洞可被用于 Endpoint Denial of Service'
    },
    'dos': {
        'techniques': ['T1499'],
        'tactics': ['Impact'],
        'impact': 'Service Disruption',
        'reasoning': 'DoS漏洞可被用于造成服务中断'
    },
    
    # 认证绕过类漏洞
    'authentication_bypass': {
        'techniques': ['T1078', 'T1550'],
        'tactics': ['Initial Access', 'Defense Evasion'],
        'impact': 'Authentication Bypass',
        'reasoning': '认证绕过漏洞可被用于 Valid Accounts 或 Use Alternate Authentication Material'
    },
    
    # 加密相关漏洞
    'weak_crypto': {
        'techniques': ['T1110'],
        'tactics': ['Credential Access'],
        'impact': 'Credential Access',
        'reasoning': '弱加密漏洞可被用于 Brute Force 或密码破解'
    },
    
    # 网络服务漏洞
    'network_service': {
        'techniques': ['T1190', 'T1210'],
        'tactics': ['Initial Access'],
        'impact': 'Network Service Exploitation',
        'reasoning': '网络服务漏洞可被用于 Exploit Public-Facing Application'
    },
    
    # 内核漏洞
    'kernel_vulnerability': {
        'techniques': ['T1068'],
        'tactics': ['Privilege Escalation'],
        'impact': 'Kernel Exploitation',
        'reasoning': '内核漏洞可被用于权限提升'
    },
    
    # Web应用漏洞
    'web_application': {
        'techniques': ['T1190'],
        'tactics': ['Initial Access'],
        'impact': 'Web Application Exploitation',
        'reasoning': 'Web应用漏洞可被用于 Exploit Public-Facing Application'
    },
    'xss': {
        'techniques': ['T1189'],
        'tactics': ['Initial Access'],
        'impact': 'Drive-by Compromise',
        'reasoning': 'XSS漏洞可被用于 Drive-by Compromise'
    },
    
    # 固件漏洞
    'firmware_vulnerability': {
        'techniques': ['T1542'],
        'tactics': ['Persistence', 'Defense Evasion'],
        'impact': 'Firmware Modification',
        'reasoning': '固件漏洞可被用于 Pre-OS Boot'
    },
    
    # 供应链漏洞
    'supply_chain': {
        'techniques': ['T1195', 'T1199'],
        'tactics': ['Initial Access'],
        'impact': 'Supply Chain Compromise',
        'reasoning': '供应链漏洞可被用于 Supply Chain Compromise'
    },
}

# 目标类型对映射的影响
TARGET_TYPE_ADJUSTMENTS = {
    'client': {
        'prefer_techniques': ['T1203', 'T1189'],
        'description': '客户端应用程序'
    },
    'server': {
        'prefer_techniques': ['T1190', 'T1210'],
        'description': '服务器端应用程序'
    },
    'driver': {
        'prefer_techniques': ['T1068', 'T1542'],
        'description': '内核驱动程序'
    },
    'kernel_module': {
        'prefer_techniques': ['T1068', 'T1542'],
        'description': '内核模块'
    },
    'web_service': {
        'prefer_techniques': ['T1190'],
        'description': 'Web服务'
    },
    'network_service': {
        'prefer_techniques': ['T1210'],
        'description': '网络服务'
    },
    'firmware': {
        'prefer_techniques': ['T1542'],
        'description': '固件'
    },
    'mobile_app': {
        'prefer_techniques': ['T1407', 'T1476'],
        'description': '移动应用'
    },
}

# ATT&CK 技术详细信息（内置默认）
DEFAULT_ATTACK_TECHNIQUES = {
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'description': '利用面向公众的应用程序漏洞获取初始访问',
        'tactics': ['Initial Access'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1203': {
        'name': 'Exploitation for Client Execution',
        'description': '利用客户端应用程序漏洞执行代码',
        'tactics': ['Execution'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1068': {
        'name': 'Exploitation for Privilege Escalation',
        'description': '利用漏洞提升权限',
        'tactics': ['Privilege Escalation'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1210': {
        'name': 'Exploitation of Remote Services',
        'description': '利用远程服务漏洞',
        'tactics': ['Initial Access', 'Lateral Movement'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1055': {
        'name': 'Process Injection',
        'description': '将代码注入到另一个进程的地址空间',
        'tactics': ['Privilege Escalation', 'Defense Evasion'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'description': '使用命令行界面或脚本解释器执行命令',
        'tactics': ['Execution'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1592': {
        'name': 'Gather Victim Host Information',
        'description': '收集受害者主机信息',
        'tactics': ['Reconnaissance'],
        'platforms': ['PRE']
    },
    'T1083': {
        'name': 'File and Directory Discovery',
        'description': '发现文件和目录',
        'tactics': ['Discovery'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1005': {
        'name': 'Data from Local System',
        'description': '从本地系统收集数据',
        'tactics': ['Collection'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1105': {
        'name': 'Ingress Tool Transfer',
        'description': '将工具传输到目标系统',
        'tactics': ['Command and Control'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1499': {
        'name': 'Endpoint Denial of Service',
        'description': '终端拒绝服务攻击',
        'tactics': ['Impact'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1078': {
        'name': 'Valid Accounts',
        'description': '使用有效账户进行访问',
        'tactics': ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']
    },
    'T1550': {
        'name': 'Use Alternate Authentication Material',
        'description': '使用替代认证材料',
        'tactics': ['Defense Evasion', 'Lateral Movement'],
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']
    },
    'T1110': {
        'name': 'Brute Force',
        'description': '暴力破解密码',
        'tactics': ['Credential Access'],
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']
    },
    'T1189': {
        'name': 'Drive-by Compromise',
        'description': '通过访问网站感染受害者系统',
        'tactics': ['Initial Access'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1542': {
        'name': 'Pre-OS Boot',
        'description': '在操作系统启动前执行恶意代码',
        'tactics': ['Persistence', 'Defense Evasion'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1195': {
        'name': 'Supply Chain Compromise',
        'description': '供应链攻击',
        'tactics': ['Initial Access'],
        'platforms': ['Linux', 'Windows', 'macOS']
    },
    'T1199': {
        'name': 'Trusted Relationship',
        'description': '利用信任关系进行攻击',
        'tactics': ['Initial Access'],
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']
    },
    'T1087': {
        'name': 'Account Discovery',
        'description': '发现账户信息',
        'tactics': ['Discovery'],
        'platforms': ['Linux', 'Windows', 'macOS', 'Cloud']
    },
    'T1407': {
        'name': 'Download Application',
        'description': '下载恶意应用程序',
        'tactics': ['Initial Access'],
        'platforms': ['Android', 'iOS']
    },
    'T1476': {
        'name': 'Modify Application',
        'description': '修改应用程序',
        'tactics': ['Persistence'],
        'platforms': ['Android', 'iOS']
    },
}


class ATTACKMapper:
    """
    MITRE ATT&CK 映射器
    
    将漏洞映射到 MITRE ATT&CK 框架的技术。
    """
    
    def __init__(
        self,
        mapping_file: str = None,
        custom_mapping_file: str = None
    ):
        """
        初始化 ATT&CK 映射器
        
        Args:
            mapping_file: 内置映射文件路径
            custom_mapping_file: 自定义映射文件路径
        """
        self.mapping_file = mapping_file or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'data', 'attack_mapping.json'
        )
        self.custom_mapping_file = custom_mapping_file
        
        # 加载映射数据
        self.vuln_to_attack_mapping: Dict[str, Dict[str, Any]] = {}
        self.attack_techniques: Dict[str, Dict[str, Any]] = {}
        
        self._load_mappings()
        
        logger.info(f"ATT&CK 映射器初始化完成，已加载 {len(self.attack_techniques)} 个技术")
    
    def _load_mappings(self):
        """
        加载映射数据
        """
        # 加载内置默认映射
        self.vuln_to_attack_mapping = DEFAULT_VULN_TO_ATTACK_MAPPING.copy()
        self.attack_techniques = DEFAULT_ATTACK_TECHNIQUES.copy()
        
        # 尝试加载映射文件
        files_to_try = [
            self.mapping_file,
            os.path.join('./data', 'attack_mapping.json'),
        ]
        
        for file_path in files_to_try:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # 合并映射
                    if 'vuln_to_attack' in data:
                        self.vuln_to_attack_mapping.update(data['vuln_to_attack'])
                    
                    if 'techniques' in data:
                        self.attack_techniques.update(data['techniques'])
                    
                    logger.info(f"已加载 ATT&CK 映射文件: {file_path}")
                    break
                    
                except Exception as e:
                    logger.warning(f"加载 ATT&CK 映射文件失败 {file_path}: {e}")
        
        # 加载自定义映射
        if self.custom_mapping_file and os.path.exists(self.custom_mapping_file):
            try:
                with open(self.custom_mapping_file, 'r', encoding='utf-8') as f:
                    custom_data = json.load(f)
                
                if 'vuln_to_attack' in custom_data:
                    self.vuln_to_attack_mapping.update(custom_data['vuln_to_attack'])
                
                if 'techniques' in custom_data:
                    self.attack_techniques.update(custom_data['techniques'])
                
                logger.info(f"已加载自定义 ATT&CK 映射: {self.custom_mapping_file}")
                
            except Exception as e:
                logger.warning(f"加载自定义映射失败: {e}")
    
    def map_vulnerability(
        self,
        vuln_type: str,
        vuln_id: str = None,
        cve_id: str = None,
        impact_type: str = None,
        target_type: str = None,
        severity: str = None
    ) -> VulnerabilityMapping:
        """
        映射单个漏洞
        
        Args:
            vuln_type: 漏洞类型
            vuln_id: 漏洞ID
            cve_id: CVE ID
            impact_type: 影响类型（RCE, Privilege Escalation, Info Leak等）
            target_type: 目标类型（Client, Server, Driver等）
            severity: 严重程度
            
        Returns:
            映射结果
        """
        vuln_type_lower = vuln_type.lower().replace('-', '_').replace(' ', '_')
        
        # 查找直接匹配
        mapping_info = None
        matched_key = None
        
        for key, info in self.vuln_to_attack_mapping.items():
            key_lower = key.lower().replace('-', '_').replace(' ', '_')
            
            # 直接匹配
            if key_lower == vuln_type_lower:
                mapping_info = info
                matched_key = key
                break
            
            # 包含匹配
            if key_lower in vuln_type_lower or vuln_type_lower in key_lower:
                mapping_info = info
                matched_key = key
                break
        
        # 如果没有找到，尝试根据影响类型推断
        if not mapping_info and impact_type:
            mapping_info = self._infer_from_impact(impact_type)
        
        # 如果没有找到，尝试根据目标类型推断
        if not mapping_info and target_type:
            mapping_info = self._infer_from_target(target_type, vuln_type)
        
        # 构建映射结果
        result = VulnerabilityMapping(
            vulnerability_type=vuln_type,
            vulnerability_id=vuln_id or '',
            cve_id=cve_id or '',
            impact_type=impact_type or '',
            target_type=target_type or '',
            confidence=0.0,
            reasoning=''
        )
        
        if mapping_info:
            # 获取技术列表
            technique_ids = mapping_info.get('techniques', [])
            
            # 根据目标类型调整
            if target_type and target_type.lower() in TARGET_TYPE_ADJUSTMENTS:
                adjustments = TARGET_TYPE_ADJUSTMENTS[target_type.lower()]
                prefer_techniques = adjustments.get('prefer_techniques', [])
                
                # 将优先技术放在前面
                adjusted_ids = []
                for tech_id in prefer_techniques:
                    if tech_id in technique_ids:
                        adjusted_ids.append(tech_id)
                for tech_id in technique_ids:
                    if tech_id not in adjusted_ids:
                        adjusted_ids.append(tech_id)
                
                technique_ids = adjusted_ids
            
            # 构建技术对象
            mapped_techniques = []
            for tech_id in technique_ids:
                tech_info = self.attack_techniques.get(tech_id, {})
                technique = ATTACKTechnique(
                    technique_id=tech_id,
                    technique_name=tech_info.get('name', tech_id),
                    description=tech_info.get('description', ''),
                    tactics=tech_info.get('tactics', []),
                    platforms=tech_info.get('platforms', []),
                    references=[f"https://attack.mitre.org/techniques/{tech_id}/"]
                )
                mapped_techniques.append(technique)
            
            result.mapped_techniques = mapped_techniques
            result.primary_technique = mapped_techniques[0] if mapped_techniques else None
            result.reasoning = mapping_info.get('reasoning', '')
            
            # 计算置信度
            if matched_key and matched_key.lower().replace('-', '_').replace(' ', '_') == vuln_type_lower:
                result.confidence = 0.9
            elif matched_key:
                result.confidence = 0.7
            else:
                result.confidence = 0.5
        
        else:
            # 未找到映射
            result.reasoning = f"无法将漏洞类型 '{vuln_type}' 映射到已知的 ATT&CK 技术，建议人工分析"
            result.confidence = 0.0
        
        return result
    
    def _infer_from_impact(
        self,
        impact_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        从影响类型推断映射
        
        Args:
            impact_type: 影响类型
            
        Returns:
            映射信息
        """
        impact_lower = impact_type.lower()
        
        # 影响类型到映射的转换
        impact_mapping = {
            'rce': DEFAULT_VULN_TO_ATTACK_MAPPING.get('rce'),
            'remote_code_execution': DEFAULT_VULN_TO_ATTACK_MAPPING.get('remote_code_execution'),
            'privilege_escalation': DEFAULT_VULN_TO_ATTACK_MAPPING.get('privilege_escalation'),
            'information_disclosure': DEFAULT_VULN_TO_ATTACK_MAPPING.get('information_disclosure'),
            'info_leak': DEFAULT_VULN_TO_ATTACK_MAPPING.get('info_leak'),
            'dos': DEFAULT_VULN_TO_ATTACK_MAPPING.get('dos'),
            'denial_of_service': DEFAULT_VULN_TO_ATTACK_MAPPING.get('denial_of_service'),
            'command_execution': DEFAULT_VULN_TO_ATTACK_MAPPING.get('command_injection'),
            'file_access': DEFAULT_VULN_TO_ATTACK_MAPPING.get('path_traversal'),
            'authentication_bypass': DEFAULT_VULN_TO_ATTACK_MAPPING.get('authentication_bypass'),
        }
        
        for key, mapping in impact_mapping.items():
            if key in impact_lower:
                return mapping
        
        return None
    
    def _infer_from_target(
        self,
        target_type: str,
        vuln_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        从目标类型推断映射
        
        Args:
            target_type: 目标类型
            vuln_type: 漏洞类型
            
        Returns:
            映射信息
        """
        target_lower = target_type.lower()
        
        # 根据目标类型选择默认映射
        if target_lower in ['client', 'browser', 'mobile_app']:
            return DEFAULT_VULN_TO_ATTACK_MAPPING.get('client_side')
        
        if target_lower in ['server', 'web_service', 'network_service']:
            return DEFAULT_VULN_TO_ATTACK_MAPPING.get('network_service')
        
        if target_lower in ['driver', 'kernel_module', 'kernel']:
            return DEFAULT_VULN_TO_ATTACK_MAPPING.get('kernel_vulnerability')
        
        if target_lower == 'firmware':
            return DEFAULT_VULN_TO_ATTACK_MAPPING.get('firmware_vulnerability')
        
        # 如果漏洞类型包含 overflow，默认为进程注入
        if 'overflow' in vuln_type.lower():
            return DEFAULT_VULN_TO_ATTACK_MAPPING.get('buffer_overflow')
        
        return None
    
    def map_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        binary_type: str = None
    ) -> MappingResult:
        """
        映射多个漏洞
        
        Args:
            vulnerabilities: 漏洞列表
            binary_type: 二进制类型
            
        Returns:
            映射结果
        """
        result = MappingResult(success=True)
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            vuln_id = vuln.get('id', '')
            cve_id = vuln.get('cve', '')
            severity = vuln.get('severity', '')
            
            # 从漏洞描述推断影响类型
            impact_type = self._infer_impact_from_vuln(vuln)
            
            # 目标类型
            target_type = binary_type or self._infer_target_from_vuln(vuln)
            
            # 执行映射
            mapping = self.map_vulnerability(
                vuln_type=vuln_type,
                vuln_id=vuln_id,
                cve_id=cve_id,
                impact_type=impact_type,
                target_type=target_type,
                severity=severity
            )
            
            if mapping.primary_technique:
                result.mappings.append(mapping)
            else:
                result.unmapped_vulnerabilities.append(vuln_type)
        
        # 添加警告
        if result.unmapped_vulnerabilities:
            result.warnings.append(
                f"{len(result.unmapped_vulnerabilities)} 个漏洞未能映射到 ATT&CK 技术: "
                f"{', '.join(result.unmapped_vulnerabilities[:5])}"
            )
        
        return result
    
    def _infer_impact_from_vuln(
        self,
        vuln: Dict[str, Any]
    ) -> str:
        """
        从漏洞信息推断影响类型
        
        Args:
            vuln: 漏洞信息
            
        Returns:
            影响类型
        """
        vuln_type = vuln.get('type', '').lower()
        description = vuln.get('description', '').lower()
        exploitation = vuln.get('exploitation', '').lower()
        
        combined_text = f"{vuln_type} {description} {exploitation}"
        
        # 影响类型推断规则
        impact_rules = [
            ('rce', ['remote code execution', 'rce', 'arbitrary code', 'execute arbitrary']),
            ('privilege_escalation', ['privilege escalation', 'eop', 'gain root', 'gain admin', 'escalate privilege']),
            ('information_disclosure', ['information disclosure', 'info leak', 'data leak', 'memory leak', 'read arbitrary']),
            ('dos', ['denial of service', 'dos', 'crash', 'hang', 'freeze']),
            ('command_execution', ['command injection', 'execute command', 'os command', 'shell injection']),
            ('file_access', ['path traversal', 'arbitrary file', 'directory traversal', 'file read', 'file write']),
            ('authentication_bypass', ['authentication bypass', 'auth bypass', 'bypass authentication', 'login bypass']),
        ]
        
        for impact, keywords in impact_rules:
            for keyword in keywords:
                if keyword in combined_text:
                    return impact
        
        # 根据漏洞类型推断
        if 'overflow' in vuln_type:
            return 'rce'
        if 'injection' in vuln_type:
            return 'command_execution'
        if 'uaf' in vuln_type or 'use_after_free' in vuln_type:
            return 'rce'
        
        return ''
    
    def _infer_target_from_vuln(
        self,
        vuln: Dict[str, Any]
    ) -> str:
        """
        从漏洞信息推断目标类型
        
        Args:
            vuln: 漏洞信息
            
        Returns:
            目标类型
        """
        location = vuln.get('location', '').lower()
        description = vuln.get('description', '').lower()
        
        combined_text = f"{location} {description}"
        
        # 目标类型推断规则
        target_rules = [
            ('kernel', ['kernel', 'driver', 'ioctl', 'syscall', 'module']),
            ('server', ['server', 'service', 'daemon', 'network', 'socket', 'listen', 'bind']),
            ('client', ['client', 'browser', 'ui', 'gui', 'frontend']),
            ('web_service', ['http', 'web', 'cgi', 'api', 'rest']),
            ('firmware', ['firmware', 'boot', 'bios', 'uefi']),
        ]
        
        for target, keywords in target_rules:
            for keyword in keywords:
                if keyword in combined_text:
                    return target
        
        return ''
    
    def get_technique_details(
        self,
        technique_id: str
    ) -> Optional[ATTACKTechnique]:
        """
        获取技术详细信息
        
        Args:
            technique_id: 技术ID
            
        Returns:
            技术信息
        """
        tech_info = self.attack_techniques.get(technique_id)
        
        if tech_info:
            return ATTACKTechnique(
                technique_id=technique_id,
                technique_name=tech_info.get('name', technique_id),
                description=tech_info.get('description', ''),
                tactics=tech_info.get('tactics', []),
                platforms=tech_info.get('platforms', []),
                references=[f"https://attack.mitre.org/techniques/{technique_id}/"]
            )
        
        return None
    
    def add_custom_mapping(
        self,
        vuln_type: str,
        technique_ids: List[str],
        reasoning: str,
        tactics: List[str] = None,
        impact_type: str = None
    ):
        """
        添加自定义映射
        
        Args:
            vuln_type: 漏洞类型
            technique_ids: 技术ID列表
            reasoning: 映射理由
            tactics: 战术列表
            impact_type: 影响类型
        """
        self.vuln_to_attack_mapping[vuln_type.lower().replace('-', '_').replace(' ', '_')] = {
            'techniques': technique_ids,
            'tactics': tactics or [],
            'reasoning': reasoning,
            'impact': impact_type or ''
        }
        
        logger.info(f"已添加自定义映射: {vuln_type} -> {technique_ids}")
    
    def save_mappings(
        self,
        output_path: str = None
    ):
        """
        保存映射到文件
        
        Args:
            output_path: 输出路径
        """
        if not output_path:
            output_path = self.mapping_file
        
        data = {
            'vuln_to_attack': self.vuln_to_attack_mapping,
            'techniques': self.attack_techniques,
            'metadata': {
                'version': '1.0',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'source': 'MITRE ATT&CK Enterprise v12'
            }
        }
        
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"ATT&CK 映射已保存: {output_path}")
            
        except Exception as e:
            logger.error(f"保存 ATT&CK 映射失败: {e}")
    
    def get_all_techniques(self) -> List[str]:
        """
        获取所有已知技术ID
        
        Returns:
            技术ID列表
        """
        return list(self.attack_techniques.keys())
    
    def get_all_vuln_types(self) -> List[str]:
        """
        获取所有已映射的漏洞类型
        
        Returns:
            漏洞类型列表
        """
        return list(self.vuln_to_attack_mapping.keys())


def map_vulnerability_to_attack(
    vuln_type: str,
    impact_type: str = None,
    target_type: str = None,
    mapping_file: str = None
) -> VulnerabilityMapping:
    """
    映射漏洞到 ATT&CK 的便捷函数
    
    Args:
        vuln_type: 漏洞类型
        impact_type: 影响类型
        target_type: 目标类型
        mapping_file: 映射文件路径
        
    Returns:
        映射结果
    """
    mapper = ATTACKMapper(mapping_file=mapping_file)
    return mapper.map_vulnerability(
        vuln_type=vuln_type,
        impact_type=impact_type,
        target_type=target_type
    )


def map_vulnerabilities_to_attack(
    vulnerabilities: List[Dict[str, Any]],
    binary_type: str = None
) -> MappingResult:
    """
    映射多个漏洞到 ATT&CK 的便捷函数
    
    Args:
        vulnerabilities: 漏洞列表
        binary_type: 二进制类型
        
    Returns:
        映射结果
    """
    mapper = ATTACKMapper()
    return mapper.map_vulnerabilities(vulnerabilities, binary_type)