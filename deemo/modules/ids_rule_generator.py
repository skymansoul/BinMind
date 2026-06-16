"""
网络入侵检测规则自动生成模块 (Suricata/Snort)

功能:
    1. 分析网络服务程序的漏洞，自动生成 Suricata/Snort IDS 检测规则
    2. 从崩溃数据、符号执行结果中提取攻击流量特征
    3. 与协议逆向模块联动，生成精确的协议匹配规则
    4. 支持多种漏洞类型（栈溢出、堆溢出、命令注入等）
"""

import os
import re
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# 网络相关导入函数列表
NETWORK_FUNCTIONS = {
    'socket', 'bind', 'listen', 'accept', 'accept4',
    'recv', 'recvfrom', 'recvmsg', 'read',
    'send', 'sendto', 'sendmsg', 'write',
    'connect', 'getaddrinfo', 'gethostbyname',
    'select', 'poll', 'epoll_create', 'epoll_wait',
    'WSASocket', 'WSAConnect', 'WSASend', 'WSARecv',
    'socket_create', 'socket_connect', 'socket_read', 'socket_write',
}

# 可远程触发的漏洞类型
REMOTE_TRIGGERABLE_VULNS = {
    'stack_overflow', 'heap_overflow', 'buffer_overflow',
    'format_string', 'command_injection', 'sql_injection',
    'integer_overflow', 'null_pointer', 'use_after_free',
    'heap_use_after_free', 'kernel_stack_overflow', 'kernel_heap_overflow',
}

# Suricata 规则动作
SURICATA_ACTIONS = ['alert', 'pass', 'drop', 'reject', 'rejectboth']

# Snort 规则动作
SNORT_ACTIONS = ['alert', 'log', 'pass', 'activate', 'dynamic', 'drop', 'sdrop', 'reject']


@dataclass
class AttackSignature:
    """攻击特征数据类"""
    signature_type: str
    pattern: bytes
    offset: int = 0
    description: str = ""
    
    def to_content_dict(self) -> Dict[str, Any]:
        """转换为内容字典"""
        return {
            "content": self.pattern,
            "offset": self.offset,
            "description": self.description
        }


@dataclass
class NetworkFunctionInfo:
    """网络函数信息数据类"""
    function_name: str
    category: str = ""
    is_server: bool = False
    is_client: bool = False


@dataclass
class IDSRuleMeta:
    """
    IDS 规则元信息
    """
    rule_id: str
    cve_id: str = ""
    vuln_id: str = ""
    description: str = ""
    severity: str = "Medium"
    reference: str = ""
    author: str = "deemo-auto-generator"
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    service_port: int = 0
    protocol: str = "tcp"
    binary_name: str = ""


@dataclass
class NetworkFunctionInfo:
    """网络函数信息数据类"""
    function_name: str
    category: str = ""
    is_server: bool = False
    is_client: bool = False
    port: int = 0
    protocol: str = "tcp"


@dataclass
class IDSRuleContent:
    """
    IDS 规则内容
    """
    action: str = "alert"
    protocol: str = "tcp"
    source_ip: str = "$EXTERNAL_NET"
    source_port: str = "any"
    dest_ip: str = "$HOME_NET"
    dest_port: str = "$SERVICE_PORTS"
    msg: str = ""
    content_matches: List[Dict[str, Any]] = field(default_factory=list)
    pcre_matches: List[str] = field(default_factory=list)
    depth: int = 0
    offset: int = 0
    within: int = 0
    distance: int = 0
    sid: int = 0
    rev: int = 1
    classtype: str = "attempted-admin"
    reference: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class IDSRuleResult:
    """
    IDS 规则生成结果
    """
    success: bool
    rule_text: str = ""
    rule_format: str = "suricata"
    rule_file: str = ""
    rule_count: int = 0
    warnings: List[str] = field(default_factory=list)
    needs_manual_review: bool = False
    review_reasons: List[str] = field(default_factory=list)


class IDSRuleGenerator:
    """
    网络入侵检测规则自动生成器
    
    分析网络服务程序的漏洞特征，自动生成 Suricata/Snort IDS 检测规则。
    """
    
    # 规则 ID 起始值（避免与现有规则冲突）
    SID_START = 9000000
    
    # 最大内容匹配长度
    MAX_CONTENT_LENGTH = 200
    
    # 最小内容匹配长度
    MIN_CONTENT_LENGTH = 4
    
    def __init__(
        self,
        output_dir: str = None,
        rule_format: str = "suricata",
        sid_start: int = None
    ):
        """
        初始化 IDS 规则生成器
        
        Args:
            output_dir: 规则输出目录
            rule_format: 规则格式 (suricata 或 snort)
            sid_start: 规则 ID 起始值
        """
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'data', 'ids_rules'
        )
        self.format = rule_format.lower()
        self.rule_format = self.format
        self.base_sid = sid_start or self.SID_START
        self.sid_start = self.base_sid
        self.current_sid = self.sid_start
        
        # 网络函数列表
        self.network_functions = set(NETWORK_FUNCTIONS)
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        if self.rule_format not in ['suricata', 'snort']:
            logger.warning(f"未知的规则格式: {rule_format}，使用 suricata")
            self.rule_format = 'suricata'
            self.format = 'suricata'
        
        logger.info(f"IDS 规则生成器初始化完成，格式: {self.rule_format}, 输出目录: {self.output_dir}")
    
    def is_network_service(
        self,
        binary_info: Dict[str, Any],
        imports: Dict[str, Any] = None
    ) -> bool:
        """
        判断二进制是否为网络服务程序
        
        Args:
            binary_info: 二进制文件信息
            imports: 导入函数信息
            
        Returns:
            是否为网络服务程序
        """
        # 检查固件信息
        firmware_info = binary_info.get('firmware_info', {})
        if firmware_info:
            device_type = firmware_info.get('device_type', '')
            if device_type.lower() in ['router', 'switch', 'gateway', 'firewall']:
                return True
        
        # 检查协议信息
        protocol_info = binary_info.get('protocol_info', {})
        if protocol_info:
            protocols = protocol_info.get('protocols', [])
            if protocols:
                return True
        
        # 检查导入函数列表（测试期望的格式）
        imports_list = binary_info.get('imports', [])
        if isinstance(imports_list, list):
            for func in imports_list:
                for net_func in NETWORK_FUNCTIONS:
                    if net_func.lower() in func.lower():
                        return True
        
        # 检查导入函数（字典格式）
        if imports:
            dangerous_funcs = imports.get('dangerous_functions', [])
            all_imports = imports.get('all_imports', [])
            
            # 合并所有导入函数
            all_funcs = set(dangerous_funcs + all_imports)
            
            # 检查是否包含网络相关函数
            for func in all_funcs:
                func_lower = func.lower()
                for net_func in NETWORK_FUNCTIONS:
                    if net_func.lower() in func_lower:
                        logger.info(f"检测到网络函数: {func}")
                        return True
        
        # 检查二进制信息中的导入（字典格式）
        if binary_info:
            imports_info = binary_info.get('imports', {})
            if isinstance(imports_info, dict):
                dangerous_funcs = imports_info.get('dangerous_functions', [])
                for func in dangerous_funcs:
                    for net_func in NETWORK_FUNCTIONS:
                        if net_func.lower() in func.lower():
                            return True
        
        # 检查字符串中的网络相关内容
        strings = binary_info.get('strings', [])
        if strings:
            network_patterns = [
                'socket', 'bind', 'listen', 'accept',
                'recv', 'send', 'connect',
                'TCP', 'UDP', 'HTTP', 'FTP',
                'port', 'listen_port', 'server_port',
                '0.0.0.0', '127.0.0.1', 'localhost',
            ]
            for s in strings:
                for pattern in network_patterns:
                    if pattern.lower() in s.lower():
                        logger.info(f"检测到网络相关字符串: {s}")
                        return True
        
        return False
    
    def is_remote_triggerable(
        self,
        vuln_info: Dict[str, Any]
    ) -> bool:
        """
        判断漏洞是否可由网络远程触发
        
        Args:
            vuln_info: 漏洞信息字典
            
        Returns:
            是否可远程触发
        """
        if isinstance(vuln_info, dict):
            vuln_type = vuln_info.get('vulnerability_type', '')
            trigger = vuln_info.get('trigger', '')
            
            # 检查触发方式
            if trigger:
                trigger_lower = trigger.lower()
                if 'network' in trigger_lower or 'remote' in trigger_lower or 'user' in trigger_lower:
                    return True
            
            # 检查漏洞类型
            vuln_type_lower = vuln_type.lower().replace('-', '_').replace(' ', '_')
            for remote_vuln in REMOTE_TRIGGERABLE_VULNS:
                if remote_vuln in vuln_type_lower:
                    return True
        else:
            # 兼容字符串类型输入
            vuln_type_lower = str(vuln_info).lower().replace('-', '_').replace(' ', '_')
            for remote_vuln in REMOTE_TRIGGERABLE_VULNS:
                if remote_vuln in vuln_type_lower:
                    return True
        
        return False
    
    def extract_attack_signature(
        self,
        crash_data: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        protocol_info: Dict[str, Any] = None,
        vuln_type: str = None,
        vuln: Dict[str, Any] = None
    ) -> List['AttackSignature']:
        """
        从漏洞信息中提取攻击特征
        
        Args:
            crash_data: 崩溃数据
            symbolic_result: 符号执行结果
            protocol_info: 协议逆向信息
            vuln_type: 漏洞类型
            vuln: 漏洞信息（兼容旧接口）
            
        Returns:
            攻击特征列表
        """
        signatures = []
        
        # 使用 vuln_type 参数或从 vuln 字典获取
        actual_vuln_type = vuln_type or (vuln.get('type') if vuln else None)
        
        # 从崩溃数据提取特征
        if crash_data:
            crashing_input = crash_data.get('crashing_input')
            if crashing_input:
                if isinstance(crashing_input, bytes):
                    signatures.append(AttackSignature(
                        signature_type="buffer_overflow",
                        pattern=crashing_input[:min(len(crashing_input), self.MAX_CONTENT_LENGTH)],
                        offset=0,
                        description="崩溃触发输入"
                    ))
        
        # 从协议信息提取特征
        if protocol_info:
            magic_bytes = protocol_info.get('magic_bytes')
            if magic_bytes:
                signatures.append(AttackSignature(
                    signature_type="protocol_magic",
                    pattern=magic_bytes,
                    offset=0,
                    description="协议魔数"
                ))
        
        return signatures
    
    def generate_rule(
        self,
        rule_content: 'IDSRuleContent',
        format: str = None
    ) -> str:
        """
        生成 IDS 规则字符串
        
        Args:
            rule_content: 规则内容对象
            format: 规则格式 (suricata 或 snort)
            
        Returns:
            规则字符串
        """
        rule_format = format or self.rule_format
        
        # 构建规则头部
        rule_parts = [
            f"{rule_content.action} {rule_content.protocol}",
            f"{rule_content.source_ip} {rule_content.source_port} ->",
            f"{rule_content.dest_ip} {rule_content.dest_port}",
            "("
        ]
        
        # 添加消息
        if rule_content.msg:
            rule_parts.append(f'msg:"{rule_content.msg}";')
        
        # 添加内容匹配
        for match in rule_content.content_matches:
            content = match.get('content', '')
            if content:
                rule_parts.append(f'content:"{content}";')
        
        # 添加规则ID
        if rule_content.sid:
            rule_parts.append(f'sid:{rule_content.sid};')
        
        # 添加类别
        if rule_content.classtype:
            rule_parts.append(f'classtype:{rule_content.classtype};')
        
        rule_parts.append(")")
        
        return " ".join(rule_parts)
    
    def _generate_generic_rule(
        self,
        vuln_info: Dict[str, Any]
    ) -> 'IDSRuleContent':
        """
        生成通用规则（测试期望的方法）
        
        Args:
            vuln_info: 漏洞信息字典
            
        Returns:
            IDSRuleContent 对象
        """
        vuln_type = vuln_info.get('vulnerability_type', 'unknown')
        cve_id = vuln_info.get('cve_id')
        description = vuln_info.get('description', 'Generic vulnerability')
        
        msg_parts = [description]
        if cve_id:
            msg_parts.append(cve_id)
        msg_parts.append("Manual review required")
        
        return IDSRuleContent(
            action="alert",
            protocol="tcp",
            source_ip="$EXTERNAL_NET",
            source_port="any",
            dest_ip="$HOME_NET",
            dest_port="any",
            msg=" | ".join(msg_parts),
            sid=self._generate_sid(),
            classtype="attempted-admin"
        )
    
    def _generate_sid(self) -> int:
        """生成唯一的规则ID"""
        sid = self.current_sid
        self.current_sid += 1
        return sid
    
    def generate_rules_for_vulnerability(
        self,
        binary_info: Dict[str, Any],
        vuln_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        为漏洞生成规则列表
        
        Args:
            binary_info: 二进制文件信息
            vuln_info: 漏洞信息
            
        Returns:
            规则列表
        """
        # 检查是否为网络服务
        if not self.is_network_service(binary_info):
            return []
        
        # 检查是否可远程触发
        if not self.is_remote_triggerable(vuln_info):
            return []
        
        vuln_type = vuln_info.get('vulnerability_type', 'unknown')
        rule_content = self._generate_generic_rule(vuln_info)
        
        return [{
            'rule': self.generate_rule(rule_content),
            'sid': rule_content.sid,
            'vulnerability_type': vuln_type
        }]
    
    def save_rules_to_file(
        self,
        rules: List[Dict[str, Any]],
        binary_name: str,
        format: str = None
    ) -> str:
        """
        保存规则到文件
        
        Args:
            rules: 规则列表
            binary_name: 二进制文件名
            format: 规则格式
            
        Returns:
            输出文件路径
        """
        filename = f"{binary_name}_{int(time.time())}.rules"
        output_path = os.path.join(self.output_dir, filename)
        
        with open(output_path, 'w') as f:
            for rule in rules:
                f.write(rule.get('rule', '') + '\n')
        
        return output_path
    
    def validate_rule_syntax(
        self,
        rule_text: str
    ) -> bool:
        """
        验证规则语法
        
        Args:
            rule_text: 规则文本
            
        Returns:
            是否有效
        """
        # 简单的语法验证
        if not rule_text.strip():
            return False
        
        if 'alert' not in rule_text and 'drop' not in rule_text:
            return False
        
        # 检查括号是否配对
        open_parens = rule_text.count('(')
        close_parens = rule_text.count(')')
        
        if open_parens != close_parens:
            return False
        
        return True
    
    def _determine_port(
        self,
        protocol_info: Dict[str, Any] = None,
        vuln_info: Dict[str, Any] = None
    ) -> str:
        """
        确定服务端口
        
        Args:
            protocol_info: 协议信息
            vuln_info: 漏洞信息
            
        Returns:
            端口号字符串
        """
        # 从协议信息获取端口（支持 default_port 字段）
        if protocol_info:
            port = protocol_info.get('port') or protocol_info.get('default_port')
            if port:
                return str(port)
        
        # 从漏洞信息获取端口（支持 network_service.port 字段）
        if vuln_info:
            network_service = vuln_info.get('network_service', {})
            port = vuln_info.get('port') or network_service.get('port')
            if port:
                return str(port)
        
        # 默认端口
        return "$SERVICE_PORTS"
    
    def _extract_content_from_input(self, input_data: bytes) -> List[str]:
        """
        从输入数据提取内容特征
        
        Args:
            input_data: 输入数据
            
        Returns:
            内容特征列表
        """
        try:
            content_str = input_data.decode('utf-8')
            return [content_str[:self.MAX_CONTENT_LENGTH]]
        except:
            return [input_data[:self.MAX_CONTENT_LENGTH].hex()]
    
    def generate_rule(
        self,
        vuln: Dict[str, Any],
        binary_info: Dict[str, Any],
        crash_data: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        protocol_info: Dict[str, Any] = None,
        cve_id: str = None,
        service_port: int = None
    ) -> str:
        """
        为单个漏洞生成 IDS 规则
        
        Args:
            vuln: 漏洞信息
            binary_info: 二进制文件信息
            crash_data: 崩溃数据
            symbolic_result: 符号执行结果
            protocol_info: 协议逆向信息
            cve_id: CVE ID
            service_port: 服务端口
            
        Returns:
            IDS 规则文本
        """
        vuln_type = vuln.get('type', 'unknown')
        vuln_description = vuln.get('description', '')
        severity = vuln.get('severity', 'Medium')
        
        binary_name = binary_info.get('name', 'unknown')
        if not binary_name:
            binary_name = os.path.basename(binary_info.get('path', 'unknown'))
        
        # 提取攻击特征
        signature = self.extract_attack_signature(
            vuln, crash_data, symbolic_result, protocol_info
        )
        
        # 确定协议和端口
        protocol = self._detect_protocol(binary_info, protocol_info)
        port = service_port or self._detect_port(binary_info, protocol_info)
        
        # 构建规则内容
        rule_content = IDSRuleContent(
            action='alert',
            protocol=protocol,
            dest_port=str(port) if port else '$SERVICE_PORTS',
            msg=f"{binary_name} {vuln_type} vulnerability",
            depth=signature.get('depth', 0),
            offset=signature.get('offset', 0),
            sid=self._get_next_sid(),
            classtype=self._get_classtype(vuln_type, severity),
        )
        
        # 添加内容匹配
        for pattern in signature.get('content_patterns', []):
            content = pattern.get('content', '')
            if len(content) >= self.MIN_CONTENT_LENGTH:
                modifiers = pattern.get('modifiers', [])
                rule_content.content_matches.append({
                    'content': self._escape_content(content),
                    'modifiers': modifiers
                })
        
        # 添加字节模式匹配
        for pattern in signature.get('byte_patterns', []):
            bytes_data = pattern.get('bytes', b'')
            if len(bytes_data) >= self.MIN_CONTENT_LENGTH:
                hex_str = ' '.join(f'{b:02X}' for b in bytes_data[:self.MAX_CONTENT_LENGTH])
                rule_content.content_matches.append({
                    'content': f'|{hex_str}|',
                    'modifiers': []
                })
        
        # 添加引用
        if cve_id:
            rule_content.reference.append(f"cve,{cve_id}")
        rule_content.reference.append(f"url,https://github.com/deemo-analyzer")
        
        # 构建规则文本
        rule_text = self._build_rule_text(rule_content)
        
        return rule_text
    
    def _detect_protocol(
        self,
        binary_info: Dict[str, Any],
        protocol_info: Dict[str, Any] = None
    ) -> str:
        """
        检测协议类型
        
        Args:
            binary_info: 二进制信息
            protocol_info: 协议逆向信息
            
        Returns:
            协议类型 (tcp, udp, icmp, ip)
        """
        # 从协议逆向信息获取
        if protocol_info:
            proto = protocol_info.get('protocol', '')
            if proto:
                proto_lower = proto.lower()
                if proto_lower in ['tcp', 'udp', 'icmp', 'ip']:
                    return proto_lower
        
        # 从字符串推断
        strings = binary_info.get('strings', [])
        if strings:
            for s in strings:
                s_lower = s.lower()
                if 'udp' in s_lower:
                    return 'udp'
                if 'tcp' in s_lower:
                    return 'tcp'
                if 'icmp' in s_lower:
                    return 'icmp'
        
        # 默认 TCP
        return 'tcp'
    
    def _detect_port(
        self,
        binary_info: Dict[str, Any],
        protocol_info: Dict[str, Any] = None
    ) -> int:
        """
        检测服务端口
        
        Args:
            binary_info: 二进制信息
            protocol_info: 协议逆向信息
            
        Returns:
            端口号
        """
        # 从协议逆向信息获取
        if protocol_info:
            port = protocol_info.get('default_port', 0)
            if port:
                return port
        
        # 从字符串推断
        strings = binary_info.get('strings', [])
        if strings:
            port_patterns = [
                r'port[:\s]*(\d+)',
                r'listen[:\s]*(\d+)',
                r':(\d{2,5})',
                r'(\d{2,5})/tcp',
                r'(\d{2,5})/udp',
            ]
            for s in strings:
                for pattern in port_patterns:
                    match = re.search(pattern, s, re.IGNORECASE)
                    if match:
                        try:
                            port = int(match.group(1))
                            if 1 <= port <= 65535:
                                return port
                        except ValueError:
                            continue
        
        return 0
    
    def _get_next_sid(self) -> int:
        """
        获取下一个规则 ID
        
        Returns:
            规则 ID
        """
        self.current_sid += 1
        return self.current_sid
    
    def _get_classtype(
        self,
        vuln_type: str,
        severity: str
    ) -> str:
        """
        根据漏洞类型获取规则分类
        
        Args:
            vuln_type: 漏洞类型
            severity: 严重程度
            
        Returns:
            分类类型
        """
        vuln_type_lower = vuln_type.lower()
        
        # 根据漏洞类型映射分类
        classtype_map = {
            'overflow': 'attempted-admin',
            'format': 'attempted-admin',
            'injection': 'attempted-admin',
            'command': 'attempted-admin',
            'sql': 'web-application-attack',
            'xss': 'web-application-attack',
            'traversal': 'attempted-recon',
            'dos': 'attempted-dos',
            'scan': 'attempted-recon',
            'info': 'misc-activity',
        }
        
        for key, classtype in classtype_map.items():
            if key in vuln_type_lower:
                return classtype
        
        # 根据严重程度
        severity_map = {
            'Critical': 'attempted-admin',
            'High': 'attempted-user',
            'Medium': 'attempted-recon',
            'Low': 'misc-activity',
        }
        
        return severity_map.get(severity, 'misc-activity')
    
    def _escape_content(self, content: str) -> str:
        """
        转义规则内容中的特殊字符
        
        Args:
            content: 原始内容
            
        Returns:
            转义后的内容
        """
        # Suricata/Snort 需要转义的字符
        escaped = content.replace('|', '|7C|')
        escaped = escaped.replace('"', '|22|')
        escaped = escaped.replace('\\', '|5C|')
        escaped = escaped.replace('\n', '|0A|')
        escaped = escaped.replace('\r', '|0D|')
        escaped = escaped.replace('\t', '|09|')
        return escaped
    
    def _build_rule_text(self, rule: IDSRuleContent) -> str:
        """
        构建 IDS 规则文本
        
        Args:
            rule: 规则内容
            
        Returns:
            规则文本
        """
        parts = []
        
        # 动作
        parts.append(rule.action)
        
        # 协议
        parts.append(rule.protocol)
        
        # 源
        parts.append(rule.source_ip)
        parts.append(rule.source_port)
        
        # 方向
        parts.append('->')
        
        # 目标
        parts.append(rule.dest_ip)
        parts.append(rule.dest_port)
        
        # 消息
        msg_escaped = rule.msg.replace('"', '\\"')
        parts.append(f'(msg:"{msg_escaped}"')
        
        # 内容匹配
        for match in rule.content_matches:
            content = match.get('content', '')
            modifiers = match.get('modifiers', [])
            
            content_escaped = content.replace('"', '\\"')
            mod_str = ''
            if modifiers:
                mod_str = ';' + ';'.join(modifiers)
            
            parts.append(f'content:"{content_escaped}"{mod_str}')
        
        # 深度和偏移
        if rule.depth:
            parts.append(f'depth:{rule.depth}')
        if rule.offset:
            parts.append(f'offset:{rule.offset}')
        
        # 分类
        parts.append(f'classtype:{rule.classtype}')
        
        # SID
        parts.append(f'sid:{rule.sid}')
        
        # 版本
        parts.append(f'rev:{rule.rev}')
        
        # 引用
        for ref in rule.reference:
            parts.append(f'reference:{ref}')
        
        # 结束
        parts.append(')')
        
        return ' '.join(parts)
    
    def generate_rules_for_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        binary_info: Dict[str, Any],
        crash_data: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        protocol_info: Dict[str, Any] = None,
        cve_mappings: Dict[str, str] = None,
        service_port: int = None
    ) -> IDSRuleResult:
        """
        为多个漏洞生成 IDS 规则
        
        Args:
            vulnerabilities: 漏洞列表
            binary_info: 二进制信息
            crash_data: 崩溃数据
            symbolic_result: 符号执行结果
            protocol_info: 协议逆向信息
            cve_mappings: CVE 映射
            service_port: 服务端口
            
        Returns:
            规则生成结果
        """
        rules = []
        warnings = []
        review_reasons = []
        
        # 检查是否为网络服务
        imports = binary_info.get('imports', {})
        if not self.is_network_service(binary_info, imports):
            warnings.append("二进制文件未检测到网络服务特征，生成的规则可能不适用")
        
        # 过滤可远程触发的漏洞
        remote_vulns = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            if self.is_remote_triggerable(vuln_type):
                remote_vulns.append(vuln)
        
        if not remote_vulns:
            warnings.append("未发现可远程触发的漏洞类型")
            return IDSRuleResult(
                success=False,
                warnings=warnings,
                needs_manual_review=True,
                review_reasons=["无可远程触发的漏洞"]
            )
        
        # 为每个漏洞生成规则
        for vuln in remote_vulns:
            vuln_type = vuln.get('type', 'unknown')
            
            # 获取 CVE ID
            cve_id = None
            if cve_mappings:
                cve_id = cve_mappings.get(vuln_type)
            
            # 提取特征
            signature = self.extract_attack_signature(
                vuln, crash_data, symbolic_result, protocol_info
            )
            
            # 检查是否有足够特征
            if not signature.get('byte_patterns') and not signature.get('content_patterns'):
                review_reasons.append(f"漏洞 {vuln_type} 缺乏具体攻击特征，需人工完善")
                # 生成通用规则框架
                rule = self._generate_generic_rule(vuln, binary_info, cve_id, service_port)
            else:
                rule = self.generate_rule(
                    vuln, binary_info, crash_data, symbolic_result,
                    protocol_info, cve_id, service_port
                )
            
            rules.append(rule)
        
        # 合并规则
        rule_text = '\n'.join(rules)
        
        result = IDSRuleResult(
            success=True,
            rule_text=rule_text,
            rule_format=self.rule_format,
            rule_count=len(rules),
            warnings=warnings,
            needs_manual_review=len(review_reasons) > 0,
            review_reasons=review_reasons
        )
        
        return result
    
    def _generate_generic_rule(
        self,
        vuln: Dict[str, Any],
        binary_info: Dict[str, Any],
        cve_id: str = None,
        service_port: int = None
    ) -> str:
        """
        生成通用规则框架（当缺乏具体特征时）
        
        Args:
            vuln: 漏洞信息
            binary_info: 二进制信息
            cve_id: CVE ID
            service_port: 服务端口
            
        Returns:
            通用规则文本
        """
        vuln_type = vuln.get('type', 'unknown')
        severity = vuln.get('severity', 'Medium')
        
        binary_name = binary_info.get('name', 'unknown')
        if not binary_name:
            binary_name = os.path.basename(binary_info.get('path', 'unknown'))
        
        # 构建基本规则
        rule_content = IDSRuleContent(
            action='alert',
            protocol='tcp',
            dest_port=str(service_port) if service_port else '$SERVICE_PORTS',
            msg=f"{binary_name} {vuln_type} vulnerability - needs manual review",
            sid=self._get_next_sid(),
            classtype=self._get_classtype(vuln_type, severity),
        )
        
        # 添加注释性内容
        rule_content.content_matches.append({
            'content': 'PLACEHOLDER',
            'modifiers': []
        })
        
        # 添加引用
        if cve_id:
            rule_content.reference.append(f"cve,{cve_id}")
        
        return self._build_rule_text(rule_content) + ' # TODO: 需人工完善具体匹配内容'
    
    def save_rules(
        self,
        rule_text: str,
        binary_name: str,
        output_path: str = None
    ) -> str:
        """
        保存 IDS 规则到文件
        
        Args:
            rule_text: 规则文本
            binary_name: 二进制名称
            output_path: 输出路径
            
        Returns:
            规则文件路径
        """
        if not output_path:
            # 根据格式确定文件扩展名
            ext = '.rules' if self.rule_format == 'suricata' else '.snort'
            output_path = os.path.join(
                self.output_dir,
                f"{binary_name}_{datetime.now().strftime('%Y%m%d')}{ext}"
            )
        
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # 添加文件头注释
            header = f"""
# IDS Rules for {binary_name}
# Generated by Deemo Binary Vulnerability Analysis Tool
# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Format: {self.rule_format}
# 
# 注意: 这些规则为自动生成，可能需要人工审核和完善
# 请根据实际流量特征调整 content、depth、offset 等参数
#

"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(rule_text)
            
            logger.info(f"IDS 规则已保存: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"保存 IDS 规则失败: {e}")
            return ""
    
    def validate_rule_syntax(self, rule_text: str) -> Tuple[bool, List[str]]:
        """
        验证规则语法（简单正则检查）
        
        Args:
            rule_text: 规则文本
            
        Returns:
            (是否有效, 错误列表)
        """
        errors = []
        
        # 检查基本结构
        if not rule_text.strip():
            errors.append("规则文本为空")
            return False, errors
        
        # 检查动作
        valid_actions = SURICATA_ACTIONS if self.rule_format == 'suricata' else SNORT_ACTIONS
        lines = rule_text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 检查动作
            first_word = line.split()[0] if line.split() else ''
            if first_word not in valid_actions:
                errors.append(f"无效的动作: {first_word}")
            
            # 检查括号闭合
            if '(' in line and ')' not in line:
                errors.append(f"括号未闭合: {line[:50]}")
            
            # 检查必需字段
            if 'msg:' not in line:
                errors.append(f"缺少 msg 字段: {line[:50]}")
            if 'sid:' not in line:
                errors.append(f"缺少 sid 字段: {line[:50]}")
            
            # 检查 content 格式
            content_matches = re.findall(r'content:"([^"]*)"', line)
            for content in content_matches:
                if len(content) < self.MIN_CONTENT_LENGTH:
                    errors.append(f"内容过短: {content}")
        
        return len(errors) == 0, errors
    
    def generate_from_analysis(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None,
        crash_data: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        protocol_info: Dict[str, Any] = None,
        cve_mappings: Dict[str, str] = None,
        auto_save: bool = True
    ) -> Dict[str, Any]:
        """
        从分析结果生成 IDS 规则
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息
            decomp_results: 反编译结果
            crash_data: 崩溃数据
            symbolic_result: 符号执行结果
            protocol_info: 协议逆向信息
            cve_mappings: CVE 映射
            auto_save: 是否自动保存
            
        Returns:
            包含规则信息的字典
        """
        # 收集漏洞
        vulnerabilities = []
        if decomp_results:
            for result in decomp_results:
                analysis = result.get('analysis', {})
                vulns = analysis.get('vulnerabilities', [])
                vulnerabilities.extend(vulns)
        
        if not vulnerabilities:
            logger.warning("未发现漏洞，无法生成 IDS 规则")
            return {
                'success': False,
                'error': 'No vulnerabilities found',
                'rule_count': 0
            }
        
        # 生成规则
        result = self.generate_rules_for_vulnerabilities(
            vulnerabilities=vulnerabilities,
            binary_info=binary_info,
            crash_data=crash_data,
            symbolic_result=symbolic_result,
            protocol_info=protocol_info,
            cve_mappings=cve_mappings
        )
        
        output = {
            'success': result.success,
            'rule_text': result.rule_text,
            'rule_format': result.rule_format,
            'rule_count': result.rule_count,
            'warnings': result.warnings,
            'needs_manual_review': result.needs_manual_review,
            'review_reasons': result.review_reasons,
            'rule_file': ''
        }
        
        # 验证语法
        is_valid, syntax_errors = self.validate_rule_syntax(result.rule_text)
        output['syntax_valid'] = is_valid
        output['syntax_errors'] = syntax_errors
        
        # 自动保存
        if auto_save and result.success:
            binary_name = os.path.basename(binary_path)
            rule_file = self.save_rules(result.rule_text, binary_name)
            output['rule_file'] = rule_file
        
        return output


def generate_ids_rules(
    binary_path: str = None,
    binary_info: Dict[str, Any] = None,
    decomp_results: List[Dict[str, Any]] = None,
    crash_data: Dict[str, Any] = None,
    symbolic_result: Dict[str, Any] = None,
    protocol_info: Dict[str, Any] = None,
    output_dir: str = None,
    rule_format: str = 'suricata',
    auto_save: bool = True,
    vulns_info: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    生成 IDS 规则的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        binary_info: 二进制信息
        decomp_results: 反编译结果
        crash_data: 崩溃数据
        symbolic_result: 符号执行结果
        protocol_info: 协议逆向信息
        output_dir: 输出目录
        rule_format: 规则格式
        auto_save: 是否自动保存
        vulns_info: 漏洞信息列表
        
    Returns:
        规则生成结果
    """
    generator = IDSRuleGenerator(
        output_dir=output_dir,
        rule_format=rule_format
    )
    
    # 如果提供了漏洞信息，使用它来生成规则
    if vulns_info and binary_info:
        all_rules = []
        for vuln_info in vulns_info:
            rules = generator.generate_rules_for_vulnerability(binary_info, vuln_info)
            all_rules.extend(rules)
        
        return {
            'success': True,
            'rules': all_rules,
            'rule_count': len(all_rules)
        }
    
    return generator.generate_from_analysis(
        binary_path=binary_path,
        binary_info=binary_info,
        decomp_results=decomp_results,
        crash_data=crash_data,
        symbolic_result=symbolic_result,
        protocol_info=protocol_info,
        auto_save=auto_save
    )