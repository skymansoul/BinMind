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
        self.rule_format = rule_format.lower()
        self.sid_start = sid_start or self.SID_START
        self.current_sid = self.sid_start
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        if self.rule_format not in ['suricata', 'snort']:
            logger.warning(f"未知的规则格式: {rule_format}，使用 suricata")
            self.rule_format = 'suricata'
        
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
        # 检查导入函数
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
        
        # 检查二进制信息中的导入
        if binary_info:
            imports_info = binary_info.get('imports', {})
            if imports_info:
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
        vuln_type: str
    ) -> bool:
        """
        判断漏洞是否可由网络远程触发
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            是否可远程触发
        """
        vuln_type_lower = vuln_type.lower().replace('-', '_').replace(' ', '_')
        
        for remote_vuln in REMOTE_TRIGGERABLE_VULNS:
            if remote_vuln in vuln_type_lower:
                return True
        
        return False
    
    def extract_attack_signature(
        self,
        vuln: Dict[str, Any],
        crash_data: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        protocol_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        从漏洞信息中提取攻击特征
        
        Args:
            vuln: 漏洞信息
            crash_data: 崩溃数据
            symbolic_result: 符号执行结果
            protocol_info: 协议逆向信息
            
        Returns:
            攻击特征字典
        """
        signature = {
            'content_patterns': [],
            'byte_patterns': [],
            'offset': 0,
            'depth': 0,
            'trigger_condition': '',
            'confidence': 0.5,
        }
        
        vuln_type = vuln.get('type', 'unknown')
        vuln_description = vuln.get('description', '')
        location = vuln.get('location', '')
        
        # 从崩溃数据提取特征
        if crash_data:
            crashing_input = crash_data.get('crashing_input')
            if crashing_input:
                if isinstance(crashing_input, bytes):
                    # 提取字节模式
                    signature['byte_patterns'].append({
                        'bytes': crashing_input[:min(len(crashing_input), self.MAX_CONTENT_LENGTH)],
                        'description': '崩溃触发输入',
                        'confidence': 0.9
                    })
                elif isinstance(crashing_input, str):
                    signature['content_patterns'].append({
                        'content': crashing_input[:min(len(crashing_input), self.MAX_CONTENT_LENGTH)],
                        'description': '崩溃触发输入',
                        'confidence': 0.9
                    })
            
            # 从崩溃地址推断偏移
            crash_address = crash_data.get('crash_address', '')
            if crash_address:
                signature['trigger_condition'] = f"触发崩溃地址: {crash_address}"
        
        # 从符号执行结果提取特征
        if symbolic_result:
            crashing_input_hex = symbolic_result.get('crashing_input_hex')
            if crashing_input_hex:
                try:
                    bytes_data = bytes.fromhex(crashing_input_hex)
                    signature['byte_patterns'].append({
                        'bytes': bytes_data[:min(len(bytes_data), self.MAX_CONTENT_LENGTH)],
                        'description': '符号执行发现的触发输入',
                        'confidence': 0.85
                    })
                except ValueError:
                    pass
            
            input_length = symbolic_result.get('input_length', 0)
            if input_length:
                signature['depth'] = input_length
        
        # 从协议逆向信息提取特征
        if protocol_info:
            fields = protocol_info.get('fields', [])
            for field_info in fields:
                field_name = field_info.get('name', '')
                field_offset = field_info.get('offset', 0)
                field_size = field_info.get('size', 0)
                
                if field_offset:
                    signature['offset'] = field_offset
                if field_size:
                    signature['depth'] = max(signature['depth'], field_offset + field_size)
        
        # 根据漏洞类型生成通用特征
        if vuln_type:
            vuln_type_lower = vuln_type.lower()
            
            # 栈溢出特征
            if 'overflow' in vuln_type_lower:
                # 检测长字符串或大量重复字符
                signature['content_patterns'].append({
                    'content': '|00|',  # 空字节填充
                    'description': '可能的缓冲区溢出填充',
                    'confidence': 0.6,
                    'modifiers': ['depth:100']
                })
                
                # 检测 NOP sled
                signature['byte_patterns'].append({
                    'bytes': bytes([0x90] * 8),  # NOP sled
                    'description': '可能的 NOP sled',
                    'confidence': 0.7
                })
            
            # 格式化字符串漏洞特征
            if 'format' in vuln_type_lower:
                format_chars = ['%s', '%n', '%x', '%p', '%d']
                for fc in format_chars:
                    signature['content_patterns'].append({
                        'content': fc,
                        'description': f'格式化字符串: {fc}',
                        'confidence': 0.8
                    })
            
            # 命令注入特征
            if 'command' in vuln_type_lower or 'injection' in vuln_type_lower:
                cmd_chars = ['; ', '| ', '`', '$(', '&&', '||', '\n']
                for cc in cmd_chars:
                    signature['content_patterns'].append({
                        'content': cc,
                        'description': f'命令注入字符: {cc}',
                        'confidence': 0.75
                    })
        
        # 计算总体置信度
        if signature['byte_patterns'] or signature['content_patterns']:
            max_conf = 0.5
            for p in signature['byte_patterns']:
                max_conf = max(max_conf, p.get('confidence', 0.5))
            for p in signature['content_patterns']:
                max_conf = max(max_conf, p.get('confidence', 0.5))
            signature['confidence'] = max_conf
        
        return signature
    
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
    binary_path: str,
    binary_info: Dict[str, Any],
    decomp_results: List[Dict[str, Any]] = None,
    crash_data: Dict[str, Any] = None,
    symbolic_result: Dict[str, Any] = None,
    protocol_info: Dict[str, Any] = None,
    output_dir: str = None,
    rule_format: str = 'suricata',
    auto_save: bool = True
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
        
    Returns:
        规则生成结果
    """
    generator = IDSRuleGenerator(
        output_dir=output_dir,
        rule_format=rule_format
    )
    
    return generator.generate_from_analysis(
        binary_path=binary_path,
        binary_info=binary_info,
        decomp_results=decomp_results,
        crash_data=crash_data,
        symbolic_result=symbolic_result,
        protocol_info=protocol_info,
        auto_save=auto_save
    )