import os
import json
import re
import fnmatch
from typing import Dict, Any, List, Optional, Callable, Pattern
from pathlib import Path
import logging

from config import Config

logger = logging.getLogger(__name__)


class RuleCondition:
    """
    规则条件对象
    
    Attributes:
        field: 检测字段
        operator: 操作符
        value: 匹配值
        regex: 正则表达式模式（可选）
    """
    
    def __init__(self, field: str, operator: str, value: Any, regex: bool = False):
        self.field = field
        self.operator = operator
        self.value = value
        self.regex = regex
        self._compiled_regex: Optional[Pattern] = None
        
        if regex:
            self._compiled_regex = re.compile(value)
    
    def matches(self, data: Dict[str, Any]) -> bool:
        """
        检查数据是否满足条件
        
        Args:
            data: 待检测的数据字典
        
        Returns:
            True 如果满足条件
        """
        if self.field not in data:
            return False
        
        field_value = data[self.field]
        
        if self.regex and self._compiled_regex:
            if isinstance(field_value, str):
                return bool(self._compiled_regex.search(field_value))
            elif isinstance(field_value, list):
                return any(self._compiled_regex.search(str(v)) for v in field_value if isinstance(v, str))
            return False
        
        if self.operator == 'equals':
            return field_value == self.value
        elif self.operator == 'not_equals':
            return field_value != self.value
        elif self.operator == 'contains':
            if isinstance(field_value, str):
                return self.value in field_value
            elif isinstance(field_value, list):
                return self.value in field_value
            return False
        elif self.operator == 'not_contains':
            if isinstance(field_value, str):
                return self.value not in field_value
            elif isinstance(field_value, list):
                return self.value not in field_value
            return True
        elif self.operator == 'in':
            return field_value in self.value
        elif self.operator == 'not_in':
            return field_value not in self.value
        elif self.operator == 'matches':
            if isinstance(field_value, str):
                return fnmatch.fnmatch(field_value, self.value)
            return False
        elif self.operator == 'greater_than':
            try:
                return float(field_value) > float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'less_than':
            try:
                return float(field_value) < float(self.value)
            except (ValueError, TypeError):
                return False
        elif self.operator == 'exists':
            return field_value is not None and field_value != ''
        elif self.operator == 'not_exists':
            return field_value is None or field_value == ''
        elif self.operator == 'empty':
            if isinstance(field_value, list):
                return len(field_value) == 0
            return field_value is None or field_value == ''
        elif self.operator == 'not_empty':
            if isinstance(field_value, list):
                return len(field_value) > 0
            return field_value is not None and field_value != ''
        
        return False


class RuleAction:
    """
    规则动作对象
    
    Attributes:
        action_type: 动作类型
        parameters: 动作参数
    """
    
    def __init__(self, action_type: str, parameters: Dict[str, Any]):
        self.action_type = action_type
        self.parameters = parameters
    
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行动作
        
        Args:
            context: 上下文数据
        
        Returns:
            动作执行结果
        """
        result = {
            'action_type': self.action_type,
            'parameters': self.parameters,
            'context': context
        }
        
        if self.action_type == 'report_vulnerability':
            result.update({
                'vulnerability_type': self.parameters.get('vulnerability_type', 'Unknown'),
                'severity': self.parameters.get('severity', 'Medium'),
                'description': self.parameters.get('description', ''),
                'recommendation': self.parameters.get('recommendation', '')
            })
        elif self.action_type == 'add_tag':
            result['tag'] = self.parameters.get('tag', '')
        elif self.action_type == 'set_severity':
            result['severity'] = self.parameters.get('severity', 'Medium')
        elif self.action_type == 'skip_analysis':
            result['skip'] = True
        
        return result


class VulnerabilityRule:
    """
    漏洞检测规则对象
    
    Attributes:
        id: 规则唯一标识
        name: 规则名称
        description: 规则描述
        severity: 默认严重程度
        conditions: 条件列表
        actions: 动作列表
        enabled: 是否启用
        tags: 规则标签
        min_version: 最小支持版本
        max_version: 最大支持版本
        target_languages: 目标语言列表
        target_formats: 目标二进制格式列表
    """
    
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get('id', '')
        self.name = rule_data.get('name', '')
        self.description = rule_data.get('description', '')
        self.severity = rule_data.get('severity', 'Medium')
        self.enabled = rule_data.get('enabled', True)
        self.tags = rule_data.get('tags', [])
        self.min_version = rule_data.get('min_version')
        self.max_version = rule_data.get('max_version')
        self.target_languages = rule_data.get('target_languages', ['c/c++'])
        self.target_formats = rule_data.get('target_formats', ['ELF', 'PE', 'MACH-O'])
        
        self.conditions: List[RuleCondition] = []
        self.actions: List[RuleAction] = []
        
        self._parse_conditions(rule_data.get('conditions', []))
        self._parse_actions(rule_data.get('actions', []))
    
    def _parse_conditions(self, conditions_data: List[Dict[str, Any]]):
        """
        解析条件列表
        
        Args:
            conditions_data: 条件数据列表
        """
        for cond_data in conditions_data:
            field = cond_data.get('field', '')
            operator = cond_data.get('operator', 'equals')
            value = cond_data.get('value', '')
            regex = cond_data.get('regex', False)
            
            condition = RuleCondition(field, operator, value, regex)
            self.conditions.append(condition)
    
    def _parse_actions(self, actions_data: List[Dict[str, Any]]):
        """
        解析动作列表
        
        Args:
            actions_data: 动作数据列表
        """
        for action_data in actions_data:
            action_type = action_data.get('type', '')
            parameters = action_data.get('parameters', {})
            
            action = RuleAction(action_type, parameters)
            self.actions.append(action)
    
    def matches(self, data: Dict[str, Any], binary_info: Dict[str, Any] = None) -> bool:
        """
        检查规则是否匹配数据
        
        Args:
            data: 待检测数据
            binary_info: 二进制文件信息（用于语言/格式过滤）
        
        Returns:
            True 如果规则匹配
        """
        if not self.enabled:
            return False
        
        if binary_info:
            language = binary_info.get('language', 'c/c++').lower()
            binary_format = binary_info.get('format', '')
            
            if self.target_languages and language not in [l.lower() for l in self.target_languages]:
                return False
            
            if self.target_formats and binary_format not in self.target_formats:
                return False
        
        for condition in self.conditions:
            if not condition.matches(data):
                return False
        
        return True
    
    def execute(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        执行规则动作
        
        Args:
            context: 上下文数据
        
        Returns:
            动作执行结果列表
        """
        results = []
        for action in self.actions:
            result = action.execute(context)
            result['rule_id'] = self.id
            result['rule_name'] = self.name
            results.append(result)
        
        return results


class RuleEngine:
    """
    规则引擎，负责加载和执行漏洞检测规则
    
    Attributes:
        rules_dir: 规则文件目录
        rules: 规则列表
        enabled_rules: 启用的规则列表
    """
    
    def __init__(self, rules_dir: str = None):
        """
        初始化规则引擎
        
        Args:
            rules_dir: 规则文件目录，默认为 data/rules/
        """
        self.rules_dir = rules_dir or os.path.join(Config.DATA_DIR, 'rules')
        self.rules: List[VulnerabilityRule] = []
        self.enabled_rules: List[VulnerabilityRule] = []
        self._ensure_dirs()
    
    def _ensure_dirs(self):
        """确保规则目录存在"""
        os.makedirs(self.rules_dir, exist_ok=True)
    
    def _validate_rule_file(self, file_path: str) -> bool:
        """
        验证规则文件路径
        
        Args:
            file_path: 文件路径
        
        Returns:
            True 如果路径安全
        """
        if not file_path or not isinstance(file_path, str):
            return False
        
        dangerous_patterns = [
            r'\.\.',
            r'\$\(',
            r'`',
            r'\|',
            r';',
            r'\n',
            r'\r'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, file_path):
                logger.warning(f"检测到危险路径模式: {file_path}")
                return False
        
        return True
    
    def load_rules(self) -> int:
        """
        加载所有规则文件
        
        Returns:
            加载的规则数量
        """
        self.rules = []
        self.enabled_rules = []
        
        if not os.path.exists(self.rules_dir):
            logger.info("规则目录不存在，使用内置规则")
            self._load_builtin_rules()
            return len(self.rules)
        
        for entry in os.listdir(self.rules_dir):
            if not entry.endswith('.json'):
                continue
            
            file_path = os.path.join(self.rules_dir, entry)
            
            if not self._validate_rule_file(file_path):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)
                    rule = VulnerabilityRule(rule_data)
                    self.rules.append(rule)
                    
                    if rule.enabled:
                        self.enabled_rules.append(rule)
                    
                    logger.debug(f"加载规则: {rule.id} - {rule.name}")
            except json.JSONDecodeError as e:
                logger.error(f"解析规则文件失败 {entry}: {e}")
            except Exception as e:
                logger.error(f"加载规则文件失败 {entry}: {e}")
        
        if not self.rules:
            self._load_builtin_rules()
        
        logger.info(f"共加载 {len(self.rules)} 条规则，其中 {len(self.enabled_rules)} 条已启用")
        return len(self.rules)
    
    def _load_builtin_rules(self):
        """加载内置规则"""
        builtin_rules = self._get_builtin_rules()
        
        for rule_data in builtin_rules:
            rule = VulnerabilityRule(rule_data)
            self.rules.append(rule)
            if rule.enabled:
                self.enabled_rules.append(rule)
        
        logger.debug(f"加载 {len(builtin_rules)} 条内置规则")
    
    def _get_builtin_rules(self) -> List[Dict[str, Any]]:
        """
        获取内置规则列表
        
        Returns:
            内置规则数据列表
        """
        return [
            {
                'id': 'CWE-121',
                'name': 'Stack-based Buffer Overflow',
                'description': '检测栈溢出漏洞模式',
                'severity': 'Critical',
                'enabled': True,
                'tags': ['memory', 'overflow', 'cwe-121'],
                'target_languages': ['c/c++'],
                'target_formats': ['ELF', 'PE', 'MACH-O'],
                'conditions': [
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'gets'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'strcpy'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'strcat'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'sprintf'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'vsprintf'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Stack-based Buffer Overflow',
                            'severity': 'Critical',
                            'description': '检测到使用危险的字符串操作函数，可能导致栈溢出漏洞',
                            'recommendation': '使用安全的替代函数如 strncpy, snprintf 等'
                        }
                    }
                ]
            },
            {
                'id': 'CWE-122',
                'name': 'Heap-based Buffer Overflow',
                'description': '检测堆溢出漏洞模式',
                'severity': 'Critical',
                'enabled': True,
                'tags': ['memory', 'overflow', 'cwe-122'],
                'target_languages': ['c/c++'],
                'target_formats': ['ELF', 'PE', 'MACH-O'],
                'conditions': [
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'malloc'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'memcpy'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'memmove'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Heap-based Buffer Overflow',
                            'severity': 'Critical',
                            'description': '检测到使用危险的内存操作函数，可能导致堆溢出漏洞',
                            'recommendation': '确保内存操作有正确的边界检查'
                        }
                    }
                ]
            },
            {
                'id': 'CWE-134',
                'name': 'Uncontrolled Format String',
                'description': '检测格式化字符串漏洞',
                'severity': 'High',
                'enabled': True,
                'tags': ['format-string', 'cwe-134'],
                'target_languages': ['c/c++'],
                'target_formats': ['ELF', 'PE', 'MACH-O'],
                'conditions': [
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'printf'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'fprintf'},
                    {'field': 'imports.dangerous_functions', 'operator': 'contains', 'value': 'sprintf'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Uncontrolled Format String',
                            'severity': 'High',
                            'description': '检测到使用格式化输出函数，可能存在格式化字符串漏洞',
                            'recommendation': '确保格式化字符串是常量，不来自不可信输入'
                        }
                    }
                ]
            },
            {
                'id': 'CWE-20',
                'name': 'Improper Input Validation',
                'description': '检测缺乏输入验证的模式',
                'severity': 'Medium',
                'enabled': True,
                'tags': ['input', 'validation', 'cwe-20'],
                'target_languages': ['c/c++', 'go', 'rust'],
                'target_formats': ['ELF', 'PE', 'MACH-O'],
                'conditions': [
                    {'field': 'key_strings', 'operator': 'contains', 'value': 'scanf'},
                    {'field': 'key_strings', 'operator': 'contains', 'value': 'gets'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Improper Input Validation',
                            'severity': 'Medium',
                            'description': '检测到可能缺乏输入验证的模式',
                            'recommendation': '对所有用户输入进行严格的验证和边界检查'
                        }
                    }
                ]
            },
            {
                'id': 'GO-001',
                'name': 'Go Unsafe Syscall',
                'description': '检测 Go 程序中使用危险的系统调用',
                'severity': 'High',
                'enabled': True,
                'tags': ['go', 'syscall', 'unsafe'],
                'target_languages': ['go'],
                'target_formats': ['ELF'],
                'conditions': [
                    {'field': 'imports.all_imports', 'operator': 'contains', 'value': 'syscall'},
                    {'field': 'imports.all_imports', 'operator': 'contains', 'value': 'syscall.RawSyscall'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Go Unsafe Syscall',
                            'severity': 'High',
                            'description': '检测到使用 syscall.RawSyscall，这是不安全的操作',
                            'recommendation': '考虑使用更安全的标准库替代方案'
                        }
                    }
                ]
            },
            {
                'id': 'RUST-001',
                'name': 'Rust Unsafe Code',
                'description': '检测 Rust 程序中的 unsafe 代码块',
                'severity': 'Medium',
                'enabled': True,
                'tags': ['rust', 'unsafe', 'ffi'],
                'target_languages': ['rust'],
                'target_formats': ['ELF'],
                'conditions': [
                    {'field': 'symbols', 'operator': 'contains', 'value': 'std::ptr::read'},
                    {'field': 'symbols', 'operator': 'contains', 'value': 'std::ptr::write'},
                    {'field': 'symbols', 'operator': 'contains', 'value': 'std::mem::transmute'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Rust Unsafe Code',
                            'severity': 'Medium',
                            'description': '检测到使用 unsafe Rust 函数，需要仔细审查',
                            'recommendation': '仔细审查所有 unsafe 代码，确保内存安全'
                        }
                    },
                    {'type': 'add_tag', 'parameters': {'tag': 'requires-review'}}
                ]
            },
            {
                'id': 'RUST-002',
                'name': 'Rust FFI Boundary',
                'description': '检测 Rust 程序中的 FFI 边界',
                'severity': 'High',
                'enabled': True,
                'tags': ['rust', 'ffi', 'c-interop'],
                'target_languages': ['rust'],
                'target_formats': ['ELF'],
                'conditions': [
                    {'field': 'symbols', 'operator': 'contains', 'value': 'extern "C"'},
                    {'field': 'symbols', 'operator': 'contains', 'value': 'std::ffi::CString'}
                ],
                'actions': [
                    {
                        'type': 'report_vulnerability',
                        'parameters': {
                            'vulnerability_type': 'Rust FFI Boundary',
                            'severity': 'High',
                            'description': '检测到 FFI 边界代码，这是安全风险的常见来源',
                            'recommendation': '仔细审查 FFI 接口，确保类型安全和内存安全'
                        }
                    },
                    {'type': 'add_tag', 'parameters': {'tag': 'ffi-boundary'}}
                ]
            }
        ]
    
    def evaluate(self, data: Dict[str, Any], binary_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        执行规则评估
        
        Args:
            data: 待检测数据
            binary_info: 二进制文件信息
        
        Returns:
            规则匹配结果列表
        """
        results = []
        
        for rule in self.enabled_rules:
            if rule.matches(data, binary_info):
                actions = rule.execute(data)
                results.extend(actions)
                logger.debug(f"规则匹配: {rule.id} - {rule.name}")
        
        return results
    
    def evaluate_function(self, function_data: Dict[str, Any], binary_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        评估单个函数的数据
        
        Args:
            function_data: 函数数据
            binary_info: 二进制文件信息
        
        Returns:
            规则匹配结果列表
        """
        results = []
        
        for rule in self.enabled_rules:
            if rule.matches(function_data, binary_info):
                context = {**function_data, **{'binary_info': binary_info}}
                actions = rule.execute(context)
                results.extend(actions)
        
        return results
    
    def get_rule_by_id(self, rule_id: str) -> Optional[VulnerabilityRule]:
        """
        根据 ID 获取规则
        
        Args:
            rule_id: 规则 ID
        
        Returns:
            VulnerabilityRule 对象，如果未找到返回 None
        """
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None
    
    def enable_rule(self, rule_id: str) -> bool:
        """
        启用规则
        
        Args:
            rule_id: 规则 ID
        
        Returns:
            True 如果成功启用
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = True
            if rule not in self.enabled_rules:
                self.enabled_rules.append(rule)
            logger.info(f"启用规则: {rule_id}")
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """
        禁用规则
        
        Args:
            rule_id: 规则 ID
        
        Returns:
            True 如果成功禁用
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = False
            if rule in self.enabled_rules:
                self.enabled_rules.remove(rule)
            logger.info(f"禁用规则: {rule_id}")
            return True
        return False
    
    def save_rule(self, rule_data: Dict[str, Any]) -> bool:
        """
        保存规则到文件
        
        Args:
            rule_data: 规则数据
        
        Returns:
            True 如果保存成功
        """
        rule_id = rule_data.get('id')
        if not rule_id:
            logger.error("规则必须包含 ID")
            return False
        
        file_path = os.path.join(self.rules_dir, f"{rule_id}.json")
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(rule_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"保存规则: {rule_id}")
            self.load_rules()
            return True
        except Exception as e:
            logger.error(f"保存规则失败: {e}")
            return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """
        删除规则文件
        
        Args:
            rule_id: 规则 ID
        
        Returns:
            True 如果删除成功
        """
        file_path = os.path.join(self.rules_dir, f"{rule_id}.json")
        
        if not os.path.exists(file_path):
            logger.warning(f"规则文件不存在: {rule_id}")
            return False
        
        try:
            os.remove(file_path)
            logger.info(f"删除规则: {rule_id}")
            self.load_rules()
            return True
        except Exception as e:
            logger.error(f"删除规则失败: {e}")
            return False


# 全局规则引擎实例
_rule_engine = None

def get_rule_engine() -> RuleEngine:
    """
    获取全局规则引擎实例
    
    Returns:
        RuleEngine 实例
    """
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
        _rule_engine.load_rules()
    return _rule_engine