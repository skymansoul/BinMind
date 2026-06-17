import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    MOVED = "moved"


class SemanticChangeCategory(Enum):
    PERMISSION_CHECK = "permission_check"
    AUTHENTICATION = "authentication"
    INPUT_VALIDATION = "input_validation"
    MEMORY_MANAGEMENT = "memory_management"
    CRYPTOGRAPHY = "cryptography"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    PERFORMANCE = "performance"
    SECURITY = "security"
    OTHER = "other"


@dataclass
class FunctionSignature:
    name: str
    address: int
    parameters: List[str] = field(default_factory=list)
    return_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': hex(self.address),
            'parameters': self.parameters,
            'return_type': self.return_type
        }


@dataclass
class SemanticChange:
    function_name: str
    old_address: int
    new_address: int
    change_type: ChangeType
    category: SemanticChangeCategory
    description: str
    security_relevant: bool = False
    severity: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'old_address': hex(self.old_address),
            'new_address': hex(self.new_address),
            'change_type': self.change_type.value,
            'category': self.category.value,
            'description': self.description,
            'security_relevant': self.security_relevant,
            'severity': self.severity
        }


@dataclass
class SemanticDiffResult:
    binary_old: str
    binary_new: str
    changes: List[SemanticChange]
    security_changes: List[SemanticChange]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_old': self.binary_old,
            'binary_new': self.binary_new,
            'changes': [c.to_dict() for c in self.changes],
            'security_changes': [c.to_dict() for c in self.security_changes],
            'summary': self.summary
        }


class SemanticDiffAnalyzer:
    
    def __init__(self):
        self.security_keywords = [
            'auth', 'authenticate', 'password', 'token', 'credential',
            'permission', 'access', 'privilege', 'admin', 'root',
            'encrypt', 'decrypt', 'hash', 'crypto', 'ssl', 'tls',
            'validate', 'sanitize', 'filter', 'escape',
            'alloc', 'free', 'malloc', 'realloc', 'memcpy', 'strcpy',
            'error', 'exception', 'log', 'audit',
            'seccomp', 'sandbox', 'chroot', 'capability'
        ]
        
        self.permission_check_patterns = [
            r'check_permission',
            r'is_admin',
            r'has_access',
            r'validate_token',
            r'auth_required',
            r'privilege_check'
        ]

    def analyze(self, old_binary_info: Dict[str, Any], new_binary_info: Dict[str, Any]) -> SemanticDiffResult:
        changes = []
        
        old_functions = self._extract_functions(old_binary_info)
        new_functions = self._extract_functions(new_binary_info)
        
        changes.extend(self._find_added_functions(old_functions, new_functions

        changes.extend(self._find_removed_functions(old_functions, new_functions

        changes.extend(self._find_modified_functions(old_functions, new_functions

        
        security_changes = [c for c in changes if c.security_relevant]
        
        summary = self._generate_summary(changes, security_changes)
        
        return SemanticDiffResult(
            binary_old=old_binary_info.get('binary_path', ''),
            binary_new=new_binary_info.get('binary_path', ''),
            changes=changes,
            security_changes=security_changes,
            summary=summary)
        

    
    def _extract_functions(self, binary_info: Dict[str, Any]) -> Dict[str, FunctionSignature]:
        functions = {}
        
        for func in binary_info.get('functions', []):
            sig = FunctionSignature()
                name=func.get('name', ''),
                address=func.get('address', 0),
                parameters=func.get('parameters', []),
                return_type=func.get('return_type', '')
            
            functions[func.get('name', '')] = sig
        
        return functions
    
    def _find_added_functions(self, old_funcs: Dict[str, FunctionSignature], new_funcs: Dict[str, FunctionSignature]) -> List[SemanticChange]:
        changes = []
        
        for name, new_sig in new_funcs.items():
            if name not in old_funcs:
                category = self._classify_function(name, new_sig)
                security_relevant = self._is_security_relevant(name, new_sig)
                
                change = SemanticChange()
                    function_name=name,
                    old_address=0,
                    new_address=new_sig.address,
                    change_type=ChangeType.ADDED,
                    category=category,
                    description=f"新增函数: {name}",
                    security_relevant=security_relevant,
                    severity=self._determine_severity(category, security_relevant)
                
                changes.append(change)
        
        return changes
    
    def _find_removed_functions(self, old_funcs: Dict[str, FunctionSignature], new_funcs: Dict[str, FunctionSignature]) -> List[SemanticChange]:
        changes = []
        
        for name, old_sig in old_funcs.items():
            if name not in new_funcs:
                category = self._classify_function(name, old_sig)
                security_relevant = self._is_security_relevant(name, old_sig)
                
                change = SemanticChange()
                    function_name=name,
                    old_address=old_sig.address,
                    new_address=0,
                    change_type=ChangeType.REMOVED,
                    category=category,
                    description=f"移除函数: {name}",
                    security_relevant=security_relevant,
                    severity=self._determine_severity(category, security_relevant)
                
                changes.append(change)
        
        return changes
    
    def _find_modified_functions(self, old_funcs: Dict[str, FunctionSignature], new_funcs: Dict[str, FunctionSignature]) -> List[SemanticChange]:
        changes = []
        
        for name, old_sig in old_funcs.items():
            if name in new_funcs:
                new_sig = new_funcs[name]
                
                if self._is_modified(old_sig, new_sig):
                    category = self._classify_function(name, new_sig)
                    security_relevant = self._is_security_relevant(name, new_sig)
                    
                    description = self._generate_modification_description(old_sig, new_sig)
                    
                    change = SemanticChange()
                        function_name=name,
                        old_address=old_sig.address,
                        new_address=new_sig.address,
                        change_type=ChangeType.MODIFIED,
                        category=category,
                        description=description,
                        security_relevant=security_relevant,
                        severity=self._determine_severity(category, security_relevant)
                    
                    changes.append(change)
        
        return changes
    
    def _is_modified(self, old_sig: FunctionSignature, new_sig: FunctionSignature) -> bool:
        if old_sig.return_type != new_sig.return_type:
            return True
        
        if len(old_sig.parameters) != len(new_sig.parameters):
            return True
        
        for old_param, new_param in zip(old_sig.parameters, new_sig.parameters):
            if old_param != new_param:
                return True
        
        return False
    
    def _generate_modification_description(self, old_sig: FunctionSignature, new_sig: FunctionSignature) -> str:
        parts = []
        
        if old_sig.return_type != new_sig.return_type:
            parts.append(f"返回类型从 {old_sig.return_type} 改为 {new_sig.return_type}")
        
        if len(old_sig.parameters) != len(new_sig.parameters):
            parts.append(f"参数数量从 {len(old_sig.parameters)} 改为 {len(new_sig.parameters)}")
        
        return "; ".join(parts) if parts else "函数实现发生变化"
    
    def _classify_function(self, name: str, sig: FunctionSignature) -> SemanticChangeCategory:
        name_lower = name.lower()
        
        if any(kw in name_lower for kw in ['auth', 'authenticate', 'login', 'token', 'credential']):
            return SemanticChangeCategory.AUTHENTICATION
        
        if any(kw in name_lower for kw in ['permission', 'access', 'privilege', 'admin']):
            return SemanticChangeCategory.PERMISSION_CHECK
        
        if any(kw in name_lower for kw in ['validate', 'sanitize', 'filter', 'escape']):
            return SemanticChangeCategory.INPUT_VALIDATION
        
        if any(kw in name_lower for kw in ['malloc', 'free', 'alloc', 'realloc', 'memcpy', 'strcpy', 'heap', 'stack']):
            return SemanticChangeCategory.MEMORY_MANAGEMENT
        
        if any(kw in name_lower for kw in ['encrypt', 'decrypt', 'hash', 'crypto', 'ssl', 'tls', 'rsa', 'aes']):
            return SemanticChangeCategory.CRYPTOGRAPHY
        
        if any(kw in name_lower for kw in ['error', 'exception', 'fail', 'handle']):
            return SemanticChangeCategory.ERROR_HANDLING
        
        if any(kw in name_lower for kw in ['log', 'audit', 'trace']):
            return SemanticChangeCategory.LOGGING
        
        if any(kw in name_lower for kw in ['config', 'setting', 'option']):
            return SemanticChangeCategory.CONFIGURATION
        
        if any(kw in name_lower for kw in ['network', 'socket', 'http', 'tcp', 'udp']):
            return SemanticChangeCategory.NETWORK
        
        if any(kw in name_lower for kw in ['seccomp', 'sandbox', 'chroot', 'capability', 'secure']):
            return SemanticChangeCategory.SECURITY
        
        return SemanticChangeCategory.OTHER
    
    def _is_security_relevant(self, name: str, sig: FunctionSignature) -> bool:
        name_lower = name.lower()
        return any(kw in name_lower for kw in self.security_keywords)
    
    def _determine_severity(self, category: SemanticChangeCategory, security_relevant: bool) -> str:
        if not security_relevant:
            return "low"
        
        high_severity_categories = [
            SemanticChangeCategory.PERMISSION_CHECK,
            SemanticChangeCategory.AUTHENTICATION,
            SemanticChangeCategory.CRYPTOGRAPHY,
            SemanticChangeCategory.SECURITY
        ]
        
        if category in high_severity_categories:
            return "high"
        
        medium_severity_categories = [
            SemanticChangeCategory.INPUT_VALIDATION,
            SemanticChangeCategory.MEMORY_MANAGEMENT,
            SemanticChangeCategory.ERROR_HANDLING
        ]
        
        if category in medium_severity_categories:
            return "medium"
        
        return "low"
    
    def _generate_summary(self, changes: List[SemanticChange], security_changes: List[SemanticChange]) -> Dict[str, Any]:
        by_category = {}
        by_severity = {}
        
        for change in changes:
            cat = change.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
            
            sev = change.severity
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            'total_changes': len(changes),
            'security_changes': len(security_changes),
            'changes_by_category': by_category,
            'changes_by_severity': by_severity,
            'high_severity_changes': by_severity.get('high', 0),
            'medium_severity_changes': by_severity.get('medium', 0)
        }


def analyze_semantic_diff(old_binary: Dict[str, Any], new_binary: Dict[str, Any]) -> SemanticDiffResult:
    analyzer = SemanticDiffAnalyzer()
    return analyzer.analyze(old_binary, new_binary)))))))