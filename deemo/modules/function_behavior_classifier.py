import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BehaviorCategory(Enum):
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASHING = "hashing"
    NETWORK = "network"
    FILE_OPERATION = "file_operation"
    MEMORY_OPERATION = "memory_operation"
    SYSTEM_CALL = "system_call"
    STRING_MANIPULATION = "string_manipulation"
    ARITHMETIC = "arithmetic"
    CONTROL_FLOW = "control_flow"
    OTHER = "other"


@dataclass
class FunctionBehavior:
    function_name: str
    address: int
    category: BehaviorCategory
    confidence: float
    evidence: List[str]
    subcategories: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'address': hex(self.address),
            'category': self.category.value,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'subcategories': self.subcategories
        }


@dataclass
class ClassificationResult:
    functions: List[FunctionBehavior]
    category_counts: Dict[str, int]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'functions': [f.to_dict() for f in self.functions],
            'category_counts': self.category_counts,
            'summary': self.summary
        }


class FunctionBehaviorClassifier:
    
    def __init__(self):
        self.behavior_patterns = {
            BehaviorCategory.ENCRYPTION: [
                r'AES', r'DES', r'3DES', r'RSA', r'blowfish', r'cast',
                r'encrypt', r'encode', r'cipher', r'crypto', r'key'
            ],
            BehaviorCategory.DECRYPTION: [
                r'decrypt', r'decode', r'unpack', r'cipher', r'crypto'
            ],
            BehaviorCategory.HASHING: [
                r'MD5', r'SHA', r'MD4', r'CRC', r'checksum', r'hash',
                r'MD2', r'ripemd', r'whirlpool'
            ],
            BehaviorCategory.NETWORK: [
                r'socket', r'connect', r'binding', r'listen', r'accept',
                r'send', r'recv', r'http', r'tcp', r'udp', r'ip'
            ],
            BehaviorCategory.FILE_OPERATION: [
                r'open', r'close', r'read', r'write', r'stat', r'lseek',
                r'fopen', r'fclose', r'fread', r'fwrite', r'readfile'
            ],
            BehaviorCategory.MEMORY_OPERATION: [
                r'malloc', r'free', r'realloc', r'calloc', r'memcpy',
                r'memset', r'memmove', r'strcpy', r'heap', r'stack'
            ],
            BehaviorCategory.SYSTEM_CALL: [
                r'syscall', r'exec', r'fork', r'clone', r'exit',
                r'wait', r'signal', r'kill'
            ],
            BehaviorCategory.STRING_MANIPULATION: [
                r'strlen', r'strcpy', r'strcat', r'strcmp', r'strstr',
                r'sprintf', r'vsprintf', r'snprintf', r'to_string'
            ],
            BehaviorCategory.ARITHMETIC: [
                r'add', r'sub', r'mul', r'div', r'mod', r'pow',
                r'sqrt', r'sin', r'cos', r'log', r'exp'
            ],
            BehaviorCategory.CONTROL_FLOW: [
                r'jmp', r'call', r'ret', r'branch', r'loop', r'if', r'while'
            ]
        }
    
    def classify(self, binary_info: Dict[str, Any]) -> ClassificationResult:
        functions = []
        category_counts = {cat.value: 0 for cat in BehaviorCategory}
        
        for func in binary_info.get('functions', []):
            name = func.get('name', '')
            address = func.get('address', 0)
            
            category, confidence, evidence = self._classify_function(name)
            
            if category != BehaviorCategory.OTHER:
                behavior = FunctionBehavior()
                    function_name=name,
                    address=address,
                    category=category,
                    confidence=confidence,
                    evidence=evidence,
                    subcategories=self._get_subcategories(category, name)
                
                functions.append(behavior)
                category_counts[category.value] += 1
        
        summary = {
            'total_functions': len(binary_info.get('functions', [])),
            'classified_functions': len(functions),
            'unclassified_functions': len(binary_info.get('functions', [])) - len(functions)
        }
        
        return ClassificationResult(
            functions=functions,
            category_counts=category_counts,
            summary=summary)
        

    
    def _classify_function(self, func_name: str) -> tuple:
        name_lower = func_name.lower()
        best_category = BehaviorCategory.OTHER
        best_confidence = 0.0
        evidence = []
        
        for category, patterns in self.behavior_patterns.items():
            matches = 0
            found_patterns = []
            
            for pattern in patterns:
                if pattern.lower() in name_lower:
                    matches += 1
                    found_patterns.append(pattern)
            
            if matches > 0:
                confidence = matches / len(patterns)
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_category = category
                    evidence = found_patterns
        
        return best_category, best_confidence, evidence
    
    def _get_subcategories(self, category: BehaviorCategory, func_name: str) -> List[str]:
        subcategories = []
        
        if category == BehaviorCategory.ENCRYPTION:
            if 'AES' in func_name:
                subcategories.append('AES')
            if 'RSA' in func_name:
                subcategories.append('RSA')
            if 'DES' in func_name:
                subcategories.append('DES')
        
        elif category == BehaviorCategory.HASHING:
            if 'MD5' in func_name:
                subcategories.append('MD5')
            if 'SHA' in func_name:
                subcategories.append('SHA')
        
        elif category == BehaviorCategory.NETWORK:
            if 'tcp' in func_name.lower():
                subcategories.append('TCP')
            if 'udp' in func_name.lower():
                subcategories.append('UDP')
            if 'http' in func_name.lower():
                subcategories.append('HTTP')
        
        elif category == BehaviorCategory.FILE_OPERATION:
            if 'read' in func_name.lower():
                subcategories.append('read')
            if 'write' in func_name.lower():
                subcategories.append('write')
        
        return subcategories


def classify_function_behavior(binary_info: Dict[str, Any]) -> ClassificationResult:
    classifier = FunctionBehaviorClassifier()
    return classifier.classify(binary_info)