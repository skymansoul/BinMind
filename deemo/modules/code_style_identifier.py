import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AuthorCategory(Enum):
    INDIVIDUAL = "individual"
    CORPORATE = "corporate"
    OPEN_SOURCE = "open_source"
    MALWARE = "malware"


@dataclass
class CodeStyle:
    author_family: str
    confidence: float
    indicators: List[str]
    characteristics: Dict[str, Any]
    attribution: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'author_family': self.author_family,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'characteristics': self.characteristics,
            'attribution': self.attribution
        }


@dataclass
class StyleAnalysisResult:
    binary_path: str
    code_styles: List[CodeStyle]
    primary_author: str
    family_match: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'code_styles': [s.to_dict() for s in self.code_styles],
            'primary_author': self.primary_author,
            'family_match': self.family_match,
            'confidence': self.confidence
        }


class CodeStyleIdentifier:
    
    def __init__(self):
        self.style_patterns = {
            'Microsoft': {
                'patterns': [r'__stdcall', r'__cdecl', r'MSVC', r'_WIN32', r'WINAPI'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_msvc',
                    'exception_handling': 'seh',
                    'naming_convention': 'pascal_case'
                }
            },
            'GCC': {
                'patterns': [r'__attribute__', r'__asm__', r'GCC', r'_GLIBC'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_gcc',
                    'exception_handling': 'eh_frame',
                    'naming_convention': 'snake_case'
                }
            },
            'Apple': {
                'patterns': [r'__objc', r'_objc_', r'Foundation', r'CoreFoundation'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_clang',
                    'exception_handling': 'objc_exception',
                    'naming_convention': 'camel_case'
                }
            },
            'Google': {
                'patterns': [r'__GNUC__', r'ABSL_', r'GOOGLE_'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_clang',
                    'exception_handling': 'cxx_exceptions',
                    'naming_convention': 'snake_case'
                }
            },
            'OpenSSL': {
                'patterns': [r'SSL_', r'EVP_', r'BIO_', r'OPENSSL_'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_gcc',
                    'exception_handling': 'none',
                    'naming_convention': 'snake_case'
                }
            },
            'Linux_Kernel': {
                'patterns': [r'__init', r'EXPORT_SYMBOL', r'KERNEL_', r'struct task_struct'],
                'characteristics': {
                    'stack_frame': 'prologue_epilogue_kernel',
                    'exception_handling': 'none',
                    'naming_convention': 'snake_case'
                }
            },
            'APT': {
                'patterns': [r'APT_', r'GPG_', r'CVE_'],
                'characteristics': {
                    'stack_frame': 'custom',
                    'exception_handling': 'none',
                    'naming_convention': 'mixed'
                }
            },
            'Mirai': {
                'patterns': [r'MIRAI_', r'BOT_', r'C2_'],
                'characteristics': {
                    'stack_frame': 'minimal',
                    'exception_handling': 'none',
                    'naming_convention': 'uppercase'
                }
            }
        }
        
        self.naming_patterns = {
            'pascal_case': r'^[A-Z][a-zA-Z0-9]*$',
            'camel_case': r'^[a-z][a-zA-Z0-9]*$',
            'snake_case': r'^[a-z_][a-z0-9_]*$',
            'uppercase': r'^[A-Z_][A-Z0-9_]*$',
            'mixed': r'.*'
        }
    
    def identify(self, binary_info: Dict[str, Any]) -> StyleAnalysisResult:
        code_styles = []
        primary_author = 'unknown'
        family_match = 'unknown'
        max_confidence = 0.0
        
        strings = binary_info.get('strings', '')
        
        for author, data in self.style_patterns.items():
            confidence = self._match_author_patterns(author, data, strings)
            
            if confidence > 0.3:
                code_style = CodeStyle()
                    author_family=author,
                    confidence=confidence,
                    indicators=self._get_indicators(author, data, strings),
                    characteristics=data['characteristics'],
                    attribution=self._calculate_attribution(author, confidence)
                
                code_styles.append(code_style)
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    primary_author = author
                    family_match = author
        
        return StyleAnalysisResult(
            binary_path=binary_info.get('binary_path', ''),
            code_styles=code_styles,
            primary_author=primary_author,
            family_match=family_match,
            confidence=max_confidence)
        

    
    def _match_author_patterns(self, author: str, data: Dict[str, Any], strings: str) -> float:
        matches = 0
        
        for pattern in data['patterns']:
            if pattern.lower() in strings.lower():
                matches += 1
        
        return matches / len(data['patterns'])
    
    def _get_indicators(self, author: str, data: Dict[str, Any], strings: str) -> List[str]:
        indicators = []
        
        for pattern in data['patterns']:
            if pattern.lower() in strings.lower():
                indicators.append(pattern)
        
        return indicators
    
    def _calculate_attribution(self, author: str, confidence: float) -> Dict[str, float]:
        return {
            'author': author,
            'confidence': confidence,
            'category': self._get_author_category(author)
        }
    
    def _get_author_category(self, author: str) -> str:
        corporate_authors = ['Microsoft', 'Apple', 'Google', 'OpenSSL', 'Linux_Kernel']
        malware_families = ['APT', 'Mirai']
        
        if author in corporate_authors:
            return AuthorCategory.CORPORATE.value
        elif author in malware_families:
            return AuthorCategory.MALWARE.value
        else:
            return AuthorCategory.INDIVIDUAL.value


def identify_code_style(binary_info: Dict[str, Any]) -> StyleAnalysisResult:
    identifier = CodeStyleIdentifier()
    return identifier.identify(binary_info)