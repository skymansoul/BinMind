import logging
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set
from enum import Enum

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    BUFFER_OVERFLOW = "buffer_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    USE_AFTER_FREE = "use_after_free"
    FORMAT_STRING = "format_string"
    INFO_LEAK = "info_leak"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INTEGER_OVERFLOW = "integer_overflow"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"


class Capability(Enum):
    """漏洞能力枚举"""
    READ_MEMORY = "read_memory"
    WRITE_MEMORY = "write_memory"
    EXECUTE_CODE = "execute_code"
    LEAK_ADDRESS = "leak_address"
    BYPASS_AUTH = "bypass_auth"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    ARBITRARY_FILE_READ = "arbitrary_file_read"
    ARBITRARY_FILE_WRITE = "arbitrary_file_write"


class TargetType(Enum):
    """目标类型枚举"""
    USERLAND = "userland"
    KERNEL = "kernel"
    WEB = "web"
    NETWORK = "network"


@dataclass
class VulnerabilityNode:
    """漏洞节点"""
    id: str
    name: str
    vuln_type: VulnerabilityType
    description: str
    address: Optional[int] = None
    severity: str = "high"
    capabilities: List[Capability] = field(default_factory=list)