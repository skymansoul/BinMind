import logging
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)



class SMCCategory:
    PACKER = "packer"
    JIT = "jit"
    POLYMORPHIC = "polymorphic"
    OBFUSCATION = "obfuscation"
    UNKNOWN = "unknown"
class CodePageModification:
    __slots__ = ('page_addr', 'before_hash', 'after_hash', 'protection_change', 'timestamp', 'func_triggering',)

    def __init__(self, page_addr, before_hash, after_hash, protection_change="", timestamp=0.0, func_triggering=""):
        self.page_addr = page_addr
        self.before_hash = before_hash
        self.after_hash = after_hash
        self.protection_change = protection_change
        self.timestamp = timestamp
        self.func_triggering = func_triggering

    def to_dict(self) -> Dict[str, Any]:
        return {
            'page': hex(self.page_addr),
            'before_hash': self.before_hash[:16],
            'after_hash': self.after_hash[:16],
            'protection': self.protection_change
        }


class SMCDynamicAnalyzer:
    """Self-modifying code detector: page-hash delta, API classification, risk scoring."""

    SMC_APIS = [
        'mprotect', 'VirtualProtect', 'VirtualProtectEx', 'NtProtectVirtualMemory',
        'FlushInstructionCache', 'CacheFlush', '__clear_cache',
        'sys_icache_flush', 'sync_icache'
    ]

    def __init__(self):
        self._modifications: List[CodePageModification] = []
        self._code_pages: Dict[int, bytes] = {}
        self._findings: List[Dict[str, Any]] = []

    def record_page(self, addr: int, data: bytes):
        self._code_pages[addr] = data

    def detect_modification(self, addr: int, new_data: bytes) -> Optional[CodePageModification]:
        old = self._code_pages.get(addr)
        if not old:
            return None
        if old == new_data:
            return None

        mod = CodePageModification(
            page_addr=addr,
            before_hash=hashlib.sha256(old).hexdigest(),
            after_hash=hashlib.sha256(new_data).hexdigest(),
            protection_change='RW->RWX' if old[:1] == new_data[:1] else 'modified')
        self._modifications.append(mod)
        self._code_pages[addr] = new_data
        return mod

    def classify_smc(self, api_calls: List[str]) -> SMCCategory:
        api_lower = ' '.join(c.lower() for c in api_calls)
        if any(kw in api_lower for kw in ('virtualprotect', 'mprotect')):
            if any(kw in api_lower for kw in ('malloc', 'mmap', 'alloca')):
                return SMCCategory.JIT
            return SMCCategory.PACKER
        if any(kw in api_lower for kw in ('flush', 'cache')):
            return SMCCategory.OBFUSCATION
        return SMCCategory.UNKNOWN

    def analyze(self, api_calls: Optional[List[str]] = None,
                mod_pages: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []

        if mod_pages:
            for mp in mod_pages:
                self.detect_modification(mp.get('addr', 0), mp.get('new_data', b''))

        smc_apis_found = [c for c in api_calls
                         if any(api in c.lower() for api in self.SMC_APIS)]
        category = self.classify_smc(api_calls)

        risk = 'high' if category == SMCCategory.PACKER else \
               'medium' if category in (SMCCategory.POLYMORPHIC, SMCCategory.OBFUSCATION) else \
               'low' if category == SMCCategory.JIT else 'medium'

        return {
            'success': True,
            'smc_category': category.value,
            'risk_level': risk,
            'total_modifications': len(self._modifications),
            'smc_apis_detected': smc_apis_found[:10],
            'modifications': [m.to_dict() for m in self._modifications[:20]],
            'is_smc_detected': len(self._modifications) > 0 or len(smc_apis_found) > 0
        }


def analyze_self_modifying_code(api_calls: List[str],
                                 mod_pages: Optional[List[Dict[str, Any]]] = None,
                                 **kwargs) -> Dict[str, Any]:
    analyzer = SMCDynamicAnalyzer()
    return analyzer.analyze(api_calls=api_calls, mod_pages=mod_pages)


__all__ = ["SMCDynamicAnalyzer", "CodePageModification", "SMCCategory",
           "analyze_self_modifying_code"]
