import logging
import os
import re
import subprocess
from typing import Dict, Any, Optional, List

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class SelfModifyingCodeHandler(BaseAnalyzer):

    SMC_PATTERNS = [
        (r'mprotect\s*\(', 'mprotect_call', 'mprotect 调用 — 可能修改代码段权限'),
        (r'VirtualProtect\s*\(', 'VirtualProtect_call', 'VirtualProtect — Windows 代码段权限修改'),
        (r'mmap\s*\(.*PROT_WRITE.*PROT_EXEC', 'mmap_wx', 'mmap request W+X memory'),
        (r'\.text.*PROT_WRITE', 'text_writable', '.text 段被设为可写'),
        (r'__clear_cache|flush_icache', 'cache_flush', '指令cache刷新 — 可能跟随代码修改'),
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}
        self._disasm: str = ""
        self._smc_regions: List[Dict[str, Any]] = []
        self._wx_violations: List[Dict[str, Any]] = []

    def _load_disassembly(self, binary_path: str) -> str:
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            self._disasm = r.stdout
        except Exception as e:
            logger.debug(f"disassemblyloadfailed: {e}")
        return self._disasm

    def _detect_smc_patterns(self) -> List[Dict[str, Any]]:
        findings = []
        for pattern, pid, desc in self.SMC_PATTERNS:
            for m in re.finditer(pattern, self._disasm, re.IGNORECASE):
                line_num = self._disasm[:m.start()].count('\n') + 1
                ctx_start = max(0, m.start() - 80)
                ctx_end = min(len(self._disasm), m.end() + 80)
                findings.append({
                    'type': pid,
                    'description': desc,
                    'line': line_num,
                    'match': m.group(0)[:80],
                    'context': self._disasm[ctx_start:ctx_end].strip()[:150],
                    'severity': 'HIGH',
                })
        return findings

    def _detect_wx_violations(self, binary_path: str) -> List[Dict[str, Any]]:
        violations = []
        try:
            r = subprocess.run(
                ['readelf', '-l', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            for line in r.stdout.split('\n'):
                if 'LOAD' in line and 'RWE' in line:
                    violations.append({
                        'type': 'wx_segment',
                        'description': 'LOAD 段同时具有 RWX 权限 — 容易support SMC',
                        'detail': line.strip(),
                        'severity': 'CRITICAL',
                    })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'iSj; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            import json as _json
            sections = _json.loads(r.stdout) if r.stdout.strip() else []
            for sec in sections:
                flags = sec.get('flags', '')
                if 'w' in flags.lower() and 'x' in flags.lower():
                    violations.append({
                        'type': 'wx_section',
                        'description': f"段 {sec.get('name', '?')} 同时具有 WX 权限",
                        'name': sec.get('name', ''),
                        'address': sec.get('paddr', 0),
                        'severity': 'HIGH',
                    })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        self._wx_violations = violations
        return violations

    def _generate_flat_image(self, binary_path: str) -> Dict[str, Any]:
        flat_sections = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'iSj; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            import json as _json
            sections = _json.loads(r.stdout) if r.stdout.strip() else []
            for sec in sections:
                name = sec.get('name', '')
                flags = sec.get('flags', '')
                if 'x' in flags.lower():
                    flat_sections.append({
                        'name': name,
                        'vaddr': sec.get('vaddr', 0),
                        'size': sec.get('size', 0),
                        'original_flags': flags,
                        'note': (
                            '代码段 — 若存在 SMC 则此区域在execute期间可能被修改'
                            if 'w' in flags.lower() else '只execute段'
                        ),
                    })
        except Exception:
            logger.debug("suppressed", exc_info=True)

        has_smc = len(self._detect_smc_patterns()) > 0 or len(self._wx_violations) > 0
        return {
            'has_smc': has_smc,
            'sections': flat_sections,
            'recommendation': (
                '使用 Pin/DynamoRIO 插桩记录所有写-executeconvert, '
                '生成时间线平坦化映像'
                if has_smc else '未detected SMC feature'
            ),
        }

    def analyze(self, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        path = binary_path or kwargs.get('binary_path', '')
        if not path:
            return {"success": True, "report": {"note": "未提供binarypath"}}

        logger.info(f"正在分析自修改代码: {path}")
        self._load_disassembly(path)

        smc_patterns = self._detect_smc_patterns()
        wx_violations = self._detect_wx_violations(path)
        flat_image = self._generate_flat_image(path)

        total_findings = len(smc_patterns) + len(wx_violations)
        logger.info(
            f"SMC analysis complete: {len(smc_patterns)} SMC mode, "
            f"{len(wx_violations)} W^X 违规"
        )
        return {
            "success": True,
            "report": {
                "smc_patterns": smc_patterns,
                "wx_violations": wx_violations,
                "flat_image": flat_image,
                "total_findings": total_findings,
                "has_self_modifying_code": flat_image.get('has_smc', False),
            }
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="SelfModifyingCodeHandler",
            type=AnalyzerType.DYNAMIC_ANALYZER,
            version="1.0.0",
            description="Self-modifying code detection, W^X violation analysis, flat image generation",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"])


