# SmartContractAnalyzer — 平台插件入口，合约安全分析主流程
# Pipeline: validate → parse → detect (并行 detectors) → report

import hashlib
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, Set

from .core.models import EVMInstruction, EVMBasicBlock, VulnerabilityReport, ContractInfo
from .core.types import ContractType, VulnerabilityType, Severity
from .parser.evm_parser import EVMBytecodeParser
from .parser.wasm_parser import WASMContractParser
from .detectors.reentrancy import ReentrancyDetector
from .detectors.integer_overflow import IntegerOverflowDetector
from .detectors.unchecked_call import UncheckedCallDetector
from .detectors.tx_origin import TxOriginDetector


# 尝试导入loguru用于结构化日志
try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False


class SmartContractAnalyzer:
    """合约安全分析主入口 — 支持EVM字节码与WASM二进制。"""

    # bytecode 指纹缓存 — 避免对相同字节码重复分析
    _fingerprint_cache: Dict[str, Dict[str, Any]] = {}
    _CACHE_MAX_SIZE = 128

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or self._default_config()
        self._setup_logging()

    def _default_config(self) -> Dict[str, Any]:

        return {
            "enabled": True,
            "detect_reentrancy": True,
            "detect_overflow": True,
            "detect_unchecked_call": True,
            "detect_tx_origin": True,
            "detect_deprecated_opcode": True,
            "detect_storage_collision": True,
            "detect_gas_inefficiency": True,
            "detect_front_running": True,
            "detect_weak_randomness": True,
            "detect_pattern_signatures": True,
            "enable_cfg_analysis": True,
            "confidence_threshold": 0.5,
            "max_vulns": 100,
            "enable_caching": True,
            "severity_override": {},
        }

    def _setup_logging(self) -> None:
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        else:
            self.logger = logging.getLogger(__name__)
        self.logger.info("SmartContractAnalyzer initialized")

# Public API

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """合约安全分析 — 输入字节码(bytes)、合约类型(evm/wasm)、输出格式(json/text)。"""
        bytecode = kwargs.get("bytecode")
        contract_type = kwargs.get("contract_type", "evm")
        output_format = kwargs.get("output_format", "json")

        # Validate input
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}

        start_time = time.time()

        # Check fingerprint cache
        if self._config.get("enable_caching", True):
            fp = self._compute_fingerprint(bytecode)
            if fp in self._fingerprint_cache:
                cached = dict(self._fingerprint_cache[fp])
                cached["analysis_time"] = time.time() - start_time
                cached["from_cache"] = True
                return {"success": True, "report": cached}

        # Dispatch by contract type
        ct = contract_type.lower()
        if ct in (ContractType.EVM.value, "evm"):
            result = self._analyze_evm(bytecode)
        elif ct in (ContractType.WASM.value, "wasm"):
            result = self._analyze_wasm(bytecode)
        else:
            return {"success": False, "error": f"unsupported contract type: {contract_type}"}

        result["analysis_time"] = time.time() - start_time

        # Write cache
        if self._config.get("enable_caching", True):
            fp = self._compute_fingerprint(bytecode)
            if len(self._fingerprint_cache) >= self._CACHE_MAX_SIZE:
                oldest = next(iter(self._fingerprint_cache))
                del self._fingerprint_cache[oldest]
            self._fingerprint_cache[fp] = dict(result)

        if output_format == "json":
            return {"success": True, "report": result}
        else:
            return {"success": True, "report": self._format_text_report(result)}

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """校验输入参数。"""
        bytecode = kwargs.get("bytecode")
        if not bytecode:
            return False, "bytecode parameter is required"
        if not isinstance(bytecode, bytes):
            return False, "bytecode must be bytes"
        return True, None

    def get_metadata(self) -> Dict[str, Any]:
        """返回分析器元数据供平台插件系统使用。"""
        return {
            "name": "SmartContractAnalyzer",
            "type": "STATIC_ANALYZER",
            "version": "1.0.0",
            "description": "Smart contract bytecode security analyzer",
            "author": "BinaryAnalysisPlatform",
            "dependencies": [],
            "supported_platforms": ["any"],
        }

# EVM analysis pipeline

    def _analyze_evm(self, bytecode: bytes) -> Dict[str, Any]:
        """执行EVM分析流程：解析→检测→过滤→报告。"""
        parser = EVMBytecodeParser(bytecode)

        # Pre-build CFG if configured
        if self._config.get("enable_cfg_analysis", True):
            parser.build_cfg_edges()

        # Run all active detectors
        vulnerabilities: List[VulnerabilityReport] = []

        if self._config.get("detect_reentrancy", True):
            vulnerabilities.extend(ReentrancyDetector(parser).detect())

        if self._config.get("detect_overflow", True):
            vulnerabilities.extend(IntegerOverflowDetector(parser).detect())

        if self._config.get("detect_unchecked_call", True):
            vulnerabilities.extend(UncheckedCallDetector(parser).detect())

        if self._config.get("detect_tx_origin", True):
            vulnerabilities.extend(TxOriginDetector(parser).detect())

        # Post-processing
        vulnerabilities = self._filter_by_confidence(vulnerabilities)
        vulnerabilities = self._apply_severity_override(vulnerabilities)

        # Metadata
        selectors = parser.find_function_selectors()
        has_selfdestruct = parser.has_instruction('SELFDESTRUCT')
        has_delegatecall = parser.has_instruction('DELEGATECALL')
        has_tx_origin = parser.has_instruction('ORIGIN')

        # Compiler hints
        hints: List[str] = []
        if len(selectors) > 0:
            hints.append(f"检测到{len(selectors)}个函数选择器 — 推测为Solidity/Vyper编译")
        if has_selfdestruct:
            hints.append("包含SELFDESTRUCT — 合约可被销毁")
        if has_delegatecall:
            hints.append("包含DELEGATECALL — 可能为代理模式")
        if has_tx_origin:
            hints.append("包含ORIGIN — 可能存在tx.origin身份验证")

        return {
            "contract_type": "evm",
            "bytecode_length": len(bytecode),
            "bytecode_hash": self._compute_fingerprint(bytecode),
            "function_selectors": selectors,
            "selector_count": len(selectors),
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": sum(
                1 for v in vulnerabilities
                if v.severity in ('CRITICAL', 'HIGH')
            ),
            "medium_severity": sum(
                1 for v in vulnerabilities if v.severity == 'MEDIUM'
            ),
            "low_severity": sum(
                1 for v in vulnerabilities if v.severity == 'LOW'
            ),
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "tags": hints,
        }

# WASM analysis

    def _analyze_wasm(self, bytecode: bytes) -> Dict[str, Any]:
        """执行WASM分析：检查敏感导入。"""
        parser = WASMContractParser(bytecode)
        vulnerabilities: List[VulnerabilityReport] = []

        sensitive_imports = parser.get_sensitive_imports_detail()
        if sensitive_imports:
            import_names = ', '.join(
                f"{s['module']}.{s['name']}" for s in sensitive_imports
            )
            vulnerabilities.append(VulnerabilityReport(
                vuln_type="storage_collision",
                severity='MEDIUM',
                confidence=0.6,
                description=f"检测到敏感外部导入: {import_names}",
                location=0,
                opcode='import',
                evidence=[
                    f"{s['module']}::{s['name']} (kind={s['kind']})"
                    for s in sensitive_imports
                ]
            ))

        export_count = parser.get_exported_function_count()

        return {
            "contract_type": "wasm",
            "bytecode_length": len(bytecode),
            "bytecode_hash": self._compute_fingerprint(bytecode),
            "magic_valid": parser.magic_valid,
            "export_count": export_count,
            "import_count": len(parser.imports),
            "sensitive_import_count": len(sensitive_imports),
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": 0,
            "medium_severity": sum(
                1 for v in vulnerabilities if v.severity == 'MEDIUM'
            ),
            "low_severity": 0,
            "vulnerabilities": [self._serialize_vuln(v) for v in vulnerabilities],
            "imports": parser.imports,
            "exports": parser.exports,
            "tags": [
                f"导出函数: {export_count}",
                f"敏感导入: {len(sensitive_imports)}",
            ],
        }

# Helpers

    def _compute_fingerprint(self, bytecode: bytes) -> str:
        """字节码SHA-256哈希，用作缓存键。"""
        return hashlib.sha256(bytecode).hexdigest()

    def _filter_by_confidence(
        self, vulnerabilities: List[VulnerabilityReport]
    ) -> List[VulnerabilityReport]:
        """按置信度阈值和最大数量过滤漏洞列表。"""
        threshold = self._config.get("confidence_threshold", 0.5)
        max_vulns = self._config.get("max_vulns", 100)
        filtered = [v for v in vulnerabilities if v.confidence >= threshold]
        return filtered[:max_vulns]

    def _apply_severity_override(
        self, vulnerabilities: List[VulnerabilityReport]
    ) -> List[VulnerabilityReport]:
        """应用用户配置的严重度覆写。"""
        overrides = self._config.get("severity_override", {})
        if not overrides:
            return vulnerabilities
        for v in vulnerabilities:
            if v.vuln_type in overrides:
                v.severity = overrides[v.vuln_type]
        return vulnerabilities

    def _serialize_vuln(self, vuln: VulnerabilityReport) -> Dict[str, Any]:
        """VulnerabilityReport转JSON可序列化字典。"""
        vt = vuln.vuln_type
        type_str = vt.value if hasattr(vt, 'value') else str(vt)
        return {
            "type": type_str,
            "severity": vuln.severity,
            "confidence": vuln.confidence,
            "description": vuln.description,
            "location": hex(vuln.location),
            "opcode": vuln.opcode,
            "swc_id": vuln.swc_id,
            "recommendation": vuln.recommendation,
            "impact": vuln.impact if vuln.impact else "",
            "evidence": vuln.evidence if vuln.evidence else [],
        }

    def _format_text_report(self, report: Dict[str, Any]) -> str:
        """渲染纯文本分析报告。"""
        lines = [
            "Smart Contract Security Analysis Report",
            "=" * 50,
            f"Contract Type: {report['contract_type'].upper()}",
            f"Bytecode Hash: {report.get('bytecode_hash', 'N/A')}",
            f"Total Vulnerabilities: {report['total_vulnerabilities']}",
            f"High/Critical: {report.get('high_severity', 0)}, "
            f"Medium: {report.get('medium_severity', 0)}, "
            f"Low: {report.get('low_severity', 0)}",
            "-" * 50,
        ]

        for i, vuln in enumerate(report.get('vulnerabilities', []), 1):
            lines.append(f"  [{i}] {vuln['type']}")
            lines.append(f"      Severity: {vuln['severity']}, Confidence: {vuln['confidence']:.0%}")
            lines.append(f"      Location: {vuln['location']}, Opcode: {vuln['opcode']}")
            lines.append(f"      {vuln['description']}")
            if vuln.get('impact'):
                lines.append(f"      Impact: {vuln['impact']}")
            if vuln.get('recommendation'):
                lines.append(f"      Fix: {vuln['recommendation']}")

        tags = report.get('tags', [])
        if tags:
            lines.append("-" * 50)
            lines.append("Compiler & Structure Hints:")
            for tag in tags:
                lines.append(f"  * {tag}")

        return "\n".join(lines)
