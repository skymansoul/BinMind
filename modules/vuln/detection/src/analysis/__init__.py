# — analysis子包
# 攻击面/供应链/CFI完整性/CFI违规分析

import os as _os
import sys as _sys

from deemo.modules.vuln.detection.src.analysis.attack_surface import (
    AttackSurfaceAnalyzer, AttackSurfaceType, RiskLevel,
    compute_surface_score,
)
from deemo.modules.vuln.detection.src.analysis.supply_chain import (
    ComponentFingerprint, LibraryComponent, SBOMComponent,
    match_components, generate_sbom,
)
from deemo.modules.vuln.detection.src.analysis.cfi_integrity import (
    CFIIntegrityAnalyzer, CFIResult, cfi_check,
)
from deemo.modules.vuln.detection.src.analysis.cfi_violation import (
    CFIViolationChecker, ViolationReport, scan_indirect_calls,
)

_debug = _os.environ.get("VULN_DEBUG", "") == "1"

__all__ = [
    "AttackSurfaceAnalyzer", "AttackSurfaceType", "RiskLevel",
    "compute_surface_score",
    "ComponentFingerprint", "LibraryComponent", "SBOMComponent",
    "match_components", "generate_sbom",
    "CFIIntegrityAnalyzer", "CFIResult", "cfi_check",
    "CFIViolationChecker", "ViolationReport", "scan_indirect_calls",
]
