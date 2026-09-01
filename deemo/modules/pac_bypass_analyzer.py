# 兼容入口：实现位于 hardware/pac_bypass_analyzer，此处聚合重导出。
from modules.hardware.pac_bypass_analyzer import (
    PACBypassAnalyzer,
    PACLeak,
    PACBypassPath,
    AnalysisResult,
    PACSignatureDetector,
    SignedGadgetFinder,
    create_pac_bypass_analyzer,
    PAC_OPCODES,
    AUTH_OPCODES,
)

__all__ = [
    'PACBypassAnalyzer',
    'PACLeak',
    'PACBypassPath',
    'AnalysisResult',
    'PACSignatureDetector',
    'SignedGadgetFinder',
    'create_pac_bypass_analyzer',
    'PAC_OPCODES',
    'AUTH_OPCODES',
]
