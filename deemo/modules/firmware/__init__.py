# 2026-07-15
# 固件分析模块入口 — 懒加载所有子模块和核心类

_LAZY_IMPORTS = {
    "FirmwareImage": ".src.core", "ExtractionResult": ".src.core",
    "FirmwareType": ".src.core", "RiskLevel": ".src.core",
    "shannon_entropy": ".src.core", "detect_file_system": ".src.core",
    "detect_firmware_type": ".src.core", "parse_cortexm_vector_table": ".src.core",
    "estimate_firmware_age": ".src.core",
    "FirmwareExtractor": ".src.extractor",
    "BootloaderAuditor": ".src.analyzers", "KernelConfigAuditor": ".src.analyzers",
    "binary_hardening": ".src.analyzers",
    "ReportFormatter": ".src.reporter", "Finding": ".src.reporter",
    "SummaryStats": ".src.reporter",
    "UEFIAnalyzer": ".uefi_analyzer", "UEFIFirmwareAnalyzer": ".uefi_analyzer",
    "FSScanner": ".fs_scanner", "FlashLayoutParser": ".flash_layout",
    "EnclaveAnalyzer": ".enclave_analyzer", "TEEAalyzer": ".tee_ta_verifier",
    "SecureBootChecker": ".secure_boot_checker", "OTADiffAnalyzer": ".ota_diff_analyzer",
    "FirmwareSymbolRecoverer": ".firmware_symbol_recovery",
    "UEFIRuntimeSecurityAnalyzer": ".uefi_runtime_security_analyzer",
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        import importlib
        mod = importlib.import_module(_LAZY_IMPORTS[name], __name__)
        attr = getattr(mod, name)
        globals()[name] = attr
        return attr
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return list(_LAZY_IMPORTS.keys())
