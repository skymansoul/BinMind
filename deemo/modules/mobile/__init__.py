# 2026-07-20
# mobile — mobile & embedded platform analysis

__version__ = "0.6.0"

_submodules = {
    "arm64e_analyzer": ".arm64e_analyzer",
    "cheri_analyzer": ".cheri_analyzer",
    "managed_code_analyzer": ".managed_code_analyzer",
    "mobile_analysis": ".mobile_analysis",
    "mobile_deobfuscation": ".mobile_deobfuscation",
    "mobile_ipc_analyzer": ".mobile_ipc_analyzer",
    "mobile_keystore": ".mobile_keystore",
    "mobile_manifest_analyzer": ".mobile_manifest_analyzer",
    "mobile_network_analyzer": ".mobile_network_analyzer",
    "mobile_ssl_pinning": ".mobile_ssl_pinning",
    "modern_language_analyzer": ".modern_language_analyzer",
    "objc_msg_send_resolver": ".objc_msg_send_resolver",
    "pac_bypass_analyzer": ".pac_bypass_analyzer",
    "riscv_ext_analyzer": ".riscv_ext_analyzer",
    "thumb_analyzer": ".thumb_analyzer",
    "wasi_sandbox_analyzer": ".wasi_sandbox_analyzer",
    "wasi_sandbox_escape": ".wasi_sandbox_escape",
    "wasm_analyzer": ".wasm_analyzer",
}

def __getattr__(name):
    if name in _submodules:
        import importlib
        return importlib.import_module(_submodules[name], package=__package__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_submodules.keys()) + ["__version__"]
