# 2026-07-20
# 懒加载代理 —— 按需导入，减少启动时间

import importlib

_MODULE_MAP = {
    # 核心反混淆引擎
    'mba_deobfuscator': '.mba_deobfuscator',
    'symbolic_executor': '.symbolic_executor',
    'emulation_tracer': '.emulation_tracer',
    'pattern_rule_engine': '.pattern_rule_engine',
    'vm_unvirtualizer': '.vm_unvirtualizer',
    # 通用反混淆
    'anti_analysis': '.anti_analysis',
    'anti_vm_bypass': '.anti_vm_bypass',
    'deobf_strategy_selector': '.deobf_strategy_selector',
    'deobfuscator': '.deobfuscator',
    'string_decoder': '.string_decoder',
    'string_unobfuscator': '.string_unobfuscator',
    'unpacker': '.unpacker',
    # 嵌入/脚本提取
    'embedded_script_extractor': '.embedded_script_extractor',
    'embedded_vm_identifier': '.embedded_vm_identifier',
    'nlp_string_decoder': '.nlp_string_decoder',
    'pyinstaller_unpacker': '.pyinstaller_unpacker',
    'repack_detector': '.repack_detector',
}

_CACHED = {}

def __getattr__(name: str):
    if name in _CACHED:
        return _CACHED[name]
    if name not in _MODULE_MAP:
        raise AttributeError(f"module 'deobfuscation' has no attribute '{name}'")
    mod = importlib.import_module(_MODULE_MAP[name], __package__ or 'modules.deobfuscation')
    _CACHED[name] = mod
    return mod

__all__ = list(_MODULE_MAP.keys())
