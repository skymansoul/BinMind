# stub_validator.py — 桩模块完整性校验
# 验证目标 compat 模块是否可加载、核心符号是否缺失。
# 参考: Neural Decompilation (arXiv:2412.07538) 管道验证 &
#   DeBinVul (arXiv:2411.04981) 多架构完整性校验
import os as _os
import sys as _sys
import importlib.util as _iu

_STUBS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_COMPAT_DIR = _os.path.join(_os.path.dirname(_STUBS_DIR), 'core', 'compat')  # fix

# 核心符号清单 — stub 中缺失任一即视为破坏性变更
_CRITICAL = {
    'binary_format_loader':   ['BinaryFormat', 'Arch', 'BinaryLoader', 'detect_format'],
    'crypto_param_extractor': ['CryptoAlgorithm', 'KeyMaterial', 'detect_algorithm'],
    'distributed_cluster':    ['PriorityTaskQueue', 'ClusterTask', 'TaskPriority'],
    'interactive_shell':      ['BinaryState', 'ColorOutput', 'InteractiveShell'],
    'precise_vtable_recovery':['VTableInfo', 'VTableRecovery', 'VTableEntry'],
    'attack_surface':         ['AttackSurfaceType', 'AttackSurfacePoint', 'RiskLevel'],
    'malware_clustering':     ['MalwareClusterer', 'MalwareCluster'],
    'type_inferrer':          ['infer_from_api_call'],
    'binary_signing':         ['extract_pe_certificate'],
    'concolic_execution':     ['ConcolicExecutor', 'prioritize_paths'],
}

def validate_stub(stub_name: str) -> dict:
    r = {'valid': True, 'errors': [], 'warnings': [], 'stub_name': stub_name}

    sp = _os.path.join(_STUBS_DIR, f'{stub_name}.py')
    cp = _os.path.join(_COMPAT_DIR, f'{stub_name}.py')

    if not _os.path.isfile(sp):
        r['valid'] = False; r['errors'].append(f'stub missing: {stub_name}')
        return r
    if not _os.path.isfile(cp):
        r['warnings'].append(f'no compat target: {stub_name}')

    try:
        spec = _iu.spec_from_file_location(f'stubs.{stub_name}', sp)
        mod = _iu.module_from_spec(spec); spec.loader.exec_module(mod)
    except Exception:
        r['valid'] = False
        r['errors'].append(f'load: {_sys.exc_info()[1]}')
        return r

    for sym in _CRITICAL.get(stub_name, []):
        if not hasattr(mod, sym):
            r['errors'].append(f'critical missing: {sym}')
            r['valid'] = False

    r['public_symbols'] = sum(1 for k in dir(mod) if not k.startswith('_'))
    return r


def validate_all() -> list[dict]:
    out = []
    for fn in sorted(_os.listdir(_STUBS_DIR)):
        if not fn.startswith('_') and fn.endswith('.py'):
            out.append(validate_stub(fn[:-3]))
    return out
