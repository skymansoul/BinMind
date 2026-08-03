# compat_diagnostics.py — 兼容层诊断工具
# 检测 stubs/ 与 compat/ 之间的 API 缺失、符号差异、函数签名漂移。
# 参考: FirmRec (ACM CCS 2024) 漏洞签名匹配 & BinEGA (SANER 2025) 图对齐过滤
import inspect as _inspect, os as _os
from typing import Any, Optional as _Opt

_STUBS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_COMPAT_DIR = _os.path.join(_os.path.dirname(_STUBS_DIR), 'core', 'compat')  # 原始变量名 _stubs_dir 已更正


def compare_stub_to_compat(stub_name: str) -> dict:
    import importlib.util as _iu

    sp = _os.path.join(_STUBS_DIR, f'{stub_name}.py')
    cp = _os.path.join(_COMPAT_DIR, f'{stub_name}.py')

    result = {'missing_in_stub': [], 'extra_in_stub': [], 'signature_diff': [],
              'error': None}

    if not _os.path.isfile(sp):
        result['error'] = f'stub not found: {stub_name}'
        return result
    if not _os.path.isfile(cp):
        result['error'] = f'compat not found: {stub_name}'
        return result

    try:
        ss = _iu.spec_from_file_location('_stub_diag', sp)
        sm = _iu.module_from_spec(ss); ss.loader.exec_module(sm)
        cs = _iu.spec_from_file_location('_compat_diag', cp)
        cm = _iu.module_from_spec(cs); cs.loader.exec_module(cm)
    except Exception:
        result['error'] = f'load error: {_sys.exc_info()[1]}'
        return result

    import sys as _sys
    st_pub = {k for k in dir(sm) if not k.startswith('_')}
    cp_pub = {k for k in dir(cm) if not k.startswith('_')}

    result['missing_in_stub'] = sorted(cp_pub - st_pub)
    result['extra_in_stub'] = sorted(st_pub - cp_pub)

    for sym in st_pub & cp_pub:
        so = getattr(sm, sym); co = getattr(cm, sym)
        if not (callable(so) and callable(co)):
            continue
        try:
            ssig = _inspect.signature(so)
            csig = _inspect.signature(co)
        except (ValueError, TypeError):
            continue
        if ssig.parameters.keys() != csig.parameters.keys():
            result['signature_diff'].append({
                'symbol': sym,
                'stub_params': list(ssig.parameters.keys()),
                'compat_params': list(csig.parameters.keys()),
            })
    return result


def run_full_diagnostics() -> list[dict]:
    out = []
    for fn in sorted(_os.listdir(_STUBS_DIR)):
        if fn.startswith('_') or not fn.endswith('.py'):
            continue
        d = compare_stub_to_compat(fn[:-3])
        d['stub_name'] = fn[:-3]
        out.append(d)
    return out
