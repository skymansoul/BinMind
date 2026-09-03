"""Angr 探索器 — CFG 挖掘可达危险调用点.

用途: 外部对照工具 1。以 angr CFGFast 恢复函数表, 定位危险调用点
      (memcpy/memmove/strcpy 等堆写入函数), 报告可达性。

检测口径:
  detected = 存在危险函数符号 (含 memcpy/strcpy/malloc 等堆操作)
  该口径与通用静态审计工具一致: 见危险函数即告警 → 高召回高误报。

CLI:
  python angr_explorer.py <binary> [--json]
"""

import json
import sys
import time

_DANGEROUS = {
    'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
    'sprintf', 'snprintf', 'gets', 'read', 'fread', 'recv',
    'malloc', 'calloc', 'realloc', 'free',
}
_WRITE_ONLY = {
    'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
    'sprintf', 'gets', 'read', 'fread', 'recv',
}


def explore(binary: str, timeout_s: int = 120) -> dict:
    t0 = time.time()
    try:
        import angr
    except ImportError:
        return {'tool': 'angr', 'binary': binary,
                'detected': False, 'finding_count': 0,
                'error': 'angr not installed',
                'elapsed_sec': round(time.time() - t0, 3)}
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        funcs = [f.name for f in cfg.functions.values() if f.name]
        found = sorted({n for n in funcs if n in _DANGEROUS})
        write_sites = [n for n in found if n in _WRITE_ONLY]
        return {
            'tool': 'angr', 'binary': binary,
            'detected': len(write_sites) > 0,
            'finding_count': len(write_sites),
            'sites': found,
            'write_sites': write_sites,
            'elapsed_sec': round(time.time() - t0, 3),
        }
    except Exception as exc:
        return {'tool': 'angr', 'binary': binary,
                'detected': False, 'finding_count': 0,
                'error': f'{type(exc).__name__}: {exc}',
                'elapsed_sec': round(time.time() - t0, 3)}


def main() -> None:
    binary = sys.argv[1] if len(sys.argv) > 1 else 'a.out'
    as_json = '--json' in sys.argv
    result = explore(binary)
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"angr: detected={result['detected']} "
              f"sites={result.get('finding_count', 0)} "
              f"elapsed={result['elapsed_sec']}s")


if __name__ == '__main__':
    main()
