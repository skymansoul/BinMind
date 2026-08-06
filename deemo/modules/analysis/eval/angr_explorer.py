# Angr 漏洞点探索脚本 — 利用符号执行找出可达的危险函数调用点
# 作为堆溢出检测的对比基线之一

import sys, time, json, os

def analyze_binary(binary_path: str) -> dict:
    """使用angr探索binary中的危险函数调用点

    返回: {detected_count, findings: [{func, addr, type}], time_ms, error}
    """
    t0 = time.perf_counter()
    result = {'tool': 'Angr', 'binary': binary_path, 'detected': False,
              'findings': [], 'time_ms': 0, 'error': ''}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        dangerous = {
            'malloc': 'heap_alloc', 'calloc': 'heap_alloc', 'realloc': 'heap_alloc',
            'memcpy': 'heap_write', 'memmove': 'heap_write', 'strcpy': 'heap_write',
            'free': 'heap_free', 'printf': 'format_string', 'sprintf': 'format_string',
            'snprintf': 'format_string', 'fprintf': 'format_string',
        }
        for func in cfg.functions.values():
            if func.name in dangerous:
                result['findings'].append({
                    'function': func.name, 'address': func.addr,
                    'type': dangerous[func.name],
                })
        result['detected'] = len(result['findings']) > 0
    except ImportError:
        result['error'] = 'angr not installed'
    except Exception as e:
        result['error'] = str(e)[:200]
    result['time_ms'] = round((time.perf_counter() - t0) * 1000, 1)
    return result

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('binary'); p.add_argument('--json', action='store_true')
    args = p.parse_args()
    r = analyze_binary(args.binary)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f'Angr: {len(r["findings"])} findings, {r["time_ms"]}ms')
        for f in r['findings']: print(f'  {f["function"]} @ 0x{f["address"]:x} [{f["type"]}]')
