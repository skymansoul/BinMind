"""

UAF全量20样本基准测试 — Temporal Path + Dominator 双验证器.
"""
from __future__ import annotations

import sys, time, re, json, importlib.util, importlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).parent.parent

# 通过importlib直接加载, 避免触发 analysis/__init__.py 的级联导入
def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, str(PROJECT_ROOT / path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

# 预加载所有依赖链, 绕开 analysis/__init__.py 的缺陷导入
# 需要模块: Interval (from analysis.interval_domain → 触发 __init__.py)
# 解决: 提前把 analysis 注册为占位模块, 只包含需要的子模块
_analysis_dummy = type(sys)('analysis')
_analysis_dummy.__path__ = [str(PROJECT_ROOT / 'analysis')]
_analysis_dummy.__package__ = 'analysis'
sys.modules['analysis'] = _analysis_dummy

# 加载 interval_domain (lpvra_types 的依赖)
_intv = _load_module('analysis.interval_domain', 'analysis/interval_domain.py')
_analysis_dummy.interval_domain = _intv
_lpvra = _load_module('analysis.lpvra_types', 'analysis/lpvra_types.py')
_uaf_types = _load_module('analysis.uaf_temporal_path_types', 'analysis/uaf_temporal_path_types.py')
_uaf_temporal = _load_module('analysis.uaf_temporal_path_verifier', 'analysis/uaf_temporal_path_verifier.py')
_uaf_dominator = _load_module('analysis.uaf_dominator_verifier', 'analysis/uaf_dominator_verifier.py')

# 20 UAF样本的真值标签 (来自 samples/uaf/README.md)
UAF_TRUTH = {
    'sample_uaf_01': True,   # 基础UAF
    'sample_uaf_02': False,  # NULL置零, SAFE
    'sample_uaf_03': True,   # 别名UAF
    'sample_uaf_04': False,  # 立即复用, SAFE
    'sample_uaf_05': True,   # Double Free
    'sample_uaf_06': True,   # 条件分支UAF
    'sample_uaf_07': True,   # 循环数组UAF
    'sample_uaf_08': True,   # 跨函数UAF
    'sample_uaf_09': True,   # 全局指针UAF
    'sample_uaf_10': True,   # 结构体成员UAF
    'sample_uaf_11': True,   # 多级别名链
    'sample_uaf_12': True,   # realloc旧指针
    'sample_uaf_13': False,  # 双重指针NULL, SAFE
    'sample_uaf_14': True,   # switch-case UAF
    'sample_uaf_15': True,   # 别名未NULL UAF
    'sample_uaf_cve_16': True,   # CVE-2021-38001
    'sample_uaf_cve_17': True,   # CVE-2022-22620
    'sample_uaf_cve_18': True,   # CVE-2023-0669
    'sample_uaf_cve_19': True,   # CVE-2020-0796
    'sample_uaf_cve_20': True,   # CVE-2015-3864
}


def find_sample_file(sample_dir: Path) -> Path | None:
    """在样本目录中定位C源文件."""
    for name in ('sample.c', 'vuln.c',
                 f'{sample_dir.name}.c',
                 f'{sample_dir.name.replace("sample_", "sample_")}.c'):
        p = sample_dir / name
        if p.exists():
            return p
    # 匹配sample_uaf_XX.c
    for f in sample_dir.glob('*.c'):
        if f.name not in ('Makefile',):
            return f
    return None


def run_temporal(source: str) -> dict:
    """运行TemporalPathVerifier."""
    TemporalPathVerifier = _uaf_temporal.TemporalPathVerifier
    TemporalVerdict = _uaf_types.TemporalVerdict
    verifier = TemporalPathVerifier(max_paths=128)
    results = verifier.verify(source)
    if not results:
        return {'verdict': 'NONE', 'reason': 'no pairs', 'findings': []}
    findings = []
    worst = 'SAFE'
    for r in results:
        findings.append({
            'verdict': r.verdict.value, 'ptr': r.ptr_var,
            'free_line': r.free_line, 'use_line': r.use_line,
            'safe_paths': r.safe_paths, 'uaf_paths': r.uaf_paths,
            'total_paths': r.total_paths, 'reason': r.reason})
        if r.verdict in (TemporalVerdict.UAF, TemporalVerdict.DOUBLE_FREE):
            worst = r.verdict.value
        elif r.verdict == TemporalVerdict.UNCERTAIN and worst == 'SAFE':
            worst = 'UNCERTAIN'
    return {'verdict': worst, 'reason': findings[0]['reason'] if findings else '',
            'findings': findings}


def _find_free_use_pairs(source: str) -> list:
    """从源码中提取 (free_line, use_line, ptr_var) 三元组."""
    import re
    lines = source.splitlines()
    free_re = re.compile(r'free\s*\(\s*(\w+(?:->\w+)*)\s*\)', re.IGNORECASE)
    alias_re = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;')
    non_ptr = {'if','else','while','for','return','int','char','void','long',
               'short','float','double','size_t','sizeof','struct','typedef',
               'static','const','unsigned','signed','NULL','free','malloc',
               'calloc','realloc','printf','memset','strcpy','strcat','memcpy',
               'strlen','strcmp','exit','main','include','break','continue',
               'switch','case','default','goto'}

    # 构建别名闭包
    parent = {}
    def find(x):
        if x not in parent: parent[x] = x
        if parent[x] != x: parent[x] = find(parent[x])
        return parent[x]
    def union(a,b):
        ra,rb = find(a), find(b)
        if ra != rb: parent[ra] = rb

    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith(('if','while','for')): continue
        m = alias_re.search(s)
        if m:
            dst, src = m.group(1), m.group(2)
            if dst not in non_ptr and src not in non_ptr:
                union(dst, src)

    # 解析 frees
    frees = [(i+1, m.group(1)) for i, l in enumerate(lines)
             for m in [free_re.search(l)] if m]

    # 解析 uses (解引用/成员访问/数组访问)
    use_pat = re.compile(r'\*\s*(\w[\w]*)|(\w[\w]*)\s*->|(\w[\w]*)\s*\[')
    uses = []
    for i, l in enumerate(lines, start=1):
        for m in use_pat.finditer(l):
            v = m.group(1) or m.group(2) or m.group(3)
            if v and v not in non_ptr:
                uses.append((i, v))
        # 函数参数中的freed变量
        for word in re.findall(r'\b([a-z_]\w*)\b', l):
            if word in non_ptr: continue
            if re.search(rf'\b{re.escape(word)}\s*=', l): continue
            if re.search(rf'\b(?:free|kfree)\s*\(\s*{re.escape(word)}\s*\)', l): continue
            uses.append((i, word))

    # 匹配 free-use 对
    pairs = []
    for fl, fvar in frees:
        froot = find(fvar) if fvar in parent else fvar
        for ul, uvar in uses:
            if ul <= fl: continue
            uroot = find(uvar) if uvar in parent else uvar
            if fvar == uvar or froot == uroot:
                if not re.search(rf'\b{re.escape(fvar)}\s*=\s*(?:NULL|0|nullptr)',
                                 '\n'.join(lines[fl:ul])):
                    pairs.append((fl, ul, fvar))
    return pairs




"""
UAF全量20样本基准测试 — Temporal Path + Dominator 双验证器.
"""
# 通过importlib直接加载, 避免触发 analysis/__init__.py 的级联导入

def run_dominator(source: str) -> dict:
    """运行UAFDominatorVerifier."""
    UAFDominatorVerifier = _uaf_dominator.UAFDominatorVerifier
    pairs = _find_free_use_pairs(source)
    if not pairs:
        return {'verdict': 'NONE', 'reason': 'no free-use pairs', 'findings': []}

    verifier = UAFDominatorVerifier()
    findings = []
    worst = 'SAFE'
    for fl, ul, pv in pairs:
        r = verifier.verify(source, fl, ul, pv)
        findings.append({
            'verdict': r.verdict, 'ptr': r.ptr_var,
            'free_line': r.free_line, 'use_line': r.use_line,
            'free_dominates_use': r.free_dominates_use,
            'nullify_postdom_free': r.nullify_postdom_free,
            'guard_protected': r.guard_protected,
            'reason': r.reason})
        if r.verdict in ('CONFIRMED',):
            worst = 'UAF'
        elif r.verdict == 'UNCERTAIN' and worst == 'SAFE':
            worst = 'UNCERTAIN'
    return {'verdict': worst, 'reason': findings[0]['reason'] if findings else '',
            'findings': findings}


def is_alarm(verdict: str) -> bool:
    return verdict in ('UAF', 'DOUBLE_FREE')


def main():
    uaf_dir = PROJECT_ROOT / 'samples' / 'uaf'
    if not uaf_dir.exists():
        print(f"UAF sample dir not found: {uaf_dir}")
        return 1

    sample_dirs = sorted(
        [d for d in uaf_dir.iterdir() if d.is_dir()],
        key=lambda d: d.name)

    tp = tn = fp = fn = 0
    tp_dom = tn_dom = fp_dom = fn_dom = 0
    rows = []

    header = f"{'Sample':22s} {'Truth':6s} {'Temporal':12s} {'Dom':10s} {'Result':8s} {'DomRes':8s} {'Path':10s}"
    print(header)
    print("-" * 90)

    for sd in sample_dirs:
        sid = sd.name
        sf = find_sample_file(sd)
        if not sf:
            print(f"  SKIP {sid}: no source found")
            continue
        source = sf.read_text(encoding='utf-8', errors='replace')
        truth = UAF_TRUTH.get(sid, True)

        # Temporal Path
        t0 = time.perf_counter()
        temporal = run_temporal(source)
        t_elapsed = (time.perf_counter() - t0) * 1000

        # Dominator
        t0 = time.perf_counter()
        dom = run_dominator(source)
        d_elapsed = (time.perf_counter() - t0) * 1000

        t_verdict = temporal['verdict']
        d_verdict = dom['verdict']

        # Temporal判定 (NONE=未发现任何free→安全样本正确不告警)
        t_alarm = is_alarm(t_verdict)
        if truth:
            if t_alarm:
                tp += 1; res = 'TP'
            elif t_verdict in ('SAFE', 'NONE'):
                fn += 1; res = 'FN'
            else:
                res = 'UNC'
        else:
            if t_alarm:
                fp += 1; res = 'FP'
            elif t_verdict in ('SAFE', 'NONE'):
                tn += 1; res = 'TN'
            else:
                res = 'UNC'

        # Dominator判定
        d_alarm = is_alarm(d_verdict)
        if truth:
            if d_alarm:
                tp_dom += 1; dres = 'TP'
            elif d_verdict == 'SAFE':
                fn_dom += 1; dres = 'FN'
            else:
                dres = 'UNC'
        else:
            if d_alarm:
                fp_dom += 1; dres = 'FP'
            elif d_verdict == 'SAFE':
                tn_dom += 1; dres = 'TN'
            else:
                dres = 'UNC'

        # 取一个代表性finding的路径信息
        t_findings = temporal.get('findings', [])
        path_str = ''
        if t_findings:
            f0 = t_findings[0]
            path_str = f"{f0.get('uaf_paths',0)}/{f0.get('total_paths',0)}"

        truth_s = 'UAF' if truth else 'SAFE'
        print(f"{sid:22s} {truth_s:6s} {t_verdict:12s} {d_verdict:10s} "
              f"{res:8s} {dres:8s} {path_str:10s}")

        rows.append({
            'sample': sid, 'truth': truth, 'temporal': t_verdict,
            'dominator': d_verdict, 't_result': res, 'd_result': dres,
            't_ms': t_elapsed, 'd_ms': d_elapsed,
            't_findings': t_findings, 'd_findings': dom.get('findings', []),
        })

    # 计算指标
    def metrics(tp, tn, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return prec, rec, f1

    p_t, r_t, f1_t = metrics(tp, tn, fp, fn)
    p_d, r_d, f1_d = metrics(tp_dom, tn_dom, fp_dom, fn_dom)

    print()
    print("=" * 60)
    print("  UAF Full Benchmark — 20 Samples")
    print("=" * 60)
    print(f"  Temporal Path:  TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"                   Precision={p_t:.4f} Recall={r_t:.4f} F1={f1_t:.4f}")
    print()
    print(f"  Dominator:       TP={tp_dom} TN={tn_dom} FP={fp_dom} FN={fn_dom}")
    print(f"                   Precision={p_d:.4f} Recall={r_d:.4f} F1={f1_d:.4f}")
    print()

    # 保存详细结果
    out = PROJECT_ROOT / 'eval' / 'uaf_benchmark_results.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        'temporal': {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                     'precision': p_t, 'recall': r_t, 'f1': f1_t},
        'dominator': {'tp': tp_dom, 'tn': tn_dom, 'fp': fp_dom, 'fn': fn_dom,
                      'precision': p_d, 'recall': r_d, 'f1': f1_d},
        'samples': rows,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"  Detailed results: {out}")

    return 0 if fn == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
