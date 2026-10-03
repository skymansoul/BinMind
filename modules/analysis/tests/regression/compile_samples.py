"""CVE 样本自动编译模块 - 编译已知漏洞样本为 ELF, 生成 Ground Truth 清单

根据 samples/ 目录下的 C 源码, 使用可配置的编译器/优化级别编译
输出: build/ 目录下的 ELF + manifest.json (包含 CVE编号/漏洞类型/触发条件)
"""

import os, sys, json, subprocess, shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

SAMPLE_ROOT = Path(__file__).parent / 'samples'
BUILD_ROOT = Path(__file__).parent / 'build'

@dataclass
class SampleManifest:
    cve_id: str
    vuln_type: str                  # heap_overflow | uaf | format_string | stack_overflow
    source_dir: str
    binary_path: str = ''
    compiler: str = 'gcc'
    opt_level: str = 'O0'
    compiled: bool = False
    compile_error: str = ''

_SAMPLES = [
    {'dir': 'cve_2021_3156_sudo_heap_overflow', 'cve': 'CVE-2021-3156',
     'type': 'heap_overflow', 'desc': 'Sudo Baron Samedit heap overflow'},
]

def detect_compilers() -> Dict[str, str]:
    """检测系统可用的编译器"""
    available = {}
    for cc in ['gcc', 'clang']:
        path = shutil.which(cc)
        if path:
            available[cc] = path
    return available

def compile_sample(sample_dir: Path, cc: str, opt: str) -> SampleManifest:
    cve_meta = None
    for s in _SAMPLES:
        if s['dir'] == sample_dir.name:
            cve_meta = s; break
    if cve_meta is None:
        return SampleManifest('unknown', 'unknown', str(sample_dir))

    src_files = list(sample_dir.glob('*.c'))
    if not src_files:
        return SampleManifest(cve_meta['cve'], cve_meta['type'],
                              str(sample_dir), '', cc, opt, False, 'no .c files')

    out_dir = BUILD_ROOT / f'{sample_dir.name}_{cc}_{opt}'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_bin = out_dir / 'vuln'
    src = src_files[0]

    cmd = [cc, f'-{opt}', '-o', str(out_bin), str(src), '-no-pie', '-fno-stack-protector', '-w']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        ok = r.returncode == 0
        return SampleManifest(
            cve_id=cve_meta['cve'], vuln_type=cve_meta['type'],
            source_dir=str(sample_dir), binary_path=str(out_bin) if ok else '',
            compiler=cc, opt_level=opt, compiled=ok,
            compile_error=r.stderr[:200] if not ok else '',
        )
    except Exception as e:
        return SampleManifest(cve_meta['cve'], cve_meta['type'],
                              str(sample_dir), '', cc, opt, False, str(e)[:200])

def compile_all() -> List[SampleManifest]:
    compilers = detect_compilers()
    if not compilers:
        print('No compiler found (gcc/clang). Install one to compile samples.')
        return []
    results = []
    for sample_dir in sorted(SAMPLE_ROOT.iterdir()):
        if not sample_dir.is_dir():
            continue
        for cc in compilers:
            for opt in ['O0', 'O2']:
                m = compile_sample(sample_dir, cc, opt)
                results.append(m)
                status = 'OK' if m.compiled else f'FAIL: {m.compile_error[:60]}'
                print(f'  [{cc}-{opt}] {m.cve_id}: {status}')
    manifest_path = BUILD_ROOT / 'manifest.json'
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, 'w') as f:
        json.dump([{
            'cve': m.cve_id, 'type': m.vuln_type, 'binary': m.binary_path,
            'compiler': m.compiler, 'opt': m.opt_level, 'compiled': m.compiled,
            'error': m.compile_error,
        } for m in results], f, indent=2)
    print(f'Manifest written to {manifest_path}')
    return results

if __name__ == '__main__':
    compile_all()
