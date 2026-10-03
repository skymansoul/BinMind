# coding: utf-8
"""编译模块 — 检测编译器, 批量编译 CVE 样本, 产出编译清单."""
import os, subprocess, sys
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class BuildResult:
    sample_name: str; source_path: str; binary_path: str
    variant: str          # 'default' | 'stripped' | 'O2'
    arch: str; success: bool; error_msg: str = ''

def detect_compiler() -> Optional[str]:
    for cc in ['gcc', 'clang', 'cc']:
        try:
            subprocess.run([cc, '--version'], capture_output=True, timeout=5)
            return cc
        except (FileNotFoundError, subprocess.TimeoutExpired): continue
    return None

def compile_sample(src: str, out: str, variant: str, cc: str = 'gcc') -> BuildResult:
    name = os.path.basename(os.path.dirname(src))
    flags = ['-g'] if variant == 'default' else []
    if variant == 'O2': flags.append('-O2')
    cmd = [cc] + flags + ['-o', out, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            if variant == 'stripped':
                subprocess.run(['strip', out], capture_output=True, timeout=10)
            return BuildResult(name, src, out, variant, 'x86_64', True)
        return BuildResult(name, src, out, variant, 'x86_64', False, r.stderr[:200])
    except Exception as e:
        return BuildResult(name, src, out, variant, 'x86_64', False, str(e))

def build_all_samples(samples_dir: str, build_dir: str,
                      variants: Optional[List[str]] = None,
                      cc: str = 'gcc') -> List[BuildResult]:
    if variants is None: variants = ['default', 'stripped', 'O2']
    results = []
    os.makedirs(build_dir, exist_ok=True)
    for entry in sorted(os.listdir(samples_dir)):
        src = os.path.join(samples_dir, entry, 'vuln.c')
        if not os.path.isfile(src): continue
        for v in variants:
            out = os.path.join(build_dir, f'{entry}_{v}.elf')
            results.append(compile_sample(src, out, v, cc))
    return results

def build_summary(results: List[BuildResult]) -> dict:
    ok = sum(1 for r in results if r.success)
    return {'total': len(results), 'success': ok, 'failed': len(results)-ok,
            'by_variant': {v: sum(1 for r in results if r.variant==v and r.success)
                          for v in set(r.variant for r in results)}}
