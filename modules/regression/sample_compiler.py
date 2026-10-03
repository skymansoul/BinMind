"""
回归测试 — 样本编译模块.

负责: 发现 round2/samples/heap_overflow 下所有样本目录,
编译 vuln.c → vuln.exe, 并反汇编生成 .asm 供扫描调度模块
使用. 编译失败不影响其他样本.

约束: 本模块只编译, 不做检测判定; 检测由 scan_scheduler
负责, 保证单一职责与可复用性.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

BASE = Path(__file__).resolve().parent.parent
SAMPLE_ROOT = BASE / 'samples' / 'heap_overflow'


@dataclass
class CompileResult:
    sample: str
    ok: bool
    binary: str = ''
    asm: str = ''
    error: str = ''


class SampleCompiler:
    """发现并编译样本, 输出二进制与反汇编文本."""

    def __init__(self, cc: str = 'gcc',
                 cflags: Optional[List[str]] = None):
        self.cc = cc
        # 默认 -O0: -O2 会常量折叠样本中的 memcpy/malloc 参数,
        # 使漏洞语义在二进制层面消失, 破坏检测基准的公平性.
        self.cflags = cflags or ['-O0', '-fno-stack-protector', '-fno-pie']

    def discover(self) -> List[str]:
        dirs = []
        for entry in sorted(SAMPLE_ROOT.iterdir()):
            if entry.is_dir() and (entry / 'vuln.c').exists():
                dirs.append(str(entry))
        return dirs

    def compile_one(self, sample_dir: str) -> CompileResult:
        d = Path(sample_dir)
        name = d.name
        src = d / 'vuln.c'
        exe = d / 'vuln.exe'
        asm = d / 'vuln.asm'
        if not src.exists():
            return CompileResult(name, False, error='no vuln.c')
        cmd = [self.cc] + self.cflags + ['-o', str(exe), str(src)]
        import locale
        env = dict(os.environ)
        env.setdefault('LANG', 'C.UTF-8')
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=120, env=env,
                              encoding='utf-8', errors='replace')
        if proc.returncode != 0:
            return CompileResult(name, False, error=proc.stderr[:500])
        # 反汇编: 供调度模块扫描 (objdump 缺失时降级为空文本)
        dis = subprocess.run(
            ['objdump', '-d', '-M', 'intel', str(exe)],
            capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace')
        asm.write_text(dis.stdout if dis.returncode == 0 else '',
                       encoding='utf-8', errors='replace')
        return CompileResult(name, True, binary=str(exe), asm=str(asm))

    def compile_all(self) -> List[CompileResult]:
        results = []
        for d in self.discover():
            results.append(self.compile_one(d))
        return results


def compile_and_summarize() -> Dict:
    """一键编译并返回摘要 (供 run_regression 与外部调用)."""
    c = SampleCompiler()
    results = c.compile_all()
    ok = [r for r in results if r.ok]
    return {
        'total': len(results),
        'ok': len(ok),
        'failed': [r.sample for r in results if not r.ok],
        'samples': [r.sample for r in ok],
        'asm_files': [r.asm for r in ok if r.asm],
    }
