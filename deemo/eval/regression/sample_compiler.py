"""
回归测试 — 样本编译模块

负责:
  - 发现所有堆溢出样本目录
  - 编译每个样本的 vuln.c → vuln.exe
  - 编译状态收集和报告
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_ROOTS = [
    os.path.join(BASE, 'tests', 'samples', 'heap_overflow'),
    os.path.join(BASE, 'tests', 'samples', 'heap_fp_reduction'),
    os.path.join(BASE, 'samples', 'cve'),
    os.path.join(BASE, 'samples', 'cve_heap_overflow'),
    os.path.join(BASE, 'samples', 'cve_gapsbv'),
    os.path.join(BASE, 'tests', 'samples', 'uaf'),
    os.path.join(BASE, 'tests', 'samples', 'format_string'),
    os.path.join(BASE, 'tests', 'samples', 'int_overflow'),
]


@dataclass
class CompileResult:
    """单个样本的编译结果."""
    sample_name: str
    sample_dir: str
    success: bool = False
    binary_path: str = ""
    source_path: str = ""
    compile_cmd: str = ""
    compile_output: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


@dataclass
class SampleManifest:
    """样本清单 — 编译后收集的元信息."""
    name: str
    directory: str
    source_path: str
    binary_path: str
    cve_id: str = ""
    has_readme: bool = False
    has_makefile: bool = False
    category: str = "heap-overflow"
    is_fp_sample: bool = False
    ground_truth: Optional[bool] = None  # True=应检出, False=应过滤, None=未知


class SampleCompiler:
    """样本编译器 — 发现并编译所有堆溢出样本."""

    _DEFAULT_CFLAGS = ['-Wall', '-O0', '-g']
    _DEFAULT_CC = 'gcc'

    def __init__(self, cc: str = "", cflags: Optional[List[str]] = None):
        self.cc = cc or self._DEFAULT_CC
        self.cflags = cflags or self._DEFAULT_CFLAGS
        self._results: List[CompileResult] = []

    def discover_samples(self) -> List[str]:
        """递归发现所有含C源码的样本目录(支持vuln.c和*.c两种命名)."""
        dirs: List[str] = []
        seen: set = set()
        for root in SAMPLE_ROOTS:
            if not os.path.isdir(root):
                continue
            for entry in Path(root).iterdir():
                if not entry.is_dir():
                    continue
                if entry.name in seen:
                    continue
                vuln_c = entry / 'vuln.c'
                if vuln_c.exists():
                    dirs.append(str(entry))
                    seen.add(entry.name)
                    continue
                c_files = list(entry.glob('*.c'))
                if c_files:
                    dirs.append(str(entry))
                    seen.add(entry.name)
        return sorted(dirs)

    def compile_one(self, sample_dir: str) -> CompileResult:
        """编译单个样本(自动发现vuln.c或首个.c文件)."""
        name = os.path.basename(sample_dir)
        result = CompileResult(
            sample_name=name,
            sample_dir=sample_dir,
        )

        src = os.path.join(sample_dir, 'vuln.c')
        if not os.path.isfile(src):
            c_files = sorted(Path(sample_dir).glob('*.c'))
            if c_files:
                src = str(c_files[0])
            else:
                result.error = 'no .c source found'
                return result
        result.source_path = src

        # 优先使用样本自带 Makefile
        makefile = os.path.join(sample_dir, 'Makefile')
        if os.path.isfile(makefile):
            return self._compile_with_make(result, sample_dir, makefile)

        # 回退: 直接 gcc
        return self._compile_direct(result, sample_dir)

    def _compile_with_make(
        self, result: CompileResult, sample_dir: str, makefile: str,
    ) -> CompileResult:
        """使用样本自带 Makefile 编译."""
        import time
        t0 = time.perf_counter()

        target = 'vuln.exe'
        cmd = f'make -C {sample_dir} -f {makefile} all'
        result.compile_cmd = cmd

        try:
            proc = subprocess.run(
                ['make', '-C', sample_dir, '-f', makefile, 'all'],
                capture_output=True, text=True, timeout=60,
                env={**os.environ, 'CFLAGS': ' '.join(self.cflags),
                     'CC': self.cc},
            )
            result.compile_output = proc.stdout + '\n' + proc.stderr
            result.elapsed_ms = (time.perf_counter() - t0) * 1000

            exe = os.path.join(sample_dir, target)
            result.binary_path = exe if os.path.isfile(exe) else ''
            result.success = os.path.isfile(exe)
            if not result.success:
                result.error = f'make failed: {proc.stderr[:200]}'
        except subprocess.TimeoutExpired:
            result.error = 'make timed out (60s)'
            result.elapsed_ms = 60000
        except FileNotFoundError:
            result.error = 'make not found — install mingw32-make or GNU make'
        except Exception as e:
            result.error = str(e)[:200]

        return result

    def _compile_direct(
        self, result: CompileResult, sample_dir: str,
    ) -> CompileResult:
        """直接 gcc 编译(自动确定输出名)."""
        import time
        t0 = time.perf_counter()

        src = result.source_path
        src_name = os.path.splitext(os.path.basename(src))[0]
        exe = os.path.join(sample_dir, f'{src_name}.exe')
        if src_name != 'vuln':
            exe = os.path.join(sample_dir, 'vuln.exe')
        cmd = [self.cc] + self.cflags + ['-o', exe, src]
        result.compile_cmd = ' '.join(cmd)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)
            result.compile_output = proc.stdout + '\n' + proc.stderr
            result.elapsed_ms = (time.perf_counter() - t0) * 1000
            result.binary_path = exe if os.path.isfile(exe) else ''
            result.success = os.path.isfile(exe)
            if not result.success:
                result.error = f'gcc failed: {proc.stderr[:200]}'
        except subprocess.TimeoutExpired:
            result.error = 'compilation timed out (60s)'
            result.elapsed_ms = 60000
        except FileNotFoundError:
            result.error = 'gcc not found'
        except Exception as e:
            result.error = str(e)[:200]

        return result

    def compile_all(self) -> List[CompileResult]:
        """编译所有发现的样本."""
        dirs = self.discover_samples()
        self._results = []
        for d in dirs:
            r = self.compile_one(d)
            self._results.append(r)
        return self._results

    def build_manifest(self) -> List[SampleManifest]:
        """从编译结果构建样本清单."""
        manifests: List[SampleManifest] = []
        for r in self._results:
            d = r.sample_dir
            name = r.sample_name
            m = SampleManifest(
                name=name,
                directory=d,
                source_path=r.source_path,
                binary_path=r.binary_path if r.success else '',
                cve_id=self._infer_cve(name),
                has_readme=os.path.isfile(os.path.join(d, 'README.md')),
                has_makefile=os.path.isfile(os.path.join(d, 'Makefile')),
                category=self._infer_category(d),
                is_fp_sample='fp_reduction' in d.lower() or name.startswith('fp_'),
                ground_truth=self._infer_ground_truth(name, d),
            )
            manifests.append(m)
        return manifests

    @staticmethod
    def _infer_cve(name: str) -> str:
        """从目录名推断CVE编号."""
        for part in name.split('-'):
            if part.upper().startswith('CVE'):
                return part.upper()
        cve_match = __import__('re').search(r'CVE[_-]\d{4}[_-]\d{4,}', name, __import__('re').IGNORECASE)
        return cve_match.group(0) if cve_match else ''

    @staticmethod
    def _infer_category(path: str) -> str:
        p = path.lower()
        if 'fp_reduction' in p or 'fp-reduction' in p:
            return 'heap-fp-reduction'
        if 'heap' in p:
            return 'heap-overflow'
        return 'unknown'

    @staticmethod
    def _infer_ground_truth(name: str, path: str) -> Optional[bool]:
        """推断样本的真实标签."""
        p = path.lower()
        # FP样本: 期望检测器判定为 SAFE
        if 'fp_reduction' in p or name.startswith('fp_'):
            return False
        # CVE样本: 期望检出
        if 'cve' in name.lower() or 'cve' in p:
            return True
        # HEAP-OVERFLOW 目录下的样本默认应检出
        if 'heap-overflow' in name.lower() or 'heap_overflow' in p:
            return True
        return None

    @property
    def results(self) -> List[CompileResult]:
        return self._results

    def summary(self) -> Dict:
        """编译汇总."""
        ok = sum(1 for r in self._results if r.success)
        fail = len(self._results) - ok
        total_time = sum(r.elapsed_ms for r in self._results)
        return {
            'total': len(self._results),
            'success': ok,
            'failed': fail,
            'total_time_ms': round(total_time, 1),
            'details': [
                {'name': r.sample_name, 'ok': r.success, 'error': r.error[:100]}
                for r in self._results
            ],
        }


__all__ = [
    'CompileResult', 'SampleManifest', 'SampleCompiler',
    'SAMPLE_ROOTS',
]


if __name__ == '__main__':
    compiler = SampleCompiler()
    results = compiler.compile_all()
    s = compiler.summary()
    print(f'Compiled: {s["success"]}/{s["total"]} ({s["failed"]} failed)')
    for d in s['details']:
        if not d['ok']:
            print(f'  FAIL: {d["name"]}: {d["error"]}')
