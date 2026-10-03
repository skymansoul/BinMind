#!/usr/bin/env python3
"""回归测试运行器: 编译样本→调用扫描器→收集结果。模块化: SampleCompiler/ScanScheduler/ResultCollector."""
import os, sys, json, time, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict

SAMPLES = Path(__file__).parent / "cve_samples"
RESULTS = Path(__file__).parent / "results"

@dataclass
class TestResult:
    sample: str; vuln_type: str; detected: bool
    elapsed_ms: float; error: str = ""

class SampleCompiler:
    def compile_all(self) -> List[Path]:
        binaries = []
        for d in sorted(SAMPLES.iterdir()):
            if not d.is_dir(): continue
            for f in d.iterdir():
                if f.suffix == '.exe' or '_O' in f.name:
                    binaries.append(f)
        return binaries

class ScanScheduler:
    def scan(self, binary: Path) -> dict:
        t0 = time.perf_counter()
        try:
            r = subprocess.run([sys.executable, '-m', 'binmind', str(binary)],
                capture_output=True, text=True, timeout=60, cwd=str(Path(__file__).parent.parent.parent))
            return {'ok': True, 'stdout': r.stdout+r.stderr, 'elapsed_ms': (time.perf_counter()-t0)*1000}
        except:
            return {'ok': False, 'stdout': '', 'elapsed_ms': (time.perf_counter()-t0)*1000}

class ResultCollector:
    def collect(self, results: List[dict]) -> List[TestResult]:
        out = []
        for r in results:
            detected = any(kw in (r.get('stdout','')+r.get('stderr','')).lower()
                for kw in ['vuln','overflow','uaf','format string','double free'])
            out.append(TestResult(
                sample=r.get('sample','?'), vuln_type=r.get('type','?'),
                detected=detected, elapsed_ms=r.get('elapsed_ms',0)))
        return out

def main():
    RESULTS.mkdir(exist_ok=True)
    compiler = SampleCompiler(); scheduler = ScanScheduler(); collector = ResultCollector()
    binaries = compiler.compile_all()
    print(f'Found {len(binaries)} binaries')
    raw = []
    for b in binaries[:20]:  # 限制20个样本避免超时
        r = scheduler.scan(b); r['sample'] = b.name
        parts = b.parent.name.split('_')
        r['type'] = '_'.join(parts[2:]) if len(parts)>2 else 'unknown'
        raw.append(r)
        print(f'  {b.name}: {"HIT" if any(kw in r.get("stdout","").lower() for kw in ["vuln","overflow","uaf"]) else "MISS"} ({r["elapsed_ms"]:.0f}ms)')
    results = collector.collect(raw)
    hits = sum(1 for r in results if r.detected)
    report = {'total': len(results), 'detected': hits, 'results': [{'sample': r.sample, 'type': r.vuln_type, 'detected': r.detected, 'elapsed_ms': r.elapsed_ms} for r in results]}
    json.dump(report, open(RESULTS / 'regression_report.json','w'), indent=2)
    print(f'\n{hits}/{len(results)} detected. Report: {RESULTS}/regression_report.json')

if __name__ == '__main__':
    main()
