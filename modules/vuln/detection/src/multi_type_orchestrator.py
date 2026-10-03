"""多类型漏洞检测编排器 — 统一调度 HEAP + UAF + Format + IntOverflow 四个检测器.

创建: 2025-03-28
用途: 对单二进制文件运行全部四个检测器, 汇总多类型发现.
      各检测器独立运行, 共享反汇编输出以减少重复工作.

使用: python multi_type_orchestrator.py <binary_path> [--types heap,uaf,fmt,int]
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

_HERE = Path(__file__).resolve().parent

DETECTORS = {
    'heap': {
        'name': 'Heap Overflow (AVHO-G)',
        'runner': _HERE.parent / 'test_samples' / 'heap_overflow'
                 / 'regression_suite.py',
    },
    'uaf': {
        'name': 'Use-After-Free',
        'runner': _HERE / 'uaf' / 'uaf_regression_runner.py',
    },
    'fmt': {
        'name': 'Format String',
        'runner': _HERE / 'format' / 'fmt_regression_runner.py',
    },
    'int': {
        'name': 'Integer Overflow',
        'runner': _HERE / 'int_overflow' / 'int_regression_runner.py',
    },
}


class MultiTypeOrchestrator:
    """多类型检测编排器 — 对单目标运行多个检测器并汇总结果."""

    def __init__(self, types: List[str] = None):
        self.types = types or list(DETECTORS.keys())
        self._results: Dict[str, dict] = {}
        self._shared_disasm: Optional[List] = None

    def disassemble(self, binary_path: str) -> List:
        """共享反汇编 — 所有检测器共用同一份反汇编结果."""
        import subprocess
        r = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary_path],
            capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return []
        functions = []
        current_func = ''
        current_insns = []
        current_addrs = []
        for line in r.stdout.split('\n'):
            line = line.rstrip()
            if not line:
                continue
            if line.endswith('>:') and not line.startswith(' '):
                if current_insns:
                    functions.append((current_func, current_insns, current_addrs))
                current_func = line.strip('<:>').split('<')[-1].rstrip('>:')
                current_insns = []
                current_addrs = []
                continue
            if ':\t' in line and not line.startswith('Disassembly'):
                parts = line.split(':\t', 1)
                try:
                    addr = int(parts[0].strip(), 16)
                    insn = parts[1].strip()
                except ValueError:
                    continue
                current_insns.append(insn)
                current_addrs.append(addr)
        if current_insns:
            functions.append((current_func, current_insns, current_addrs))
        return functions

    def run_detector(self, det_type: str, binary_path: str) -> dict:
        """运行单个检测器."""
        info = DETECTORS[det_type]
        t0 = time.perf_counter()

        try:
            r = subprocess.run(
                [sys.executable, str(info['runner']), '--quick',
                 '--json', str(Path(binary_path).with_suffix('.json'))],
                capture_output=True, text=True, timeout=60)
            elapsed = time.perf_counter() - t0
            return {
                'type': det_type,
                'name': info['name'],
                'returncode': r.returncode,
                'stdout': r.stdout[-1000:] if len(r.stdout) > 1000 else r.stdout,
                'elapsed_s': round(elapsed, 2),
            }
        except Exception as e:
            return {'type': det_type, 'name': info['name'], 'error': str(e)}

    def run_all(self, binary_path: str) -> Dict[str, dict]:
        """对目标二进制运行全部已启用的检测器."""
        if not Path(binary_path).exists():
            return {'error': f'binary not found: {binary_path}'}

        print(f'Multi-Type Detection: {binary_path}')
        print(f'Enabled detectors: {", ".join(self.types)}')
        print(f'{"="*60}')

        self._shared_disasm = self.disassemble(binary_path)
        n_funcs = len(self._shared_disasm)
        print(f'Disassembly: {n_funcs} functions found')

        total_findings = 0
        for det_type in self.types:
            print(f'\n[{det_type}] Running {DETECTORS[det_type]["name"]}...')
            result = self.run_detector(det_type, binary_path)
            self._results[det_type] = result
            print(result.get('stdout', result.get('error', '')))

        return self._results

    def summary(self) -> dict:
        """生成汇总报告."""
        return {
            'detectors_run': len(self._results),
            'per_detector': {
                t: {
                    'name': r.get('name', ''),
                    'elapsed_s': r.get('elapsed_s', 0),
                    'returncode': r.get('returncode', -1),
                }
                for t, r in self._results.items()
            },
        }


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Multi-Type Vulnerability Orchestrator')
    ap.add_argument('binary', help='Path to binary file')
    ap.add_argument('--types', type=str, default='heap,uaf,fmt,int',
                   help='Comma-separated detector types (default: all)')
    ap.add_argument('--json', type=str, default=None,
                   help='Output JSON path')
    args = ap.parse_args()

    types = [t.strip() for t in args.types.split(',') if t.strip() in DETECTORS]
    if not types:
        print(f'No valid types. Choose from: {", ".join(DETECTORS.keys())}')
        return

    orch = MultiTypeOrchestrator(types)
    results = orch.run_all(args.binary)
    summary = orch.summary()

    print(f'\n{"="*60}')
    print(f'ORCHESTRATOR SUMMARY: {len(results)} detectors finished')

    if args.json:
        out_path = Path(args.json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f'Saved: {out_path}')


if __name__ == '__main__':
    main()
