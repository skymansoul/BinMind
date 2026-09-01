"""差分模糊测试：同一种子集分别执行两个实现，对比退出码与输出发现差异。"""

import os
import random
import subprocess
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class DifferentialFuzzer:

    def __init__(self, binary_path, mode='cross-compiler', output_dir=None,
                 reference_binary=None):
        # reference_binary 缺省时对比自身，仅探测非确定性行为
        self.binary_path = binary_path
        self.reference_binary = reference_binary or binary_path
        self.mode = mode
        self.output_dir = output_dir
        self.differences_found = []

    def run(self):
        try:
            if self.mode in ('cross-compiler', 'cross-version', 'cross-architecture'):
                return self._run_diff()
            logger.warning("未知的 fuzz 模式: %s", self.mode)
            return {'success': False, 'error': f"Unknown mode: {self.mode}"}
        except Exception as e:
            logger.error("fuzzer 异常: %s", e)
            return {'success': False, 'error': str(e)}

    def _run_diff(self):
        corpus = self._seed_corpus()
        for idx, seed in enumerate(corpus):
            a = self._run_one(self.binary_path, seed)
            b = self._run_one(self.reference_binary, seed)
            self._compare(idx, seed, a, b)
        self._generate_report()
        return {
            'success': True,
            'seeds_executed': len(corpus),
            'differences_found': len(self.differences_found),
            'differences': self.differences_found,
        }

    def _seed_corpus(self) -> List[bytes]:
        # 固定随机种子保证可复现，覆盖空/极值/边界/随机四类输入
        seeds = [b'', b'\x00' * 64, b'\xff' * 64, b'A' * 256]
        rng = random.Random(1337)
        for _ in range(8):
            seeds.append(rng.randbytes(64))
        return seeds

    def _run_one(self, path: str, data: bytes):
        """统一经 stdin 单次执行，返回 (状态, 退出码, 输出) 三元组。"""
        try:
            r = subprocess.run([path], input=data, capture_output=True,
                               stdin=subprocess.PIPE, timeout=3)
            return ('ok', r.returncode, r.stdout + r.stderr)
        except subprocess.TimeoutExpired:
            return ('timeout', None, b'')
        except (OSError, subprocess.SubprocessError) as e:
            return ('error', None, str(e).encode(errors='replace'))

    def _compare(self, idx: int, seed: bytes, a, b):
        a_ok = a[0] == 'ok' and a[1] == 0
        b_ok = b[0] == 'ok' and b[1] == 0
        seed_tag = seed[:16].hex()
        if a_ok != b_ok:
            self.differences_found.append({
                'type': 'crash_mismatch',
                'seed_index': idx,
                'seed': seed_tag,
                'description': '一侧正常退出而另一侧崩溃',
            })
        elif a_ok and b_ok and a[1] != b[1]:
            self.differences_found.append({
                'type': 'exit_code_mismatch',
                'seed_index': idx,
                'seed': seed_tag,
                'description': f'退出码不一致: {a[1]} vs {b[1]}',
            })
        elif a_ok and b_ok and a[1] == b[1] and a[2] != b[2]:
            self.differences_found.append({
                'type': 'output_mismatch',
                'seed_index': idx,
                'seed': seed_tag,
                'description': '输出不一致',
            })

    def _generate_report(self):
        if not self.output_dir:
            return
        os.makedirs(self.output_dir, exist_ok=True)
        report_path = os.path.join(self.output_dir, 'differential_report.txt')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Differential Fuzzing Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Binary: {self.binary_path}\n")
            f.write(f"Reference: {self.reference_binary}\n")
            f.write(f"Mode: {self.mode}\n")
            f.write(f"Differences Found: {len(self.differences_found)}\n\n")
            for diff in self.differences_found:
                f.write(f"- Type: {diff['type']}\n")
                f.write(f"  Seed: {diff['seed']} (index {diff['seed_index']})\n")
                f.write(f"  Description: {diff['description']}\n\n")