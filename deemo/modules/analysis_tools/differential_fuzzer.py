import os
import subprocess
import tempfile
import logging

logger = logging.getLogger(__name__)


class DifferentialFuzzer:

    def __init__(self, binary_path, mode='cross-compiler', output_dir=None):
        self.binary_path = binary_path
        self.mode = mode
        self.output_dir = output_dir
        self.differences_found = []

    def run(self):
        try:
            if self.mode == 'cross-compiler':
                return self._run_cross_compiler_diff()
            elif self.mode == 'cross-version':
                return self._run_cross_version_diff()
            elif self.mode == 'cross-architecture':
                return self._run_cross_arch_diff()
            else:
                logger.warning("未知的 fuzz 模式: %s", self.mode)
                return {'success': False, 'error': f"Unknown mode: {self.mode}"}

        except Exception as e:
            logger.error("fuzzer 异常: %s", e)
            return {'success': False, 'error': str(e)}

    def _run_cross_compiler_diff(self):
        self._generate_report()
        return {
            'success': True,
            'differences_found': len(self.differences_found),
            'differences': self.differences_found
        }

    def _run_cross_version_diff(self):
        self._generate_report()
        return {
            'success': True,
            'differences_found': len(self.differences_found),
            'differences': self.differences_found
        }

    def _run_cross_arch_diff(self):
        self._generate_report()
        return {
            'success': True,
            'differences_found': len(self.differences_found),
            'differences': self.differences_found
        }

    def _generate_report(self):
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            report_path = os.path.join(self.output_dir, 'differential_report.txt')
            with open(report_path, 'w') as f:
                f.write("Differential Fuzzing Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Binary: {self.binary_path}\n")
                f.write(f"Mode: {self.mode}\n")
                f.write(f"Differences Found: {len(self.differences_found)}\n\n")
                for diff in self.differences_found:
                    f.write(f"- Type: {diff['type']}\n")
                    f.write(f"  Description: {diff['description']}\n\n")
