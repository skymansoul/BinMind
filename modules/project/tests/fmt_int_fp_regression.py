# 格式化字符串/整数溢出 FP-Reduction 回归测试
# 双模式: 抑制开 (默认) vs 关 (基线), 验证两类改进的独立贡献:
#   fmt 调用点上下文验证 / int 回绕净化检测
# 有效 finding 口径: 非 is_false_positive 计入检出
import sys
import io
import json
import time
import pathlib
import subprocess
from typing import Dict, List, Tuple

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

_PROJ_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

# 本套件的目标样本 (cve_samples/ 下的独立目录)
_TARGETS = {
    "fmt_safe_const_wrapper": False,
    "fmt_safe_param_multi": False,
    "fmt_vuln_param_wrapper": True,
    "int_safe_mask_after_add": False,
    "int_safe_trunc_after_mul": False,
    "int_safe_shr_after_add": False,
    "int_vuln_mask_missing": True,
}


class FmtIntFpRegressionRunner:
    """fmt/int FP-Reduction 回归编排器."""

    def __init__(self, samples_root: str = "cve_samples",
                 build_dir: str = "cve_samples/build"):
        self._root = pathlib.Path(samples_root)
        self._build = pathlib.Path(build_dir)
        self._build.mkdir(parents=True, exist_ok=True)

    def compile_all(self) -> Dict[str, str]:
        binaries = {}
        for name in _TARGETS:
            src = self._root / name / "main.c"
            if not src.exists():
                continue
            exe = self._build / f"{name}.exe"
            r = subprocess.run(
                ['gcc', '-Wall', '-O0', '-fno-stack-protector', '-g',
                 '-o', str(exe), str(src)],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                binaries[name] = str(exe)
        return binaries

    def _disassemble(self, binary: str):
        import re
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', binary],
            capture_output=True, text=True, timeout=30)
        lines = []
        labels = {}
        pending = None
        for line in proc.stdout.split('\n'):
            s = line.strip()
            m = re.match(r'^[0-9a-f]+\s+<([\w@.]+)>:', s)
            if m:
                pending = m.group(1).split('@')[0]
                continue
            if not re.match(r'^[0-9a-f]+:\t', s):
                continue
            tab = s.split('\t')
            if len(tab) >= 2 and tab[-1].strip():
                if pending:
                    labels[len(lines)] = pending
                    pending = None
                lines.append(tab[-1].strip())
        return lines, labels

    def _func_map(self, lines, labels):
        funcs = {}
        cur = "_entry_"
        start = 0
        for i, l in enumerate(lines):
            if i in labels:
                if cur != "_entry_":
                    funcs[cur] = (start, i)
                cur = labels[i]
                start = i
            if l.strip().startswith('ret'):
                if cur not in funcs:
                    funcs[cur] = (start, i)
                cur = f"func_{i}"
                start = i + 1
        if cur not in funcs and start < len(lines):
            funcs[cur] = (start, len(lines) - 1)
        return funcs

    def scan(self, binaries: Dict[str, str], suppression: bool
             ) -> Dict[str, Dict]:
        from analysis.format_string_detector import FormatStringDetector
        from analysis.integer_overflow_detector import IntegerOverflowDetector
        results = {}
        for name, path in sorted(binaries.items()):
            lines, labels = self._disassemble(path)
            funcs = self._func_map(lines, labels)
            if name.startswith('fmt_'):
                det = FormatStringDetector(
                    call_site_validation=suppression)
                findings = det.analyze(lines, funcs)
            else:
                det = IntegerOverflowDetector(
                    wrap_sanitize_validation=suppression)
                findings = det.analyze(lines, funcs)
            valid = [f for f in findings if not f.is_false_positive]
            results[name] = {
                "expected_vuln": _TARGETS[name],
                "detected": len(valid) > 0,
                "num_findings": len(valid),
                "total_findings": len(findings),
                "fp_flagged": sum(1 for f in findings
                                  if f.is_false_positive),
            }
        return results

    @staticmethod
    def metrics(results: Dict[str, Dict]) -> Dict:
        tp = fp = tn = fn = 0
        for r in results.values():
            if r["expected_vuln"] and r["detected"]:
                tp += 1
            elif r["expected_vuln"]:
                fn += 1
            elif r["detected"]:
                fp += 1
            else:
                tn += 1
        return {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "recall": tp / max(tp + fn, 1),
            "precision": tp / max(tp + fp, 1),
            "fpr": fp / max(fp + tn, 1),
            "f1": 2 * tp / max(2 * tp + fp + fn, 1),
        }

    def run(self) -> Dict:
        print("=" * 64)
        print("  fmt/int FP-Reduction 回归测试")
        print("=" * 64)
        binaries = self.compile_all()
        print(f"  编译: {len(binaries)}/{len(_TARGETS)}")

        on = self.scan(binaries, suppression=True)
        off = self.scan(binaries, suppression=False)
        m_on = self.metrics(on)
        m_off = self.metrics(off)

        print(f"\n{'模式':<12} {'Recall':>8} {'Prec':>8} {'FPR':>8} {'F1':>8}")
        print(f"{'抑制 ON ':<12} {m_on['recall']:7.1%} "
              f"{m_on['precision']:7.1%} {m_on['fpr']:7.1%} "
              f"{m_on['f1']:7.2f}")
        print(f"{'抑制 OFF':<12} {m_off['recall']:7.1%} "
              f"{m_off['precision']:7.1%} {m_off['fpr']:7.1%} "
              f"{m_off['f1']:7.2f}")
        print(f"\n  误报下降: {m_off['FP']} → {m_on['FP']}")

        for name in sorted(on):
            r_on, r_off = on[name], off[name]
            status = ("TP" if (r_on["expected_vuln"] and r_on["detected"])
                      else "FN" if r_on["expected_vuln"]
                      else "FP" if r_on["detected"] else "TN")
            print(f"    [{status}] {name:<28} ON={r_on['num_findings']} "
                  f"OFF={r_off['num_findings']} "
                  f"(FP标记={r_on['fp_flagged']})")

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics_on": m_on,
            "metrics_off": m_off,
            "per_sample": on,
        }
        out = self._build / "fmt_int_fp_regression_report.json"
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  报告: {out}")
        return report


def main():
    FmtIntFpRegressionRunner().run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
