# UAF FP-Reduction 回归测试编排: 编译 → 双模式扫描 → 对比报告
# 覆盖: uaf_samples/ (新 FP 陷阱) + cve_samples/uaf* (既有套件无回归校验)
# 双模式: 值传递抑制开 (默认) vs 关 (基线)
# 有效 finding 口径: 非 is_false_positive 的 finding 计入检出
from __future__ import annotations
import sys
import io
import json
import time
import pathlib
import subprocess
from typing import Dict, List

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

_PROJ_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))


class UafFpRegressionRunner:
    """UAF FP-Reduction 回归编排器."""

    def __init__(self, new_dir: str = "uaf_samples",
                 legacy_dir: str = "cve_samples",
                 build_dir: str = "uaf_samples/build"):
        self._new_dir = pathlib.Path(new_dir)
        self._legacy_dir = pathlib.Path(legacy_dir)
        self._build = pathlib.Path(build_dir)
        self._build.mkdir(parents=True, exist_ok=True)

    def _discover(self, root: pathlib.Path) -> Dict[str, bool]:
        """发现样本目录: {名称: 是否漏洞}.

        漏洞类型以 README 的 **漏洞类型** 行或名称中的 safe 标记为准.
        """
        out = {}
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name == 'build':
                continue
            if not (d / 'main.c').exists():
                continue
            vuln = not ('safe' in d.name.lower())
            readme = d / 'README.md'
            if readme.exists():
                for line in readme.read_text(encoding='utf-8').split('\n'):
                    if '漏洞类型' in line:
                        vuln = 'safe' not in line
                        break
            out[d.name] = vuln
        return out

    def compile(self, samples: Dict[str, bool]) -> Dict[str, str]:
        """编译样本, 返回 {名称: 二进制路径}."""
        binaries = {}
        for name in sorted(samples.keys()):
            srcs = [self._new_dir / name / "main.c",
                    self._legacy_dir / name / "main.c"]
            src = next((s for s in srcs if s.exists()), None)
            if src is None:
                continue
            exe = self._build / f"{name}.exe"
            r = subprocess.run(
                ['gcc', '-Wall', '-O0', '-fno-stack-protector', '-g',
                 '-o', str(exe), str(src)],
                capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                binaries[name] = str(exe)
        return binaries

    def scan(self, binaries: Dict[str, str],
             samples: Dict[str, bool],
             suppression: bool) -> Dict[str, Dict]:
        """扫描全部样本, 返回 {名称: 结果}."""
        from tests.run_scanner import SampleScanner
        from analysis.uaf_detector import UafDetector

        scanner = SampleScanner(use_advanced_engine=False)
        results = {}
        for name, path in sorted(binaries.items()):
            instrs, addrs, labels = scanner.disassemble(path)
            funcs = scanner.extract_function_boundaries(instrs, labels)
            det = UafDetector()
            det._uaf_value_pass_suppression = suppression
            fs = det.analyze(instrs, funcs, instr_addrs=addrs)
            # 有效 finding: 非 FP 标记 (值传递抑制后 INFO+FP 不计入)
            valid = [f for f in fs if not f.is_false_positive]
            results[name] = {
                "expected_vuln": samples[name],
                "detected": len(valid) > 0,
                "num_findings": len(valid),
                "total_findings": len(fs),
                "fp_flagged": sum(1 for f in fs if f.is_false_positive),
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
        print("  UAF FP-Reduction 回归测试")
        print("=" * 64)
        new_samples = self._discover(self._new_dir)
        legacy = self._discover(self._legacy_dir)
        legacy = {k: v for k, v in legacy.items() if k.startswith('uaf')}
        all_samples = {**legacy, **new_samples}
        print(f"  样本: 既有 {len(legacy)} + 新增 {len(new_samples)}")

        print("\n[1/3] 编译...")
        binaries = self.compile(all_samples)
        print(f"  编译成功: {len(binaries)}/{len(all_samples)}")

        print("\n[2/3] 扫描 (抑制 ON / OFF)...")
        on = self.scan(binaries, all_samples, suppression=True)
        off = self.scan(binaries, all_samples, suppression=False)

        print("\n[3/3] 报告...")
        m_on = self.metrics(on)
        m_off = self.metrics(off)
        print(f"\n{'模式':<14} {'Recall':>8} {'Prec':>8} {'FPR':>8} {'F1':>8}")
        print(f"{'抑制 ON ':<14} {m_on['recall']:7.1%} "
              f"{m_on['precision']:7.1%} {m_on['fpr']:7.1%} "
              f"{m_on['f1']:7.2f}")
        print(f"{'抑制 OFF':<14} {m_off['recall']:7.1%} "
              f"{m_off['precision']:7.1%} {m_off['fpr']:7.1%} "
              f"{m_off['f1']:7.2f}")
        print(f"\n  误报下降: {m_off['FP']} → {m_on['FP']}, "
              f"召回保持: {'是' if m_on['recall'] >= m_off['recall'] else '否!'}")

        for name in sorted(on.keys()):
            r_on, r_off = on[name], off[name]
            status = ("TP" if (r_on["expected_vuln"] and r_on["detected"])
                      else "FN" if r_on["expected_vuln"]
                      else "FP" if r_on["detected"] else "TN")
            print(f"    [{status}] {name:<26} ON={r_on['num_findings']} "
                  f"OFF={r_off['num_findings']} "
                  f"(FP标记={r_on['fp_flagged']})")

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics_on": m_on,
            "metrics_off": m_off,
            "per_sample": on,
        }
        out = self._build / "uaf_fp_regression_report.json"
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  报告: {out}")
        return report


def main():
    UafFpRegressionRunner().run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
