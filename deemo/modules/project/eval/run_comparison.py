# 检测方法对比实验: ASA-VRA vs NaivePattern vs RegexOnly
# 核心展示: ASA-VRA在保持高召回同时将FPR降至0%,
#   对比朴素方法的极高FPR — 这就是方法学创新的量化证据
# 输出: JSON对比报告 + 可视化图表(可选) + LaTeX表格
import sys, json, time, subprocess
from pathlib import Path
from typing import Dict, List

_PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

from eval.baseline_detectors import (NaivePatternDetector, RegexOnlyDetector,
                                      BaselineResult, compute_baseline_metrics)


def discover_binaries(build_dir: str = "cve_samples/build") -> List[Path]:
    """发现所有已编译的二进制文件."""
    bd = _PROJ_ROOT / build_dir
    if not bd.exists():
        return []
    return sorted([f for f in bd.iterdir()
                   if f.suffix == '.exe' and f.is_file()])


def get_sample_type(name: str) -> str:
    """根据样本名推断类型."""
    n = name.lower()
    if n.startswith('uaf'):
        return 'uaf'
    if any(p in n for p in ['safe', 'path_cond', 'early_return',
                              'stride_loop_safe', 'mem_region']):
        return 'safe'
    return 'heap_overflow'


def load_asa_vra_results(report_path: str = "cve_samples/build/regression_report.json") -> Dict:
    """从现有回归报告加载ASA-VRA结果."""
    rp = _PROJ_ROOT / report_path
    if not rp.exists():
        return {}
    with open(rp, 'r', encoding='utf-8') as f:
        data = json.load(f)
    results = {}
    for s in data.get('samples', []):
        name = s['name']
        results[name] = {
            'detected': s['detected'],
            'num_findings': s['num_findings'],
            'expected_type': s['expected_type'],
        }
    return results


def run_comparison() -> Dict:
    """运行完整的检测方法对比实验."""
    print("=" * 60)
    print("  检测方法对比实验: ASA-VRA vs 基线方法")
    print("=" * 60)

    binaries = discover_binaries()
    if not binaries:
        print("[ERROR] 未找到已编译的二进制文件, 先运行 regression_harness")
        return {}

    print(f"\n发现 {len(binaries)} 个二进制文件")

    # 加载ASA-VRA结果
    asa_results = load_asa_vra_results()
    print(f"ASA-VRA: 已有 {len(asa_results)} 个样本结果")

    # 运行基线检测器
    naive_detector = NaivePatternDetector()
    regex_detector = RegexOnlyDetector()

    all_results: Dict[str, List[BaselineResult]] = {
        'naive': [], 'regex_only': [], 'asa_vra': []}
    expected_types: Dict[str, str] = {}

    # 只比较堆溢出+安全样本 (UAF由独立流程处理)
    heap_safe_binaries = [b for b in binaries
                          if get_sample_type(b.stem) != 'uaf']
    print(f"  堆溢出/安全样本: {len(heap_safe_binaries)} (排除UAF)")

    for i, binary in enumerate(heap_safe_binaries):
        name = binary.stem
        etype = get_sample_type(name)
        expected_types[name] = etype

        # 朴素模式匹配
        nr = naive_detector.analyze(str(binary))
        nr.sample_type = etype
        all_results['naive'].append(nr)

        # 纯正则
        rr = regex_detector.analyze(str(binary))
        rr.sample_type = etype
        all_results['regex_only'].append(rr)

        # ASA-VRA (从已有结果加载)
        av = asa_results.get(name, {})
        ar = BaselineResult(
            detector_name='asa_vra',
            sample_name=name,
            sample_type=etype,
            detected=av.get('detected', False),
            num_findings=av.get('num_findings', 0))
        all_results['asa_vra'].append(ar)

        if (i + 1) % 5 == 0:
            print(f"  进度: {i + 1}/{len(heap_safe_binaries)}")

    # 计算指标
    print(f"\n[计算指标]")
    metrics = {}
    for detector_name in ['regex_only', 'naive', 'asa_vra']:
        m = compute_baseline_metrics(
            all_results[detector_name], expected_types)
        metrics[detector_name] = m

    # 打印对比表
    print(f"\n{'='*70}")
    print(f"  检测方法对比结果")
    print(f"{'='*70}")
    print(f"{'方法':<20} {'Recall':>8} {'Prec':>8} {'FPR':>8} "
          f"{'F1':>8} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}")
    print(f"{'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*8} "
          f"{'-'*5} {'-'*5} {'-'*5} {'-'*5}")
    for name, m in metrics.items():
        label = {'naive': '朴素模式匹配', 'regex_only': '纯正则匹配',
                 'asa_vra': 'ASA-VRA (我们)'}[name]
        print(f"{label:<20} {m['recall']:7.1%} {m['precision']:7.1%} "
              f"{m['fpr']:7.1%} {m['f1']:7.2f} "
              f"{m['TP']:5d} {m['FP']:5d} {m['TN']:5d} {m['FN']:5d}")

    # FPR reduction
    asa = metrics.get('asa_vra', {})
    for name in ['regex_only', 'naive']:
        other = metrics.get(name, {})
        if asa.get('fpr', 1) < other.get('fpr', 1):
            reduction = (1 - asa['fpr'] / max(other['fpr'], 0.001))
            label = {'naive': '朴素模式匹配', 'regex_only': '纯正则'}[name]
            print(f"\n  FPR Reduction vs {label}: {reduction:.0%} "
                  f"({other['fpr']:.1%} → {asa['fpr']:.1%})")

    # 导出报告
    out_dir = _PROJ_ROOT / "eval_output"
    out_dir.mkdir(parents=True, exist_ok=True)

    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'samples': len(binaries),
        'methods': {
            name: {
                **m,
                'per_sample': [
                    {'name': r.sample_name, 'type': r.sample_type,
                     'detected': r.detected, 'findings': r.num_findings}
                    for r in all_results[name]
                ]
            }
            for name, m in metrics.items()
        },
        'key_finding': (
            f"ASA-VRA achieves {asa.get('fpr',0):.1%} FPR while maintaining "
            f"{asa.get('recall',0):.1%} recall, vs naive methods with "
            f"{metrics.get('naive',{}).get('fpr',0):.1%} FPR")
    }

    report_path = out_dir / "method_comparison.json"
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n报告: {report_path}")

    # LaTeX表格
    latex_path = out_dir / "comparison_table.tex"
    lines = [
        r"\begin{table}[htbp]",
        r"  \centering",
        r"  \caption{Detection Method Comparison: "
        r"ASA-VRA vs Baseline Methods}",
        r"  \label{tab:method-comparison}",
        r"  \begin{tabular}{lcccc}",
        r"    \toprule",
        r"    \textbf{Method} & \textbf{Recall} & \textbf{Precision} & "
        r"\textbf{FPR} & \textbf{F1} \\",
        r"    \midrule",
    ]
    for name, label in [('regex_only', 'Regex-Only'),
                         ('naive', 'Naive Pattern Match'),
                         ('asa_vra', 'ASA-VRA (Ours)')]:
        m = metrics.get(name, {})
        if m:
            lines.append(
                f"    {label} & {m['recall']:.1%} & {m['precision']:.1%} & "
                f"{m['fpr']:.1%} & {m['f1']:.2f} \\\\")
    lines.extend([
        r"    \bottomrule",
        r"  \end{tabular}",
        r"\end{table}",
    ])
    with open(latex_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"LaTeX: {latex_path}")

    return report


if __name__ == '__main__':
    run_comparison()
