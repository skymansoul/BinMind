"""

包含: 四组消融配置的运行函数 + 候选评估 + 柱状图生成.
"""
from typing import Dict, List, Tuple


def evaluate_candidates(
    candidates: list, ir_lines: list, code: str,
) -> Tuple[int, str]:
    """运行候选检测, 返回 (检出数, 判定摘要).

    语义与heap_overflow_pipeline一致:
      PROVEN_OVERFLOW → 保留候选(检出漏洞)
      PROVEN_SAFE → 过滤候选(证明安全, 移除)
      INCONCLUSIVE → 保留候选(保守保留, 检出疑似漏洞)
    """
    from core.cj_solver import solve_candidate
    from core.cj_constraint_types import SolverVerdict
    if not candidates:
        return 0, "no_candidates"
    detected = False
    verdict_str = "inconclusive"
    for c in candidates:
        result, _ = solve_candidate(c, ir_lines, code)
        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            detected = True
            verdict_str = result.reason[:80]
            break
        if result.verdict == SolverVerdict.PROVEN_SAFE:
            verdict_str = result.reason[:80]
        elif result.verdict == SolverVerdict.INCONCLUSIVE:
            if not detected:
                detected = True
                verdict_str = "retain(inconclusive): " + result.reason[:60]
    return (1 if detected else 0), verdict_str


def run_baseline(code: str, ir_lines: list) -> int:
    """配置A: 纯pattern检测, 不经过CJ/BVF/LSP过滤."""
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        candidates = detect_heap_overflow(ir_lines, code)
        return len(candidates)
    except Exception:
        return 0


def run_cj_bvf_no_lsp(
    candidates: list, ir_lines: list, code: str,
) -> Tuple[int, str]:
    """配置B: CJ+BVF, 关闭LSP/PCBVF/CAAWP."""
    import core.lsp_orchestrator as lsp_mod
    import core.cj_pcbvf_bridge as pcbvf_mod
    import core.caawp_bridge as caawp_mod

    orig_lsp = lsp_mod.try_lsp_proof
    orig_pcbvf = pcbvf_mod.try_pcbvf_proof
    orig_caawp = caawp_mod.try_caawp_proof

    lsp_mod.try_lsp_proof = lambda *a, **kw: None
    pcbvf_mod.try_pcbvf_proof = lambda *a, **kw: None
    caawp_mod.try_caawp_proof = lambda *a, **kw: None

    try:
        return evaluate_candidates(candidates, ir_lines, code)
    finally:
        lsp_mod.try_lsp_proof = orig_lsp
        pcbvf_mod.try_pcbvf_proof = orig_pcbvf
        caawp_mod.try_caawp_proof = orig_caawp


def run_cj_bvf_lsp(
    candidates: list, ir_lines: list, code: str,
) -> Tuple[int, str]:
    """配置C: CJ+BVF+LSP, 关闭PCBVF/CAAWP."""
    import core.cj_pcbvf_bridge as pcbvf_mod
    import core.caawp_bridge as caawp_mod

    orig_pcbvf = pcbvf_mod.try_pcbvf_proof
    orig_caawp = caawp_mod.try_caawp_proof

    pcbvf_mod.try_pcbvf_proof = lambda *a, **kw: None
    caawp_mod.try_caawp_proof = lambda *a, **kw: None

    try:
        return evaluate_candidates(candidates, ir_lines, code)
    finally:
        pcbvf_mod.try_pcbvf_proof = orig_pcbvf
        caawp_mod.try_caawp_proof = orig_caawp


def run_full_pipeline(
    candidates: list, ir_lines: list, code: str,
) -> Tuple[int, str]:
    """配置D: 完整管线(CJ+BVF+LSP+PCBVF+CAAWP)."""
    return evaluate_candidates(candidates, ir_lines, code)


def generate_chart(metrics: Dict, results_dir):
    """生成消融对比柱状图."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print(" matplotlib not available, skipping chart")
        return

    configs = ["Baseline", "CJ+BVF", "CJ+BVF+LSP", "Full"]
    x = np.arange(len(configs))
    width = 0.18

    fig, ax1 = plt.subplots(figsize=(10, 5.5))

    precs = [metrics[c]["precision"] for c in configs]
    recs = [metrics[c]["recall"] for c in configs]
    f1s = [metrics[c]["f1"] for c in configs]
    fprs = [metrics[c]["fpr"] for c in configs]

    bars1 = ax1.bar(x - 1.5*width, precs, width,
                     label='Precision', color='#2196F3')
    bars2 = ax1.bar(x - 0.5*width, recs, width,
                     label='Recall', color='#4CAF50')
    bars3 = ax1.bar(x + 0.5*width, f1s, width,
                     label='F1', color='#FF9800')
    bars4 = ax1.bar(x + 1.5*width, fprs, width,
                     label='FPR', color='#F44336')

    ax1.set_ylabel('Score', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=11)
    ax1.set_ylim(-0.05, 1.15)
    ax1.legend(loc='upper left', fontsize=10)
    ax1.set_title(
        'LSP Ablation: Precision/Recall/F1/FPR across 4 configs',
        fontsize=13)
    ax1.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)

    for bars in [bars1, bars2, bars3, bars4]:
        for bar in bars:
            h = bar.get_height()
            if h > 0.01:
                ax1.text(bar.get_x() + bar.get_width()/2.,
                         h + 0.01, f'{h:.2f}',
                         ha='center', va='bottom', fontsize=7)

    chart_path = results_dir / "ablation_lsp_chart.png"
    fig.tight_layout()
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)
    print(f" Chart: {chart_path}")


__all__ = [
    'evaluate_candidates', 'run_baseline', 'run_cj_bvf_no_lsp',
    'run_cj_bvf_lsp', 'run_full_pipeline', 'generate_chart',
]
