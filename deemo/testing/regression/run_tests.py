# 回归测试主入口 —— 编译→扫描→解析→统计。
# 用法: python -m testing.regression.run_tests [--timeout N]
# 创建: 2026-08-14

import json, os, sys, time
from testing.regression.compile_samples import compile_all
from testing.regression.scan_runner import run_all
from testing.regression.result_parser import (
    parse_scan_output, match_against_expected, compute_statistics,
)


def main(timeout_sec: int = 120):
    print("=" * 60)
    print("BinMind 回归测试套件")
    print("=" * 60)

    # 阶段1: 编译
    print("\n[1/4] 编译样本...")
    compile_results = compile_all()
    ok = sum(1 for v in compile_results.values()
            if isinstance(v, dict) and v.get("success"))
    total = len([v for v in compile_results.values()
                if isinstance(v, dict)])
    print(f"  编译: {ok}/{total} 成功")
    for name, info in compile_results.items():
        if isinstance(info, dict) and not info.get("success"):
            print(f"    FAIL {name}: {info.get('error', 'unknown')[:80]}")

    if ok == 0:
        print("  无可用二进制, 终止测试")
        return

    # 阶段2: 扫描
    print("\n[2/4] 执行扫描...")
    t0 = time.time()
    scan_results = run_all(compile_results, timeout_sec)
    scan_time = time.time() - t0
    scan_ok = sum(1 for r in scan_results if r.success)
    print(f"  扫描: {scan_ok}/{len(scan_results)} 成功, 耗时 {scan_time:.1f}s")

    # 阶段3: 解析+比对
    print("\n[3/4] 解析结果并比对预期...")
    matches = []
    for sr in scan_results:
        parsed = parse_scan_output(sr)
        match = match_against_expected(sr.sample_name, parsed)
        matches.append(match)
        status = "DETECTED" if match.detected else "MISSED"
        print(f"  {match.sample_name}: {status} ({match.expected_type})"
              f" conf={match.detection_confidence:.2f}"
              + (f" kw='{match.matched_keyword}'" if match.matched_keyword else ""))

    # 阶段4: 统计
    print("\n[4/4] 统计汇总...")
    stats = compute_statistics(matches)
    print(f"  检出率: {stats.get('detection_rate', 0):.1%}")
    print(f"  检出: {stats.get('detected', 0)}/{stats.get('total_samples', 0)}")
    print(f"  平均误报/样本: {stats.get('avg_fp_per_sample', 0):.1f}")
    print(f"  平均置信度: {stats.get('avg_confidence', 0):.3f}")
    print(f"  分类检出率: {json.dumps(stats.get('by_type', {}), indent=4)}")

    # 输出完整报告JSON
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "compile": {k: {"success": v["success"]} for k, v in compile_results.items()
                   if isinstance(v, dict)},
        "scan_duration_sec": round(scan_time, 1),
        "matches": [{"sample": m.sample_name, "detected": m.detected,
                     "confidence": m.detection_confidence,
                     "type": m.expected_type} for m in matches],
        "statistics": stats,
    }
    report_path = os.path.join(os.path.dirname(__file__), "report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n报告已保存: {report_path}")

    return report


if __name__ == "__main__":
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--timeout" else 120
    main(timeout)
