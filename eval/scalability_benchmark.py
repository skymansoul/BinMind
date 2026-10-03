#!/usr/bin/env python3
"""
可扩展性基准 — 合成大文件测量堆写模式验证 (Heap Write Verification)管线时间复杂度.
生成100/500/1000/2000/5000行合成C源码, 逐级测量分析耗时,
验证理论O(N)线性复杂度假设.
"""
from __future__ import annotations
import os, sys, time, json
from pathlib import Path
from typing import Dict, List, Tuple

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier


def gen_c_source(n_allocs: int, n_writes: int,
                 safe_ratio: float = 0.5) -> str:
    """合成C源码: n_allocs个分配点 + n_writes个写入点.

    safe_ratio为安全写入比例(写入大小≤分配大小).
    每个分配约3行(malloc+check+free), 每个写入约2行.
    """
    lines = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "int main(int argc, char *argv[]) {",
    ]
    for i in range(n_allocs):
        sz = 64 + (i * 7) % 256
        lines.append(f"    char *buf_{i} = malloc({sz});")
        lines.append(f"    if (!buf_{i}) return -1;")
    for i in range(n_writes):
        target = i % max(n_allocs, 1)
        if i < int(n_writes * safe_ratio):
            # 安全写入: memcpy大小 < 分配大小
            sz = 64 + (target * 7) % 256
            wsz = sz - 8
            lines.append(f"    memcpy(buf_{target}, src, {wsz});")
        else:
            # 溢出写入: memcpy大小 > 分配大小
            sz = 64 + (target * 7) % 256
            wsz = sz + 32
            lines.append(f"    memcpy(buf_{target}, src, {wsz});")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines)


def gen_loop_heavy(n_loops: int) -> str:
    """合成含大量循环写入的C源码, 测试循环累积判定路径."""
    lines = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "int main() {",
    ]
    for i in range(n_loops):
        lines.append(f"    char *arr_{i} = malloc(256);")
        lines.append(f"    for (int j = 0; j < 128; j++) {{")
        lines.append(f"        arr_{i}[j] = 'x';")
        lines.append(f"    }}")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines)


def gen_alias_heavy(n_chains: int) -> str:
    """合成含多跳别名链的C源码, 测试APAS别名闭包."""
    lines = [
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <string.h>",
        "",
        "int main() {",
    ]
    for i in range(n_chains):
        lines.append(f"    char *root_{i} = malloc(128);")
        lines.append(f"    char *a_{i} = root_{i};")
        lines.append(f"    char *b_{i} = a_{i};")
        lines.append(f"    char *c_{i} = b_{i};")
        lines.append(f"    memcpy(c_{i}, data, 64);")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines)


def bench_single(source: str) -> Dict:
    """单次基准: 运行堆写模式验证并测量耗时和结果数."""
    verifier = HeapOverflowSrcVerifier()
    t0 = time.perf_counter()
    results = verifier.verify(source)
    dt = time.perf_counter() - t0
    return {
        "time_ms": round(dt * 1000, 2),
        "results": len(results),
        "lines": len(source.splitlines()),
    }


def run_scalability_benchmark() -> List[Dict]:
    """运行全量可扩展性基准."""
    configs = [
        ("linear", [(10, 10), (30, 30), (100, 100),
                    (300, 300), (500, 500), (1000, 1000)]),
        ("loop_heavy", [10, 30, 100, 300, 500, 1000]),
        ("alias_heavy", [10, 30, 100, 300, 500, 1000]),
    ]
    all_results = []
    for mode, params in configs:
        print(f"\n[scalability] mode={mode}")
        for p in params:
            if mode == "linear":
                n_a, n_w = p
                src = gen_c_source(n_a, n_w)
                label = f"n_allocs={n_a}, n_writes={n_w}"
            elif mode == "loop_heavy":
                src = gen_loop_heavy(p)
                label = f"n_loops={p}"
            else:
                src = gen_alias_heavy(p)
                label = f"n_chains={p}"
            r = bench_single(src)
            r["mode"] = mode
            r["label"] = label
            all_results.append(r)
            print(f"  {label}: {r['lines']} lines, "
                  f"{r['time_ms']:.1f}ms, {r['results']} results")
    return all_results


def verify_linear_trend(results: List[Dict]) -> Dict:
    """验证线性趋势: 计算相邻配置的时间增长比和行数增长比."""
    by_mode = {}
    for r in results:
        m = r["mode"]
        by_mode.setdefault(m, []).append(r)
    report = {}
    for mode, items in by_mode.items():
        ratios = []
        for i in range(1, len(items)):
            if items[i - 1]["lines"] == 0:
                continue
            line_ratio = items[i]["lines"] / items[i - 1]["lines"]
            time_ratio = (items[i]["time_ms"] / items[i - 1]["time_ms"]
                         if items[i - 1]["time_ms"] > 0 else 0)
            is_linear = time_ratio <= line_ratio * 2.0
            ratios.append({
                "from_lines": items[i - 1]["lines"],
                "to_lines": items[i]["lines"],
                "line_ratio": round(line_ratio, 2),
                "time_ratio": round(time_ratio, 2),
                "is_approx_linear": is_linear,
            })
        report[mode] = ratios
    return report


def main():
    print("[scalability] HOSV Scalability Benchmark")
    print("=" * 60)
    results = run_scalability_benchmark()
    report = verify_linear_trend(results)
    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_json = out_dir / "scalability_benchmark.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"results": results, "linearity": report},
                  f, indent=2, ensure_ascii=False)
    print(f"\n[scalability] JSON: {out_json}")
    print("\n[scalability] Linearity Report:")
    for mode, ratios in report.items():
        print(f"  {mode}:")
        for r in ratios:
            status = "OK" if r["is_approx_linear"] else "WARN"
            print(f"    {r['from_lines']}→{r['to_lines']} lines: "
                  f"line×{r['line_ratio']:.1f} time×{r['time_ratio']:.1f} "
                  f"[{status}]")


if __name__ == "__main__":
    main()
