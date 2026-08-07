# 回归测试结果收集与汇总
# 从各检测器输出中提取TP/FP/FN统计, 生成结构化可比较的数据
# 输出: build/result_summary.json + 终端表格

import json
import sys
import time
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Optional

BUILD = Path(__file__).parent / "build"
SAMPLES = Path(__file__).parent / "samples"

# 每个样本的ground truth和期望行为
# positive_expected: True=应检出漏洞, False=应报告为安全(FP测试)
GROUND_TRUTH: Dict[str, Dict[str, Any]] = {
# 原有堆溢出
    "CVE-2014-0160_heartbleed": {"type": "buffer_overflow", "positive": True},
    "CVE-2015-7547_glibc_getaddrinfo": {"type": "buffer_overflow", "positive": True},
    "CVE-2016-6309_openssl_uaf": {"type": "use_after_free", "positive": True},
    "CVE-2017-13089_wget_overflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2018-1000001_glibc_realpath": {"type": "buffer_overflow", "positive": True},
    "CVE-2019-12900_bzip2_uaf": {"type": "use_after_free", "positive": True},
    "CVE-2020-10713_grub2_overflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2021-3156_sudo_heapoverflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2022-3602_spider_overflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2023-38545_curl_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2024-6387_regreSSHion": {"type": "use_after_free", "positive": True},
    "CVE-2014-9471_man_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2016-10191_ffmpeg_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2018-1160_ntfs3g_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2020-12026_radare2_heap": {"type": "buffer_overflow", "positive": True},
# 新增堆溢出(CVE)
    "CVE-2022-0185_kernel_heap_overflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2022-23270_windns_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2019-17558_digest_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2018-6789_exim_heap_overflow": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-001_bounds_check_insufficient": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-002_safe_bounds_check": {"type": "buffer_overflow", "positive": False},
    "HEAP-FP-003_realloc_overflow": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-004_loop_overflow": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-005_calloc_multiplication": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-006_glibc_alignment_edge": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-007_indirect_size_flow": {"type": "buffer_overflow", "positive": True},
    "HEAP-FP-008_safe_same_size": {"type": "buffer_overflow", "positive": False},
    "CVE-2016-6187_kernel_heap_overflow": {"type": "buffer_overflow", "positive": True},
    "CVE-2020-25656_linux_heap": {"type": "buffer_overflow", "positive": True},
    "CVE-2023-6817_libc_heap": {"type": "buffer_overflow", "positive": True},
}


class ResultCollector:
    """结果收集器——汇总各阶段输出并做统计分析"""

    def __init__(self):
        self.heap_samples = {k: v for k, v in GROUND_TRUTH.items()
                            if v["type"] == "buffer_overflow"}
        self.uaf_samples = {k: v for k, v in GROUND_TRUTH.items()
                           if v["type"] == "use_after_free"}
        self.fmt_samples = {k: v for k, v in GROUND_TRUTH.items()
                           if v["type"] == "format_string"}

    def load_heap_results(self) -> Dict[str, Any]:
        """从batch_results.json加载堆溢出检测结果"""
        path = BUILD / "batch_results.json"
        if not path.exists():
            return {"available": False, "reason": "batch_results.json not found"}
        with open(path) as f:
            return json.load(f)

    def collect_all(self) -> Dict[str, Any]:
        """收集全部结果并生成汇总报告"""
        heap_raw = self.load_heap_results()
        heap_analysis = self._analyze_heap(heap_raw)

        summary = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "version": "2.0",
            "total_samples": len(GROUND_TRUTH),
            "heap_overflow": {
                "total_samples": len(self.heap_samples),
                "positive_expected": sum(1 for v in self.heap_samples.values() if v["positive"]),
                "negative_expected": sum(1 for v in self.heap_samples.values() if not v["positive"]),
            },
            "uaf": {
                "total_samples": len(self.uaf_samples),
            },
            "format_string": {
                "total_samples": len(self.fmt_samples),
            },
            "heap_raw": heap_raw,
            "heap_analysis": heap_analysis,
        }
        return summary

    def _analyze_heap(self, heap_raw: Dict) -> Dict[str, Any]:
        """分析堆溢出检测的TP/FP/FN"""
        analysis = {
            "raw_sinks": heap_raw.get("sinks", 0),
            "confirmed_sinks": heap_raw.get("confirmed", 0),
            "filtered_sinks": heap_raw.get("filtered", 0),
            "fp_ratio_before": 0.0,
            "fp_ratio_after": 0.0,
            "fp_reduction_pct": 0.0,
        }
        total = analysis["raw_sinks"]
        confirmed = analysis["confirmed_sinks"]
        filtered = analysis["filtered_sinks"]

        if total > 0:
            analysis["fp_ratio_before"] = round((total - confirmed) / total, 3)
            analysis["fp_ratio_after"] = round((total - confirmed - filtered) / max(1, total), 3)
            analysis["fp_reduction_pct"] = round((total - confirmed) / max(1, total) * 100, 1)

        return analysis

    def compute_metrics(self,
                         sample_results: Dict[str, bool]
                         ) -> Dict[str, float]:
        """基于per-sample检测结果计算指标"""
        tp = 0; fp = 0; tn = 0; fn = 0

        for sample_name, gt_info in GROUND_TRUTH.items():
            detected = sample_results.get(sample_name, False)
            expected = gt_info["positive"]

            if expected and detected:
                tp += 1
            elif expected and not detected:
                fn += 1
            elif not expected and detected:
                fp += 1
            else:
                tn += 1

        total = tp + fp + tn + fn
        recall = tp / max(1, tp + fn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * recall * precision / max(0.001, recall + precision)

        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "f1": round(f1, 3),
            "accuracy": round((tp + tn) / max(1, total), 3),
        }

    def print_table(self, summary: Dict[str, Any]):
        """打印终端友好的汇总表格"""
        print()
        print("=" * 72)
        print("  堆溢出回归测试 —— 结果汇总")
        print("=" * 72)

        ha = summary.get("heap_analysis", {})
        ho = summary.get("heap_overflow", {})

        print(f"  堆溢出样本总数:   {ho.get('total_samples', 0)}")
        print(f"  期望检出(TP+FN):   {ho.get('positive_expected', 0)}")
        print(f"  期望不检出(TN+FP): {ho.get('negative_expected', 0)}")
        print()
        print(f"  原始sink总数:      {ha.get('raw_sinks', 'N/A')}")
        print(f"  确认sink:          {ha.get('confirmed_sinks', 'N/A')}")
        print(f"  过滤sink:          {ha.get('filtered_sinks', 'N/A')}")
        print(f"  误报率(过滤前):    {ha.get('fp_ratio_before', 0):.1%}")
        print(f"  误报率(过滤后):    {ha.get('fp_ratio_after', 0):.1%}")
        print(f"  误报降低率:        {ha.get('fp_reduction_pct', 0):.1f}%")
        print("=" * 72)


def main():
    collector = ResultCollector()
    summary = collector.collect_all()

    # 保存到文件
    out_path = BUILD / "result_summary.json"
    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"结果汇总: {out_path}")

    collector.print_table(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
