# 统一漏洞扫描编排器 — 整合全部5种检测引擎, 单次扫描产出综合报告.
# 创建: 2026-04-19

from typing import Dict, List, Optional
from .heap_overflow_detect import HeapOverflowDetector
from .uaf_detect import UAFDetector
from .uaf_lifecycle import UAFLifecycleTracker
from .format_string_detect import FormatStringDetector
from .fmt_taint_detect import TaintAwareFmtDetector
from .integer_overflow_detect import IntegerOverflowDetector
from .stack_overflow_detect import StackOverflowDetector
from .taint_engine import TaintTracker
from .vuln_scores import VulnScoreCalibrator


class UnifiedScanner:
    """统一扫描编排器 — 单次扫描覆盖5种漏洞类型.

    各引擎独立运行, 结果经 VulnScoreCalibrator 交叉验证后输出.
    """

    def __init__(self):
        self._heap = HeapOverflowDetector()
        self._uaf = UAFDetector()
        self._uaf_lifecycle = UAFLifecycleTracker()
        self._fmt = FormatStringDetector()
        self._fmt_taint = TaintAwareFmtDetector()
        self._int_overflow = IntegerOverflowDetector()
        self._stack = StackOverflowDetector()
        self._taint = TaintTracker()
        self._calibrator = VulnScoreCalibrator()

    def scan_instruction(self, ins: dict):
        """将单条指令送入所有相关引擎."""
        mnem = ins.get("mnemonic","").lower()
        ops = ins.get("operands",[])
        addr = ins.get("address",0)

        self._heap.analyze_instruction(ins)
        self._uaf.analyze_instruction(ins)
        self._uaf_lifecycle.analyze(ins)
        self._int_overflow.analyze(ins)

        # 格式字符串: call 指令, 分离函数名和实参
        if mnem == "call" and ops:
            func = ops[0].strip().lower().split("@")[0]
            call_args = ops[1:] if len(ops) > 1 else []  # 实参不含函数名
            self._fmt.analyze_call(
                func_name=func, args=call_args,
                fmt_source="unknown", address=addr)
            self._fmt_taint.analyze_call(
                func_name=func, args=call_args,
                fmt_source="unknown", address=addr)

        # 污点传播
        if mnem in ("mov","lea"):
            self._taint.analyze_block([ins])
        elif mnem == "call" and ops:
            self._taint.analyze_block([ins])

    def finalize(self, instructions: List[dict] = None,
                  binary_data: bytes = None) -> dict:
        """汇总所有引擎发现, 交叉验证评分."""
        # 堆检测
        raw_heap = self._heap.raw_findings
        filtered_heap = self._heap.finalize(instructions or [])

        # UAF
        raw_uaf = self._uaf.findings + self._uaf_lifecycle.findings

        # 格式字符串
        raw_fmt = self._fmt.findings + self._fmt_taint.findings

        # 整数溢出
        raw_int = self._int_overflow.findings

        # 栈溢出: 若提供binary_data则提取帧, 始终收集已存在的findings
        if binary_data:
            self._stack.extract_frames(binary_data)
        raw_stack = self._stack.findings

        # 合并+标注引擎来源
        all_raw = []
        for engine, findings in [
            ("heap_overflow", raw_heap),
            ("uaf_detector", raw_uaf),
            ("format_string", raw_fmt),
            ("integer_overflow", raw_int),
            ("stack_overflow", raw_stack),
        ]:
            for f in findings:
                f["engine"] = engine
                all_raw.append(f)

        scored = self._calibrator.calibrate(all_raw)

        return {
            "total_raw_findings": len(all_raw),
            "scored_findings": len(scored),
            "by_severity": {
                "critical": sum(1 for s in scored if s.severity == "critical"),
                "high": sum(1 for s in scored if s.severity == "high"),
                "medium": sum(1 for s in scored if s.severity == "medium"),
                "low": sum(1 for s in scored if s.severity == "low"),
            },
            "by_type": {
                "heap_overflow": len(raw_heap),
                "use_after_free": len(raw_uaf),
                "format_string": len(raw_fmt),
                "integer_overflow": len(raw_int),
                "stack_overflow": len(raw_stack),
            },
            "findings": [s.to_dict() for s in scored],
            "fp_filter_stats": self._heap.stats.get("fp_filter", {}),
        }

    @property
    def engines_status(self) -> dict:
        return {
            "heap_overflow": len(self._heap.raw_findings) > 0,
            "uaf": len(self._uaf.findings) > 0 or len(self._uaf_lifecycle.findings) > 0,
            "format_string": len(self._fmt.findings) > 0 or len(self._fmt_taint.findings) > 0,
            "integer_overflow": len(self._int_overflow.findings) > 0,
            "stack_overflow": len(self._stack.findings) > 0,
            "taint_engine": True,
        }


__all__ = ["UnifiedScanner"]
