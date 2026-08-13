# AWSC 同源关联过滤器 (Co-Source FP Filter) — finalize 管线 Stage 10.
#
# 决策:
#   在 Stage9 SAWCE 之后追加 AWSC 同源过滤, 专门消除
#   "分配大小 = 写入大小" 且同根来源的误报. 该误报类区间分析
#   无法识别 (两区间均宽化), 需寄存器级根来源等价判定.
#
# 不修改既有阶段: 仅接收 Stage1-9 存活告警, 逐条执行
#   分配根 vs 写入根 的 def-use 同源比较.
# 判定为 safe 的告警标注 fp_stage="stage10_awsc" 供消融审计.
#
# 创建: 2026-07-03

from typing import Dict, List, Optional, Tuple

from .co_source_engine import AWSCEngine, Root
from .heap_constraint import HeapConstraintTracker
from .disasm_util import norm_reg


class AWSCFPFilter:
    """AWSC 同源关联过滤器."""

    def __init__(self, use_win64_abi: bool = False,
                 alloc_model=None):
        self._engine = AWSCEngine(use_win64_abi=use_win64_abi)
        self._alloc_model = alloc_model
        self._filtered = 0
        self._overflow_confirmed = 0
        self._passed = 0

    def filter(self, findings: List[dict],
               instructions: List[dict],
               alloc_tracker: HeapConstraintTracker,
               func_ranges: Optional[List[Tuple[int, int]]] = None
               ) -> List[dict]:
        """对 Stage1-9 存活告警执行 AWSC 同源过滤."""
        survivors = []
        for finding in findings:
            if "heap" not in finding.get("type", "").lower():
                survivors.append(finding)
                continue

            verdict, detail = self._analyze_one(
                finding, instructions, alloc_tracker, func_ranges)

            if verdict == "safe":
                # soundness守卫: 同源判定safe但数值写量已超可用量时,
                # 数值证据优先, 保守保留不滤 (避免滤掉真实溢出).
                # 仅当写量为已知具体值 (非未知区间 sentinel) 才应用,
                # 否则未知写量不构成对同源判定的反证.
                ws = finding.get("write_size")
                alloc_value = finding.get("alloc_size", 0) or None
                if isinstance(ws, int) and 0 < ws < 2**31 - 1 \
                        and alloc_value and 0 < alloc_value < 2**31 - 1:
                    usable_guard = self._compute_usable(finding)
                    if ws > usable_guard:
                        self._passed += 1
                        survivors.append(finding)
                        continue
                finding["fp_stage"] = "stage10_awsc"
                finding["fp_reason"] = detail
                self._filtered += 1
                continue
            if verdict == "overflow":
                finding["awsc_confirmed"] = True
                finding["awsc_detail"] = detail
                finding["awsc_dst_offset"] = finding.get("_awsc_offset", 0)
                self._overflow_confirmed += 1

            self._passed += 1
            survivors.append(finding)

        return survivors

    def _analyze_one(self, finding: dict, instructions: List[dict],
                     alloc_tracker: HeapConstraintTracker,
                     func_ranges) -> Tuple[str, str]:
        """对单条告警执行同源分析.

        返回: (verdict, detail)
          verdict ∈ {"safe", "overflow", "unknown"}
        """
        write_addr = finding.get("write_addr", 0)
        alloc_addr = finding.get("_snapshot_alloc_addr",
                                 finding.get("alloc_addr", 0))
        write_reg = norm_reg(finding.get("size_operand", ""))
        ptr_reg = norm_reg(finding.get("ptr_operand", ""))
        alloc_reg = self._find_alloc_size_reg(
            instructions, alloc_addr, func_ranges)
        usable = finding.get("usable_size", 0) or 0

        if not write_reg:
            return ("unknown", "no_write_reg")
        if alloc_reg is None:
            return ("unknown", "no_alloc_reg")

        write_root = self._engine.trace_size_root(
            instructions, write_addr, write_reg, func_ranges)
        alloc_root = self._engine.trace_size_root(
            instructions, alloc_addr, alloc_reg, func_ranges)

        alloc_value = finding.get("alloc_size", 0) or None
        if usable == 0 and alloc_value:
            usable = self._compute_usable(finding)

        # 写入目标偏移: memcpy(buf+0x10, src, n) 的 +0x10 计入写末端.
        # 偏移来自目标指针 (ptr_operand) 相对分配基址的 lea/add 常量,
        # 若追踪失败视为 0 (安全侧).
        dst_offset = 0
        if ptr_reg:
            dst_offset = self._engine.trace_dst_offset(
                instructions, write_addr, ptr_reg, func_ranges)
        finding["_awsc_offset"] = dst_offset

        verdict, over, reason = self._engine.correlate(
            alloc_root, write_root, usable, alloc_value, dst_offset=dst_offset)
        return verdict, f"alloc_root={alloc_root} write_root={write_root} " \
                        f"usable={usable} dst_offset={dst_offset} {reason}"

    def _compute_usable(self, finding: dict) -> int:
        """计算分配器可用量 (含 padding).

        优先使用 finding 保留的原始请求 alloc_request; 缺失时回退
        alloc_size (对齐上界) 逆推请求下界. usable_size 以原始请求
        为输入做 request2size 映射, 避免对齐值导致可用量偏高.
        """
        request = finding.get("alloc_request")
        if not request or request >= 2**31 - 1:
            alloc_size = finding.get("alloc_size", 0) or 0
            request = max(0, alloc_size - 15)
        if self._alloc_model is not None:
            return self._alloc_model.usable_size(request)
        # 默认 glibc 近似: chunk = align(request+24), usable = chunk - 8
        chunk = max(32, (request + 8 + 15) & ~15)
        return chunk - 8

    @staticmethod
    def _find_alloc_size_reg(instructions: List[dict], alloc_addr: int,
                             func_ranges) -> Optional[str]:
        """在分配调用点前方查找 size 参数寄存器 (SysV rdi / Win64 rcx)."""
        if not instructions:
            return None
        # 向后最多看 20 条, 找到最近一次写 rdi/rcx 的指令
        idx = -1
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == alloc_addr:
                idx = i
                break
        if idx < 0:
            return None
        for j in range(idx - 1, max(0, idx - 20) - 1, -1):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            dst = norm_reg(ops[0])
            if dst in ("rdi", "rcx", "edi", "ecx"):
                src = ops[1].strip()
                src_reg = norm_reg(src)
                if "[" not in src.lower() and src_reg:
                    return src_reg
                return dst
        return None

    @property
    def stats(self) -> dict:
        return {
            "stage10_awsc_filtered": self._filtered,
            "awsc_overflow_confirmed": self._overflow_confirmed,
            "passed": self._passed,
            "total_processed": self._filtered + self._overflow_confirmed
                              + self._passed,
        }


__all__ = ["AWSCFPFilter"]
