# 创建: 2026-08-05 | 整数溢出检测——运算结果→分配大小的传播链分析
#
"""整数溢出检测——追踪算术运算结果如何影响后续内存操作的大小参数。

现有检测对整数溢出的处理为零——BIFT污点传播是二值的(污点/非污点)，
无法表达"这个值经过乘法后可能溢出"的语义。

核心方案——运算语义感知的污点增强:
1. 识别关键算术模式: mul/imul/shl/add——这些操作可能产生溢出。
2. 对操作数做宽化(widening): 若操作数为n位, 结果可能需要>n位存储。
   例: unsigned short a,b; a*b → 可能超过16位范围。
3. 若溢出结果流向malloc/memcpy的size参数→标记。
4. 三类检测:
   (a) mul→malloc: 乘法结果作分配大小, 可能分配不足
   (b) add→memcpy: 加法结果作拷贝偏移, 可能越界
   (c) shl→array_index: 左移结果作数组索引, 可能超出边界

与堆溢出检测的关系: 整数溢出是堆溢出的上游根因之一——
size_constraint_inferrer检测"malloc和memcpy的size关系",
本模块检测"size本身是否因溢出而错误"。

参考:
- CWE-190 Integer Overflow (MITRE)
- Dietz et al. "Understanding Integer Overflow in C/C++" (ICSE 2015)
- IOC (Integer Overflow Checker for C/C++, LLVM 2019) — 源码级, 本模块在二进制级
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class OverflowPattern(Enum):
    MUL_TO_MALLOC = "mul_to_malloc"       # mul/imul → 结果流向malloc size
    ADD_TO_OFFSET = "add_to_offset"       # add → 结果用作指针偏移
    SHL_TO_INDEX = "shl_to_index"         # shl → 结果用作数组索引
    SUB_UNDERFLOW = "sub_underflow"       # sub → 可能下溢(无符号)
    CAST_TRUNCATION = "cast_truncation"   # 大类型→小类型截断


@dataclass
class ArithmeticOp:
    """一次算术操作。"""
    addr: int
    op: str             # mul / imul / add / sub / shl / movzx
    operands: str       # 操作数文本
    operand_bits: int = 32  # 操作数位宽(默认32)
    result_bits: int = 32   # 结果所需最小位宽
    has_overflow_risk: bool = False


@dataclass
class OverflowFinding:
    """一次整数溢出发现。"""
    pattern: OverflowPattern
    source_op: ArithmeticOp
    sink_addr: int       # malloc/memcpy/数组访问的地址
    sink_func: str       # 汇函数名
    confidence: float
    severity: str = "HIGH"


class IntegerOverflowDetector:
    """整数溢出检测器——基于运算语义的污点增强。

    使用:
      detector = IntegerOverflowDetector()
      detector.scan_arithmetic(addr, "mul", "cx", operand_bits=16)
      # 若cx流向malloc size → 标记为MUL_TO_MALLOC
      detector.check_sink(addr, "memcpy", tainted_ops)
    """

    # 算术指令→位宽扩展规则
    _OP_WIDTH_RULES = {
        "mul": 2,    # 两个n位操作数相乘 → 最多2n位
        "imul": 2,
        "add": 1.5,  # n位加法 → 最多n+1位, 保守取1.5x
        "sub": 1.5,  # 减法同理——无符号下溢
        "shl": 2,    # 左移k位 → 最多n+k位
    }

    def __init__(self):
        self._arithmetic_ops: Dict[int, ArithmeticOp] = {}
        self._findings: List[OverflowFinding] = []
        self._tainted_ops: Dict[int, ArithmeticOp] = {}

    def scan_arithmetic(
        self, addr: int, mnemonic: str, operands: str,
        operand_bits: int = 32,
    ) -> Optional[ArithmeticOp]:
        """扫描一条算术指令——判断是否有溢出风险。"""
        _mnem_lower = mnemonic.lower()
        _factor = self._OP_WIDTH_RULES.get(_mnem_lower)
        if _factor is None:
            return None

        _result_bits = int(operand_bits * _factor)
        _has_risk = _result_bits > operand_bits

        _op = ArithmeticOp(
            addr=addr, op=_mnem_lower, operands=operands,
            operand_bits=operand_bits, result_bits=_result_bits,
            has_overflow_risk=_has_risk,
        )
        self._arithmetic_ops[addr] = _op
        return _op

    def mark_tainted(self, op_addr: int):
        """标记一个算术操作的结果被污点数据影响。"""
        _op = self._arithmetic_ops.get(op_addr)
        if _op and _op.has_overflow_risk:
            self._tainted_ops[op_addr] = _op

    def check_sink(
        self, sink_addr: int, sink_func: str,
        tainted_op_addrs: List[int],
    ) -> List[OverflowFinding]:
        """在汇点(malloc/memcpy)检查是否有溢出风险操作流入。

        tainted_op_addrs: 从污点分析得知流入此汇的算术操作地址列表。
        """
        _new_findings = []
        for _op_addr in tainted_op_addrs:
            _op = self._tainted_ops.get(_op_addr)
            if _op is None:
                continue

            _pattern = self._classify_pattern(_op.op, sink_func)
            _finding = OverflowFinding(
                pattern=_pattern,
                source_op=_op,
                sink_addr=sink_addr,
                sink_func=sink_func,
                confidence=self._compute_confidence(_op, sink_func),
            )
            _new_findings.append(_finding)

        self._findings.extend(_new_findings)
        return _new_findings

    def generate_report(self) -> dict:
        """生成检测报告——按模式分组统计。"""
        _by_pattern: Dict[OverflowPattern, int] = {}
        for _f in self._findings:
            _by_pattern[_f.pattern] = _by_pattern.get(_f.pattern, 0) + 1

        return {
            "total_findings": len(self._findings),
            "by_pattern": {k.value: v for k, v in _by_pattern.items()},
            "high_confidence": sum(1 for f in self._findings if f.confidence > 0.7),
            "medium_confidence": sum(1 for f in self._findings if 0.4 < f.confidence <= 0.7),
            "low_confidence": sum(1 for f in self._findings if f.confidence <= 0.4),
        }

    @staticmethod
    def _classify_pattern(op: str, sink_func: str) -> OverflowPattern:
        _sink_lower = sink_func.lower()
        if op in ("mul", "imul"):
            if "malloc" in _sink_lower or "alloc" in _sink_lower:
                return OverflowPattern.MUL_TO_MALLOC
            return OverflowPattern.MUL_TO_MALLOC
        if op in ("add", "sub"):
            if "memcpy" in _sink_lower or "memmove" in _sink_lower:
                return OverflowPattern.ADD_TO_OFFSET
            return OverflowPattern.ADD_TO_OFFSET
        if op == "shl":
            return OverflowPattern.SHL_TO_INDEX
        if op == "sub":
            return OverflowPattern.SUB_UNDERFLOW
        if "movzx" in op or "movsx" in op:
            return OverflowPattern.CAST_TRUNCATION
        return OverflowPattern.MUL_TO_MALLOC

    @staticmethod
    def _compute_confidence(op: ArithmeticOp, sink_func: str) -> float:
        """基于溢出幅度和汇类型计算置信度。"""
        _overflow_ratio = op.result_bits / max(op.operand_bits, 1)
        _base = min(0.9, 0.4 + _overflow_ratio * 0.15)
        # mul→malloc是最高置信的模式
        if "malloc" in sink_func and op.op in ("mul", "imul"):
            _base += 0.15
        return min(0.95, _base)


# ---- smoke ----
def _check():
    _d = IntegerOverflowDetector()

    # mul cx, 0x100 → 若cx来自网络输入且16位→可能溢出
    _op = _d.scan_arithmetic(0x1000, "mul", "cx, 0x100", operand_bits=16)
    assert _op and _op.has_overflow_risk, "16-bit mul should have overflow risk"

    _d.mark_tainted(0x1000)
    _findings = _d.check_sink(0x1020, "call malloc", [0x1000])
    assert len(_findings) == 1
    assert _findings[0].pattern == OverflowPattern.MUL_TO_MALLOC

    # shl eax, 2 → 32位左移2位, 用于数组索引
    _op2 = _d.scan_arithmetic(0x2000, "shl", "eax, 2", operand_bits=32)
    _d.mark_tainted(0x2000)
    _d.check_sink(0x2020, "mov [rbx+rax*4]", [0x2000])

    _report = _d.generate_report()
    print(f"[int_overflow] findings={_report['total_findings']} "
          f"by_pattern={_report['by_pattern']}")
    print("[OK] integer_overflow_detector passed")


if __name__ == "__main__":
    _check()
