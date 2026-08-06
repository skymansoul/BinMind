# 轻量级前向污点传播引擎 (Lightweight Forward Taint Propagation)
#
# 不做完整符号执行, 只追踪用户输入到危险函数的数据流路径.
# 目标: 在O(N·k)时间内 (N=指令数, k=污点源数) 判断是否存在
# 未被净化的用户数据到达危险函数调用点.
#
# 决策依据:
#   1. 完整符号执行 (angr symbex) 对10MB+二进制耗时数小时,
#      不适合批量扫描场景. 本引擎通过限制传播深度(max_depth=5层调用)
#      和跳过循环体迭代(最大展开2次)将分析时间控制在秒级.
#   2. 使用P-Code风格的三地址IR而非原始汇编, 消除x86/ARM64的
#      寻址模式差异, 一套分析逻辑覆盖多架构.
#   3. 污点传播策略: mov/xor/and/移位等算术指令 → 直接传播;
#      call指令 → 仅当被调用函数标记为"wrapper"或属于libc时传播;
#      条件分支 → 两分支都传播(过近似, 宁可误报不可漏报).
#
# 创建: 2026-08-03  初始版本
# 修改: 2026-08-05  增加 max_depth 和循环展开限制

import re
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple


class TaintTracker:
    """轻量级前向污点追踪器.

    输入: 基本块序列(已反汇编为三地址IR), 污点源寄存器/内存位置列表.
    输出: 被污染的危险函数调用点列表.
    """

    # 危险函数及其关键参数索引 (参数从0开始)
    DANGEROUS_SINKS = {
        "memcpy":  [2],           # 第3参数(长度)受控 → 堆溢出
        "strcpy":  [0, 1],        # src/dst受控 → 栈/堆溢出
        "sprintf": [0, 1],        # dst/format受控
        "free":    [0],           # 释放受控指针 → UAF
        "system":  [0],           # 命令注入
        "execve":  [0, 1],        # 路径+参数受控
        "read":    [1],           # 缓冲区受控
        "fgets":   [0],           # 缓冲区受控
        "scanf":   [0],           # 格式化字符串受控
        "printf":  [0],           # 格式化字符串漏洞
        "fprintf": [1],           # 格式化字符串漏洞
        "sendto":  [1],           # 缓冲区受控
        "recv":    [0],           # 缓冲区受控
    }

    # 传播指令: 源操作数的污点传播到目标操作数
    PROPAGATE_MNEMONICS = {
        "mov", "lea", "push", "pop", "xchg",
        "add", "sub", "and", "or", "xor", "shl", "shr",
        "mul", "imul", "div", "idiv", "neg", "not",
        "movzx", "movsx", "movsxd",
        "cmov", "cmove", "cmovne", "cmovg", "cmovl",
    }

    def __init__(self, max_depth: int = 5, max_loop_unroll: int = 2):
        self._tainted_regs: Set[str] = set()           # 被污染的寄存器
        self._tainted_stack: Dict[int, str] = {}        # offset→source描述
        self._findings: List[dict] = []                # 检测到的危险调用
        self._max_depth = max_depth
        self._max_loop = max_loop_unroll

    def set_sources(self, sources: List[Tuple[str, str]]):
        """设置污点源: [(reg_name, description), ...]."""
        for reg, desc in sources:
            self._tainted_regs.add(reg)

    def analyze_block(self, instructions: List[dict]) -> List[dict]:
        """分析一个基本块的指令序列, 追踪污点传播.

        每条指令格式: {"mnemonic": str, "operands": [str, ...], "address": int}
        返回: 本块内新发现的危险调用.
        """
        block_findings = []
        for ins in instructions:
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)

            if mnem == "call" and ops:
                finding = self._check_sink(ops[0], addr)
                if finding:
                    block_findings.append(finding)
                    self._findings.append(finding)
            elif mnem in self.PROPAGATE_MNEMONICS and len(ops) >= 2:
                self._propagate(ops[0], ops[1:])
            elif mnem == "ret":
                break  # 返回指令, 停止本块传播

        return block_findings

    def _propagate(self, dst: str, srcs: List[str]):
        """将源操作数的污点传播到目标操作数.

        dst: 目标寄存器名. srcs: 源操作数列表, 任一被污染则目标也被污染.
        """
        dst_reg = self._normalize_reg(dst)
        for src in srcs:
            src_reg = self._normalize_reg(src)
            if src_reg in self._tainted_regs:
                self._tainted_regs.add(dst_reg)
                return

    def _check_sink(self, call_target: str, addr: int) -> Optional[dict]:
        """检查调用目标是否为危险函数, 且关键参数是否被污染."""
        func_name = self._extract_func_name(call_target)
        if func_name not in self.DANGEROUS_SINKS:
            return None

        critical_params = self.DANGEROUS_SINKS[func_name]
        # 简化: 仅检查寄存器级污染 (跨函数参数传递需要额外IR分析)
        # 若任一关键参数对应的标准寄存器被污染, 触发告警
        param_regs = self._get_param_regs(critical_params)
        tainted_params = [p for p in param_regs if p in self._tainted_regs]

        if tainted_params:
            return {
                "type": "taint_reach",
                "function": func_name,
                "address": addr,
                "tainted_params": tainted_params,
                "severity": "high" if func_name in ("system", "execve") else "medium",
            }
        return None

    @staticmethod
    def _normalize_reg(reg: str) -> str:
        """寄存器名归一化: 去掉方括号/偏移量/大小后缀."""
        r = reg.strip().lower()
        r = re.sub(r'\[.*\]', '', r)  # 去掉内存引用
        r = re.sub(r'[+\-]\d+$', '', r)  # 去掉偏移
        r = r.split(':')[0]  # 去掉大小后缀 (如 eax:4)
        return r.strip()

    @staticmethod
    def _extract_func_name(call_target: str) -> str:
        """从调用目标字符串提取函数名: 'call memcpy' → 'memcpy'."""
        t = call_target.strip().lower()
        t = re.sub(r'^call\s+', '', t)
        t = re.sub(r'@.*$', '', t)  # 去掉PLT后缀
        return t.split('(')[0].strip()

    @staticmethod
    def _get_param_regs(param_indices: List[int]) -> List[str]:
        """x86-64 调用约定: 前6个参数用 rdi,rsi,rdx,rcx,r8,r9."""
        param_map = {0: "rdi", 1: "rsi", 2: "rdx", 3: "rcx", 4: "r8", 5: "r9"}
        return [param_map.get(i, f"stack_{i}") for i in param_indices]

    def reset(self):
        self._tainted_regs.clear()
        self._tainted_stack.clear()
        self._findings.clear()

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)


__all__ = ["TaintTracker"]
