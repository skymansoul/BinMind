# objdump -d 输出解析器——从x86-64 ELF二进制中提取结构化反汇编信息
# 为检测管线提供: 指令序列、基本块边界、CFG边
# 无需调试符号或源码——仅依赖objdump文本输出
#
# 设计决策:
#   - 用objdump而非capstone/pyelftools: objdump无处不在, 无需额外依赖
# 基本块识别: 跳转目标+跳转指令作为块边界
#   - CFG构建: 无条件跳转→单边, 条件跳转→双边(fall-through + taken),
#     call→调用边+返回边, ret→无出边

from __future__ import annotations

import re
import subprocess
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class EdgeType(Enum):
    FALL_THROUGH = 0    # 顺序执行
    JUMP = 1            # 无条件跳转
    COND_TAKEN = 2      # 条件跳转(成立)
    COND_NEXT = 3       # 条件跳转(不成立=fall-through)
    CALL = 4            # 函数调用
    RET = 5             # 返回


@dataclass
class CFGEdge:
    src_addr: int
    dst_addr: int
    edge_type: EdgeType


@dataclass
class FunctionInfo:
    """单个函数的完整反汇编信息"""
    name: str
    start_addr: int
    end_addr: int
    instructions: List[str] = field(default_factory=list)
    instr_addrs: List[int] = field(default_factory=list)
    bb_boundaries: List[Tuple[int, int]] = field(default_factory=list)
    cfg_edges: List[Tuple[int, int]] = field(default_factory=list)
    call_sites: List[Tuple[int, str]] = field(default_factory=list)


class ObjdumpParser:
    """objdump -d 输出解析器。

    使用方式:
        parser = ObjdumpParser()
        funcs = parser.parse_binary("/path/to/binary")
        for func in funcs:
            if 'main' in func.name:
                # func.instructions: 指令字符串列表
                # func.bb_boundaries: [(start_idx, end_idx), ...]
                # func.cfg_edges: [(src_bb, dst_bb), ...]
    """

    # objdump函数起始行: 0000000000001149 <main>:
    _FUNC_START = re.compile(
        r'^([0-9a-f]+)\s+<([^>]+)>:\s*$')
    # 指令行: 地址: 字节码\t指令文本
    _INSTR_LINE = re.compile(
        r'^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+(.+)$')
    # 跳转/调用指令
    _JUMP_INSTR = re.compile(
        r'\b(jmp|ja|jae|jb|jbe|jc|jcxz|je|jecxz|jg|jge|jl|jle|'
        r'jna|jnae|jnb|jnbe|jnc|jne|jng|jnge|jnl|jnle|jno|jnp|'
        r'jns|jnz|jo|jp|jpe|jpo|js|jz|loop|loope|loopne|call|ret)\b', re.I)
    # 条件跳转(不是无条件jmp/ret)
    _COND_JUMP = re.compile(
        r'\b(ja|jae|jb|jbe|jc|jcxz|je|jecxz|jg|jge|jl|jle|'
        r'jna|jnae|jnb|jnbe|jnc|jne|jng|jnge|jnl|jnle|jno|jnp|'
        r'jns|jnz|jo|jp|jpe|jpo|js|jz|loop|loope|loopne)\b', re.I)
    # 无条件跳转
    _UNCOND_JUMP = re.compile(r'\b(jmp|ret)\b', re.I)
    # call指令
    _CALL_INSTR = re.compile(r'\bcall\b', re.I)

    def __init__(self, objdump_path: str = 'objdump'):
        self._objdump = objdump_path

    def parse_binary(self, binary_path: str) -> List[FunctionInfo]:
        """解析整个二进制文件——返回所有函数的FunctionInfo列表"""
        disasm = self._run_objdump(binary_path)
        return self._parse_output(disasm)

    def parse_function(self, binary_path: str,
                        func_name: str) -> Optional[FunctionInfo]:
        """解析单个函数"""
        funcs = self.parse_binary(binary_path)
        for f in funcs:
            if f.name == func_name:
                return f
        # 模糊匹配
        for f in funcs:
            if func_name in f.name:
                return f
        return None

    def _run_objdump(self, binary_path: str) -> str:
        """执行 objdump -d -M intel"""
        import os as _os
        _path = _os.path.abspath(str(binary_path))
        # Windows: MinGW gcc自动加.exe后缀
        if not _os.path.exists(_path) and _os.name == 'nt':
            if _os.path.exists(_path + '.exe'):
                _path = _path + '.exe'
        try:
            result = subprocess.run(
                [self._objdump, '-d', '-M', 'intel', _path],
                capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.warning("objdump returned %d: %s",
                             result.returncode, result.stderr[:200])
            return result.stdout
        except FileNotFoundError:
            logger.error("objdump not found at '%s'", self._objdump)
            return ""
        except subprocess.TimeoutExpired:
            logger.error("objdump timed out on %s", binary_path)
            return ""

    def _parse_output(self, disasm: str) -> List[FunctionInfo]:
        """解析objdump输出——提取函数、指令、基本块、CFG"""
        funcs = []
        current_func = None
        current_instrs = []
        current_addrs = []

        for line in disasm.split('\n'):
            line = line.rstrip()
            if not line:
                continue

            # 函数起始
            mf = self._FUNC_START.match(line)
            if mf:
                if current_func is not None and current_instrs:
                    self._finalize_function(current_func, current_instrs,
                                            current_addrs)
                    funcs.append(current_func)
                current_func = FunctionInfo(
                    name=mf.group(2),
                    start_addr=int(mf.group(1), 16),
                    end_addr=0)
                current_instrs = []
                current_addrs = []
                continue

            # 指令行
            mi = self._INSTR_LINE.match(line)
            if mi and current_func is not None:
                addr = int(mi.group(1), 16)
                instr_text = mi.group(3).strip()
                # 清理指令文本: 去掉注释部分
                if '#' in instr_text:
                    instr_text = instr_text.split('#')[0].strip()
                current_instrs.append(instr_text)
                current_addrs.append(addr)

        # 最后一个函数
        if current_func is not None and current_instrs:
            self._finalize_function(current_func, current_instrs,
                                    current_addrs)
            funcs.append(current_func)

        return funcs

    def _finalize_function(self, func: FunctionInfo,
                           instructions: List[str],
                           addrs: List[int]):
        """补全函数信息: 基本块、CFG、调用点"""
        func.instructions = instructions
        func.instr_addrs = addrs
        if addrs:
            func.end_addr = addrs[-1]

        n = len(instructions)
        if n == 0:
            return

        # 找基本块入口(leader)指令索引
        leaders: Set[int] = {0}  # 第一条指令肯定是leader
        addr_to_idx: Dict[int, int] = {a: i for i, a in enumerate(addrs)}

        for i, instr in enumerate(instructions):
            # 跳转目标 → 新基本块入口
            target = self._extract_jump_target(instr)
            if target is not None and target in addr_to_idx:
                leaders.add(addr_to_idx[target])
            # 跳转指令 → 下一条指令是新基本块入口(除非是无条件跳转)
            if self._JUMP_INSTR.search(instr):
                if i + 1 < n:
                    leaders.add(i + 1)

        sorted_leaders = sorted(leaders)

        # 构建基本块边界 [(start_idx, end_idx), ...]
        bb_boundaries = []
        for j, leader in enumerate(sorted_leaders):
            start = leader
            end = (sorted_leaders[j + 1] if j + 1 < len(sorted_leaders)
                   else n)
            bb_boundaries.append((start, end))
        func.bb_boundaries = bb_boundaries

        # 构建bb_id映射
        bb_of_instr: Dict[int, int] = {}
        for bb_id, (s, e) in enumerate(bb_boundaries):
            for idx in range(s, e):
                bb_of_instr[idx] = bb_id

        # 构建CFG边
        cfg_edges: List[Tuple[int, int]] = []
        for bb_id, (s, e) in enumerate(bb_boundaries):
            if e == 0:
                continue
            last_idx = e - 1
            if last_idx >= n:
                continue
            last_instr = instructions[last_idx].lower()

            # 条件跳转: taken边 + fall-through边
            if self._COND_JUMP.search(last_instr):
                target = self._extract_jump_target(last_instr)
                if target is not None and target in addr_to_idx:
                    tgt_idx = addr_to_idx[target]
                    tgt_bb = bb_of_instr.get(tgt_idx)
                    if tgt_bb is not None:
                        cfg_edges.append((bb_id, tgt_bb))
                # fall-through到下一个块
                if bb_id + 1 < len(bb_boundaries):
                    cfg_edges.append((bb_id, bb_id + 1))

            # 无条件跳转: 仅taken边
            elif self._UNCOND_JUMP.search(last_instr):
                if 'ret' in last_instr:
                    continue  # ret无出边
                target = self._extract_jump_target(last_instr)
                if target is not None and target in addr_to_idx:
                    tgt_idx = addr_to_idx[target]
                    tgt_bb = bb_of_instr.get(tgt_idx)
                    if tgt_bb is not None:
                        cfg_edges.append((bb_id, tgt_bb))

            # call: 调用边 + fall-through(返回)边
            elif self._CALL_INSTR.search(last_instr):
                target = self._extract_jump_target(last_instr)
                if target is not None:
                    # call被当作函数调用点记录
                    func.call_sites.append((addrs[last_idx]
                                           if last_idx < len(addrs) else 0,
                                           hex(target) if target else ''))
                if bb_id + 1 < len(bb_boundaries):
                    cfg_edges.append((bb_id, bb_id + 1))

            # 普通指令: fall-through
            else:
                if bb_id + 1 < len(bb_boundaries):
                    cfg_edges.append((bb_id, bb_id + 1))

        func.cfg_edges = cfg_edges

    def _extract_jump_target(self, instr: str) -> Optional[int]:
        """从跳转/调用指令中提取目标地址"""
        # 匹配模式: jmp 0x1234, call 0x1234, je 0x1234
        # Intel语法: jmp   0x1234 <label>
        m = re.search(r'(?:0x)?([0-9a-f]{4,})\b', instr, re.I)
        if m:
            try:
                return int(m.group(1), 16)
            except ValueError:
                return None
        return None
