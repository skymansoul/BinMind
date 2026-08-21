# Tool invocation bridge for differential_fuzz_oracle.py
# 通过subprocess调用objdump/radare2等命令行反汇编器
import re
import hashlib
import subprocess
from typing import Dict, Set, Tuple, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


# ---- 本地类型定义 (与differential_fuzz_oracle.py保持接口兼容) ----
class ToolName(str, Enum):
    GHIDRA = 'ghidra'
    IDA = 'ida'
    RADARE2 = 'radare2'
    BINARY_NINJA = 'binary_ninja'
    CUSTOM = 'custom'

@dataclass
class ToolOutput:
    tool: 'ToolName'
    instructions: Dict[int, str]
    cfg_edges: Set[Tuple[int, int]]
    function_boundaries: Set[Tuple[int, int]]
    basic_blocks: List[Tuple[int, int]]
    function_names: Dict[int, str]
    error_count: int = 0
    warnings: List[str] = field(default_factory=list)

class ToolInvoker:
    """调用外部二进制分析工具并解析输出为ToolOutput格式。

    支持的工具（按可用性降序）:
      objdump: GNU binutils的一部分，Linux/Mac普遍可用
      r2/radare2: 需单独安装，提供更丰富的反汇编信息
      llvm-objdump: LLVM工具链的一部分

    对未安装的工具，invoke()返回含error_count的ToolOutput。
    """

    @staticmethod
    def invoke_objdump(binary_path: str,
                       base_addr: int = 0) -> ToolOutput:
        """调用objdump反汇编二进制文件。

        objdump -d 输出格式:
          401000: 55             push rbp
          401001: 48 89 e5       mov rbp, rsp
        """
        instructions: Dict[int, str] = {}
        cfg_edges: Set[Tuple[int, int]] = set()
        func_boundaries: Set[Tuple[int, int]] = set()
        errors = 0
        warnings = []

        try:
            result = subprocess.run(
                ['objdump', '-d', binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return ToolOutput(
                    tool=ToolName.CUSTOM,
                    instructions={}, cfg_edges=set(),
                    function_boundaries=set(), basic_blocks=[],
                    function_names={}, error_count=1,
                    warnings=[f"objdump returned {result.returncode}"])

            current_func_start = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                # 函数标签: 0000000000401000 <main>:
                if '<' in line and '>:' in line:
                    if current_func_start is not None:
                        func_boundaries.add((current_func_start, prev_addr))
                    m = re.search(r'([0-9a-f]+)\s*<(\w+)>:', line)
                    if m:
                        current_func_start = int(m.group(1), 16)
                        prev_addr = current_func_start
                    continue

                # 指令行: 401000: 55    push rbp
                m = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f ]+)\s+(.+)', line)
                if m:
                    addr = int(m.group(1), 16)
                    instr = m.group(3).strip()
                    instructions[addr] = instr
                    if addr > 0 and prev_addr > 0:
                        cfg_edges.add((prev_addr, addr))
                    prev_addr = addr
                    # 检测分支
                    if instr.startswith(('j', 'call', 'ret')):
                        m_target = re.search(r'(0x[0-9a-f]+)', instr)
                        if m_target:
                            target = int(m_target.group(1), 16)
                            cfg_edges.add((addr, target))

            if current_func_start is not None:
                func_boundaries.add((current_func_start, prev_addr))

        except FileNotFoundError:
            errors = 1
            warnings.append("objdump not found in PATH")
        except subprocess.TimeoutExpired:
            errors = 1
            warnings.append("objdump timed out")
        except Exception as e:
            errors = 1
            warnings.append(f"objdump error: {e}")

        return ToolOutput(
            tool=ToolName.CUSTOM if errors > 0 else ToolName.CUSTOM,
            instructions=instructions,
            cfg_edges=cfg_edges,
            function_boundaries=func_boundaries,
            basic_blocks=[], function_names={},
            error_count=errors, warnings=warnings)

    @staticmethod
    def compare_binary_across_tools(
            binary_path: str,
            oracle: DifferentialFuzzOracle
    ) -> ConsensusReport:
        """对同一二进制调用多个工具，返回共识分析报告。

        至少尝试objdump。若radare2可用则也调用。
        """
        objdump_out = ToolInvoker.invoke_objdump(binary_path)
        objdump_out.tool = ToolName.CUSTOM  # 使用CUSTOM标记objdump
        oracle.add_tool_output(objdump_out)

        # 尝试radare2
        try:
            result = subprocess.run(
                ['r2', '-q', '-c', 'aaa; pdf @ main', binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                r2_out = ToolOutput(
                    tool=ToolName.RADARE2,
                    instructions={}, cfg_edges=set(),
                    function_boundaries=set(), basic_blocks=[],
                    function_names={}, error_count=0)
                for line in result.stdout.split('\n'):
                    m = re.match(r'\s*0x([0-9a-f]+)\s+(.+)', line.strip())
                    if m:
                        addr = int(m.group(1), 16)
                        r2_out.instructions[addr] = m.group(2).strip()
                oracle.add_tool_output(r2_out)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass  # radare2不可用，仅使用objdump的结果

        return oracle.analyze_consensus()


# demo entry
