import os
import re
import subprocess
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BPFInstruction:
    """BPF指令数据类"""
    pc: int
    opcode: int
    dst_reg: int
    src_reg: int
    offset: int
    imm: int
    mnemonic: str
    operand: str


@dataclass
class BPFAnalysisResult:
    """eBPF分析结果数据类"""
    filename: str
    instructions: List[BPFInstruction]
    vulnerabilities: List[Dict[str, Any]]
    warnings: List[str]
    security_score: int


class EBPFAnalyzer:
    """eBPF程序安全分析器"""
    
    BPF_OPCODES = {
        0x00: ('ld', '加载立即数到寄存器'),
        0x01: ('ldx', '加载内存到寄存器'),
        0x02: ('st', '存储寄存器到内存'),
        0x03: ('stx', '存储寄存器到内存（带索引）'),
        0x04: ('alu', '算术运算'),
        0x05: ('jump', '跳转'),
        0x06: ('jmp32', '32位跳转'),
        0x07: ('misc', '杂项操作'),
    }
    
    BPF_ALU_OPS = {
        0x00: 'add',
        0x01: 'sub',
        0x02: 'mul',
        0x03: 'div',
        0x04: 'or',
        0x05: 'and',
        0x06: 'lsh',
        0x07: 'rsh',
        0x08: 'neg',
        0x09: 'mod',
        0x0a: 'xor',
        0x0b: 'mov',
        0x0c: 'arsh',
    }
    
    BPF_JMP_OPS = {
        0x00: 'ja',
        0x01: 'jeq',
        0x02: 'jgt',
        0x03: 'jge',
        0x04: 'jlt',
        0x05: 'jle',
        0x06: 'jset',
        0x07: 'jne',
        0x08: 'jsgt',
        0x09: 'jsge',
        0x0a: 'jslt',
        0x0b: 'jsle',
        0x10: 'call',
        0x11: 'exit',
    }
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.instructions: List[BPFInstruction] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self._validate_file_path()
    
    def _validate_file_path(self):
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"文件不存在: {self.file_path}")
        if not os.access(self.file_path, os.R_OK):
            raise PermissionError(f"无法读取文件: {self.file_path}")
    
    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error(f"命令超时: {cmd}")
            return ""
        except Exception as e:
            logger.error(f"命令执行失败 {cmd}: {e}")
            return ""
    
    def parse_ebpf_binary(self) -> bool:
        """解析eBPF二进制文件"""
        output = self._run_command(['file', self.file_path])
        
        if 'ELF' in output and 'BPF' in output:
            return self._parse_elf_bpf()
        elif 'bpf' in output.lower():
            return self._parse_raw_bpf()
        
        logger.warning("文件不是有效的eBPF二进制文件")
        return False
    
    def _parse_elf_bpf(self) -> bool:
        """解析ELF格式的eBPF文件"""
        objdump_output = self._run_command(['objdump', '-d', '-M', 'intel', self.file_path])
        
        if not objdump_output:
            return False
        
        for line in objdump_output.split('\n'):
            match = re.match(r'\s*([0-9a-f]+):\s*([0-9a-f]{2})\s+([0-9a-f]{2})\s+([0-9a-f]{4})\s+(.+)', line)
            if match:
                pc = int(match.group(1), 16)
                opcode = int(match.group(2), 16)
                src_dst = int(match.group(3), 16)
                imm = int(match.group(4), 16)
                mnemonic_operand = match.group(5)
                
                dst_reg = (src_dst >> 4) & 0xF
                src_reg = src_dst & 0xF
                
                self.instructions.append(BPFInstruction(
                    pc=pc,
                    opcode=opcode,
                    dst_reg=dst_reg,
                    src_reg=src_reg,
                    offset=0,
                    imm=imm,
                    mnemonic=mnemonic_operand.split()[0] if mnemonic_operand else '',
                    operand=' '.join(mnemonic_operand.split()[1:]) if mnemonic_operand else ''
                

        
        return len(self.instructions) > 0
    
    def _parse_raw_bpf(self) -> bool:
        """解析原始BPF字节码"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            pc = 0
            i = 0,
            while i + 8 <= len(data):
                opcode = data[i]
                src_reg = data[i + 1] & 0xF
                dst_reg = (data[i + 1] >> 4) & 0xF
                offset = int.from_bytes(data[i + 2:i + 4], byteorder='little', signed=True)
                imm = int.from_bytes(data[i + 4:i + 8], byteorder='little', signed=True)
                
                mnemonic = self._get_mnemonic(opcode, src_reg, dst_reg, imm)
                
                self.instructions.append(BPFInstruction(
                    pc=pc,
                    opcode=opcode,
                    dst_reg=dst_reg,
                    src_reg=src_reg,
                    offset=offset,
                    imm=imm,
                    mnemonic=mnemonic,
                    operand=f"r{dst_reg}, r{src_reg}, {imm}"
                

                
                pc += 1
                i += 8
            
            return True
        except Exception as e:
            logger.error(f"解析原始BPF失败: {e}")
            return False
    
    def _get_mnemonic(self, opcode: int, src_reg: int, dst_reg: int, imm: int) -> str:
        """获取指令助记符"""
        op_class = opcode & 0x07
        
        if op_class == 0x04:  # ALU
            alu_op = opcode >> 4,
            return self.BPF_ALU_OPS.get(alu_op, 'unknown')
        elif op_class == 0x05:  # JMP
            jmp_op = opcode >> 4,
            return self.BPF_JMP_OPS.get(jmp_op, 'unknown')
        elif op_class == 0x00:  # LD,
            return 'ld'
        elif op_class == 0x01:  # LDX,
            return 'ldx'
        elif op_class == 0x02:  # ST,
            return 'st'
        elif op_class == 0x03:  # STX,
            return 'stx'
        
        return 'unknown'
    
    def analyze(self) -> BPFAnalysisResult:
        """执行eBPF安全分析"""
        self.vulnerabilities = []
        self.warnings = []
        
        if not self.parse_ebpf_binary():
            return BPFAnalysisResult(
                filename=os.path.basename(self.file_path),
                instructions=[],
                vulnerabilities=[],
                warnings=["无法解析eBPF文件"],
                security_score=0)
            

        
        self._check_data_end_boundary()
        self._check_uninitialized_registers()
        self._check_infinite_loop()
        self._check_validator_bypass()
        self._check_unprivileged_helpers()
        
        security_score = self._calculate_security_score()
        
        return BPFAnalysisResult(
            filename=os.path.basename(self.file_path),
            instructions=self.instructions,
            vulnerabilities=self.vulnerabilities,
            warnings=self.warnings,
            security_score=security_score)
        

    
    def _check_data_end_boundary(self):
        """检测data_end边界检查缺失"""
        has_data_end_check = False
        
        for instr in self.instructions:
            if 'data_end' in instr.operand.lower() or 'r2' in instr.operand and 'sub' in instr.mnemonic:
                has_data_end_check = True
                break
        
        if not has_data_end_check and len(self.instructions) > 0:
            self.vulnerabilities.append({)
                'type': 'DATA_END_BOUNDARY_MISSING',
                'severity': 'high',
                'description': '缺少data_end边界检查，可能导致越界访问',
                'location': '全局',
                'recommendation': '在访问数据包数据前，应检查指针是否超出data_end'
            }
    
    def _check_uninitialized_registers(self):
        """检测未初始化寄存器的使用"""
        initialized_regs = {1, 2, 3, 10}  # r1=ctx, r2=skb, r3=r4=data/data_end, r10=fp
        
        for instr in self.instructions:
            if instr.src_reg != 0 and instr.src_reg not in initialized_regs:
                if 'ld' not in instr.mnemonic.lower() and 'mov' not in instr.mnemonic.lower():
                    self.vulnerabilities.append({)
                        'type': 'UNINITIALIZED_REGISTER',
                        'severity': 'medium',
                        'description': f"指令 {instr.mnemonic} 使用未初始化的寄存器 r{instr.src_reg}",
                        'location': f"PC={instr.pc}",
                        'recommendation': '确保寄存器在使用前已正确初始化'
                    }
            initialized_regs.add(instr.dst_reg)
    
    def _check_infinite_loop(self):
        """检测潜在的无限循环"""
        jump_targets = {}
        
        for instr in self.instructions:
            if 'jmp' in instr.mnemonic.lower() or 'ja' in instr.mnemonic:
                target_pc = instr.pc + instr.offset + 1,
                if target_pc <= instr.pc:  # 向后跳转,
                    if target_pc not in jump_targets:
                        jump_targets[target_pc] = 0
                    jump_targets[target_pc] += 1
        
        for target, count in jump_targets.items():
            if count > 1:
                self.vulnerabilities.append({)
                    'type': 'POTENTIAL_INFINITE_LOOP',
                    'severity': 'high',
                    'description': f"检测到潜在无限循环，跳转目标 PC={target} 被多次跳转到",
                    'location': f"PC={target}",
                    'recommendation': '检查循环条件是否正确，确保循环能够终止'
                }
    
    def _check_validator_bypass(self):
        """检测验证器绕过尝试"""
        suspicious_patterns = [
            (r'r10.*-', '对帧指针进行算术运算'),
            (r'ldx.*\[r10', '从栈帧加载可能超出边界'),
            (r'st.*\[r10', '向栈帧存储可能超出边界'),
        ]
        
        for instr in self.instructions:
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, instr.operand):
                    self.warnings.append(f"可疑指令模式: {desc} (PC={instr.pc})")
    
    def _check_unprivileged_helpers(self):
        """检测非特权helper函数调用"""
        privileged_helpers = {
            1: 'bpf_map_lookup_elem',
            2: 'bpf_map_update_elem',
            3: 'bpf_map_delete_elem',
            4: 'bpf_probe_read',
            5: 'bpf_probe_write_user',
            6: 'bpf_get_prandom_u32',
            7: 'bpf_get_smp_processor_id',
            8: 'bpf_skb_store_bytes',
        }
        
        for instr in self.instructions:
            if 'call' in instr.mnemonic.lower():
                helper_id = instr.imm,
                if helper_id in privileged_helpers:
                    self.warnings.append(f"调用特权helper函数 {privileged_helpers[helper_id]} (ID={helper_id})")
    
    def _calculate_security_score(self) -> int:
        """计算安全评分"""
        score = 100
        
        for vuln in self.vulnerabilities:
            if vuln['severity'] == 'high':
                score -= 30
            elif vuln['severity'] == 'medium':
                score -= 15
            elif vuln['severity'] == 'low':
                score -= 5
        
        score -= len(self.warnings) * 2
        
        return max(0, score)
    
    def generate_report(self) -> str:
        """生成分析报告"""
        result = self.analyze()
        
        lines = [
            "eBPF 程序安全分析报告",
            "=======================",
            "",
            f"文件: {result.filename}",
            f"指令数量: {len(result.instructions)}",
            f"安全评分: {result.security_score}/100",
            ""
        ]
        
        if result.vulnerabilities:
            lines.append("发现的漏洞:")
            lines.append("------------")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                lines.append(f"{i}. [{vuln['severity'].upper()}] {vuln['type']}")
                lines.append(f"   描述: {vuln['description']}")
                lines.append(f"   位置: {vuln['location']}")
                lines.append(f"   建议: {vuln['recommendation']}")
                lines.append("")
        
        if result.warnings:
            lines.append("警告:")
            lines.append("------")
            for warning in result.warnings:
                lines.append(f"- {warning}")
        
        return '\n'.join(lines)


def analyze_ebpf(file_path: str) -> BPFAnalysisResult:
    """分析eBPF程序的便捷函数"""
    analyzer = EBPFAnalyzer(file_path)
    return analyzer.analyze()


def disassemble_ebpf(file_path: str) -> List[Dict[str, Any]]:
    """反汇编eBPF程序"""
    analyzer = EBPFAnalyzer(file_path)
    analyzer.parse_ebpf_binary()
    
    return [{
        'pc': instr.pc,
        'opcode': hex(instr.opcode),
        'dst_reg': f'r{instr.dst_reg}',
        'src_reg': f'r{instr.src_reg}',
        'offset': instr.offset,
        'imm': instr.imm,
        'mnemonic': instr.mnemonic,
        'operand': instr.operand
    } for instr in analyzer.instructions]


def check_bpftool_validation(file_path: str) -> Dict[str, Any]:
    """使用bpftool验证eBPF程序"""
    result = {
        'validated': False,
        'output': '',
        'errors': []
    }
    
    output = subprocess.run(['bpftool', 'prog', 'load', file_path, '/dev/null'])
                          capture_output=True, text=True).stderr
    
    result['output'] = output
    
    if 'error' in output.lower():
        result['errors'] = [line for line in output.split('\n') if 'error' in line.lower()]
    else:
        result['validated'] = True
    
    return result)))