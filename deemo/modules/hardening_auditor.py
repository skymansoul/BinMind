"""
二进制安全加固审计与自动强化建议模块

对二进制进行全面的安全加固评估，检查编译器/链接器已启用的防御机制，
并给出缺失的加固选项和可能的构建修复建议，甚至可以生成加固后的重打包脚本框架。

检查项目：
- ELF: NX/栈不可执行、RELRO (Full/Partial)、Canary、PIE、FORTIFY_SOURCE、CET (IBT/SHSTK)
- PE: NX/DEP、ASLR、SafeSEH、Control Flow Guard、Authenticode签名、High Entropy VA
- Mach-O: PIE、Canary、ARC、栈保护
"""

import os
import re
import struct
import subprocess
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class HardeningStatus(Enum):
    """加固状态"""
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PARTIAL = "Partial"
    UNKNOWN = "Unknown"


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class HardeningCheck:
    """加固检查项"""
    name: str
    description: str
    status: HardeningStatus
    risk_level: RiskLevel
    current_value: str = ""
    recommended_value: str = ""
    fix_command: str = ""
    cve_references: List[str] = field(default_factory=list)
    details: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'risk_level': self.risk_level.value,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
            'fix_command': self.fix_command,
            'cve_references': self.cve_references,
            'details': self.details
        }


@dataclass
class HardeningAuditReport:
    """加固审计报告"""
    binary_path: str
    binary_format: str
    checks: List[HardeningCheck] = field(default_factory=list)
    overall_score: int = 0
    risk_level: RiskLevel = RiskLevel.INFO
    recommendations: List[str] = field(default_factory=list)
    hardening_script: str = ""
    audit_success: bool = False
    error_message: str = ""
    
    def get_enabled_checks(self) -> List[HardeningCheck]:
        return [c for c in self.checks if c.status == HardeningStatus.ENABLED]
    
    def get_disabled_checks(self) -> List[HardeningCheck]:
        return [c for c in self.checks if c.status == HardeningStatus.DISABLED]
    
    def get_failed_checks(self) -> List[HardeningCheck]:
        return [c for c in self.checks if c.status in [HardeningStatus.DISABLED, HardeningStatus.UNKNOWN]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'binary_format': self.binary_format,
            'checks': [c.to_dict() for c in self.checks],
            'overall_score': self.overall_score,
            'risk_level': self.risk_level.value,
            'recommendations': self.recommendations,
            'hardening_script': self.hardening_script,
            'audit_success': self.audit_success,
            'error_message': self.error_message
        }


@dataclass
class HardeningRecommendation:
    """加固建议"""
    category: str
    issue: str
    solution: str
    priority: RiskLevel
    commands: List[str] = field(default_factory=list)
    explanation: str = ""


class HardeningAuditor:
    """
    二进制安全加固审计器
    
    对 ELF/PE/Mach-O 二进制进行全面的安全加固评估，
    并提供自动化的强化建议和修复脚本。
    """
    
    def __init__(self, binary_path: str, timeout: int = 120):
        """
        初始化审计器
        
        Args:
            binary_path: 二进制文件路径
            timeout: 审计超时时间
        """
        self.binary_path = binary_path
        self.timeout = timeout
        self.binary_format = self._detect_format()
        
    def _detect_format(self) -> str:
        """检测二进制格式"""
        try:
            with open(self.binary_path, 'rb') as f:
                header = f.read(16)
                
            if header[:4] == b'\x7fELF':
                return 'ELF'
            elif header[:2] == b'MZ':
                return 'PE'
            elif header[:4] in [b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', 
                                b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe']:
                return 'MACH-O'
            else:
                return 'UNKNOWN'
        except Exception as e:
            logger.error(f"检测二进制格式失败: {e}")
            return 'UNKNOWN'
    
    def audit(self) -> HardeningAuditReport:
        """
        执行全面的安全加固审计
        
        Returns:
            HardeningAuditReport 审计报告
        """
        logger.info(f"开始审计二进制文件: {self.binary_path}")
        
        report = HardeningAuditReport(
            binary_path=self.binary_path,
            binary_format=self.binary_format
        )
        
        try:
            if self.binary_format == 'ELF':
                self._audit_elf(report)
            elif self.binary_format == 'PE':
                self._audit_pe(report)
            elif self.binary_format == 'MACH-O':
                self._audit_macho(report)
            else:
                report.error_message = "不支持的二进制格式"
                return report
            
            self._calculate_overall_score(report)
            self._generate_hardening_script(report)
            
            report.audit_success = True
            logger.info(f"审计完成，整体评分: {report.overall_score}/100")
            
        except Exception as e:
            logger.error(f"审计失败: {e}")
            report.error_message = str(e)
        
        return report
    
    def _audit_elf(self, report: HardeningAuditReport) -> None:
        """审计 ELF 二进制"""
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                self._check_nx_elf(elf, report)
                self._check_relro_elf(elf, report)
                self._check_pie_elf(elf, report)
                self._check_canary_elf(elf, report)
                self._check_fortify_source_elf(elf, report)
                self._check_cet_elf(elf, report)
                self._check_stack_protector_elf(elf, report)
                self._check_bind_now_elf(elf, report)
                self._check_glibc_hooks_elf(elf, report)
                
        except ImportError:
            logger.warning("pyelftools 不可用，使用 readelf 进行审计")
            self._audit_elf_with_readelf(report)
        except Exception as e:
            logger.error(f"ELF 审计失败: {e}")
            raise
    
    def _check_nx_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 NX (不可执行位)"""
        try:
            has_nx = True
            for segment in elf.iter_phdrs():
                if segment['p_type'] == 'PT_GNU_STACK':
                    if segment['p_flags'] & 0x1:
                        has_nx = False
                    break
            
            check = HardeningCheck(
                name='NX (Non-Executable Stack)',
                description='栈内存页不可执行，防止 shellcode 执行',
                status=HardeningStatus.ENABLED if has_nx else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not has_nx else RiskLevel.INFO,
                current_value='启用' if has_nx else '禁用',
                recommended_value='启用',
                fix_command='gcc -z noexecstack -o binary binary.c',
                details='NX 位确保栈上的数据不能作为代码执行'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"NX 检查失败: {e}")
    
    def _check_relro_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 RELRO"""
        try:
            relro_status = HardeningStatus.UNKNOWN
            relro_value = '未知'
            
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_GNU_RELRO':
                    relro_status = HardeningStatus.PARTIAL
                    relro_value = 'Partial RELRO'
                    break
            
            for section in elf.iter_sections():
                if section.name == '.data.rel.ro':
                    relro_status = HardeningStatus.ENABLED
                    relro_value = 'Full RELRO'
                    break
            
            check = HardeningCheck(
                name='RELRO (Relocation Read-Only)',
                description='GOT 表只读，防止 GOT覆写攻击',
                status=relro_status,
                risk_level=RiskLevel.MEDIUM if relro_status != HardeningStatus.ENABLED else RiskLevel.INFO,
                current_value=relro_value,
                recommended_value='Full RELRO',
                fix_command='gcc -Wl,-z,relro,-z,now -o binary binary.c',
                details='Full RELRO 在加载时解析所有符号并标记 GOT 只读'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"RELRO 检查失败: {e}")
    
    def _check_pie_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 PIE (位置无关可执行文件)"""
        try:
            is_pie = elf.header['e_type'] == 'ET_DYN'
            
            check = HardeningCheck(
                name='PIE (Position Independent Executable)',
                description='地址空间布局随机化，增加利用难度',
                status=HardeningStatus.ENABLED if is_pie else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if not is_pie else RiskLevel.INFO,
                current_value='启用 (PIE)' if is_pie else '禁用 (ET_EXEC)',
                recommended_value='启用',
                fix_command='gcc -fPIE -pie -o binary binary.c',
                details='PIE 使代码段地址随机化，增大 ROP 利用难度'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"PIE 检查失败: {e}")
    
    def _check_canary_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查栈保护 Canary"""
        try:
            has_canary = False
            
            for section in elf.iter_sections():
                if '__stack_chk_fail' in section.name or '__stack_chk_guard' in section.name:
                    has_canary = True
                    break
                if '.note.GNU-stack' in section.name:
                    data = section.data() if hasattr(section, 'data') else b''
                    if b'stack-protector' in data.lower():
                        has_canary = True
                        break
            
            for symbol in elf.iter_symbols():
                if '__stack_chk_fail' in symbol.name:
                    has_canary = True
                    break
            
            check = HardeningCheck(
                name='Stack Canary (栈溢出检测)',
                description='在栈帧中插入 Canary 值，检测栈溢出',
                status=HardeningStatus.ENABLED if has_canary else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not has_canary else RiskLevel.INFO,
                current_value='启用' if has_canary else '禁用',
                recommended_value='启用',
                fix_command='gcc -fstack-protector-strong -o binary binary.c',
                details='Canary 值在函数返回前检查，发现溢出时终止程序'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Canary 检查失败: {e}")
    
    def _check_fortify_source_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 FORTIFY_SOURCE"""
        try:
            has_fortify = False
            fortify_level = 0
            
            for section in elf.iter_sections():
                if section.name.startswith('.text'):
                    data = section.data() if hasattr(section, '__bytes__') else b''
                    if b'__fortify_fail' in data:
                        has_fortify = True
                        fortify_level = 2
                        break
                    elif b'__chk' in data:
                        has_fortify = True
                        fortify_level = max(fortify_level, 1)
            
            check = HardeningCheck(
                name='FORTIFY_SOURCE',
                description='编译时检查危险的内存函数使用',
                status=HardeningStatus.ENABLED if has_fortify else HardeningStatus.DISABLED,
                risk_level=RiskLevel.LOW if not has_fortify else RiskLevel.INFO,
                current_value=f'Level {fortify_level}' if has_fortify else '禁用',
                recommended_value='Level 2',
                fix_command='gcc -D_FORTIFY_SOURCE=2 -O2 -o binary binary.c',
                details='_FORTIFY_SOURCE=2 提供更强的运行时检查'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"FORTIFY_SOURCE 检查失败: {e}")
    
    def _check_cet_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 CET (Intel CET / ARM PAC)"""
        try:
            has_cet = False
            cet_type = ''
            
            for section in elf.iter_sections():
                if section.name == '.note.gnu.property':
                    data = section.data()
                    if len(data) >= 32:
                        for i in range(len(data) - 8):
                            if data[i:i+4] == b'GNU' and data[i+4] == 0:
                                flags = data[i+8:i+12]
                                if len(flags) >= 4:
                                    if flags[0] & 0x01:
                                        has_cet = True
                                        cet_type = 'IBT (Indirect Branch Tracking)'
                                    if flags[0] & 0x02:
                                        has_cet = True
                                        cet_type = 'SHSTK (Shadow Stack)'
                                    if has_cet:
                                        break
                    break
            
            if not has_cet:
                for segment in elf.iter_segments():
                    if segment['p_type'] == 'PT_GNU_PROPERTY':
                        prop_data = segment.data()
                        if b'GNU_PROPERTY_X86_FEATURE_1_AND' in prop_data:
                            has_cet = True
                            cet_type = 'IBT/SHSTK'
                            break
            
            check = HardeningCheck(
                name='CET (Control-flow Enforcement Technology)',
                description='Intel CET 防护：IBT 验证间接跳转，SHSTK 保护返回地址',
                status=HardeningStatus.ENABLED if has_cet else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not has_cet else RiskLevel.INFO,
                current_value=cet_type if has_cet else '禁用',
                recommended_value='IBT + SHSTK',
                fix_command='gcc -fcf-protection=full -o binary binary.c',
                details='CET 有效防止 ROP/JOP/BROP 利用'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"CET 检查失败: {e}")
    
    def _check_stack_protector_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查栈保护级别"""
        try:
            protector_level = 'none'
            
            for section in elf.iter_sections():
                if '__stack_chk_fail' in section.name:
                    data = section.data() if hasattr(section, 'data') else b''
                    if b'stack-protector-strong' in data or b'sstack-protector-all' in data:
                        protector_level = 'strong'
                    else:
                        protector_level = 'regular'
                    break
            
            check = HardeningCheck(
                name='Stack Protector Level',
                description='栈保护函数级别',
                status=HardeningStatus.ENABLED if protector_level != 'none' else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if protector_level != 'strong' else RiskLevel.INFO,
                current_value=protector_level,
                recommended_value='strong',
                fix_command='gcc -fstack-protector-strong -o binary binary.c',
                details='strong 级别保护所有函数使用局部变量和数组'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Stack Protector 检查失败: {e}")
    
    def _check_bind_now_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 BIND_NOW"""
        try:
            bind_now = False
            
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_GNU_BIND_NOW':
                    bind_now = True
                    break
            
            check = HardeningCheck(
                name='BIND_NOW',
                description='启动时解析所有符号，减少运行时泄漏',
                status=HardeningStatus.ENABLED if bind_now else HardeningStatus.DISABLED,
                risk_level=RiskLevel.LOW if not bind_now else RiskLevel.INFO,
                current_value='启用' if bind_now else '禁用',
                recommended_value='启用 (配合 Full RELRO)',
                fix_command='gcc -Wl,-z,relro,-z,now -o binary binary.c',
                details='BIND_NOW 与 Full RELRO 配合使用'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"BIND_NOW 检查失败: {e}")
    
    def _check_glibc_hooks_elf(self, elf, report: HardeningAuditReport) -> None:
        """检查 glibc 钩子函数可用性"""
        try:
            hooks_available = []
            
            for symbol in elf.iter_symbols():
                name = symbol.name
                if any(hook in name for hook in ['__malloc_hook', '__free_hook', '__realloc_hook', '__memalign_hook', '__after_morecore_hook']):
                    hooks_available.append(name)
            
            check = HardeningCheck(
                name='Glibc Hooks Availability',
                description='glibc 内存分配钩子函数（已废弃于新版本）',
                status=HardeningStatus.DISABLED if hooks_available else HardeningStatus.ENABLED,
                risk_level=RiskLevel.INFO,
                current_value=f'发现 {len(hooks_available)} 个钩子' if hooks_available else '无（安全）',
                recommended_value='无钩子（使用 glibc 2.34+）',
                details='glibc 2.34+ 已移除这些钩子，推荐使用 IO_FILE 链'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Glibc Hooks 检查失败: {e}")
    
    def _audit_elf_with_readelf(self, report: HardeningAuditReport) -> None:
        """使用 readelf 进行 ELF 审计（备用方法）"""
        try:
            result = subprocess.run(
                ['readelf', '-l', '-n', '-S', self.binary_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout
            
            nx_check = HardeningCheck(
                name='NX (Non-Executable Stack)',
                description='栈内存页不可执行',
                status=HardeningStatus.DISABLED if 'GNU_STACK' in output and 'RWE' in output else HardeningStatus.ENABLED if 'GNU_STACK' in output else HardeningStatus.UNKNOWN,
                risk_level=RiskLevel.HIGH,
                current_value='需要人工检查',
                recommended_value='启用'
            )
            report.checks.append(nx_check)
            
        except Exception as e:
            logger.error(f"readelf 审计失败: {e}")
    
    def _audit_pe(self, report: HardeningAuditReport) -> None:
        """审计 PE 二进制"""
        try:
            import pefile
            
            pe = pefile.PE(self.binary_path)
            
            self._check_dep_pe(pe, report)
            self._check_aslr_pe(pe, report)
            self._check_safeseh_pe(pe, report)
            self._check_cfg_pe(pe, report)
            self._check_gs_pe(pe, report)
            self._check_high_entropy_va_pe(pe, report)
            self._check_authenticode_pe(pe, report)
            
        except ImportError:
            logger.error("pefile 未安装，无法审计 PE 文件")
            report.error_message = "pefile 库未安装"
        except Exception as e:
            logger.error(f"PE 审计失败: {e}")
    
    def _check_dep_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 DEP (Data Execution Prevention)"""
        try:
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            nx_enabled = bool(dll_chars & 0x0100)
            
            check = HardeningCheck(
                name='DEP / NX (Data Execution Prevention)',
                description='数据执行保护，防止栈/堆内存执行代码',
                status=HardeningStatus.ENABLED if nx_enabled else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not nx_enabled else RiskLevel.INFO,
                current_value='启用' if nx_enabled else '禁用',
                recommended_value='启用',
                fix_command='链接器选项: /NXCOMPAT',
                details='DEP 强制内存页不可执行'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"DEP 检查失败: {e}")
    
    def _check_aslr_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 ASLR (Address Space Layout Randomization)"""
        try:
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            aslr_enabled = bool(dll_chars & 0x0040)
            
            check = HardeningCheck(
                name='ASLR (Address Space Layout Randomization)',
                description='地址空间布局随机化',
                status=HardeningStatus.ENABLED if aslr_enabled else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if not aslr_enabled else RiskLevel.INFO,
                current_value='启用' if aslr_enabled else '禁用',
                recommended_value='启用',
                fix_command='编译选项: /DYNAMICBASE，链接器选项: /HIGHENTROPYVA:YES',
                details='ASLR 随机化模块加载地址'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"ASLR 检查失败: {e}")
    
    def _check_safeseh_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 SafeSEH"""
        try:
            has_safeseh = False
            
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                for entry in pe.DIRECTORY_ENTRY_LOAD_CONFIG:
                    if hasattr(entry, 'SEHandlerTable') and entry.SEHandlerTable:
                        has_safeseh = True
                        break
            
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            no_seh = bool(dll_chars & 0x0400)
            
            safeseh_enabled = has_safeseh and not no_seh
            
            check = HardeningCheck(
                name='SafeSEH (Structured Exception Handler Overwrite Protection)',
                description='SEH 覆写保护',
                status=HardeningStatus.ENABLED if safeseh_enabled else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if not safeseh_enabled else RiskLevel.INFO,
                current_value='启用' if safeseh_enabled else '禁用',
                recommended_value='启用',
                fix_command='编译选项: /SAFESEH，链接器选项: /SAFESEH:YES',
                details='SafeSEH 在异常处理前验证处理器'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"SafeSEH 检查失败: {e}")
    
    def _check_cfg_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 CFG (Control Flow Guard)"""
        try:
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            cfg_enabled = bool(dll_chars & 0x4000)
            
            check = HardeningCheck(
                name='CFG (Control Flow Guard)',
                description='控制流保护，验证间接调用和跳转目标',
                status=HardeningStatus.ENABLED if cfg_enabled else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not cfg_enabled else RiskLevel.INFO,
                current_value='启用' if cfg_enabled else '禁用',
                recommended_value='启用',
                fix_command='编译选项: /guard:cf，链接器选项: /GUARD:CF',
                details='CFG 有效防止跳转表覆写和虚函数表覆写'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"CFG 检查失败: {e}")
    
    def _check_gs_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 GS (Stack Security)"""
        try:
            has_gs = False
            
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                for entry in pe.DIRECTORY_ENTRY_LOAD_CONFIG:
                    if hasattr(entry, 'SecurityCookie') and entry.SecurityCookie:
                        has_gs = True
                        break
            
            check = HardeningCheck(
                name='GS (Stack Security Checks)',
                description='栈安全检查，类似于栈 Canary',
                status=HardeningStatus.ENABLED if has_gs else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if not has_gs else RiskLevel.INFO,
                current_value='启用' if has_gs else '禁用',
                recommended_value='启用',
                fix_command='编译选项: /GS',
                details='GS 在栈帧中插入安全 cookie'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"GS 检查失败: {e}")
    
    def _check_high_entropy_va_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查高熵 VA (High Entropy VA)"""
        try:
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            heva_enabled = bool(dll_chars & 0x0020)
            
            check = HardeningCheck(
                name='High Entropy VA (64-bit)',
                description='高熵地址空间随机化（64位）',
                status=HardeningStatus.ENABLED if heva_enabled else HardeningStatus.DISABLED,
                risk_level=RiskLevel.LOW if not heva_enabled else RiskLevel.INFO,
                current_value='启用' if heva_enabled else '禁用',
                recommended_value='启用 (64位)',
                fix_command='链接器选项: /HIGHENTROPYVA:YES',
                details='High Entropy VA 提供 64 位地址空间的更多随机化熵'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"High Entropy VA 检查失败: {e}")
    
    def _check_authenticode_pe(self, pe, report: HardeningAuditReport) -> None:
        """检查 Authenticode 签名"""
        try:
            has_signature = False
            
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                security_dir = pe.DIRECTORY_ENTRY_SECURITY
                if security_dir:
                    has_signature = True
            
            check = HardeningCheck(
                name='Authenticode Signature',
                description='代码签名验证（仅表示已签名，不保证无恶意）',
                status=HardeningStatus.ENABLED if has_signature else HardeningStatus.DISABLED,
                risk_level=RiskLevel.INFO,
                current_value='已签名' if has_signature else '未签名',
                recommended_value='建议签名（用于发布版本）',
                fix_command='SignTool sign /f certificate.pfx /p password /t http://timestamp.digicert.com binary.exe',
                details='Authenticode 不能防止二进制被篡改'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Authenticode 检查失败: {e}")
    
    def _audit_macho(self, report: HardeningAuditReport) -> None:
        """审计 Mach-O 二进制"""
        try:
            result = subprocess.run(
                ['otool', '-hv', self.binary_path],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = result.stdout
            
            self._check_macho_pie(output, report)
            self._check_macho_canary(output, report)
            self._check_macho_arc(output, report)
            
        except Exception as e:
            logger.error(f"Mach-O 审计失败: {e}")
    
    def _check_macho_pie(self, output: str, report: HardeningAuditReport) -> None:
        """检查 Mach-O PIE"""
        try:
            is_pie = 'PIE' in output and 'NOUNDEAD' in output
            
            check = HardeningCheck(
                name='PIE (Position Independent Executable)',
                description='位置无关可执行文件',
                status=HardeningStatus.ENABLED if is_pie else HardeningStatus.DISABLED,
                risk_level=RiskLevel.MEDIUM if not is_pie else RiskLevel.INFO,
                current_value='启用' if is_pie else '禁用',
                recommended_value='启用',
                fix_command='clang -fPIE -pie',
                details='PIE 使代码段地址随机化'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Mach-O PIE 检查失败: {e}")
    
    def _check_macho_canary(self, output: str, report: HardeningAuditReport) -> None:
        """检查 Mach-O 栈保护"""
        try:
            has_stack_protector = 'SSP' in output or 'stack_chk' in output.lower()
            
            check = HardeningCheck(
                name='Stack Canary',
                description='栈溢出检测',
                status=HardeningStatus.ENABLED if has_stack_protector else HardeningStatus.DISABLED,
                risk_level=RiskLevel.HIGH if not has_stack_protector else RiskLevel.INFO,
                current_value='启用' if has_stack_protector else '禁用',
                recommended_value='启用',
                fix_command='clang -fstack-protector-strong',
                details='Canary 值检测栈溢出'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Mach-O Canary 检查失败: {e}")
    
    def _check_macho_arc(self, output: str, report: HardeningAuditReport) -> None:
        """检查 ARC (Automatic Reference Counting)"""
        try:
            has_arc = 'OBJC' in output or 'arc' in output.lower()
            
            check = HardeningCheck(
                name='ARC (Automatic Reference Counting)',
                description='自动引用计数（Objective-C 内存管理）',
                status=HardeningStatus.ENABLED if has_arc else HardeningStatus.DISABLED,
                risk_level=RiskLevel.INFO,
                current_value='启用' if has_arc else 'N/A (非 Objective-C)',
                recommended_value='启用 (如使用 Objective-C)',
                fix_command='clang -fobjc-arc',
                details='ARC 自动管理 Objective-C 对象引用'
            )
            report.checks.append(check)
            
        except Exception as e:
            logger.debug(f"Mach-O ARC 检查失败: {e}")
    
    def _calculate_overall_score(self, report: HardeningAuditReport) -> None:
        """计算整体加固评分"""
        if not report.checks:
            return
        
        total_weight = 0
        achieved_weight = 0
        
        weight_map = {
            RiskLevel.CRITICAL: 20,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
            RiskLevel.INFO: 0
        }
        
        for check in report.checks:
            weight = weight_map.get(check.risk_level, 0)
            if weight == 0:
                continue
                
            total_weight += weight
            
            if check.status == HardeningStatus.ENABLED:
                achieved_weight += weight
            elif check.status == HardeningStatus.PARTIAL:
                achieved_weight += weight * 0.5
        
        if total_weight > 0:
            report.overall_score = int((achieved_weight / total_weight) * 100)
        else:
            report.overall_score = 100
        
        if report.overall_score >= 80:
            report.risk_level = RiskLevel.LOW
        elif report.overall_score >= 60:
            report.risk_level = RiskLevel.MEDIUM
        elif report.overall_score >= 40:
            report.risk_level = RiskLevel.HIGH
        else:
            report.risk_level = RiskLevel.CRITICAL
        
        disabled_checks = report.get_failed_checks()
        for check in disabled_checks:
            report.recommendations.append(
                f"启用 {check.name}: {check.fix_command}"
            )
    
    def _generate_hardening_script(self, report: HardeningAuditReport) -> None:
        """生成加固脚本"""
        lines = []
        lines.append("#!/bin/bash")
        lines.append("# 二进制安全加固脚本")
        lines.append(f"# 目标文件: {os.path.basename(self.binary_path)}")
        lines.append(f"# 生成时间: {__import__('datetime').datetime.now().isoformat()}")
        lines.append("")
        lines.append("set -e")
        lines.append("")
        lines.append("# 检测源文件")
        lines.append("SRC_FILE=\"$1\"")
        lines.append("OUTPUT_FILE=\"${2:-hardened_$(basename $SRC_FILE)}\"")
        lines.append("")
        lines.append("if [ -z \"$SRC_FILE\" ]; then")
        lines.append('    echo "用法: $0 <源文件> [输出文件]"')
        lines.append("    exit 1")
        lines.append("fi")
        lines.append("")
        
        disabled_checks = report.get_failed_checks()
        
        if self.binary_format == 'ELF':
            flags = []
            for check in disabled_checks:
                if check.name == 'NX':
                    flags.append('-z noexecstack')
                elif check.name == 'RELRO':
                    flags.append('-Wl,-z,relro,-z,now')
                elif check.name == 'PIE':
                    flags.append('-fPIE -pie')
                elif 'Canary' in check.name:
                    flags.append('-fstack-protector-strong')
                elif 'FORTIFY' in check.name:
                    flags.append('-D_FORTIFY_SOURCE=2 -O2')
                elif 'CET' in check.name:
                    flags.append('-fcf-protection=full')
            
            if flags:
                flags_str = ' '.join(flags)
                lines.append(f"# 推荐编译命令")
                lines.append(f"gcc {flags_str} -o \"$OUTPUT_FILE\" \"$SRC_FILE\"")
                lines.append("")
            
        elif self.binary_format == 'PE':
            lines.append("# MSVC 编译选项")
            lines.append("# cl /GS /DYNAMICBASE /NXCOMPAT /SAFESEH /guard:cf /HIGHENTROPYVA:YES source.cpp /link /OUT:output.exe")
            lines.append("")
        
        lines.append("# 后加固检查")
        lines.append('echo "验证加固状态..."')
        lines.append(f'# 使用 checksec 或类似工具验证')
        lines.append("")
        lines.append('echo "加固完成: $OUTPUT_FILE"')
        
        report.hardening_script = '\n'.join(lines)


def audit_binary(binary_path: str, timeout: int = 120) -> HardeningAuditReport:
    """
    审计二进制文件的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        timeout: 审计超时时间
        
    Returns:
        HardeningAuditReport 审计报告
    """
    auditor = HardeningAuditor(binary_path, timeout)
    return auditor.audit()


def format_audit_report(report: HardeningAuditReport) -> str:
    """
    格式化审计报告为可读字符串
    
    Args:
        report: HardeningAuditReport 对象
        
    Returns:
        格式化的报告字符串
    """
    lines = []
    lines.append("=" * 70)
    lines.append("二进制安全加固审计报告")
    lines.append("=" * 70)
    
    lines.append(f"\n目标文件: {report.binary_path}")
    lines.append(f"文件格式: {report.binary_format}")
    lines.append(f"整体评分: {report.overall_score}/100")
    lines.append(f"风险等级: {report.risk_level.value}")
    lines.append(f"审计状态: {'成功' if report.audit_success else '失败'}")
    
    lines.append("\n" + "-" * 70)
    lines.append("加固检查详情")
    lines.append("-" * 70)
    
    for check in report.checks:
        status_icon = "✓" if check.status == HardeningStatus.ENABLED else "✗" if check.status == HardeningStatus.DISABLED else "◐"
        risk_color = ""
        if check.risk_level == RiskLevel.CRITICAL:
            risk_color = "[CRITICAL]"
        elif check.risk_level == RiskLevel.HIGH:
            risk_color = "[HIGH]"
        elif check.risk_level == RiskLevel.MEDIUM:
            risk_color = "[MEDIUM]"
        
        lines.append(f"\n{status_icon} {check.name} {risk_color}")
        lines.append(f"   状态: {check.status.value} ({check.current_value})")
        lines.append(f"   描述: {check.description}")
        
        if check.status != HardeningStatus.ENABLED and check.fix_command:
            lines.append(f"   修复: {check.fix_command}")
    
    if report.recommendations:
        lines.append("\n" + "-" * 70)
        lines.append("修复建议")
        lines.append("-" * 70)
        for i, rec in enumerate(report.recommendations[:10], 1):
            lines.append(f"  [{i}] {rec}")
    
    if report.hardening_script:
        lines.append("\n" + "-" * 70)
        lines.append("加固脚本")
        lines.append("-" * 70)
        lines.append(report.hardening_script[:500])
        if len(report.hardening_script) > 500:
            lines.append(f"... (共 {len(report.hardening_script)} 字符)")
    
    if report.error_message:
        lines.append(f"\n错误: {report.error_message}")
    
    lines.append("\n" + "=" * 70)
    
    return '\n'.join(lines)
