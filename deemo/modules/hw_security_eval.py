"""
基于硬件辅助安全特性的漏洞可利用性评估模块

评估当前二进制架构下硬件安全扩展对漏洞利用的影响，例如：
- ARM Pointer Authentication (PAC)
- Branch Target Identification (BTI)
- Intel CET (IBT/SHSTK)
- AMD SEV
- SMAP/SMEP

分析漏洞在开启这些特性后的利用难度，更新利用生成和风险评分。
"""

import os
import struct
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ExploitabilityDifficulty(Enum):
    """漏洞利用难度枚举"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    VERY_HARD = "very_hard"
    EXPLOITATION_IMPOSSIBLE = "exploitation_impossible"


class HardwareFeature(Enum):
    """硬件安全特性枚举"""
    ARM_PAC = "arm_pac"
    ARM_BTI = "arm_bti"
    INTEL_CET_IBT = "intel_cet_ibt"
    INTEL_CET_SHSTK = "intel_cet_shstk"
    SMEP = "smep"
    SMAP = "smap"
    KPTI = "kpti"
    KASLR = "kaslr"
    PAGE_TABLE_ISOLATION = "page_table_isolation"
    CET = "cet"
    IBT = "ibt"
    SHSTK = "shstk"


class ExploitDifficulty(Enum):
    """利用难度等级"""
    TRIVIAL = "Trivial"
    EASY = "Easy"
    MEDIUM = "Medium"
    HARD = "Hard"
    EXTREMELY_HARD = "Extremely Hard"
    IMPOSSIBLE = "Impossible"


class ExploitabilityImpact(Enum):
    """可利用性影响"""
    BLOCKED = "Blocked"
    SIGNIFICANTLY_REDUCED = "Significantly Reduced"
    PARTIALLY_REDUCED = "Partially Reduced"
    NO_IMPACT = "No Impact"
    UNKNOWN = "Unknown"


@dataclass
class HardwareSecurityFeature:
    """硬件安全特性"""
    name: str
    feature_type: HardwareFeature
    enabled: bool
    description: str
    impact_on_exploitation: ExploitabilityImpact
    affected_attack_techniques: List[str] = field(default_factory=list)
    bypass_techniques: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    details: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'feature_type': self.feature_type.value,
            'enabled': self.enabled,
            'description': self.description,
            'impact_on_exploitation': self.impact_on_exploitation.value,
            'affected_attack_techniques': self.affected_attack_techniques,
            'bypass_techniques': self.bypass_techniques,
            'requirements': self.requirements,
            'details': self.details
        }


@dataclass
class VulnerabilityExploitabilityAssessment:
    """漏洞可利用性评估"""
    vulnerability_type: str
    original_difficulty: ExploitabilityDifficulty
    adjusted_difficulty: ExploitabilityDifficulty
    difficulty_change: str
    hardware_features: List[HardwareSecurityFeature]
    impacted_attack_techniques: List[str]
    suggested_bypass_techniques: List[str]
    information_leak_requirements: List[str]
    assessment_notes: List[str]
    risk_adjustment: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type,
            'original_difficulty': self.original_difficulty.value,
            'adjusted_difficulty': self.adjusted_difficulty.value,
            'difficulty_change': self.difficulty_change,
            'hardware_features': [f.to_dict() for f in self.hardware_features],
            'impacted_attack_techniques': self.impacted_attack_techniques,
            'suggested_bypass_techniques': self.suggested_bypass_techniques,
            'information_leak_requirements': self.information_leak_requirements,
            'assessment_notes': self.assessment_notes,
            'risk_adjustment': self.risk_adjustment
        }


@dataclass
class HardwareSecurityEvaluationReport:
    """硬件安全评估报告"""
    binary_path: str
    architecture: str
    detected_features: List[HardwareSecurityFeature]
    vulnerability_assessments: List[VulnerabilityExploitabilityAssessment]
    overall_exploitability_rating: str
    security_posture: str
    recommendations: List[str]
    evaluation_success: bool = False
    error_message: str = ""
    
    def get_blocked_features(self) -> List[HardwareSecurityFeature]:
        return [f for f in self.detected_features if not f.enabled and 
                f.feature_type in [HardwareFeature.ARM_PAC, HardwareFeature.ARM_BTI,
                                 HardwareFeature.INTEL_CET_IBT, HardwareFeature.INTEL_CET_SHSTK]]
    
    def get_enabled_features(self) -> List[HardwareSecurityFeature]:
        return [f for f in self.detected_features if f.enabled]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'architecture': self.architecture,
            'detected_features': [f.to_dict() for f in self.detected_features],
            'vulnerability_assessments': [v.to_dict() for v in self.vulnerability_assessments],
            'overall_exploitability_rating': self.overall_exploitability_rating,
            'security_posture': self.security_posture,
            'recommendations': self.recommendations,
            'evaluation_success': self.evaluation_success,
            'error_message': self.error_message
        }


class HardwareSecurityEvaluator:
    """
    硬件安全评估器
    
    检测二进制中编译支持的硬件安全特性，并评估这些特性对不同类型漏洞利用的影响。
    """
    
    def __init__(self, binary_path: str, binary_info: Dict[str, Any] = None):
        """
        初始化评估器
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 可选的二进制信息字典
        """
        self.binary_path = binary_path
        self.binary_info = binary_info or {}
        self.architecture = self._detect_architecture()
        
    def _detect_architecture(self) -> str:
        """检测架构"""
        arch = self.binary_info.get('arch', '')
        if arch in ['i386', 'amd64', 'x86_64', 'x86']:
            return 'x86_64'
        elif arch in ['aarch64', 'arm64', 'ARM64']:
            return 'arm64'
        elif arch in ['arm', 'aarch32']:
            return 'arm'
        else:
            try:
                with open(self.binary_path, 'rb') as f:
                    header = f.read(20)
                    if header[:4] == b'\x7fELF':
                        machine = struct.unpack('<H', header[18:20])[0]
                        if machine == 62:
                            return 'x86_64'
                        elif machine == 183:
                            return 'arm64'
                        elif machine == 40:
                            return 'arm'
            except Exception:
                pass
            return 'unknown'
    
    def evaluate(self) -> HardwareSecurityEvaluationReport:
        """
        执行硬件安全评估
        
        Returns:
            HardwareSecurityEvaluationReport 评估报告
        """
        logger.info(f"开始硬件安全评估: {self.binary_path}")
        
        report = HardwareSecurityEvaluationReport(
            binary_path=self.binary_path,
            architecture=self.architecture
        )
        
        try:
            if self.architecture == 'x86_64':
                self._evaluate_x86_64(report)
            elif self.architecture == 'arm64':
                self._evaluate_arm64(report)
            elif self.architecture == 'arm':
                self._evaluate_arm(report)
            else:
                logger.warning(f"未知架构: {self.architecture}")
            
            self._assess_vulnerability_exploitability(report)
            self._calculate_security_posture(report)
            
            report.evaluation_success = True
            logger.info(f"硬件安全评估完成: {len(report.detected_features)} 个特性")
            
        except Exception as e:
            logger.error(f"硬件安全评估失败: {e}")
            report.error_message = str(e)
        
        return report
    
    def _evaluate_x86_64(self, report: HardwareSecurityEvaluationReport) -> None:
        """评估 x86_64 架构硬件安全特性"""
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                cet_ibt = self._check_intel_cet_ibt(elf)
                cet_shstk = self._check_intel_cet_shstk(elf)
                
                report.detected_features.append(cet_ibt)
                report.detected_features.append(cet_shstk)
                
        except ImportError:
            logger.warning("pyelftools 不可用，使用备用方法")
            self._evaluate_x86_64_fallback(report)
    
    def _check_intel_cet_ibt(self, elf) -> HardwareSecurityFeature:
        """检查 Intel CET IBT (Indirect Branch Tracking)"""
        enabled = False
        details = ""
        
        for section in elf.iter_sections():
            if section.name == '.note.gnu.property':
                data = section.data()
                if b'GNU_PROPERTY_X86_FEATURE_1_AND' in data:
                    idx = data.find(b'GNU_PROPERTY_X86_FEATURE_1_AND')
                    if idx >= 0 and idx + 16 <= len(data):
                        flags = data[idx + 8:idx + 12]
                        if len(flags) >= 4 and flags[0] & 0x01:
                            enabled = True
                            details = "检测到 ENDBR64 指令"
                        else:
                            details = "GNU_PROPERTY_X86_FEATURE_1_AND 存在但 IBT 未启用"
                    break
        
        if not enabled:
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_GNU_PROPERTY':
                    prop_data = segment.data()
                    if b'GNU_PROPERTY_X86_FEATURE_1_AND' in prop_data:
                        enabled = True
                        details = "通过 PT_GNU_PROPERTY 检测到 IBT 支持"
                        break
        
        return HardwareSecurityFeature(
            name="Intel CET-IBT (Indirect Branch Tracking)",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=enabled,
            description="间接分支跟踪，要求间接跳转目标为有效的 ENDBR64 指令",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED if enabled else ExploitabilityImpact.NO_IMPACT,
            affected_attack_techniques=['ROP (Return-Oriented Programming)', 'JOP (Jump-Oriented Programming)', 
                                       'COP (Call-Oriented Programming)', 'SROP (Sigreturn-Oriented Programming)'],
            bypass_techniques=['使用直接跳转', '利用 leaver gadgets', '信息泄露绕过 IBT'],
            requirements=['编译器支持 (-fcf-protection=branch)', '处理器支持 (Intel CET)'],
            details=details
        )
    
    def _check_intel_cet_shstk(self, elf) -> HardwareSecurityFeature:
        """检查 Intel CET SHSTK (Shadow Stack)"""
        enabled = False
        details = ""
        
        for section in elf.iter_sections():
            if section.name == '.note.gnu.property':
                data = section.data()
                if b'GNU_PROPERTY_X86_FEATURE_1_AND' in data:
                    idx = data.find(b'GNU_PROPERTY_X86_FEATURE_1_AND')
                    if idx >= 0 and idx + 16 <= len(data):
                        flags = data[idx + 8:idx + 12]
                        if len(flags) >= 4 and flags[0] & 0x02:
                            enabled = True
                            details = "检测到 Shadow Stack 支持"
                        else:
                            details = "GNU_PROPERTY_X86_FEATURE_1_AND 存在但 SHSTK 未启用"
                    break
        
        return HardwareSecurityFeature(
            name="Intel CET-SHSTK (Shadow Stack)",
            feature_type=HardwareFeature.INTEL_CET_SHSTK,
            enabled=enabled,
            description="影子栈保护返回地址，检测返回地址篡改",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED if enabled else ExploitabilityImpact.NO_IMPACT,
            affected_attack_techniques=['Stack Buffer Overflow (直接覆盖返回地址)', 'Return-to-libc (ret2libc)',
                                       'ROP (覆盖返回地址)'],
            bypass_techniques=['覆盖其他寄存器', '利用栈迁移', '利用条件分支', 'SROP 替代方案'],
            requirements=['编译器支持 (-fcf-protection=return)', '处理器支持 (Intel CET-SHSTK)',
                        '操作系统支持 (Linux 5.19+)'],
            details=details
        )
    
    def _evaluate_x86_64_fallback(self, report: HardwareSecurityEvaluationReport) -> None:
        """使用 fallback 方法评估 x86_64"""
        try:
            result_list = []
            try:
                import subprocess
                result = subprocess.run(
                    ['readelf', '-n', self.binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout
            except Exception:
                output = ""
            
            ibt_enabled = 'GNU_PROPERTY_X86_FEATURE_1_AND' in output
            
            report.detected_features.append(HardwareSecurityFeature(
                name="Intel CET-IBT",
                feature_type=HardwareFeature.INTEL_CET_IBT,
                enabled=ibt_enabled,
                description="间接分支跟踪",
                impact_on_exploitation=ExploitabilityImpact.BLOCKED if ibt_enabled else ExploitabilityImpact.UNKNOWN,
                affected_attack_techniques=['ROP', 'JOP'],
                bypass_techniques=['直接跳转'],
                details="通过 readelf 检测"
            ))
            
            report.detected_features.append(HardwareSecurityFeature(
                name="Intel CET-SHSTK",
                feature_type=HardwareFeature.INTEL_CET_SHSTK,
                enabled=False,
                description="影子栈",
                impact_on_exploitation=ExploitabilityImpact.UNKNOWN,
                affected_attack_techniques=['栈溢出'],
                bypass_techniques=['栈迁移'],
                details="无法确认状态"
            ))
            
        except Exception as e:
            logger.debug(f"x86_64 fallback 评估失败: {e}")
    
    def _evaluate_arm64(self, report: HardwareSecurityEvaluationReport) -> None:
        """评估 ARM64 架构硬件安全特性"""
        pac_enabled = self._check_arm_pac(report)
        bti_enabled = self._check_arm_bti(report)
        
        if pac_enabled:
            report.detected_features.append(pac_enabled)
        if bti_enabled:
            report.detected_features.append(bti_enabled)
    
    def _check_arm_pac(self, report: HardwareSecurityEvaluationReport) -> Optional[HardwareSecurityFeature]:
        """检查 ARM Pointer Authentication (PAC)"""
        enabled = False
        details = ""
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
                
                pac_signals = [
                    b'paciasp', b'paciasp', b'pacibsp', b'paciz', b'pacizz',
                    b'autiasp', b'autiasp', b'autibsp', b'autiz', b'autizz',
                    b'xpaci', b'xpaclri', b'pacda', b'pacdb', b'pacdc', b'pacdz',
                    b'autda', b'autdb', b'autdc', b'autdz',
                    b'pacga'
                ]
                
                pac_instructions_found = sum(1 for sig in pac_signals if sig in data)
                
                if pac_instructions_found > 0:
                    enabled = True
                    details = f"检测到 {pac_instructions_found} 处 PAC 相关指令"
                else:
                    details = "未检测到 PAC 指令"
                    
        except Exception as e:
            logger.debug(f"PAC 检测失败: {e}")
        
        return HardwareSecurityFeature(
            name="ARM Pointer Authentication (PAC)",
            feature_type=HardwareFeature.ARM_PAC,
            enabled=enabled,
            description="指针认证，使用 PACIABP/RETAA 等指令签名返回地址和指针",
            impact_on_exploitation=ExploitabilityImpact.EXTREMELY_HARD if enabled else ExploitabilityImpact.NO_IMPACT,
            affected_attack_techniques=['ROP (需要伪造 PAC)', 'JOP (需要伪造 PAC)',
                                       'ret2libc (需要伪造 PAC)', 'Stack Pivot (需要伪造 PAC)'],
            bypass_techniques=['信息泄露 PAC 密钥', '利用 PAC 签名算法弱点', 
                              ' Gargoyle (代码重用而非栈操控)'],
            requirements=['编译器支持 (-msign-return-address)', '处理器支持 (ARMv8.3-A+)',
                        '内核支持 (CONFIG_ARM64_PTR_AUTH)'],
            details=details
        )
    
    def _check_arm_bti(self, report: HardwareSecurityEvaluationReport) -> Optional[HardwareSecurityFeature]:
        """检查 ARM Branch Target Identification (BTI)"""
        enabled = False
        details = ""
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
                
                bti_patterns = [b'bti', b'bti.j', b'bti.c', b'bti.e']
                bti_found = any(pattern in data for pattern in bti_patterns)
                
                if bti_found:
                    enabled = True
                    details = "检测到 BTI 指令"
                else:
                    details = "未检测到 BTI 指令"
                    
        except Exception as e:
            logger.debug(f"BTI 检测失败: {e}")
        
        return HardwareSecurityFeature(
            name="ARM Branch Target Identification (BTI)",
            feature_type=HardwareFeature.ARM_BTI,
            enabled=enabled,
            description="分支目标识别，要求间接跳转目标为有效的 BTI 指令 (bti j/c/e)",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED if enabled else ExploitabilityImpact.NO_IMPACT,
            affected_attack_techniques=['ROP', 'JOP', '间接分支劫持'],
            bypass_techniques=['使用直接跳转', '利用 BTI 指令作为跳转目标 (landing pad)',
                              '信息泄露绕过'],
            requirements=['编译器支持 (-mbranch-protection=bti)', '处理器支持 (ARMv8.5-A+)'],
            details=details
        )
    
    def _evaluate_arm(self, report: HardwareSecurityEvaluationReport) -> None:
        """评估 ARM32 架构"""
        report.detected_features.append(HardwareSecurityFeature(
            name="ARMv7 Memory Tagging (MTE) - Not Available",
            feature_type=HardwareFeature.ARM_PAC,
            enabled=False,
            description="ARMv7 不支持 PAC/BTI，这些特性从 ARMv8.3-A 开始引入",
            impact_on_exploitation=ExploitabilityImpact.NO_IMPACT,
            affected_attack_techniques=[],
            bypass_techniques=[],
            requirements=[],
            details="ARM32 架构不支持现代硬件安全扩展"
        ))
    
    def _assess_vulnerability_exploitability(
        self, 
        report: HardwareSecurityEvaluationReport
    ) -> None:
        """评估漏洞在硬件安全特性下的可利用性"""
        vuln_types = [
            ('buffer_overflow_stack', '栈缓冲区溢出', ExploitabilityDifficulty.EASY),
            ('buffer_overflow_heap', '堆缓冲区溢出', ExploitabilityDifficulty.MEDIUM),
            ('use_after_free', 'Use-After-Free', ExploitabilityDifficulty.MEDIUM),
            ('format_string', '格式化字符串', ExploitabilityDifficulty.EASY),
            ('integer_overflow', '整数溢出', ExploitabilityDifficulty.MEDIUM),
            ('double_free', 'Double Free', ExploitabilityDifficulty.HARD),
            ('race_condition', '竞争条件', ExploitabilityDifficulty.HARD),
        ]
        
        for vuln_id, vuln_name, base_difficulty in vuln_types:
            assessment = self._assess_single_vulnerability(
                vuln_id, vuln_name, base_difficulty, report
            )
            report.vulnerability_assessments.append(assessment)
    
    def _assess_single_vulnerability(
        self,
        vuln_id: str,
        vuln_name: str,
        base_difficulty: ExploitabilityDifficulty,
        report: HardwareSecurityEvaluationReport
    ) -> VulnerabilityExploitabilityAssessment:
        """评估单个漏洞类型的可利用性"""
        adjusted_difficulty = base_difficulty
        impacted_techniques = []
        suggested_bypasses = []
        info_leak_requirements = []
        notes = []
        hw_features = []
        
        cet_ibt = self._find_feature(report, HardwareFeature.INTEL_CET_IBT)
        cet_shstk = self._find_feature(report, HardwareFeature.INTEL_CET_SHSTK)
        arm_pac = self._find_feature(report, HardwareFeature.ARM_PAC)
        arm_bti = self._find_feature(report, HardwareFeature.ARM_BTI)
        
        if 'stack' in vuln_id.lower():
            if cet_shstk and cet_shstk.enabled:
                adjusted_difficulty = ExploitabilityDifficulty.EXTREMELY_HARD
                impacted_techniques.append('返回地址覆盖')
                suggested_bypasses.append('利用条件分支而非返回地址')
                suggested_bypasses.append('栈迁移技术')
                info_leak_requirements.append('可能需要泄露 shadow stack 地址')
                hw_features.append(cet_shstk)
                notes.append('Shadow Stack 阻止直接覆盖返回地址')
            
            if arm_pac and arm_pac.enabled:
                adjusted_difficulty = ExploitabilityDifficulty.EXTREMELY_HARD
                impacted_techniques.append('返回地址覆盖')
                impacted_techniques.append('栈帧伪造')
                suggested_bypasses.append('泄露 PAC 密钥或算法')
                suggested_bypasses.append('利用 PAC 签名验证时机问题')
                suggested_bypasses.append('Gargoyle 技术（非栈操控）')
                info_leak_requirements.append('必须泄露 PAC 签名值')
                hw_features.append(arm_pac)
                notes.append('PAC 要求伪造有效的指针认证码')
        
        if cet_ibt and cet_ibt.enabled:
            if adjusted_difficulty in [ExploitabilityDifficulty.EASY, ExploitabilityDifficulty.MEDIUM]:
                adjusted_difficulty = ExploitabilityDifficulty.HARD
            
            impacted_techniques.append('间接跳转 gadgets')
            suggested_bypasses.append('使用 ENDBR64 指令的 gadgets')
            suggested_bypasses.append('利用 leaver/sequencer gadgets')
            hw_features.append(cet_ibt)
            notes.append('IBT 要求间接跳转目标是有效的 ENDBR64')
        
        if arm_bti and arm_bti.enabled:
            impacted_techniques.append('间接跳转 gadgets')
            suggested_bypasses.append('利用 BTI 指令 (bti j/c) 作为有效的间接跳转目标')
            hw_features.append(arm_bti)
        
        if 'uaf' in vuln_id.lower() or 'double_free' in vuln_id.lower():
            if arm_pac and arm_pac.enabled:
                adjusted_difficulty = ExploitabilityDifficulty.HARD
                impacted_techniques.append('指针覆盖')
                suggested_bypasses.append('泄露函数指针的 PAC 值')
                hw_features.append(arm_pac)
        
        difficulty_change = self._get_difficulty_change(base_difficulty, adjusted_difficulty)
        
        return VulnerabilityExploitabilityAssessment(
            vulnerability_type=vuln_name,
            original_difficulty=base_difficulty,
            adjusted_difficulty=adjusted_difficulty,
            difficulty_change=difficulty_change,
            hardware_features=hw_features,
            impacted_attack_techniques=impacted_techniques,
            suggested_bypass_techniques=suggested_bypasses,
            information_leak_requirements=info_leak_requirements,
            assessment_notes=notes,
            risk_adjustment=self._get_risk_adjustment(base_difficulty, adjusted_difficulty)
        )
    
    def _find_feature(
        self, 
        report: HardwareSecurityEvaluationReport, 
        feature_type: HardwareFeature
    ) -> Optional[HardwareSecurityFeature]:
        """查找指定类型的硬件特性"""
        for feature in report.detected_features:
            if feature.feature_type == feature_type:
                return feature
        return None
    
    def _get_difficulty_change(
        self, 
        original: ExploitabilityDifficulty, 
        adjusted: ExploitabilityDifficulty
    ) -> str:
        """获取难度变化描述"""
        difficulty_order = [
            ExploitabilityDifficulty.TRIVIAL,
            ExploitabilityDifficulty.EASY,
            ExploitabilityDifficulty.MEDIUM,
            ExploitabilityDifficulty.HARD,
            ExploitabilityDifficulty.EXTREMELY_HARD,
            ExploitabilityDifficulty.IMPOSSIBLE
        ]
        
        orig_idx = difficulty_order.index(original) if original in difficulty_order else 0
        adj_idx = difficulty_order.index(adjusted) if adjusted in difficulty_order else 0
        
        if adj_idx > orig_idx:
            return f"难度增加: {original.value} → {adjusted.value}"
        elif adj_idx < orig_idx:
            return f"难度降低: {original.value} → {adjusted.value}"
        else:
            return "难度不变"
    
    def _get_risk_adjustment(
        self, 
        original: ExploitabilityDifficulty, 
        adjusted: ExploitabilityDifficulty
    ) -> str:
        """获取风险调整描述"""
        difficulty_order = [
            ExploitabilityDifficulty.TRIVIAL,
            ExploitabilityDifficulty.EASY,
            ExploitabilityDifficulty.MEDIUM,
            ExploitabilityDifficulty.HARD,
            ExploitabilityDifficulty.EXTREMELY_HARD,
            ExploitabilityDifficulty.IMPOSSIBLE
        ]
        
        orig_idx = difficulty_order.index(original) if original in difficulty_order else 0
        adj_idx = difficulty_order.index(adjusted) if adjusted in difficulty_order else 0
        
        idx_diff = adj_idx - orig_idx
        
        if idx_diff >= 3:
            return "风险显著降低 - 硬件防护有效阻止攻击"
        elif idx_diff >= 1:
            return "风险有所降低 - 利用难度增加"
        elif idx_diff < 0:
            return "风险增加 - 硬件防护可能被绕过"
        else:
            return "风险无显著变化"
    
    def _calculate_security_posture(
        self, 
        report: HardwareSecurityEvaluationReport
    ) -> None:
        """计算整体安全态势"""
        enabled_count = len(report.get_enabled_features())
        total_count = len(report.detected_features)
        
        if total_count == 0:
            report.overall_exploitability_rating = "无法评估"
            report.security_posture = "未知"
            report.recommendations.append("无法检测到硬件安全特性，请检查架构支持")
            return
        
        hw_protection_ratio = enabled_count / total_count if total_count > 0 else 0
        
        hard_vulns = sum(
            1 for v in report.vulnerability_assessments 
            if v.adjusted_difficulty in [ExploitabilityDifficulty.HARD, 
                                         ExploitabilityDifficulty.EXTREMELY_HARD,
                                         ExploitabilityDifficulty.IMPOSSIBLE]
        )
        
        if hw_protection_ratio >= 0.75 and hard_vulns >= 3:
            report.overall_exploitability_rating = "极低"
            report.security_posture = "强防护"
            report.recommendations.append("硬件安全扩展已有效部署")
        elif hw_protection_ratio >= 0.5 and hard_vulns >= 2:
            report.overall_exploitability_rating = "低"
            report.security_posture = "良好"
            report.recommendations.append("建议启用所有硬件安全特性")
        elif hw_protection_ratio >= 0.25:
            report.overall_exploitability_rating = "中等"
            report.security_posture = "一般"
            report.recommendations.append("建议升级编译器和启用更多硬件安全特性")
        else:
            report.overall_exploitability_rating = "高"
            report.security_posture = "薄弱"
            report.recommendations.append("强烈建议启用所有可用的硬件安全特性")
        
        report.recommendations.append(f"已启用 {enabled_count}/{total_count} 个硬件安全特性")


def evaluate_hardware_security(
    binary_path: str, 
    binary_info: Dict[str, Any] = None
) -> HardwareSecurityEvaluationReport:
    """
    评估硬件安全的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        binary_info: 可选的二进制信息
        
    Returns:
        HardwareSecurityEvaluationReport 评估报告
    """
    evaluator = HardwareSecurityEvaluator(binary_path, binary_info)
    return evaluator.evaluate()


def format_evaluation_report(report: HardwareSecurityEvaluationReport) -> str:
    """
    格式化评估报告为可读字符串
    
    Args:
        report: HardwareSecurityEvaluationReport 对象
        
    Returns:
        格式化的报告字符串
    """
    lines = []
    lines.append("=" * 70)
    lines.append("硬件辅助安全特性漏洞可利用性评估报告")
    lines.append("=" * 70)
    
    lines.append(f"\n目标文件: {report.binary_path}")
    lines.append(f"架构: {report.architecture}")
    lines.append(f"评估状态: {'成功' if report.evaluation_success else '失败'}")
    
    lines.append("\n" + "-" * 70)
    lines.append("检测到的硬件安全特性")
    lines.append("-" * 70)
    
    for feature in report.detected_features:
        status = "启用" if feature.enabled else "禁用"
        impact = feature.impact_on_exploitation.value
        
        lines.append(f"\n  {feature.name}")
        lines.append(f"    状态: {status}")
        lines.append(f"    利用影响: {impact}")
        lines.append(f"    描述: {feature.description}")
        
        if feature.enabled and feature.affected_attack_techniques:
            lines.append(f"    受影响技术: {', '.join(feature.affected_attack_techniques[:3])}")
        
        if feature.enabled and feature.bypass_techniques:
            lines.append(f"    绕过技术: {', '.join(feature.bypass_techniques[:2])}")
    
    if report.vulnerability_assessments:
        lines.append("\n" + "-" * 70)
        lines.append("漏洞可利用性调整")
        lines.append("-" * 70)
        
        for assessment in report.vulnerability_assessments:
            if assessment.difficulty_change != "难度不变":
                lines.append(f"\n  {assessment.vulnerability_type}")
                lines.append(f"    原始难度: {assessment.original_difficulty.value}")
                lines.append(f"    调整后: {assessment.adjusted_difficulty.value}")
                lines.append(f"    变化: {assessment.difficulty_change}")
                
                if assessment.impacted_attack_techniques:
                    lines.append(f"    受影响技术: {', '.join(assessment.impacted_attack_techniques[:2])}")
    
    lines.append("\n" + "-" * 70)
    lines.append("总体评估")
    lines.append("-" * 70)
    lines.append(f"  可利用性评级: {report.overall_exploitability_rating}")
    lines.append(f"  安全态势: {report.security_posture}")
    
    if report.recommendations:
        lines.append("\n  建议:")
        for rec in report.recommendations[:5]:
            lines.append(f"    - {rec}")
    
    if report.error_message:
        lines.append(f"\n错误: {report.error_message}")
    
    lines.append("\n" + "=" * 70)
    
    return '\n'.join(lines)


def get_hw_security_eval_prompt(
    vuln_info: Dict[str, Any],
    hw_features: List[Dict[str, Any]]
) -> str:
    """
    生成硬件安全评估的提示词模板（供 AI 分析使用）
    
    Args:
        vuln_info: 漏洞信息
        hw_features: 硬件特性列表
        
    Returns:
        格式化的提示词
    """
    prompt = """
请分析以下漏洞在硬件安全特性影响下的可利用性。

## 漏洞信息
- 类型: {vuln_type}
- 描述: {description}
- 位置: {location}
- 原始可利用性: {original_exploitability}

## 硬件安全特性
{features_list}

## 分析要求
1. 评估每个硬件特性对该漏洞利用的具体影响
2. 确定利用难度是否因硬件防护而增加
3. 提出可能的绕过路线（如需要信息泄露）
4. 给出最终的风险评估调整

请以 JSON 格式输出分析结果：
```json
{{
    "hardware_impact": "影响描述",
    "difficulty_increase": true/false,
    "new_difficulty": "调整后的难度",
    "bypass_required": ["绕过技术1", "绕过技术2"],
    "info_leak_needed": ["所需信息泄露1", "所需信息泄露2"],
    "risk_adjustment": "风险调整说明",
    "confidence": 0.0-1.0
}}
```
"""
    
    vuln_type = vuln_info.get('type', 'Unknown')
    description = vuln_info.get('description', 'N/A')
    location = vuln_info.get('location', 'N/A')
    original_exp = vuln_info.get('exploitability', 'Unknown')
    
    features_lines = []
    for feature in hw_features:
        features_lines.append(f"- {feature.get('name', 'Unknown')}: {feature.get('description', '')}")
        features_lines.append(f"  启用状态: {feature.get('enabled', False)}")
        features_lines.append(f"  利用影响: {feature.get('impact_on_exploitation', 'N/A')}")
    
    features_str = '\n'.join(features_lines) if features_lines else "无硬件安全特性信息"
    
    return prompt.format(
        vuln_type=vuln_type,
        description=description,
        location=location,
        original_exploitability=original_exp,
        features_list=features_str
    )
