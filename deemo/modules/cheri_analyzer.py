import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class CHERICapability:
    """
    CHERI能力信息
    """
    name: str
    type: str
    base: int
    length: int
    permissions: str
    offset: int
    description: str = ""

@dataclass
class CHERIInstruction:
    """
    CHERI指令信息
    """
    opcode: str
    mnemonic: str
    category: str
    description: str
    detected: bool = False

@dataclass
class CHERIVulnerability:
    """
    CHERI漏洞信息
    """
    name: str
    vulnerability_type: str
    severity: str
    confidence: float
    location: int
    description: str
    mitigation: str
    affected_code: str = ""

@dataclass
class CHERIAnalysisResult:
    """
    CHERI分析结果汇总
    """
    capabilities: List[CHERICapability]
    instructions: List[CHERIInstruction]
    vulnerabilities: List[CHERIVulnerability]
    capability_usage_summary: Dict[str, int]
    summary: str

# CHERI指令集特征
CHERI_INSTRUCTIONS = {
    # 能力加载/存储
    'ldc': {
        'mnemonic': 'ldc',
        'category': 'load',
        'description': '加载能力'
    },
    'ldcx': {
        'mnemonic': 'ldcx',
        'category': 'load',
        'description': '加载能力（索引）'
    },
    'ldcs': {
        'mnemonic': 'ldcs',
        'category': 'load',
        'description': '加载能力（带标签）'
    },
    'stc': {
        'mnemonic': 'stc',
        'category': 'store',
        'description': '存储能力'
    },
    'stcx': {
        'mnemonic': 'stcx',
        'category': 'store',
        'description': '存储能力（索引）'
    },
    'stcs': {
        'mnemonic': 'stcs',
        'category': 'store',
        'description': '存储能力（带标签）'
    },
    # 能力操作
    'csetbounds': {
        'mnemonic': 'csetbounds',
        'category': 'manipulate',
        'description': '设置能力边界'
    },
    'csetoffset': {
        'mnemonic': 'csetoffset',
        'category': 'manipulate',
        'description': '设置能力偏移'
    },
    'csetaddr': {
        'mnemonic': 'csetaddr',
        'category': 'manipulate',
        'description': '设置能力地址'
    },
    'cgetbounds': {
        'mnemonic': 'cgetbounds',
        'category': 'query',
        'description': '获取能力边界'
    },
    'cgetoffset': {
        'mnemonic': 'cgetoffset',
        'category': 'query',
        'description': '获取能力偏移'
    },
    'cgetbase': {
        'mnemonic': 'cgetbase',
        'category': 'query',
        'description': '获取能力基址'
    },
    # 能力授权
    'cseal': {
        'mnemonic': 'cseal',
        'category': 'seal',
        'description': '密封能力'
    },
    'cunseal': {
        'mnemonic': 'cunseal',
        'category': 'seal',
        'description': '解封能力'
    },
    'ccopyseal': {
        'mnemonic': 'ccopyseal',
        'category': 'seal',
        'description': '复制并密封能力'
    },
    # 能力权限
    'candperm': {
        'mnemonic': 'candperm',
        'category': 'permission',
        'description': '与权限'
    },
    'corperm': {
        'mnemonic': 'corperm',
        'category': 'permission',
        'description': '或权限'
    },
    'cnotperm': {
        'mnemonic': 'cnotperm',
        'category': 'permission',
        'description': '非权限'
    },
    'cgetperm': {
        'mnemonic': 'cgetperm',
        'category': 'permission',
        'description': '获取权限'
    },
    # 能力比较
    'ccmp': {
        'mnemonic': 'ccmp',
        'category': 'compare',
        'description': '比较能力'
    },
    'ccmpi': {
        'mnemonic': 'ccmpi',
        'category': 'compare',
        'description': '比较能力（立即数）'
    },
    'ccmpu': {
        'mnemonic': 'ccmpu',
        'category': 'compare',
        'description': '无符号比较能力'
    },
    # 能力分支
    'cbnz': {
        'mnemonic': 'cbnz',
        'category': 'branch',
        'description': '能力非零分支'
    },
    'cbz': {
        'mnemonic': 'cbz',
        'category': 'branch',
        'description': '能力零分支'
    },
    # 能力调用/返回
    'ccall': {
        'mnemonic': 'ccall',
        'category': 'call',
        'description': '能力调用'
    },
    'cret': {
        'mnemonic': 'cret',
        'category': 'call',
        'description': '能力返回'
    },
    # 能力异常
    'cfromptr': {
        'mnemonic': 'cfromptr',
        'category': 'convert',
        'description': '从指针创建能力'
    },
    'ctoptr': {
        'mnemonic': 'ctoptr',
        'category': 'convert',
        'description': '转换能力为指针'
    },
    'cnull': {
        'mnemonic': 'cnull',
        'category': 'convert',
        'description': '空能力'
    },
    # 能力栈操作
    'cspush': {
        'mnemonic': 'cspush',
        'category': 'stack',
        'description': '压栈能力'
    },
    'cspop': {
        'mnemonic': 'cspop',
        'category': 'stack',
        'description': '弹栈能力'
    }
}

# CHERI权限标志
CHERI_PERMISSIONS = {
    'P': 'Permit_Execute',
    'L': 'Permit_Load',
    'S': 'Permit_Store',
    'M': 'Permit_Modify',
    'G': 'Permit_Global',
    'A': 'Permit_Access_System_Registers',
    'C': 'Permit_Call',
    'U': 'Permit_Unseal',
    'T': 'Tag'
}

# CHERI漏洞模式
CHERI_VULNERABILITY_PATTERNS = {
    'capability_leak': {
        'name': '能力泄露',
        'description': '能力被存储到非能力内存区域，可能导致权限提升',
        'severity': 'critical',
        'patterns': ['stc.*non-cap', 'store.*cap.*unsafe']
    },
    'permission_escalation': {
        'name': '权限提升',
        'description': '能力权限被不当扩展',
        'severity': 'critical',
        'patterns': ['corperm.*all', 'csetperm.*unsafe']
    },
    'seal_bypass': {
        'name': '密封绕过',
        'description': '密封能力被不当解封',
        'severity': 'high',
        'patterns': ['cunseal.*untrusted', 'ccopyseal.*invalid']
    },
    'capability_forgery': {
        'name': '能力伪造',
        'description': '从原始指针创建能力可能绕过安全检查',
        'severity': 'high',
        'patterns': ['cfromptr.*untrusted', 'cfromptr.*raw']
    },
    'bound_violation': {
        'name': '边界检查绕过',
        'description': '能力边界被不当修改',
        'severity': 'high',
        'patterns': ['csetbounds.*large', 'csetbounds.*unsafe']
    },
    'tag_forgery': {
        'name': '标签伪造',
        'description': '能力标签被不当设置',
        'severity': 'medium',
        'patterns': ['settag.*user', 'tag.*forged']
    },
    'null_deref': {
        'name': '空能力解引用',
        'description': '对空能力进行操作',
        'severity': 'medium',
        'patterns': ['cnull.*deref', 'cnull.*use']
    },
    'capability_delegation': {
        'name': '不当能力委托',
        'description': '能力被委托给非预期的接收者',
        'severity': 'medium',
        'patterns': ['ccall.*untrusted', 'cseal.*shared']
    }
}

class CHERIAnalyzer:
    """
    CHERI能力架构分析模块
    
    核心功能：
    1. 分析Morello二进制中的能力使用
    2. 检测能力越权访问
    3. 检测能力委托漏洞
    4. 识别能力操作模式
    """
    
    def __init__(self):
        """初始化CHERI分析器"""
        logger.info("CHERIAnalyzer 初始化完成")
    
    def _get_disassembly(self, binary_path: str) -> str:
        """
        获取二进制文件的反汇编内容
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            反汇编内容字符串
        """
        try:
            import subprocess
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'pd 500', binary_path]
            result = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            
            
            if result.returncode == 0:
                return result.stdout
        
        except Exception as e:
            logger.debug(f"获取反汇编失败: {e}")
        
        return ""
    
    def _extract_instructions(self, disassembly: str) -> List[str]:
        """
        从反汇编中提取指令
        
        Args:
            disassembly: 反汇编内容
        
        Returns:
            指令列表
        """
        instructions = []
        
        for line in disassembly.split('\n'):
            parts = line.split(';')
            if len(parts) >= 2:
                instr_part = parts[1].strip()
                if instr_part:
                    instructions.append(instr_part)
        
        return instructions
    
    def _detect_cheri_instructions(self, instructions: List[str]) -> List[CHERIInstruction]:
        """
        检测CHERI指令
        
        Args:
            instructions: 指令列表
        
        Returns:
            CHERI指令列表
        """
        detected = []
        
        for instr in instructions:
            for opcode, info in CHERI_INSTRUCTIONS.items():
                if opcode in instr:
                    detected.append(CHERIInstruction(
                        opcode=opcode,
                        mnemonic=info['mnemonic'],
                        category=info['category'],
                        description=info['description'],
                        detected=True
                    

        
        return detected
    
    def _detect_cheri_vulnerabilities(, self)
        instructions: List[str],
        disassembly: str
    ) -> List[CHERIVulnerability]:
        """
        检测CHERI相关漏洞
        
        Args:
            instructions: 指令列表
            disassembly: 反汇编内容
        
        Returns:
            CHERI漏洞列表
        """
        vulnerabilities = []
        location_counter = 0
        
        for vuln_type, vuln_info in CHERI_VULNERABILITY_PATTERNS.items():
            for pattern in vuln_info['patterns']:
                for instr in instructions:
                    if pattern.lower() in instr.lower():
                        vulnerabilities.append(CHERIVulnerability(
                            name=vuln_info['name'],
                            vulnerability_type=vuln_type,
                            severity=vuln_info['severity'],
                            confidence=0.85,
                            location=location_counter,
                            description=vuln_info['description'],
                            mitigation=self._get_mitigation(vuln_type),
                            affected_code=instr
                        

                        location_counter += 1
                
                if pattern.lower() in disassembly.lower():
                    vulnerabilities.append(CHERIVulnerability(
                        name=vuln_info['name'],
                        vulnerability_type=vuln_type,
                        severity=vuln_info['severity'],
                        confidence=0.7,
                        location=location_counter,
                        description=vuln_info['description'],
                        mitigation=self._get_mitigation(vuln_type),
                        affected_code="反汇编中检测到模式"
                    

                    location_counter += 1
        
        return vulnerabilities
    
    def _get_mitigation(self, vuln_type: str) -> str:
        """
        根据漏洞类型获取缓解建议
        
        Args:
            vuln_type: 漏洞类型
        
        Returns:
            缓解建议字符串
        """
        mitigations = {
            'capability_leak': '确保能力只存储到能力内存区域，使用适当的能力类型',
            'permission_escalation': '最小化能力权限，仅授予必要的权限',
            'seal_bypass': '仅在可信代码路径中解封能力，验证密封密钥',
            'capability_forgery': '谨慎使用 cfromptr，确保输入指针来自可信来源',
            'bound_violation': '验证能力边界修改的合法性，使用边界检查',
            'tag_forgery': '避免用户态代码修改能力标签',
            'null_deref': '在使用能力前检查是否为空',
            'capability_delegation': '仔细验证能力委托的接收者，使用密封保护敏感能力'
        }
        return mitigations.get(vuln_type, '需要进一步分析以确定缓解措施')
    
    def _analyze_capability_usage(self, instructions: List[CHERIInstruction]) -> Dict[str, int]:
        """
        分析能力使用情况
        
        Args:
            instructions: CHERI指令列表
        
        Returns:
            能力使用统计
        """
        usage = {
            'load': 0,
            'store': 0,
            'manipulate': 0,
            'query': 0,
            'seal': 0,
            'permission': 0,
            'compare': 0,
            'branch': 0,
            'call': 0,
            'convert': 0,
            'stack': 0
        }
        
        for instr in instructions:
            if instr.category in usage:
                usage[instr.category] += 1
        
        return usage
    
    def _extract_capabilities(self, disassembly: str) -> List[CHERICapability]:
        """
        从反汇编中提取能力信息
        
        Args:
            disassembly: 反汇编内容
        
        Returns:
            能力列表
        """
        capabilities = []
        
        import re
        
        # 尝试从反汇编中提取能力相关信息
        capability_patterns = [
            (r'c0\s*=\s*ldc', 'General purpose capability 0'),
            (r'c1\s*=\s*ldc', 'General purpose capability 1'),
            (r'c2\s*=\s*ldc', 'General purpose capability 2'),
            (r'c3\s*=\s*ldc', 'General purpose capability 3'),
            (r'csp\s*=', 'Capability stack pointer'),
            (r'ccall\s+c[0-9]+', 'Capability call'),
            (r'cret', 'Capability return')
        ]
        
        for pattern, desc in capability_patterns:
            match = re.search(pattern, disassembly)
            if match:
                capabilities.append(CHERICapability(
                    name=desc,
                    type='capability_register',
                    base=0,
                    length=0,
                    permissions='unknown',
                    offset=match.start(),
                    description=desc
                

        
        return capabilities
    
    def analyze_binary(self, binary_path: str) -> CHERIAnalysisResult:
        """
        分析二进制文件中的CHERI能力使用情况
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            CHERIAnalysisResult 对象
        """
        logger.info(f"开始分析二进制文件的CHERI特征: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return CHERIAnalysisResult(
                capabilities=[],
                instructions=[],
                vulnerabilities=[],
                capability_usage_summary={},
                summary="文件不存在")
            

        
        try:
            # 获取反汇编
            disassembly = self._get_disassembly(binary_path)
            instructions = self._extract_instructions(disassembly)
            
            # 检测CHERI指令
            cheri_instr = self._detect_cheri_instructions(instructions)
            
            # 检测CHERI漏洞
            vulnerabilities = self._detect_cheri_vulnerabilities(instructions, disassembly)
            
            # 分析能力使用
            cap_usage = self._analyze_capability_usage(cheri_instr)
            
            # 提取能力信息
            capabilities = self._extract_capabilities(disassembly)
            
            # 生成摘要
            summary_parts = []
            if cheri_instr:
                summary_parts.append(f"发现 {len(cheri_instr)} 条CHERI指令")
            if capabilities:
                summary_parts.append(f"发现 {len(capabilities)} 个能力")
            if vulnerabilities:
                summary_parts.append(f"发现 {len(vulnerabilities)} 个CHERI安全问题")
            
            summary = "; ".join(summary_parts) if summary_parts else "未发现CHERI特征"
            logger.info(f"CHERI分析完成: {summary}")
            
            return CHERIAnalysisResult(
                capabilities=capabilities,
                instructions=cheri_instr,
                vulnerabilities=vulnerabilities,
                capability_usage_summary=cap_usage,
                summary=summary)
            

            
        except Exception as e:
            logger.error(f"分析二进制文件失败: {e}")
            return CHERIAnalysisResult(
                capabilities=[],
                instructions=[],
                vulnerabilities=[],
                capability_usage_summary={},
                summary=f"分析失败: {e}")
            

    
    def format_report(self, result: CHERIAnalysisResult) -> str:
        """
        格式化分析报告为Markdown格式
        
        Args:
            result: 分析结果
        
        Returns:
            Markdown格式的报告字符串
        """
        output = []
        
        output.append("## CHERI 能力架构分析报告")
        output.append(f"\n**摘要**: {result.summary}\n")
        
        if result.capabilities:
            output.append("### 检测到的能力")
            output.append("| 名称 | 类型 | 偏移 | 描述 |")
            output.append("|------|------|------|------|")
            
            for cap in result.capabilities:
                output.append(f"| {cap.name} | {cap.type} | 0x{cap.offset:x} | {cap.description} |")
            
            output.append("")
        
        if result.instructions:
            output.append("### CHERI指令分类统计")
            output.append("| 类别 | 指令数 |")
            output.append("|------|--------|")
            
            for category, count in result.capability_usage_summary.items():
                if count > 0:
                    output.append(f"| {category} | {count} |")
            
            output.append("")
        
        if result.vulnerabilities:
            output.append("### ⚠️ CHERI安全问题")
            output.append("| 漏洞名称 | 类型 | 严重程度 | 置信度 |")
            output.append("|----------|------|----------|--------|")
            
            severity_colors = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            for vuln in sorted(result.vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low'].index(x.severity)):
                color = severity_colors.get(vuln.severity, '⚪')
                output.append(f"| {vuln.name} | {vuln.vulnerability_type} | {color} {vuln.severity} | {vuln.confidence:.2f} |")
            
            output.append("")
            
            output.append("### 🛡️ 缓解建议")
            for vuln in result.vulnerabilities:
                output.append(f"#### {vuln.name}")
                output.append(f"- **问题**: {vuln.description}")
                output.append(f"- **缓解**: {vuln.mitigation}")
                output.append("")
        
        output.append("### 📌 CHERI安全最佳实践")
        output.append("1. 遵循最小权限原则，只为能力授予必要的权限")
        output.append("2. 使用密封保护敏感能力，防止未授权访问")
        output.append("3. 验证能力边界，防止越界访问")
        output.append("4. 谨慎使用 cfromptr，避免从不可信指针创建能力")
        output.append("5. 使用能力安全的内存分配器")
        output.append("6. 在委托能力前验证接收者的可信度")
        
        return '\n'.join(output)


def get_cheri_analyzer() -> CHERIAnalyzer:
    """
    获取全局CHERI分析器实例
    
    Returns:
        CHERIAnalyzer 实例
    """
    global _cheri_analyzer
    if _cheri_analyzer is None:
        _cheri_analyzer = CHERIAnalyzer()
    return _cheri_analyzer


# 全局CHERI分析器实例
_cheri_analyzer = None)))))))