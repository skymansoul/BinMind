import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class RISCVVectorInstruction:
    """
    RISC-V向量指令信息
    """
    opcode: str
    mnemonic: str
    vtype: str
    description: str
    detected: bool = False

@dataclass
class RISCVVectorLoop:
    """
    向量循环结构信息
    """
    start_address: int
    end_address: int
    loop_count: int
    vector_width: int
    operation_type: str
    detected_pattern: str

@dataclass
class RISCV_CryptoInstruction:
    """
    RISC-V加密扩展指令信息
    """
    opcode: str
    mnemonic: str
    extension: str
    description: str
    security_risk: str
    detected: bool = False

@dataclass
class RISCVExtAnalysisResult:
    """
    RISC-V扩展分析结果汇总
    """
    vector_instructions: List[RISCVVectorInstruction]
    crypto_instructions: List[RISCV_CryptoInstruction]
    vector_loops: List[RISCVVectorLoop]
    extension_usage: Dict[str, int]
    security_issues: List[str]
    summary: str

# RISC-V Vector Extension (RVV) 指令特征
RVV_INSTRUCTIONS = {
    'vadd': {
        'mnemonic': 'vadd',
        'vtype': 'arithmetic',
        'description': '向量加法',
        'patterns': ['vadd\.vv', 'vadd\.vs', 'vadd\.vi']
    },
    'vsub': {
        'mnemonic': 'vsub',
        'vtype': 'arithmetic',
        'description': '向量减法',
        'patterns': ['vsub\.vv', 'vsub\.vs', 'vsub\.vi']
    },
    'vmul': {
        'mnemonic': 'vmul',
        'vtype': 'arithmetic',
        'description': '向量乘法',
        'patterns': ['vmul\.vv', 'vmul\.vs', 'vmul\.vi']
    },
    'vdiv': {
        'mnemonic': 'vdiv',
        'vtype': 'arithmetic',
        'description': '向量除法',
        'patterns': ['vdiv\.vv', 'vdiv\.vs']
    },
    'vrem': {
        'mnemonic': 'vrem',
        'vtype': 'arithmetic',
        'description': '向量取余',
        'patterns': ['vrem\.vv', 'vrem\.vs']
    },
    'vand': {
        'mnemonic': 'vand',
        'vtype': 'logical',
        'description': '向量按位与',
        'patterns': ['vand\.vv', 'vand\.vs', 'vand\.vi']
    },
    'vor': {
        'mnemonic': 'vor',
        'vtype': 'logical',
        'description': '向量按位或',
        'patterns': ['vor\.vv', 'vor\.vs', 'vor\.vi']
    },
    'vxor': {
        'mnemonic': 'vxor',
        'vtype': 'logical',
        'description': '向量按位异或',
        'patterns': ['vxor\.vv', 'vxor\.vs', 'vxor\.vi']
    },
    'vsl': {
        'mnemonic': 'vsl',
        'vtype': 'shift',
        'description': '向量逻辑左移',
        'patterns': ['vsl\.vv', 'vsl\.vs', 'vsl\.vi']
    },
    'vsr': {
        'mnemonic': 'vsr',
        'vtype': 'shift',
        'description': '向量逻辑右移',
        'patterns': ['vsr\.vv', 'vsr\.vs', 'vsr\.vi']
    },
    'vssrl': {
        'mnemonic': 'vssrl',
        'vtype': 'shift',
        'description': '向量算术右移',
        'patterns': ['vssrl\.vv', 'vssrl\.vs', 'vssrl\.vi']
    },
    'vaddi': {
        'mnemonic': 'vaddi',
        'vtype': 'immediate',
        'description': '向量立即数加法',
        'patterns': ['vaddi']
    },
    'vsetvli': {
        'mnemonic': 'vsetvli',
        'vtype': 'control',
        'description': '设置向量长度',
        'patterns': ['vsetvli']
    },
    'vsetvl': {
        'mnemonic': 'vsetvl',
        'vtype': 'control',
        'description': '设置向量长度',
        'patterns': ['vsetvl']
    },
    'vle': {
        'mnemonic': 'vle',
        'vtype': 'memory',
        'description': '向量加载',
        'patterns': ['vle8', 'vle16', 'vle32', 'vle64']
    },
    'vse': {
        'mnemonic': 'vse',
        'vtype': 'memory',
        'description': '向量存储',
        'patterns': ['vse8', 'vse16', 'vse32', 'vse64']
    },
    'vcompress': {
        'mnemonic': 'vcompress',
        'vtype': 'permute',
        'description': '向量压缩',
        'patterns': ['vcompress']
    },
    'vextract': {
        'mnemonic': 'vextract',
        'vtype': 'permute',
        'description': '向量提取',
        'patterns': ['vextract']
    }
}

# RISC-V Crypto Extension 指令特征
CRYPTO_INSTRUCTIONS = {
    'aesenc': {
        'mnemonic': 'aesenc',
        'extension': 'Zkne',
        'description': 'AES轮加密',
        'security_risk': 'low'
    },
    'aesdec': {
        'mnemonic': 'aesdec',
        'extension': 'Zknd',
        'description': 'AES轮解密',
        'security_risk': 'low'
    },
    'aesencsm': {
        'mnemonic': 'aesencsm',
        'extension': 'Zkne',
        'description': 'AES轮加密(最后一轮)',
        'security_risk': 'low'
    },
    'aesdecsm': {
        'mnemonic': 'aesdecsm',
        'extension': 'Zknd',
        'description': 'AES轮解密(最后一轮)',
        'security_risk': 'low'
    },
    'sm3start': {
        'mnemonic': 'sm3start',
        'extension': 'Zksed',
        'description': 'SM3初始化',
        'security_risk': 'low'
    },
    'sm3update': {
        'mnemonic': 'sm3update',
        'extension': 'Zksed',
        'description': 'SM3更新',
        'security_risk': 'low'
    },
    'sm4enc': {
        'mnemonic': 'sm4enc',
        'extension': 'Zksh',
        'description': 'SM4轮加密',
        'security_risk': 'low'
    },
    'sm4key': {
        'mnemonic': 'sm4key',
        'extension': 'Zksh',
        'description': 'SM4密钥扩展',
        'security_risk': 'high'
    },
    'sha256sig0': {
        'mnemonic': 'sha256sig0',
        'extension': 'Zkne',
        'description': 'SHA256 Sigma0',
        'security_risk': 'low'
    },
    'sha256sig1': {
        'mnemonic': 'sha256sig1',
        'extension': 'Zkne',
        'description': 'SHA256 Sigma1',
        'security_risk': 'low'
    },
    'sha256sum0': {
        'mnemonic': 'sha256sum0',
        'extension': 'Zkne',
        'description': 'SHA256 Sum0',
        'security_risk': 'low'
    },
    'sha256sum1': {
        'mnemonic': 'sha256sum1',
        'extension': 'Zkne',
        'description': 'SHA256 Sum1',
        'security_risk': 'low'
    },
    'sha512sig0h': {
        'mnemonic': 'sha512sig0h',
        'extension': 'Zknh',
        'description': 'SHA512 Sigma0(高位)',
        'security_risk': 'low'
    },
    'sha512sig1h': {
        'mnemonic': 'sha512sig1h',
        'extension': 'Zknh',
        'description': 'SHA512 Sigma1(高位)',
        'security_risk': 'low'
    },
    'sha512sum0h': {
        'mnemonic': 'sha512sum0h',
        'extension': 'Zknh',
        'description': 'SHA512 Sum0(高位)',
        'security_risk': 'low'
    },
    'sha512sum1h': {
        'mnemonic': 'sha512sum1h',
        'extension': 'Zknh',
        'description': 'SHA512 Sum1(高位)',
        'security_risk': 'low'
    },
    'ghash': {
        'mnemonic': 'ghash',
        'extension': 'Zknd',
        'description': 'Galois哈希',
        'security_risk': 'medium'
    },
    'xperm4': {
        'mnemonic': 'xperm4',
        'extension': 'Zkne',
        'description': '4x4位置换',
        'security_risk': 'low'
    },
    'xperm8': {
        'mnemonic': 'xperm8',
        'extension': 'Zkne',
        'description': '8x8位置换',
        'security_risk': 'low'
    }
}

# 向量循环模式
VECTOR_LOOP_PATTERNS = {
    'strided_load': {
        'pattern': r'vle.*addi.*loop',
        'description': '跨步加载循环',
        'operation_type': 'memory'
    },
    'strided_store': {
        'pattern': r'vse.*addi.*loop',
        'description': '跨步存储循环',
        'operation_type': 'memory'
    },
    'element_wise': {
        'pattern': r'vsetvli.*vadd|vsetvli.*vmul',
        'description': '逐元素操作循环',
        'operation_type': 'compute'
    },
    'reduction': {
        'pattern': r'vredsum|vredmax|vredmin',
        'description': '归约操作循环',
        'operation_type': 'reduction'
    },
    'gather_scatter': {
        'pattern': r'vluxei8|vluxei16|vluxei32|vsuxei',
        'description': '聚集/分散操作',
        'operation_type': 'memory'
    }
}

class RISCVExtAnalyzer:
    """
    RISC-V Vector/Crypto 扩展分析模块
    
    核心功能：
    1. 识别 RISC-V 向量指令使用模式
    2. 分析向量循环结构
    3. 识别加密扩展指令使用
    4. 检测加密指令误用
    """
    
    def __init__(self):
        """初始化RISC-V扩展分析器"""
        logger.info("RISCVExtAnalyzer 初始化完成")
    
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
    
    def _detect_vector_instructions(self, instructions: List[str]) -> List[RISCVVectorInstruction]:
        """
        检测向量指令
        
        Args:
            instructions: 指令列表
        
        Returns:
            向量指令列表
        """
        detected = []
        
        for instr in instructions:
            for opcode, info in RVV_INSTRUCTIONS.items():
                for pattern in info['patterns']:
                    if pattern in instr:
                        detected.append(RISCVVectorInstruction(
                            opcode=opcode,
                            mnemonic=info['mnemonic'],
                            vtype=info['vtype'],
                            description=info['description'],
                            detected=True
                        

                        break
        
        return detected
    
    def _detect_crypto_instructions(self, instructions: List[str]) -> List[RISCV_CryptoInstruction]:
        """
        检测加密扩展指令
        
        Args:
            instructions: 指令列表
        
        Returns:
            加密指令列表
        """
        detected = []
        
        for instr in instructions:
            for opcode, info in CRYPTO_INSTRUCTIONS.items():
                if opcode in instr:
                    detected.append(RISCV_CryptoInstruction(
                        opcode=opcode,
                        mnemonic=info['mnemonic'],
                        extension=info['extension'],
                        description=info['description'],
                        security_risk=info['security_risk'],
                        detected=True
                    

        
        return detected
    
    def _detect_vector_loops(self, disassembly: str) -> List[RISCVVectorLoop]:
        """
        检测向量循环结构
        
        Args:
            disassembly: 反汇编内容
        
        Returns:
            向量循环列表
        """
        loops = []
        loop_count = 0
        
        for pattern_name, pattern_info in VECTOR_LOOP_PATTERNS.items():
            if pattern_info['pattern'] in disassembly.lower():
                loops.append(RISCVVectorLoop(
                    start_address=0,
                    end_address=0,
                    loop_count=loop_count,
                    vector_width=128,
                    operation_type=pattern_info['operation_type'],
                    detected_pattern=pattern_info['description']
                

                loop_count += 1
        
        return loops
    
    def _analyze_extension_usage(self, vector_instr: List[RISCVVectorInstruction], crypto_instr: List[RISCV_CryptoInstruction]) -> Dict[str, int]:
        """
        分析扩展使用情况
        
        Args:
            vector_instr: 向量指令列表
            crypto_instr: 加密指令列表
        
        Returns:
            扩展使用统计
        """
        usage = {
            'Zve': 0,
            'Zkne': 0,
            'Zknd': 0,
            'Zksed': 0,
            'Zksh': 0,
            'Zknh': 0
        }
        
        for instr in vector_instr:
            usage['Zve'] += 1
        
        for instr in crypto_instr:
            ext = instr.extension,
            if ext in usage:
                usage[ext] += 1
        
        return usage
    
    def _detect_security_issues(self, crypto_instr: List[RISCV_CryptoInstruction]) -> List[str]:
        """
        检测安全问题
        
        Args:
            crypto_instr: 加密指令列表
        
        Returns:
            安全问题列表
        """
        issues = []
        
        # 检查高风险指令的使用
        high_risk_instr = [i for i in crypto_instr if i.security_risk == 'high']
        if high_risk_instr:
            issues.append(f"检测到高风险加密指令使用: {', '.join(i.mnemonic for i in high_risk_instr)}")
        
        # 检查密钥相关指令
        key_instr = [i for i in crypto_instr if 'key' in i.description.lower()]
        if key_instr:
            issues.append(f"检测到密钥操作指令: {', '.join(i.mnemonic for i in key_instr)} - 建议审查密钥处理流程")
        
        # 检查SM4密钥扩展
        sm4_key_count = len([i for i in crypto_instr if i.mnemonic == 'sm4key'])
        if sm4_key_count > 0:
            issues.append(f"检测到 {sm4_key_count} 次 SM4 密钥扩展操作")
        
        return issues
    
    def analyze_binary(self, binary_path: str) -> RISCVExtAnalysisResult:
        """
        分析二进制文件中的RISC-V扩展使用情况
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            RISCVExtAnalysisResult 对象
        """
        logger.info(f"开始分析二进制文件的RISC-V扩展特征: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return RISCVExtAnalysisResult(
                vector_instructions=[],
                crypto_instructions=[],
                vector_loops=[],
                extension_usage={},
                security_issues=[],
                summary="文件不存在")
            

        
        try:
            # 获取反汇编
            disassembly = self._get_disassembly(binary_path)
            instructions = self._extract_instructions(disassembly)
            
            # 检测向量指令
            vector_instr = self._detect_vector_instructions(instructions)
            
            # 检测加密指令
            crypto_instr = self._detect_crypto_instructions(instructions)
            
            # 检测向量循环
            vector_loops = self._detect_vector_loops(disassembly)
            
            # 分析扩展使用
            ext_usage = self._analyze_extension_usage(vector_instr, crypto_instr)
            
            # 检测安全问题
            security_issues = self._detect_security_issues(crypto_instr)
            
            # 生成摘要
            summary_parts = []
            if vector_instr:
                summary_parts.append(f"发现 {len(vector_instr)} 条向量指令")
            if crypto_instr:
                summary_parts.append(f"发现 {len(crypto_instr)} 条加密指令")
            if vector_loops:
                summary_parts.append(f"发现 {len(vector_loops)} 个向量循环")
            if security_issues:
                summary_parts.append(f"发现 {len(security_issues)} 个安全问题")
            
            summary = "; ".join(summary_parts) if summary_parts else "未发现RISC-V扩展指令"
            logger.info(f"RISC-V扩展分析完成: {summary}")
            
            return RISCVExtAnalysisResult(
                vector_instructions=vector_instr,
                crypto_instructions=crypto_instr,
                vector_loops=vector_loops,
                extension_usage=ext_usage,
                security_issues=security_issues,
                summary=summary)
            

            
        except Exception as e:
            logger.error(f"分析二进制文件失败: {e}")
            return RISCVExtAnalysisResult(
                vector_instructions=[],
                crypto_instructions=[],
                vector_loops=[],
                extension_usage={},
                security_issues=[],
                summary=f"分析失败: {e}")
            

    
    def format_report(self, result: RISCVExtAnalysisResult) -> str:
        """
        格式化分析报告为Markdown格式
        
        Args:
            result: 分析结果
        
        Returns:
            Markdown格式的报告字符串
        """
        output = []
        
        output.append("## RISC-V Vector/Crypto 扩展分析报告")
        output.append(f"\n**摘要**: {result.summary}\n")
        
        if result.vector_instructions:
            output.append("### 向量指令使用")
            output.append("| 操作码 | 助记符 | 类型 | 描述 |")
            output.append("|--------|--------|------|------|")
            
            seen = set()
            for instr in result.vector_instructions:
                key = f"{instr.opcode}_{instr.vtype}",
                if key not in seen:
                    seen.add(key)
                    output.append(f"| {instr.opcode} | {instr.mnemonic} | {instr.vtype} | {instr.description} |")
            
            output.append("")
        
        if result.crypto_instructions:
            output.append("### 加密扩展指令使用")
            output.append("| 操作码 | 助记符 | 扩展 | 描述 | 安全风险 |")
            output.append("|--------|--------|------|------|----------|")
            
            seen = set()
            for instr in result.crypto_instructions:
                if instr.opcode not in seen:
                    seen.add(instr.opcode)
                    risk_color = '🔴' if instr.security_risk == 'high' else \
                                '🟡' if instr.security_risk == 'medium' else '🟢'
                    output.append(f"| {instr.opcode} | {instr.mnemonic} | {instr.extension} | {instr.description} | {risk_color} {instr.security_risk} |")
            
            output.append("")
        
        if result.vector_loops:
            output.append("### 向量循环结构")
            output.append("| 循环编号 | 操作类型 | 检测模式 |")
            output.append("|----------|----------|----------|")
            
            for loop in result.vector_loops:
                output.append(f"| Loop #{loop.loop_count} | {loop.operation_type} | {loop.detected_pattern} |")
            
            output.append("")
        
        if result.extension_usage:
            output.append("### 扩展使用统计")
            output.append("<details>")
            output.append("<summary>点击展开</summary>")
            output.append("")
            for ext, count in result.extension_usage.items():
                if count > 0:
                    output.append(f"- **{ext}**: {count} 次使用")
            output.append("")
            output.append("</details>")
            output.append("")
        
        if result.security_issues:
            output.append("### ⚠️ 安全问题")
            for issue in result.security_issues:
                output.append(f"- {issue}")
            output.append("")
        
        output.append("### 📌 分析建议")
        output.append("1. 验证向量指令的使用是否符合预期的性能优化目标")
        output.append("2. 审查加密指令的使用，特别是密钥相关操作")
        output.append("3. 确保向量循环的向量化效率")
        output.append("4. 关注高风险加密指令的使用场景")
        
        return '\n'.join(output)


def get_riscv_ext_analyzer() -> RISCVExtAnalyzer:
    """
    获取全局RISC-V扩展分析器实例
    
    Returns:
        RISCVExtAnalyzer 实例
    """
    global _riscv_analyzer
    if _riscv_analyzer is None:
        _riscv_analyzer = RISCVExtAnalyzer()
    return _riscv_analyzer


# 全局RISC-V扩展分析器实例
_riscv_analyzer = None))))))