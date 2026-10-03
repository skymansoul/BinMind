import os
import logging
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RISCVVectorInstruction:
    opcode: str
    mnemonic: str
    vtype: str
    description: str
    detected: bool = False

@dataclass
class RISCVVectorLoop:
    start_address: int
    end_address: int
    loop_count: int
    vector_width: int
    operation_type: str
    detected_pattern: str

@dataclass
class RISCV_CryptoInstruction:
    opcode: str
    mnemonic: str
    extension: str
    description: str
    security_risk: str
    detected: bool = False

class RISCVExtAnalysisResult:
    __slots__ = ('vector_instructions', 'crypto_instructions', 'vector_loops', 'extension_usage', 'security_issues', 'summary',)

    def __init__(self, vector_instructions, crypto_instructions, vector_loops, extension_usage, security_issues, summary):
        self.vector_instructions = vector_instructions
        self.crypto_instructions = crypto_instructions
        self.vector_loops = vector_loops
        self.extension_usage = extension_usage
        self.security_issues = security_issues
        self.summary = summary


# RISC-V Vector Extension (RVV) 指令特征表
RVV_INSTRUCTIONS = {
    'vadd': {
        'mnemonic': 'vadd',
        'vtype': 'arithmetic',
        'description': 'vector加法',
        'patterns': ['vadd\.vv', 'vadd\.vs', 'vadd\.vi']
    },
    'vsub': {
        'mnemonic': 'vsub',
        'vtype': 'arithmetic',
        'description': 'vector减法',
        'patterns': ['vsub\.vv', 'vsub\.vs', 'vsub\.vi']
    },
    'vmul': {
        'mnemonic': 'vmul',
        'vtype': 'arithmetic',
        'description': 'vector乘法',
        'patterns': ['vmul\.vv', 'vmul\.vs', 'vmul\.vi']
    },
    'vdiv': {
        'mnemonic': 'vdiv',
        'vtype': 'arithmetic',
        'description': 'vector除法',
        'patterns': ['vdiv\.vv', 'vdiv\.vs']
    },
    'vrem': {
        'mnemonic': 'vrem',
        'vtype': 'arithmetic',
        'description': 'vector取余',
        'patterns': ['vrem\.vv', 'vrem\.vs']
    },
    'vand': {
        'mnemonic': 'vand',
        'vtype': 'logical',
        'description': 'vector按位与',
        'patterns': ['vand\.vv', 'vand\.vs', 'vand\.vi']
    },
    'vor': {
        'mnemonic': 'vor',
        'vtype': 'logical',
        'description': 'vector按位 or ',
        'patterns': ['vor\.vv', 'vor\.vs', 'vor\.vi']
    },
    'vxor': {
        'mnemonic': 'vxor',
        'vtype': 'logical',
        'description': 'vector按位异 or ',
        'patterns': ['vxor\.vv', 'vxor\.vs', 'vxor\.vi']
    },
    'vsl': {
        'mnemonic': 'vsl',
        'vtype': 'shift',
        'description': 'vector逻辑左移',
        'patterns': ['vsl\.vv', 'vsl\.vs', 'vsl\.vi']
    },
    'vsr': {
        'mnemonic': 'vsr',
        'vtype': 'shift',
        'description': 'vector逻辑右移',
        'patterns': ['vsr\.vv', 'vsr\.vs', 'vsr\.vi']
    },
    'vssrl': {
        'mnemonic': 'vssrl',
        'vtype': 'shift',
        'description': 'vector算术右移',
        'patterns': ['vssrl\.vv', 'vssrl\.vs', 'vssrl\.vi']
    },
    'vaddi': {
        'mnemonic': 'vaddi',
        'vtype': 'immediate',
        'description': 'vector立即数加法',
        'patterns': ['vaddi']
    },
    'vsetvli': {
        'mnemonic': 'vsetvli',
        'vtype': 'control',
        'description': 'settingvectorlength',
        'patterns': ['vsetvli']
    },
    'vsetvl': {
        'mnemonic': 'vsetvl',
        'vtype': 'control',
        'description': 'settingvectorlength',
        'patterns': ['vsetvl']
    },
    'vle': {
        'mnemonic': 'vle',
        'vtype': 'memory',
        'description': 'vectorload',
        'patterns': ['vle8', 'vle16', 'vle32', 'vle64']
    },
    'vse': {
        'mnemonic': 'vse',
        'vtype': 'memory',
        'description': 'vector存储',
        'patterns': ['vse8', 'vse16', 'vse32', 'vse64']
    },
    'vcompress': {
        'mnemonic': 'vcompress',
        'vtype': 'permute',
        'description': 'vectorcompress',
        'patterns': ['vcompress']
    },
    'vextract': {
        'mnemonic': 'vextract',
        'vtype': 'permute',
        'description': 'vectorextract',
        'patterns': ['vextract']
    }
}

# RISC-V Crypto Extension 指令特征表
CRYPTO_INSTRUCTIONS = {
    'aesenc': {
        'mnemonic': 'aesenc',
        'extension': 'Zkne',
        'description': 'AES轮encrypt',
        'security_risk': 'low'
    },
    'aesdec': {
        'mnemonic': 'aesdec',
        'extension': 'Zknd',
        'description': 'AES轮decrypt',
        'security_risk': 'low'
    },
    'aesencsm': {
        'mnemonic': 'aesencsm',
        'extension': 'Zkne',
        'description': 'AES轮encrypt(最后一轮)',
        'security_risk': 'low'
    },
    'aesdecsm': {
        'mnemonic': 'aesdecsm',
        'extension': 'Zknd',
        'description': 'AES轮decrypt(最后一轮)',
        'security_risk': 'low'
    },
    'sm3start': {
        'mnemonic': 'sm3start',
        'extension': 'Zksed',
        'description': 'SM3initialize',
        'security_risk': 'low'
    },
    'sm3update': {
        'mnemonic': 'sm3update',
        'extension': 'Zksed',
        'description': 'SM3update',
        'security_risk': 'low'
    },
    'sm4enc': {
        'mnemonic': 'sm4enc',
        'extension': 'Zksh',
        'description': 'SM4轮encrypt',
        'security_risk': 'low'
    },
    'sm4key': {
        'mnemonic': 'sm4key',
        'extension': 'Zksh',
        'description': 'SM4secret keyextension',
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
        'description': 'Galoishash',
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

# 向量循环模式匹配表
VECTOR_LOOP_PATTERNS = {
    'strided_load': {
        'pattern': r'vle.*addi.*loop',
        'description': '跨步loadloop',
        'operation_type': 'memory'
    },
    'strided_store': {
        'pattern': r'vse.*addi.*loop',
        'description': '跨步存储loop',
        'operation_type': 'memory'
    },
    'element_wise': {
        'pattern': r'vsetvli.*vadd|vsetvli.*vmul',
        'description': '逐元素操作loop',
        'operation_type': 'compute'
    },
    'reduction': {
        'pattern': r'vredsum|vredmax|vredmin',
        'description': '归约操作loop',
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
    RISC-V Vector/Crypto扩展分析模块。

    核心能力：
    1. 识别RISC-V向量指令使用模式
    2. 解析向量循环结构
    3. 识别加密扩展指令
    4. 检测加密指令误用
    """

    def __init__(self):
        """初始化RISC-V扩展分析器。"""
        logger.info("RISCVExtAnalyzer initializecomplete")

    # 原为推导式，改为显式迭代以提升可维护性
    def _get_disassembly(self, binary_path: str) -> str:
        """
        获取目标二进制反汇编文本。

        """
        try:
            import subprocess
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'pd 500', binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                return result.stdout

        except Exception as e:
            logger.debug(f"获取disassemblyfailed: {e}")

        return ""

    def _extract_instructions(self, disassembly: str) -> List[str]:
        """
        从反汇编文本提取指令序列。

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
        匹配并提取向量运算指令。

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
                        ))

                        break

        return detected

    def _detect_crypto_instructions(self, instructions: List[str]) -> List[RISCV_CryptoInstruction]:
        """
        匹配并提取加密扩展指令。

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
                    ))

        return detected

    def _detect_vector_loops(self, disassembly: str) -> List[RISCVVectorLoop]:
        """
        识别反汇编中的向量循环结构。

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
                ))

                loop_count += 1

        return loops

    def _analyze_extension_usage(self, vector_instr: List[RISCVVectorInstruction], crypto_instr: List[RISCV_CryptoInstruction]) -> Dict[str, int]:
        """
        统计各扩展指令的使用频次。

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
            ext = instr.extension
            if ext in usage:
                usage[ext] += 1

        return usage

    def _detect_security_issues(self, crypto_instr: List[RISCV_CryptoInstruction]) -> List[str]:
        """
        检测加密指令相关的安全隐患。

        """
        issues = []

        # 高风险指令审查
        high_risk_instr = [i for i in crypto_instr if i.security_risk == 'high']
        if high_risk_instr:
            issues.append(f"detected高风险encrypt指令使用: {', '.join(i.mnemonic for i in high_risk_instr)}")

        # 密钥操作指令审查
        key_instr = [i for i in crypto_instr if 'key' in i.description.lower()]
        if key_instr:
            issues.append(f"detectedsecret key操作指令: {', '.join(i.mnemonic for i in key_instr)} - 建议审查secret key处理流程")

        # SM4密钥扩展审查
        sm4_key_count = sum(1 for i in crypto_instr if i.extension == 'Zksh' and 'key' in i.description.lower())
        if sm4_key_count > 0:
            issues.append(f"detected {sm4_key_count} 次 SM4 secret keyextension操作")

        return issues

    def analyze_binary(self, binary_path: str) -> RISCVExtAnalysisResult:
        """
        对目标二进制执行RISC-V扩展使用分析。

        """
        logger.info(f"start分析binaryfile的RISC-Vextensionfeature: {binary_path}")

        if not os.path.exists(binary_path):
            logger.error(f"file not found: {binary_path}")
            return RISCVExtAnalysisResult(
                vector_instructions=[],
                crypto_instructions=[],
                vector_loops=[],
                extension_usage={},
                security_issues=[],
                summary="file not found")



        try:
            # Step 1: 提取反汇编
            disassembly = self._get_disassembly(binary_path)
            instructions = self._extract_instructions(disassembly)

            # Step 2: 检测向量指令
            vector_instr = self._detect_vector_instructions(instructions)

            # Step 3: 检测加密指令
            crypto_instr = self._detect_crypto_instructions(instructions)

            # Step 4: 检测向量循环
            vector_loops = self._detect_vector_loops(disassembly)

            # Step 5: 统计扩展使用
            ext_usage = self._analyze_extension_usage(vector_instr, crypto_instr)

            # Step 6: 安全审计
            security_issues = self._detect_security_issues(crypto_instr)

            # Step 7: 生成摘要
            summary_parts = []
            if vector_instr:
                summary_parts.append(f"发现 {len(vector_instr)} 条vector指令")
            if crypto_instr:
                summary_parts.append(f"发现 {len(crypto_instr)} 条encrypt指令")
            if vector_loops:
                summary_parts.append(f"发现 {len(vector_loops)} 个vectorloop")
            if security_issues:
                summary_parts.append(f"发现 {len(security_issues)} 个安全问题")

            summary = "; ".join(summary_parts) if summary_parts else "未发现RISC-Vextension指令"
            logger.info(f"RISC-Vextensionanalysis complete: {summary}")

            return RISCVExtAnalysisResult(
                vector_instructions=vector_instr,
                crypto_instructions=crypto_instr,
                vector_loops=vector_loops,
                extension_usage=ext_usage,
                security_issues=security_issues,
                summary=summary)



        except Exception as e:
            logger.error(f"分析binaryfilefailed: {e}")
            return RISCVExtAnalysisResult(
                vector_instructions=[],
                crypto_instructions=[],
                vector_loops=[],
                extension_usage={},
                security_issues=[],
                summary=f"analysis failed: {e}")



    def format_report(self, result: RISCVExtAnalysisResult) -> str:
        """
        将分析结果渲染为Markdown报告。

        """
        output = []

        output.append("## RISC-V Vector/Crypto extensionanalysis report")
        output.append(f"\n**summary**: {result.summary}\n")

        if result.vector_instructions:
            output.append("### vector指令使用")
            output.append("| 操作码 | 助记符 | type | description |")
            output.append("|--------|--------|------|------|")

            seen = set()
            for instr in result.vector_instructions:
                key = f"{instr.opcode}_{instr.vtype}"
                if key not in seen:
                    seen.add(key)
                    output.append(f"| {instr.opcode} | {instr.mnemonic} | {instr.vtype} | {instr.description} |")

            output.append("")

        if result.crypto_instructions:
            output.append("### encryptextension指令使用")
            output.append("| 操作码 | 助记符 | extension | description | 安全风险 |")
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
            output.append("### vectorloop结构")
            output.append("| loop编号 | 操作type | 检测mode |")
            output.append("|----------|----------|----------|")

            for loop in result.vector_loops:
                output.append(f"| Loop #{loop.loop_count} | {loop.operation_type} | {loop.detected_pattern} |")

            output.append("")

        if result.extension_usage:
            output.append("### extension使用统计")
            output.append("<details>")
            output.append("<summary>点击展开</summary>")
            output.append("")
            for ext, nCount in result.extension_usage.items():
                if nCount > 0:
                    output.append(f"- **{ext}**: {nCount} 次使用")
            output.append("")
            output.append("</details>")
            output.append("")

        if result.security_issues:
            output.append("### ⚠️ 安全问题")
            for issue in result.security_issues:
                output.append(f"- {issue}")
            output.append("")

        output.append("### 📌 分析建议")
        output.append("1. validatevector指令的使用是否符合预期的performanceoptimizetarget")
        output.append("2. 审查encrypt指令的使用，特别是secret key相关操作")
        output.append("3. 确保vectorloop的vector化效率")
        output.append("4. 关注高风险encrypt指令的使用场景")

        return '\n'.join(output)


def get_riscv_ext_analyzer() -> RISCVExtAnalyzer:
    """
    返回全局RISC-V扩展分析器单例。

    """
    global _riscv_analyzer
    if _riscv_analyzer is None:
        _riscv_analyzer = RISCVExtAnalyzer()
    return _riscv_analyzer

# 全局RISC-V扩展分析器单例
_riscv_analyzer = None
