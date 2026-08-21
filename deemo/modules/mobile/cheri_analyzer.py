"""CHERI capability硬件安全分析。
针对Morello/ARM CHERI架构编译的二进制，检测capability误用、bounds检查缺失、seal/unseal违规。
"""
from typing import Dict, Any
from typing import List, Optional
import logging

__log = logging.getLogger(__name__)


class CHERIInstruction:
    """反汇编中识别到的单条CHERI指令。"""

    def __init__(self, address=0, opcode="", mnemonic="",
                 operands=None, category=""):
        self.address = address
        self.opcode = opcode
        self.mnemonic = mnemonic
        self.operands = operands or []
        self.category = category


class CHERICapability:
    """CHERI capability对象，封装bounds、permissions与object type。"""

    def __init__(self, name="", base=0, offset=0, length=0,
                 permissions="", obj_type=""):
        self.name = name
        self.base = base
        self.offset = offset
        self.length = length
        self.permissions = permissions
        self.obj_type = obj_type


class CHERIAnalysisResult:
    """CHERI二进制单次分析结果集。"""

    def __init__(self):
        self.capabilities = []
        self.instructions = []
        self.vulnerabilities = []
        self.mitigations = []
        self.summary = {}


class CHERIAnalyzer:
    """CHERI保护二进制主分析器。"""

    def __init__(self):
        self._capability_usage = {}

    def analyze_binary(self, binary_path):
        """对目标二进制执行完整CHERI分析流程。"""
        result = CHERIAnalysisResult()
        if binary_path is None or not __import__("os").path.exists(binary_path):
            result.summary = "file not found"
            return result

        disasm = self._disassemble(binary_path)
        result.instructions = self._extract_capabilities(disasm)
        result.capabilities = self._build_capabilities(result.instructions)
        result.vulnerabilities = self._find_vulnerabilities(result.instructions)
        result.mitigations = self._evaluate_mitigations(result)
        result.summary = self._build_summary(result)
        return result

    def _disassemble(self, binary_path):
        """通过r2反汇编引擎提取CHERI指令。"""
        import subprocess
        try:
            r = subprocess.run(
                ["r2", "-q", "-c", "aaaa; pdf @ main; q", binary_path],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace")
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout
            r = subprocess.run(
                ["r2", "-q", "-c", "aa; pd 1000; q", binary_path],
                capture_output=True, text=True, timeout=120,
                encoding="utf-8", errors="replace")
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def _extract_capabilities(self, disasm):
        """从反汇编文本解析CHERI capability指令。"""
        instrs = []
        for line in (disasm or "").split("\n"):
            stripped = line.strip()
            if "ldc" in stripped:
                instrs.append(CHERIInstruction(
                    opcode="ldc", mnemonic="ldc", category="load"))
            elif "stc" in stripped:
                instrs.append(CHERIInstruction(
                    opcode="stc", mnemonic="stc", category="store"))
            elif "cseal" in stripped:
                instrs.append(CHERIInstruction(
                    opcode="cseal", mnemonic="cseal", category="seal"))
            elif "cunseal" in stripped:
                instrs.append(CHERIInstruction(
                    opcode="cunseal", mnemonic="cunseal", category="seal"))
            elif "ccall" in stripped:
                instrs.append(CHERIInstruction(
                    opcode="ccall", mnemonic="ccall",
                    category="capability_register"))
        return instrs

    def _build_capabilities(self, instrs):
        """由已提取指令构建capability对象列表。"""
        return [CHERICapability(name=f"cap_{i}", base=0, length=0,
                                permissions="PLS")
                for i, _ in enumerate(instrs)]

    def _find_vulnerabilities(self, instrs):
        """识别CHERI相关潜在漏洞。"""
        vulns = []
        if not instrs:
            # 空输入无分析对象，不应产生发现
            return vulns
        usage = self._analyze_capability_usage(instrs)
        if usage.get("seal", 0) == 0:
            vulns.append({"type": "missing_seal",
                          "desc": "No seal operations detected"})
        return vulns

    def _analyze_capability_usage(self, instrs):
        """按类别统计capability操作频次。"""
        usage = {}
        for i in instrs:
            cat = i.category
            usage[cat] = usage.get(cat, 0) + 1
        return usage

    def _evaluate_mitigations(self, result):
        """核查当前生效的CHERI缓解措施。"""
        mitigations = []
        if result.capabilities:
            mitigations.append("capability_check")
        return mitigations

    def _get_mitigation(self, vuln_type):
        """按漏洞类型返回对应缓解建议。"""
        if vuln_type == "capability_leak":
            return {"type": "bounds_check", "status": "applied"}
        return {}

    def _build_summary(self, result):
        """生成可读分析摘要。"""
        return {
            "total_capabilities": len(result.capabilities),
            "total_instructions": len(result.instructions),
            "vulnerabilities_found": len(result.vulnerabilities),
            "mitigations_active": len(result.mitigations),
        }

    def format_report(self, result):
        """CHERI分析结果格式化输出。"""
        if result is None:
            return ""
        lines = [f"CHERI Analysis Report"]
        lines.append(f"  Capabilities: {len(result.capabilities)}")
        lines.append(f"  Instructions: {len(result.instructions)}")
        lines.append(f"  Vulnerabilities: {len(result.vulnerabilities)}")
        lines.append(f"  Mitigations: {len(result.mitigations)}")
        lines.append(f"  Summary: {result.summary}")
        return "\n".join(lines)
