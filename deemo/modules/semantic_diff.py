#!/usr/bin/env python3
"""
跨版本二进制语义差异分析引擎

提取函数语义签名，在两个版本间匹配函数，定位补丁点并尝试生成差异利用原型。
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)


class DiffResultType(Enum):
    """差异结果类型"""
    FUNCTION_ADDED = "function_added"
    FUNCTION_REMOVED = "function_removed"
    FUNCTION_MODIFIED = "function_modified"
    FUNCTION_UNCHANGED = "function_unchanged"
    PATCH_CANDIDATE = "patch_candidate"


class SemanticSignatureType(Enum):
    """语义签名类型"""
    SYMBOLIC_INPUT_OUTPUT = "symbolic_input_output"
    MEMORY_SIDE_EFFECT = "memory_side_effect"
    CONTROL_FLOW_GRAPH = "control_flow_graph"
    DATA_FLOW_GRAPH = "data_flow_graph"


@dataclass
class SemanticSignature:
    """函数语义签名"""
    function_name: str
    function_address: int
    signature_type: SemanticSignatureType
    signature_data: Dict[str, Any]
    confidence: float = 1.0


@dataclass
class FunctionMatch:
    """函数匹配结果"""
    old_function: Optional[SemanticSignature]
    new_function: Optional[SemanticSignature]
    similarity_score: float
    match_type: DiffResultType


@dataclass
class PatchLocation:
    """补丁位置"""
    address: int
    old_bytes: Optional[bytes] = None
    new_bytes: Optional[bytes] = None
    description: str = ""
    severity: str = "unknown"


@dataclass
class DiffAnalysisResult:
    """差异分析结果"""
    success: bool
    matches: List[FunctionMatch]
    patch_locations: List[PatchLocation]
    diff_count: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    exploit_prototype: Optional[str] = None


@dataclass
class SymbolicRelation:
    """符号输入输出关系"""
    inputs: List[str]
    outputs: List[str]
    constraints: List[str]


class SignatureExtractor(ABC):
    """语义签名提取器基类"""
    
    @abstractmethod
    def extract(self, function_ir: Any) -> SemanticSignature:
        """
        提取函数语义签名
        
        Args:
            function_ir: 函数IR
        
        Returns:
            语义签名
        """
        pass


class SymbolicSignatureExtractor(SignatureExtractor):
    """符号输入输出签名提取器"""
    
    def extract(self, function_ir: Any) -> SemanticSignature:
        """提取符号签名"""
        signature_data = {
            "inputs": self._extract_inputs(function_ir),
            "outputs": self._extract_outputs(function_ir),
            "constraints": self._extract_constraints(function_ir)
        }
        
        return SemanticSignature(
            function_name=function_ir.name,
            function_address=function_ir.address,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data=signature_data,
            confidence=0.8
        )
    
    def _extract_inputs(self, function_ir: Any) -> List[str]:
        """提取输入变量"""
        inputs = []
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'opcode') and instr.opcode in ["Iop_Load", "load"]:
                        inputs.append(f"mem_{hex(instr.address)}")
                    if hasattr(instr, 'operands'):
                        for op in instr.operands:
                            if isinstance(op, str) and op.startswith(('eax', 'ebx', 'ecx', 'edx', 'rdi', 'rsi')):
                                inputs.append(op)
        return list(set(inputs))
    
    def _extract_outputs(self, function_ir: Any) -> List[str]:
        """提取输出变量"""
        outputs = []
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'opcode') and instr.opcode in ["Iop_Store", "store"]:
                        outputs.append(f"mem_{hex(instr.address)}")
                    if hasattr(instr, 'opcode') and instr.opcode == "Iop_Ret":
                        outputs.append("return")
        return list(set(outputs))
    
    def _extract_constraints(self, function_ir: Any) -> List[str]:
        """提取约束条件"""
        constraints = []
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'opcode') and instr.opcode in ["Iop_CmpNE", "Iop_CmpEQ", "Iop_CmpLT"]:
                        constraints.append(f"{instr.opcode}: {', '.join(str(o) for o in instr.operands)}")
        return constraints


class MemorySideEffectExtractor(SignatureExtractor):
    """内存副作用签名提取器"""
    
    def extract(self, function_ir: Any) -> SemanticSignature:
        """提取内存副作用签名"""
        signature_data = {
            "read_regions": self._extract_read_regions(function_ir),
            "write_regions": self._extract_write_regions(function_ir),
            "global_access": self._extract_global_access(function_ir)
        }
        
        return SemanticSignature(
            function_name=function_ir.name,
            function_address=function_ir.address,
            signature_type=SemanticSignatureType.MEMORY_SIDE_EFFECT,
            signature_data=signature_data,
            confidence=0.75
        )
    
    def _extract_read_regions(self, function_ir: Any) -> List[str]:
        """提取读内存区域"""
        regions = []
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'opcode') and instr.opcode in ["Iop_Load", "load"]:
                        regions.append(f"0x{instr.address:x}")
        return list(set(regions))
    
    def _extract_write_regions(self, function_ir: Any) -> List[str]:
        """提取写内存区域"""
        regions = []
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'opcode') and instr.opcode in ["Iop_Store", "store"]:
                        regions.append(f"0x{instr.address:x}")
        return list(set(regions))
    
    def _extract_global_access(self, function_ir: Any) -> bool:
        """检测是否访问全局变量"""
        if hasattr(function_ir, 'basic_blocks'):
            for block in function_ir.basic_blocks:
                for instr in block.instructions:
                    if hasattr(instr, 'operands'):
                        for op in instr.operands:
                            if isinstance(op, str) and op.startswith(('0x', 'global_', '__g')):
                                return True
        return False


class FunctionMatcher:
    """函数匹配器"""
    
    def __init__(self):
        """初始化匹配器"""
        self.extractors = [
            SymbolicSignatureExtractor(),
            MemorySideEffectExtractor()
        ]
    
    def compute_signature_similarity(self, sig1: SemanticSignature, sig2: SemanticSignature) -> float:
        """
        计算两个签名的相似度
        
        Args:
            sig1: 第一个签名
            sig2: 第二个签名
        
        Returns:
            相似度分数 (0-1)
        """
        if sig1.signature_type != sig2.signature_type:
            return 0.0
        
        data1 = sig1.signature_data
        data2 = sig2.signature_data
        
        score = 0.0
        weight = 0.0
        
        if "inputs" in data1 and "inputs" in data2:
            inputs1 = set(data1["inputs"])
            inputs2 = set(data2["inputs"])
            intersection = len(inputs1 & inputs2)
            union = len(inputs1 | inputs2)
            if union > 0:
                score += (intersection / union) * 0.3
                weight += 0.3
        
        if "outputs" in data1 and "outputs" in data2:
            outputs1 = set(data1["outputs"])
            outputs2 = set(data2["outputs"])
            intersection = len(outputs1 & outputs2)
            union = len(outputs1 | outputs2)
            if union > 0:
                score += (intersection / union) * 0.3
                weight += 0.3
        
        if "constraints" in data1 and "constraints" in data2:
            constraints1 = set(data1["constraints"])
            constraints2 = set(data2["constraints"])
            intersection = len(constraints1 & constraints2)
            union = len(constraints1 | constraints2)
            if union > 0:
                score += (intersection / union) * 0.2
                weight += 0.2
        
        if "read_regions" in data1 and "read_regions" in data2:
            regions1 = set(data1["read_regions"])
            regions2 = set(data2["read_regions"])
            intersection = len(regions1 & regions2)
            union = len(regions1 | regions2)
            if union > 0:
                score += (intersection / union) * 0.1
                weight += 0.1
        
        if "write_regions" in data1 and "write_regions" in data2:
            regions1 = set(data1["write_regions"])
            regions2 = set(data2["write_regions"])
            intersection = len(regions1 & regions2)
            union = len(regions1 | regions2)
            if union > 0:
                score += (intersection / union) * 0.1
                weight += 0.1
        
        if weight > 0:
            return score / weight
        return 0.0
    
    def match_functions(self, old_signatures: List[SemanticSignature], 
                       new_signatures: List[SemanticSignature]) -> List[FunctionMatch]:
        """
        匹配两个版本的函数
        
        Args:
            old_signatures: 旧版本函数签名列表
            new_signatures: 新版本函数签名列表
        
        Returns:
            匹配结果列表
        """
        matches = []
        matched_new = set()
        
        for old_sig in old_signatures:
            best_match = None
            best_score = 0.0
            
            for idx, new_sig in enumerate(new_signatures):
                if idx in matched_new:
                    continue
                
                score = self.compute_signature_similarity(old_sig, new_sig)
                if score > best_score and score >= 0.5:
                    best_score = score
                    best_match = new_sig
            
            if best_match:
                matched_new.add(new_signatures.index(best_match))
                match_type = self._determine_match_type(best_score)
                matches.append(FunctionMatch(
                    old_function=old_sig,
                    new_function=best_match,
                    similarity_score=best_score,
                    match_type=match_type
                ))
            else:
                matches.append(FunctionMatch(
                    old_function=old_sig,
                    new_function=None,
                    similarity_score=0.0,
                    match_type=DiffResultType.FUNCTION_REMOVED
                ))
        
        for idx, new_sig in enumerate(new_signatures):
            if idx not in matched_new:
                matches.append(FunctionMatch(
                    old_function=None,
                    new_function=new_sig,
                    similarity_score=0.0,
                    match_type=DiffResultType.FUNCTION_ADDED
                ))
        
        return matches
    
    def _determine_match_type(self, score: float) -> DiffResultType:
        """根据相似度确定匹配类型"""
        if score >= 0.95:
            return DiffResultType.FUNCTION_UNCHANGED
        elif score >= 0.7:
            return DiffResultType.FUNCTION_MODIFIED
        else:
            return DiffResultType.PATCH_CANDIDATE


class SemanticDiffAnalyzer:
    """
    跨版本二进制语义差异分析引擎
    
    提取函数语义签名，在两个版本间匹配函数，定位补丁点并尝试生成差异利用原型。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.matcher = FunctionMatcher()
        self.signature_extractors = [
            SymbolicSignatureExtractor(),
            MemorySideEffectExtractor()
        ]
    
    def extract_signatures(self, functions_ir: List[Any]) -> List[SemanticSignature]:
        """
        从函数IR列表提取语义签名
        
        Args:
            functions_ir: 函数IR列表
        
        Returns:
            语义签名列表
        """
        signatures = []
        
        for func_ir in functions_ir:
            for extractor in self.signature_extractors:
                try:
                    signature = extractor.extract(func_ir)
                    signatures.append(signature)
                except Exception as e:
                    logger.warning(f"提取签名失败: {e}")
        
        return signatures
    
    def analyze(self, old_binary_path: str, new_binary_path: str,
                old_functions_ir: Optional[List[Any]] = None,
                new_functions_ir: Optional[List[Any]] = None) -> DiffAnalysisResult:
        """
        执行跨版本语义差异分析
        
        Args:
            old_binary_path: 旧版本二进制路径
            new_binary_path: 新版本二进制路径
            old_functions_ir: 已提升的旧版本函数IR（可选）
            new_functions_ir: 已提升的新版本函数IR（可选）
        
        Returns:
            差异分析结果
        """
        if not os.path.exists(old_binary_path):
            return DiffAnalysisResult(
                success=False,
                matches=[],
                patch_locations=[],
                errors=[f"旧版本文件不存在: {old_binary_path}"]
            )
        
        if not os.path.exists(new_binary_path):
            return DiffAnalysisResult(
                success=False,
                matches=[],
                patch_locations=[],
                errors=[f"新版本文件不存在: {new_binary_path}"]
            )
        
        try:
            if old_functions_ir is None:
                old_functions_ir = self._load_binary_functions(old_binary_path)
            
            if new_functions_ir is None:
                new_functions_ir = self._load_binary_functions(new_binary_path)
            
            old_signatures = self.extract_signatures(old_functions_ir)
            new_signatures = self.extract_signatures(new_functions_ir)
            
            matches = self.matcher.match_functions(old_signatures, new_signatures)
            
            patch_locations = self._identify_patch_locations(matches)
            
            diff_count = sum(1 for m in matches if m.match_type != DiffResultType.FUNCTION_UNCHANGED)
            
            exploit_prototype = self._generate_exploit_prototype(patch_locations)
            
            return DiffAnalysisResult(
                success=True,
                matches=matches,
                patch_locations=patch_locations,
                diff_count=diff_count,
                exploit_prototype=exploit_prototype
            )
        
        except Exception as e:
            logger.error(f"差异分析失败: {e}")
            return DiffAnalysisResult(
                success=False,
                matches=[],
                patch_locations=[],
                errors=[str(e)]
            )
    
    def _load_binary_functions(self, binary_path: str) -> List[Any]:
        """加载二进制函数（占位实现）"""
        from modules.ir_lifter import IRLifter, Architecture, IRType
        
        try:
            lifter = IRLifter(Architecture.X86_64, IRType.VEX)
            result = lifter.lift_binary(binary_path)
            return result.functions if result.success else []
        except Exception as e:
            logger.warning(f"加载二进制失败: {e}")
            return []
    
    def _identify_patch_locations(self, matches: List[FunctionMatch]) -> List[PatchLocation]:
        """识别补丁位置"""
        locations = []
        
        for match in matches:
            if match.match_type in [DiffResultType.FUNCTION_MODIFIED, DiffResultType.PATCH_CANDIDATE]:
                if match.old_function and match.new_function:
                    loc = PatchLocation(
                        address=match.new_function.function_address,
                        description=f"函数 {match.new_function.function_name} 被修改",
                        severity="high" if match.match_type == DiffResultType.PATCH_CANDIDATE else "medium"
                    )
                    locations.append(loc)
            elif match.match_type == DiffResultType.FUNCTION_ADDED:
                if match.new_function:
                    loc = PatchLocation(
                        address=match.new_function.function_address,
                        description=f"新增函数 {match.new_function.function_name}",
                        severity="medium"
                    )
                    locations.append(loc)
        
        return locations
    
    def _generate_exploit_prototype(self, patch_locations: List[PatchLocation]) -> Optional[str]:
        """生成差异利用原型"""
        if not patch_locations:
            return None
        
        prototypes = []
        
        for loc in patch_locations:
            if loc.severity == "high":
                prototype = f"""# 差异利用原型 - {loc.description}
# 目标地址: 0x{loc.address:x}

def exploit():
    # 1. 定位漏洞点
    target_addr = 0x{loc.address:x}
    
    # 2. 构造payload
    payload = b'A' * 100
    
    # 3. 触发漏洞
    # TODO: 根据具体漏洞类型完善
    
    return payload
"""
                prototypes.append(prototype)
        
        return "\n\n".join(prototypes) if prototypes else None
    
    def generate_report(self, result: DiffAnalysisResult) -> str:
        """
        生成分析报告
        
        Args:
            result: 差异分析结果
        
        Returns:
            报告字符串
        """
        report = []
        report.append("=" * 60)
        report.append("跨版本二进制语义差异分析报告")
        report.append("=" * 60)
        report.append(f"差异数量: {result.diff_count}")
        report.append(f"成功: {result.success}")
        report.append("")
        
        if result.patch_locations:
            report.append("补丁位置:")
            report.append("-" * 40)
            for loc in result.patch_locations:
                report.append(f"地址: 0x{loc.address:x}")
                report.append(f"  描述: {loc.description}")
                report.append(f"  严重程度: {loc.severity}")
                report.append("")
        
        if result.exploit_prototype:
            report.append("利用原型:")
            report.append("-" * 40)
            report.append(result.exploit_prototype)
        
        return "\n".join(report)
    
    def save_result(self, result: DiffAnalysisResult, output_path: str) -> bool:
        """
        保存分析结果
        
        Args:
            result: 分析结果
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        try:
            import json
            
            result_dict = {
                "success": result.success,
                "diff_count": result.diff_count,
                "matches": [
                    {
                        "old_function": m.old_function.function_name if m.old_function else None,
                        "new_function": m.new_function.function_name if m.new_function else None,
                        "similarity_score": m.similarity_score,
                        "match_type": m.match_type.value
                    } for m in result.matches
                ],
                "patch_locations": [
                    {
                        "address": hex(loc.address),
                        "description": loc.description,
                        "severity": loc.severity
                    } for loc in result.patch_locations
                ],
                "exploit_prototype": result.exploit_prototype
            }
            
            with open(output_path, "w") as f:
                json.dump(result_dict, f, indent=2)
            
            logger.info(f"结果保存成功: {output_path}")
            return True
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
            return False
