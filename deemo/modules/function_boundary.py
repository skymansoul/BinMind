"""
机器学习辅助二进制函数边界识别模块

利用预训练的机器学习模型识别二进制中函数起始地址和结束边界。
"""

import os
import json
import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

try:
    from config import Config
except ImportError:
    class Config:
        FUNCTION_BOUNDARY_MODEL_DIR = "data/models"
        FUNCTION_BOUNDARY_OUTPUT_DIR = "data/function_boundary"
        LOG_LEVEL = "INFO"
        DEFAULT_MODEL_PATH = "model.onnx"


logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL, "INFO"))
logger = logging.getLogger(__name__)


class BoundaryType(Enum):
    """边界类型枚举"""
    FUNCTION_START = "function_start"
    FUNCTION_END = "function_end"
    INSTRUCTION = "instruction"
    DATA = "data"


class ConfidenceLevel(Enum):
    """置信度等级枚举"""
    HIGH = "high"        # > 0.9
    MEDIUM = "medium"    # 0.7 - 0.9
    LOW = "low"          # < 0.7


@dataclass
class BoundaryCandidate:
    """边界候选"""
    address: int
    boundary_type: BoundaryType
    confidence: float
    context: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "address": hex(self.address),
            "boundary_type": self.boundary_type.value,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "context": self.context
        }
    
    @property
    def confidence_level(self) -> ConfidenceLevel:
        """获取置信度等级"""
        if self.confidence >= 0.9:
            return ConfidenceLevel.HIGH
        elif self.confidence >= 0.7:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW


@dataclass
class FunctionBoundary:
    """函数边界"""
    start_address: int
    end_address: Optional[int] = None
    name: Optional[str] = None
    confidence: float = 0.0
    instructions_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address) if self.end_address else None,
            "name": self.name,
            "confidence": self.confidence,
            "instructions_count": self.instructions_count
        }


@dataclass
class BoundaryDetectionResult:
    """边界检测结果"""
    binary_path: str
    boundaries: List[FunctionBoundary]
    candidates: List[BoundaryCandidate]
    total_functions_detected: int
    high_confidence_count: int
    medium_confidence_count: int
    low_confidence_count: int
    timestamp: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "boundaries": [b.to_dict() for b in self.boundaries],
            "candidates": [c.to_dict() for c in self.candidates],
            "total_functions_detected": self.total_functions_detected,
            "confidence_distribution": {
                "high": self.high_confidence_count,
                "medium": self.medium_confidence_count,
                "low": self.low_confidence_count
            },
            "timestamp": self.timestamp
        }


class MLFunctionBoundaryDetector:
    """
    机器学习函数边界检测器
    
    使用预训练模型识别二进制函数边界。
    """
    
    # 函数起始模式（启发式规则）
    FUNCTION_START_PATTERNS = [
        b'\x55',                                    # push rbp
        b'\x48\x89\xe5',                            # mov rbp, rsp
        b'\x48\x83\xec',                            # sub rsp, ...
        b'\x50',                                    # push rax (函数序言)
        b'\xff\x25',                                # jmp qword ptr [...] (PLT)
    ]
    
    # 函数结束模式
    FUNCTION_END_PATTERNS = [
        b'\xc3',                                    # ret
        b'\xc2',                                    # ret imm16
        b'\xcb',                                    # retf
        b'\xcf',                                    # iret
        b'\xff\xe0',                                # jmp rax
        b'\xff\xe1',                                # jmp rcx
        b'\xff\xe4',                                # jmp rsp
    ]
    
    def __init__(self, model_path: Optional[str] = None, output_dir: Optional[str] = None):
        """
        初始化边界检测器
        
        Args:
            model_path: 模型文件路径
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir or Config.FUNCTION_BOUNDARY_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.model_path = model_path
        self.model_loaded = False
        
        # 尝试加载模型
        self._load_model()
        
        logger.info(f"ML函数边界检测器初始化，输出目录: {self.output_dir}")
        logger.info(f"模型已加载: {self.model_loaded}")
    
    def _load_model(self) -> None:
        """加载ML模型"""
        if self.model_path and os.path.exists(self.model_path):
            try:
                # 尝试加载ONNX模型
                try:
                    import onnxruntime as ort
                    self.session = ort.InferenceSession(self.model_path)
                    self.model_loaded = True
                    logger.info(f"成功加载ONNX模型: {self.model_path}")
                except ImportError:
                    logger.warning("onnxruntime未安装，使用启发式规则")
            except Exception as e:
                logger.warning(f"模型加载失败: {e}")
        else:
            logger.info("未提供模型路径，使用启发式规则")
    
    def _extract_features(self, binary_data: bytes, offset: int, window_size: int = 32) -> List[float]:
        """
        提取特征向量
        
        Args:
            binary_data: 二进制数据
            offset: 当前偏移
            window_size: 窗口大小
            
        Returns:
            特征向量
        """
        features = []
        
        # 获取窗口数据
        start = max(0, offset - window_size)
        end = min(len(binary_data), offset + window_size)
        
        window_data = binary_data[start:end]
        
        # 统计字节频率
        byte_counts = [0] * 256
        for byte in window_data:
            byte_counts[byte] += 1
        
        # 归一化
        total = len(window_data)
        if total > 0:
            features = [c / total for c in byte_counts]
        
        return features
    
    def _predict_with_model(self, features: List[float]) -> Tuple[float, float]:
        """
        使用模型预测
        
        Args:
            features: 特征向量
            
        Returns:
            (起始置信度, 结束置信度)
        """
        if not self.model_loaded:
            return (0.0, 0.0)
        
        try:
            import numpy as np
            input_data = np.array([features], dtype=np.float32)
            outputs = self.session.run(None, {"input": input_data})
            
            start_conf = float(outputs[0][0][0])
            end_conf = float(outputs[0][0][1])
            
            return (start_conf, end_conf)
        except Exception as e:
            logger.warning(f"模型预测失败: {e}")
            return (0.0, 0.0)
    
    def _predict_with_rules(self, binary_data: bytes, offset: int) -> Tuple[float, float]:
        """
        使用启发式规则预测
        
        Args:
            binary_data: 二进制数据
            offset: 当前偏移
            
        Returns:
            (起始置信度, 结束置信度)
        """
        start_conf = 0.0
        end_conf = 0.0
        
        # 检查函数起始模式
        for pattern in self.FUNCTION_START_PATTERNS:
            if offset + len(pattern) <= len(binary_data):
                if binary_data[offset:offset+len(pattern)] == pattern:
                    start_conf = 0.8
                    # 检查前面是否是函数结束指令
                    if offset > 2:
                        for end_pattern in self.FUNCTION_END_PATTERNS:
                            if binary_data[offset-len(end_pattern):offset] == end_pattern:
                                start_conf = 0.95
                    break
        
        # 检查函数结束模式
        for pattern in self.FUNCTION_END_PATTERNS:
            if offset + len(pattern) <= len(binary_data):
                if binary_data[offset:offset+len(pattern)] == pattern:
                    end_conf = 0.8
                    # 检查后面是否是函数起始指令
                    if offset + len(pattern) + 5 <= len(binary_data):
                        for start_pattern in self.FUNCTION_START_PATTERNS:
                            if binary_data[offset+len(pattern):offset+len(pattern)+len(start_pattern)] == start_pattern:
                                end_conf = 0.95
                    break
        
        return (start_conf, end_conf)
    
    def detect_boundaries(self, binary_path: str, min_confidence: float = 0.5) -> BoundaryDetectionResult:
        """
        检测函数边界
        
        Args:
            binary_path: 二进制文件路径
            min_confidence: 最小置信度阈值
            
        Returns:
            BoundaryDetectionResult对象
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 读取二进制数据
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
        
        candidates = []
        boundaries = []
        
        # 扫描二进制数据
        offset = 0
        while offset < len(binary_data):
            # 提取特征并预测
            features = self._extract_features(binary_data, offset)
            model_start, model_end = self._predict_with_model(features)
            rule_start, rule_end = self._predict_with_rules(binary_data, offset)
            
            # 融合模型和规则结果
            start_conf = max(model_start, rule_start)
            end_conf = max(model_end, rule_end)
            
            # 创建候选
            if start_conf >= min_confidence:
                candidates.append(BoundaryCandidate(
                    address=offset,
                    boundary_type=BoundaryType.FUNCTION_START,
                    confidence=start_conf,
                    context=self._get_context(binary_data, offset)
                ))
            
            if end_conf >= min_confidence:
                candidates.append(BoundaryCandidate(
                    address=offset,
                    boundary_type=BoundaryType.FUNCTION_END,
                    confidence=end_conf,
                    context=self._get_context(binary_data, offset)
                ))
            
            offset += 1
        
        # 合并候选为函数边界
        boundaries = self._merge_candidates(candidates)
        
        # 统计置信度分布
        high_count = sum(1 for b in boundaries if b.confidence >= 0.9)
        medium_count = sum(1 for b in boundaries if 0.7 <= b.confidence < 0.9)
        low_count = sum(1 for b in boundaries if b.confidence < 0.7)
        
        result = BoundaryDetectionResult(
            binary_path=binary_path,
            boundaries=boundaries,
            candidates=candidates,
            total_functions_detected=len(boundaries),
            high_confidence_count=high_count,
            medium_confidence_count=medium_count,
            low_confidence_count=low_count,
            timestamp=timestamp
        )
        
        logger.info(f"边界检测完成: {len(boundaries)} 个函数, {high_count} 高置信度")
        return result
    
    def _get_context(self, binary_data: bytes, offset: int, context_size: int = 16) -> str:
        """
        获取上下文信息
        
        Args:
            binary_data: 二进制数据
            offset: 当前偏移
            context_size: 上下文大小
            
        Returns:
            十六进制上下文字符串
        """
        start = max(0, offset - context_size)
        end = min(len(binary_data), offset + context_size)
        
        context_data = binary_data[start:end]
        return context_data.hex()
    
    def _merge_candidates(self, candidates: List[BoundaryCandidate]) -> List[FunctionBoundary]:
        """
        合并候选为函数边界
        
        Args:
            candidates: 边界候选列表
            
        Returns:
            函数边界列表
        """
        boundaries = []
        
        # 按地址排序
        candidates.sort(key=lambda c: c.address)
        
        # 分离起始和结束候选
        start_candidates = [c for c in candidates if c.boundary_type == BoundaryType.FUNCTION_START]
        end_candidates = [c for c in candidates if c.boundary_type == BoundaryType.FUNCTION_END]
        
        # 配对起始和结束
        i = 0
        while i < len(start_candidates):
            start = start_candidates[i]
            
            # 找到下一个起始或文件结尾
            next_start_addr = start_candidates[i+1].address if i+1 < len(start_candidates) else None
            
            # 找到这个函数的结束
            end = None
            for e in end_candidates:
                if e.address > start.address:
                    # 检查是否在当前函数范围内
                    if next_start_addr is None or e.address < next_start_addr:
                        end = e
                        break
            
            if end:
                boundaries.append(FunctionBoundary(
                    start_address=start.address,
                    end_address=end.address,
                    confidence=min(start.confidence, end.confidence),
                    instructions_count=(end.address - start.address) // 2  # 估算
                ))
            else:
                # 没有找到结束，只记录起始
                boundaries.append(FunctionBoundary(
                    start_address=start.address,
                    confidence=start.confidence
                ))
            
            i += 1
        
        return boundaries
    
    def merge_with_existing(self, detected_boundaries: List[FunctionBoundary],
                           existing_boundaries: List[Dict[str, Any]]) -> List[FunctionBoundary]:
        """
        与现有函数列表合并
        
        Args:
            detected_boundaries: 检测到的边界
            existing_boundaries: 现有边界列表
            
        Returns:
            合并后的边界列表
        """
        merged = []
        
        # 将现有边界转换为FunctionBoundary
        existing_funcs = {}
        for func in existing_boundaries:
            start = int(func["start_address"], 16) if isinstance(func["start_address"], str) else func["start_address"]
            existing_funcs[start] = FunctionBoundary(
                start_address=start,
                end_address=int(func.get("end_address", "0"), 16) if func.get("end_address") else None,
                name=func.get("name"),
                confidence=0.7
            )
        
        # 合并
        for detected in detected_boundaries:
            if detected.start_address in existing_funcs:
                # 已有此函数，更新置信度
                existing = existing_funcs[detected.start_address]
                merged.append(FunctionBoundary(
                    start_address=existing.start_address,
                    end_address=existing.end_address or detected.end_address,
                    name=existing.name,
                    confidence=max(existing.confidence, detected.confidence)
                ))
            else:
                # 新函数
                merged.append(detected)
        
        # 添加现有但未被检测到的函数
        for start, existing in existing_funcs.items():
            if not any(b.start_address == start for b in detected_boundaries):
                merged.append(existing)
        
        # 按地址排序
        merged.sort(key=lambda b: b.start_address)
        
        return merged
    
    def generate_report(self, result: BoundaryDetectionResult) -> str:
        """
        生成边界检测报告
        
        Args:
            result: 边界检测结果
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# 函数边界检测报告",
            "",
            f"**检测时间**: {result.timestamp}",
            f"**目标文件**: {result.binary_path}",
            "",
            "## 检测摘要",
            "",
            f"- 检测到函数: **{result.total_functions_detected}** 个",
            f"- 高置信度: **{result.high_confidence_count}** 个 (> 0.9)",
            f"- 中等置信度: **{result.medium_confidence_count}** 个 (0.7-0.9)",
            f"- 低置信度: **{result.low_confidence_count}** 个 (< 0.7)",
            "",
            "## 置信度分布",
            "",
            "| 置信度等级 | 数量 | 占比 |",
            "|------------|------|------|",
            f"| 高 | {result.high_confidence_count} | {(result.high_confidence_count / max(result.total_functions_detected, 1) * 100):.1f}% |",
            f"| 中 | {result.medium_confidence_count} | {(result.medium_confidence_count / max(result.total_functions_detected, 1) * 100):.1f}% |",
            f"| 低 | {result.low_confidence_count} | {(result.low_confidence_count / max(result.total_functions_detected, 1) * 100):.1f}% |",
            "",
            "## 检测到的函数边界",
            "",
            "| 起始地址 | 结束地址 | 指令数 | 置信度 |",
            "|----------|----------|--------|--------|",
        ]
        
        for boundary in result.boundaries[:50]:  # 限制显示数量
            start = hex(boundary.start_address)
            end = hex(boundary.end_address) if boundary.end_address else "N/A"
            report_lines.append(f"| `{start}` | `{end}` | {boundary.instructions_count} | {boundary.confidence:.2f} |")
        
        if len(result.boundaries) > 50:
            report_lines.append(f"| ... | ... | ... | ... |")
            report_lines.append(f"| (共 {len(result.boundaries)} 个函数) | | | |")
        
        report_lines.append("")
        
        return "\n".join(report_lines)
    
    def save_result(self, result: BoundaryDetectionResult, filename: Optional[str] = None) -> str:
        """
        保存边界检测结果
        
        Args:
            result: 边界检测结果
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"boundary_{timestamp}"
        
        # 保存JSON结果
        json_path = self.output_dir / f"{filename}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 保存报告
        report_path = self.output_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(result))
        
        logger.info(f"边界检测结果已保存: {json_path}")
        return str(json_path)


if __name__ == "__main__":
    # 示例用法
    import sys
    
    detector = MLFunctionBoundaryDetector()
    
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        result = detector.detect_boundaries(binary_path)
        detector.save_result(result)
        
        print(f"边界检测完成!")
        print(f"检测到 {result.total_functions_detected} 个函数")
        print(f"高置信度: {result.high_confidence_count}")
        print(f"中等置信度: {result.medium_confidence_count}")
        print(f"低置信度: {result.low_confidence_count}")
    else:
        print("用法: python function_boundary.py <二进制文件路径>")