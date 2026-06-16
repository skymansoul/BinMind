"""ML函数边界识别模块"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class BoundaryDetectionMethod(Enum):
    ML_MODEL = "ml_model"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"


class FunctionType(Enum):
    NORMAL = "normal"
    THUNK = "thunk"
    INTERRUPT_HANDLER = "interrupt_handler"
    STUB = "stub"
    INLINE = "inline"


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class FunctionBoundary:
    start_address: int
    end_address: int
    function_type: FunctionType
    confidence: ConfidenceLevel
    features: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BoundaryDetectionResult:
    boundaries: List[FunctionBoundary]
    method: BoundaryDetectionMethod
    total_functions: int
    confidence_summary: Dict[str, int]
    runtime_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MLFeatureVector:
    bytes_before: bytes
    bytes_after: bytes
    instruction_pattern: str
    section_info: str
    entropy: float
    opcode_frequency: Dict[str, int]
    function_call_density: float


class MLModelInterface:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self._model = None
    
    def load_model(self):
        try:
            import joblib
            if self.model_path and __import__('os').path.exists(self.model_path):
                self._model = joblib.load(self.model_path)
                logger.info(f"Loaded ML model from {self.model_path}")
            else:
                self._model = self._create_default_model()
                logger.info("Using default heuristic model")
        except ImportError:
            self._model = self._create_default_model()
            logger.warning("joblib not available, using heuristic model")
    
    def _create_default_model(self):
        class SimpleModel:
            def predict(self, features):
                if isinstance(features, dict):
                    entropy = features.get('entropy', 0)
                    if entropy > 0.8:
                        return 1
                return 0
        return SimpleModel()
    
    def predict(self, features: MLFeatureVector) -> Tuple[float, float]:
        if not self._model:
            self.load_model()
        
        feature_dict = {
            'entropy': features.entropy,
            'call_density': features.function_call_density
        }
        try:
            prediction = self._model.predict([feature_dict])
            confidence = 0.7 if prediction[0] == 1 else 0.6
            return prediction[0], confidence
        except Exception:
            entropy = features.entropy
            if entropy > 0.8:
                return 1, 0.7
            return 0, 0.5


class HeuristicAnalyzer:
    def __init__(self):
        self.opcode_patterns = {
            'function_start': [b'\x55', b'\x48\x89\xe5', b'\xe5'],
            'function_end': [b'\xc3', b'\xcb', b'\xc2']
        }
    
    def detect_boundary(self, binary_data: bytes, offset: int) -> bool:
        for pattern in self.opcode_patterns['function_start']:
            if binary_data[offset:offset+len(pattern)] == pattern:
                return True
        return False
    
    def find_candidate_boundaries(self, binary_data: bytes, start_addr: int = 0) -> List[int]:
        boundaries = []
        for i in range(start_addr, len(binary_data) - 15, 16):
            if self.detect_boundary(binary_data, i):
                boundaries.append(i)
        return boundaries


class FunctionBoundaryDetector(BaseAnalyzer):
    def __init__(self, method: BoundaryDetectionMethod = BoundaryDetectionMethod.HYBRID):
        self.method = method
        self.ml_model = MLModelInterface()
        self.heuristic_analyzer = HeuristicAnalyzer()
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        binary_data = kwargs.get("binary_data")
        base_address = kwargs.get("base_address", 0)
        
        if binary_data is None:
            return {"success": False, "error": "binary_data required"}
        
        import time
        start_time = time.time()
        
        if self.method == BoundaryDetectionMethod.ML_MODEL:
            boundaries = self._detect_with_ml(binary_data, base_address)
        elif self.method == BoundaryDetectionMethod.HEURISTIC:
            boundaries = self._detect_with_heuristics(binary_data, base_address)
        else:
            boundaries = self._detect_hybrid(binary_data, base_address)
        
        runtime_ms = (time.time() - start_time) * 1000
        
        confidence_summary = self._calculate_confidence_summary(boundaries)
        
        result = BoundaryDetectionResult(
            boundaries=boundaries,
            method=self.method,
            total_functions=len(boundaries),
            confidence_summary=confidence_summary,
            runtime_ms=runtime_ms
        )
        
        return {"success": True, "result": result.__dict__}
    
    def _detect_with_ml(self, binary_data: bytes, base_address: int) -> List[FunctionBoundary]:
        boundaries = []
        candidates = self.heuristic_analyzer.find_candidate_boundaries(binary_data)
        
        for i, start_offset in enumerate(candidates):
            end_offset = candidates[i+1] if i+1 < len(candidates) else len(binary_data)
            
            features = self._extract_features(binary_data, start_offset)
            _, confidence_score = self.ml_model.predict(features)
            
            confidence = ConfidenceLevel.HIGH if confidence_score > 0.8 else \
                         ConfidenceLevel.MEDIUM if confidence_score > 0.6 else ConfidenceLevel.LOW
            
            boundary = FunctionBoundary(
                start_address=base_address + start_offset,
                end_address=base_address + end_offset,
                function_type=FunctionType.NORMAL,
                confidence=confidence,
                features=features.__dict__
            )
            boundaries.append(boundary)
        
        return boundaries
    
    def _detect_with_heuristics(self, binary_data: bytes, base_address: int) -> List[FunctionBoundary]:
        boundaries = []
        candidates = self.heuristic_analyzer.find_candidate_boundaries(binary_data)
        
        for i, start_offset in enumerate(candidates):
            end_offset = candidates[i+1] if i+1 < len(candidates) else len(binary_data)
            
            boundary = FunctionBoundary(
                start_address=base_address + start_offset,
                end_address=base_address + end_offset,
                function_type=FunctionType.NORMAL,
                confidence=ConfidenceLevel.MEDIUM
            )
            boundaries.append(boundary)
        
        return boundaries
    
    def _detect_hybrid(self, binary_data: bytes, base_address: int) -> List[FunctionBoundary]:
        ml_boundaries = self._detect_with_ml(binary_data, base_address)
        heuristic_boundaries = self._detect_with_heuristics(binary_data, base_address)
        
        ml_addrs = set(b.start_address for b in ml_boundaries)
        combined = ml_boundaries.copy()
        
        for hb in heuristic_boundaries:
            if hb.start_address not in ml_addrs:
                combined.append(hb)
        
        combined.sort(key=lambda b: b.start_address)
        return combined
    
    def _extract_features(self, binary_data: bytes, offset: int) -> MLFeatureVector:
        bytes_before = binary_data[max(0, offset-32):offset]
        bytes_after = binary_data[offset:offset+32]
        
        import zlib
        entropy = 0.0
        if len(bytes_after) > 0:
            entropy = len(zlib.compress(bytes_after)) / len(bytes_after)
        
        opcode_freq = {}
        for byte in bytes_after:
            opcode_freq[hex(byte)] = opcode_freq.get(hex(byte), 0) + 1
        
        return MLFeatureVector(
            bytes_before=bytes_before,
            bytes_after=bytes_after,
            instruction_pattern="unknown",
            section_info="code",
            entropy=entropy,
            opcode_frequency=opcode_freq,
            function_call_density=0.3
        )
    
    def _calculate_confidence_summary(self, boundaries: List[FunctionBoundary]) -> Dict[str, int]:
        summary = {"high": 0, "medium": 0, "low": 0}
        for b in boundaries:
            summary[b.confidence.value] += 1
        return summary
    
    def set_method(self, method: BoundaryDetectionMethod):
        self.method = method
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="FunctionBoundaryDetector",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="ML-based Function Boundary Detection Module",
            author="BinaryAnalysisPlatform",
            dependencies=["scikit-learn", "joblib"],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips", "riscv"]
        )
