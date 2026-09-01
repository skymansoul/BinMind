import logging
from enum import Enum

logger = logging.getLogger(__name__)

class BoundaryDetectionMethod(str, Enum):
    LINEAR_SWEEP = "linear_sweep"
    RECURSIVE_DESCENT = "recursive_descent"
    HEURISTIC = "heuristic"
    ML_MODEL = "ml_model"
    HYBRID = "hybrid"

class FunctionType(str, Enum):
    NORMAL = "normal"
    THUNK = "thunk"
    INTERRUPT_HANDLER = "interrupt_handler"
    STUB = "stub"
    INLINE = "inline"

class ConfidenceLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class FunctionBoundary:
    def __init__(self, start=0, end=0, confidence=ConfidenceLevel.LOW):
        self.start = start; self.end = end; self.confidence = confidence

class BoundaryDetectionResult:
    def __init__(self): self.boundaries = []; self.confidence = ConfidenceLevel.LOW

class MLFeatureVector:
    def __init__(self, bytes_before=b"", bytes_after=b"", instruction_pattern="",
                 section_info="", entropy=0.0, opcode_frequency=None,
                 function_call_density=0.0):
        self.bytes_before = bytes_before; self.bytes_after = bytes_after
        self.instruction_pattern = instruction_pattern; self.section_info = section_info
        self.entropy = entropy; self.opcode_frequency = opcode_frequency or {}
        self.function_call_density = function_call_density; self.features = []

class MLModelInterface:
    def __init__(self, model_path=None):
        self.model_path = model_path; self._model = None
        if model_path:
            try:
                import onnxruntime as ort
                self._model = ort.InferenceSession(model_path)
            except Exception:
                pass
    def predict(self, features):
        if self._model is not None:
            import numpy as np
            vec = np.array(features.features, dtype=np.float32).reshape(1, -1)
            out = self._model.run(None, {"input": vec})
            score = float(out[0][0][0])
            return (int(score > 0.5), score)
        return (0, 0.5)

class HeuristicAnalyzer:
    def __init__(self): self.signatures = [b"\x55\x48\x89\xe5", b"\x55\x89\xe5"]
    def detect_boundary(self, data, offset):
        for sig in self.signatures:
            if data[offset:offset+len(sig)] == sig: return True
        return False
    def find_candidate_boundaries(self, data):
        return [i for i in range(0, len(data), 16) if self.detect_boundary(data, i)]

class FunctionBoundaryDetector:
    def __init__(self, method=None, config=None):
        self.method = method or BoundaryDetectionMethod.HEURISTIC
        self.config = config or {}
        self._heuristic = HeuristicAnalyzer()
    def get_metadata(self):
        return type("Meta", (), {"name":"FunctionBoundaryDetector","type":"static_analyzer","version":"1.0"})()
    def analyze(self, binary_path=None, data=None):
        if binary_path is None and data is None:
            return []
        if data is None:
            with open(binary_path, "rb") as f:
                data = f.read()
        return self.analyze_heuristic_method(data)
    def analyze_heuristic_method(self, data):
        results = []
        for offset in self._heuristic.find_candidate_boundaries(data):
            results.append({"address": offset, "type": "function_start", "confidence": 0.8})
        return results
    def analyze_ml_method(self, data):
        results = []
        step = self.config.get("ml_step", 16)
        for offset in range(0, len(data) - 64, step):
            vec = MLFeatureVector(
                bytes_before=data[max(0, offset-16):offset],
                bytes_after=data[offset:offset+64],
                entropy=self._byte_entropy(data[offset:offset+64]),
            )
            label, score = MLModelInterface().predict(vec)
            if label == 1 and score > 0.5:
                results.append({"address": offset, "type": "function_start",
                                 "confidence": score})
        return results
    def analyze_hybrid_method(self, data):
        heur = self.analyze_heuristic_method(data)
        ml = self.analyze_ml_method(data)
        seen = set()
        merged = []
        for item in heur + ml:
            addr = item["address"]
            if addr not in seen:
                seen.add(addr)
                merged.append(item)
        return merged
    def analyze_missing_data(self): return []
    def analyze_with_data(self, data): return self.analyze(data=data)
    @staticmethod
    def _byte_entropy(block):
        if not block:
            return 0.0
        from collections import Counter
        import math
        cnt = Counter(block)
        total = len(block)
        return -sum((c/total) * math.log2(c/total) for c in cnt.values())
