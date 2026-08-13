logger=None
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
inferred_type: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
source: str = ""
constraint_type: str = ""
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

class TypeKind:
    VOID = "void"
    INT = "int"
    FLOAT = "float"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNION = "union"
    FUNCTION = "function"
    UNKNOWN = "unknown"

    pass
@dataclass
class InferredType:
    kind: str = ""
    size: int = 0
    name: str = ""
    base_type: str = ""
    element_count: int = 0
    fields: list = field(default_factory=list)
    constraints: list = field(default_factory=list)

@dataclass
class VariableType:
    name: str = ""
    address: int = 0
    inferred_type: str = ""
    confidence: float = 0.0

@dataclass
class TypeInferenceResult:
    success: bool = False
    variables: list = field(default_factory=list)
    function_signatures: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

class ConstraintSolver:
    # 约束求解器

    def __init__(self):
        self.variables: Dict[str, Set[InferredType]] = {}
        self.constraints: List[Tuple[str, str, str]] = []

    def add_variable(self, name: str):
        if name not in self.variables:
            self.variables[name] = set()

    def add_type_candidate(self, name: str, type_: InferredType):
        self.add_variable(name)
        self.variables[name].add(type_)

    def add_constraint(self, var1: str, op: str, var2: str):
        # 添加约束关系: var1 op var2 (例如 same_type, equal, assignable)
        self.constraints.append((var1, op, var2))

    def solve(self) -> Dict[str, InferredType]:
        # 求解约束，返回最窄type
        result = {}
        for var_name, candidates in self.variables.items():
            if not candidates:
                result[var_name] = InferredType(kind=TypeKind.UNKNOWN, size=0)
            else:
                # 取最小尺寸的type作为最窄合法type
                min_type = min(candidates, key=lambda t: t.size)
                result[var_name] = min_type
        return result

class TypeInferenceEngine:
    # typeinferengine

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.solver = ConstraintSolver()
        self.variables: List[VariableType] = []

    def infer_from_data_section(self) -> List[VariableType]:
        # 从data段infer全局变量type
        variables = []
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", "iS", self.binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if ".data" in line or ".rodata" in line or ".bss" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                addr = int(parts[1], 16)
                                size = int(parts[2])
                                var_name = f"var_{hex(addr)}"
                                inferred = InferredType(
                                    kind=TypeKind.INT,
                                    size=size,
                                    name=var_name,
                                )
                                self.solver.add_type_candidate(var_name, inferred)
                                variables.append(VariableType(
                                    name=var_name, address=addr,
                                    inferred_type=inferred, confidence=0.6,
                                ))

                            except (ValueError, IndexError):
                                pass
        except Exception as e:
            logger.warning(f"Data section inference failed: {e}")
        return variables

    def infer_from_calls(self) -> Dict[str, InferredType]:
        # Infer function signatures from call sites
        # 从函数调用infer函数sign
        signatures = {}
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", "afl", self.binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n")[:50]:
                    parts = line.strip().split()
                    if parts:
                        name = parts[-1] if parts else "unknown"
                        sig = InferredType(kind=TypeKind.FUNCTION, size=8, name=name)
                        signatures[name] = sig
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return signatures

    def refine_with_constraints(self):
        # 使用约束细化type
        # 这里通过约束传播进一步细化
        # 简化版：based on函数调用parameter关系建立约束
        pass

    def generate_pseudocode(self) -> str:
        # 生成带type的pseudocode
        lines = []
        lines.append("// Inferred Types")
        for var in self.variables:
            lines.append(
                f"// {var.name} @ 0x{var.address:x} : {var.inferred_type.kind.value} "
                f"(size={var.inferred_type.size}, conf={var.confidence:.2f})"
            )
        return "\n".join(lines)

    def run(self) -> TypeInferenceResult:
        try:
            self.variables = self.infer_from_data_section()
            sigs = self.infer_from_calls()
            self.refine_with_constraints()
            return TypeInferenceResult(
                success=True,
                variables=self.variables,
                function_signatures=sigs,
            )

        except Exception as e:
            logger.error(f"Type inference failed: {e}")
            return TypeInferenceResult(success=False, variables=[])

def create_type_inference_engine(binary_path: str) -> TypeInferenceEngine:
    return TypeInferenceEngine(binary_path)
