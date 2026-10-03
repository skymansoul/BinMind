import logging
from dataclasses import dataclass, field
from typing import Dict, List
from enum import Enum

logger = logging.getLogger(__name__)


class SemanticRole(Enum):
    LOOP_COUNTER = "loop_counter"
    BUFFER_POINTER = "buffer_pointer"
    BUFFER_LENGTH = "buffer_length"
    CHECKSUM_VALUE = "checksum_value"
    RETURN_VALUE = "return_value"
    TEMPORARY = "temporary"
    CONSTANT = "constant"
    POINTER = "pointer"
    COUNTER = "counter"
    FLAG = "flag"
    CRYPTO_KEY = "crypto_key"
    CRYPTO_IV = "crypto_iv"
    CANARY = "canary"
    UNKNOWN = "unknown"

class VariableInfo:
    __slots__ = ('name', 'type', 'definition_location', 'usage_locations',
                 'operations', 'role', 'confidence')

    def __init__(self, name, var_type, definition_location, usage_locations=None,
                 operations=None, role=None, confidence=0.0):
        self.name = name
        self.type = var_type
        self.definition_location = definition_location
        self.usage_locations = usage_locations if usage_locations is not None else []
        self.operations = operations if operations is not None else []
        self.role = role if role is not None else SemanticRole.UNKNOWN
        self.confidence = confidence


class SemanticRoleLabeler:

    s_patterns = {
        SemanticRole.LOOP_COUNTER: ["inc", "dec", "cmp", "jmp"],
        SemanticRole.BUFFER_POINTER: ["mov", "lea", "offset"],
        SemanticRole.BUFFER_LENGTH: ["mov", "cmp", "length"],
        SemanticRole.CHECKSUM_VALUE: ["xor", "add", "rol"],
        SemanticRole.FLAG: ["and", "or", "test"],
        SemanticRole.CRYPTO_KEY: ["mov", "xor", "aes", "key", "expand"],
        SemanticRole.CRYPTO_IV: ["xor", "mov", "iv", "nonce", "counter"],
        SemanticRole.CANARY: ["fs:", "gs:", "__stack_chk", "canary", "cookie"],
    }

    def __init__(self):
        self._label_history: Dict[str, Dict[SemanticRole, int]] = {}

    def label_variables(self, variables):
        for var in variables:
            scores = {}
            for role, ops in self.s_patterns.items():
                score = sum(1 for op in var.operations if any(o in op.lower() for o in ops))
                score = score / len(var.operations) if var.operations else 0
                scores[role] = min(max(score, 0.0), 1.0)
            if scores:
                var.role = max(scores, key=scores.get)
                var.confidence = scores[var.role]
                # 累积历史以支持跨函数一致性
                if var.name not in self._label_history:
                    self._label_history[var.name] = {}
                prev = self._label_history[var.name].get(var.role, 0)
                self._label_history[var.name][var.role] = prev + 1
        return variables

    def label_from_assembly(self, var_name: str, assembly_snippet: str) -> SemanticRole:
        lowered = assembly_snippet.lower()
        # canary: fs/gs 段 + 固定偏移
        if 'fs:0x' in lowered or 'gs:0x' in lowered:
            if any(off in lowered for off in ['0x28', '0x14']):
                return SemanticRole.CANARY
        # 循环计数器: inc/dec/add/sub + 条件跳转
        if any(r in lowered for r in ['inc ', 'dec ', 'add ', 'sub ']) and \
           any(j in lowered for j in ['jne', 'je ', 'jnz', 'jz ']):
            return SemanticRole.LOOP_COUNTER
        # 校验和: xor + add + rol/shl 连续组合
        if 'xor' in lowered and 'add' in lowered and ('rol' in lowered or 'shl' in lowered):
            return SemanticRole.CHECKSUM_VALUE
        # 加密常量: aeskeygenassist / aesimc / vaes 指令
        if any(k in lowered for k in ['aeskeygenassist', 'aesimc', 'vaes']):
            return SemanticRole.CRYPTO_KEY
        if any(k in lowered for k in ['aesenc', 'aesdec', 'vaesenc', 'vaesdec']):
            return SemanticRole.CRYPTO_IV
        return SemanticRole.UNKNOWN

    def cross_function_consensus(self, var_name: str) -> Optional[SemanticRole]:
        """跨函数角色投票, 若同一变量名在多个函数中被标注为同一角色
        则该标注的可信度更高（类似于跨函数类型推断的投票机制）
        """
        if var_name not in self._label_history:
            return None
        counts = self._label_history[var_name]
        if not counts:
            return None
        best_role = max(counts, key=counts.get)
        # 需要至少2次一致标注才返回共识角色
        if counts[best_role] >= 2:
            return best_role
        return None


__all__ = ["SemanticRole", "VariableInfo", "SemanticRoleLabeler"]
