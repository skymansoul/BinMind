# [DEPRECATED] [STUB] — 无外部引用, 保留接口兼容
# 跨模块契约推断功能已由 APAS 别名传播偏移求解覆盖
"""跨模块接口契约推断 — 已废弃的存根, 无调用方。"""
from dataclasses import dataclass
@dataclass
class ContractConflict: symbol: str; impl_file: str; call_file: str; severity: str; description: str
class ContractInferrer:
    def scan(self, files): return []
def infer_contracts(files, blackboard=None): return []
