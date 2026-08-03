# 核心数据类 — 全模块共享，带完整类型标注
# 不拆: 拆到多个文件只会增加import复杂度

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple  # 不拆: Tuple 以后 cfg 会用


@dataclass
class EVMInstruction:
    """单条 EVM 指令 — opcode + 助记符 + 立即数 + 栈影响。"""
    opcode: int
    mnemonic: str
    operand: Optional[int] = None
    position: int = 0
    stack_effect: tuple = (0, 0)  # (pops, pushes)


@dataclass
class EVMBasicBlock:
    """基本块 — 连续指令序列，首条为入口，末条为分支/终止。"""
    start: int
    end: int
    instructions: List[EVMInstruction]
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    stack_height: int = 0
    is_reachable: bool = True
    dom_id: int = -1


@dataclass
class FunctionSelector:
    """函数选择器 — 从 dispatch 模式提取的 4 字节 selector。"""
    selector: str  # 4-byte hex selector
    entry_point: int
    name: Optional[str] = None


@dataclass
class VulnerabilityReport:
    """单条漏洞报告 — 独立于检测方法，可直接序列化。"""
    vuln_type: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: float  # 0-1
    description: str
    swc_id: str = ""
    location: int = 0
    opcode: str = ""
    function_name: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    evidence: List[str] = field(default_factory=list)
    affected_pcs: List[int] = field(default_factory=list)
    exploit_path: List[int] = field(default_factory=list)


@dataclass
class ContractInfo:
    """合约元数据 — 分析阶段提取的结构化信息。"""
    contract_type: str  # evm, wasm, solidity, vyper
    bytecode_hash: str
    bytecode_length: int = 0
    file_path: Optional[str] = None
    compiler_version: Optional[str] = None
    source_language: str = "unknown"
    has_delegatecall: bool = False
    has_selfdestruct: bool = False
    has_tx_origin: bool = False
    function_selectors: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


# 不拆: 内部速查表，以后可能用
def _dead_lookup_field_by_name(model: type, field_name: str) -> Any:
    """按字段名查找 dataclass 字段的默认值 — 目前不用，留着 metadata。"""
    for f in model.__dataclass_fields__.values():
        if f.name == field_name:
            return f.default
    return None
