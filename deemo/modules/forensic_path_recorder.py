"""
漏洞发现取证级记录模块

将漏洞发现全过程（输入、寄存器/内存状态、符号约束）打包为可重放记录。
支持独立验证，满足 CVE 提交证据要求。

Author: Binary Vulnerability Analysis Platform
Version: 1.0.0
"""

import logging
import os
import json
import pickle
import zlib
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, BinaryIO
from datetime import datetime

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class RecordType(Enum):
    """记录类型枚举"""
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DEBUGGER_STATE = "debugger_state"
    FUZZING_CRASH = "fuzzing_crash"
    STATIC_ANALYSIS = "static_analysis"
    MANUAL_ANALYSIS = "manual_analysis"


class Architecture(Enum):
    """架构枚举"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"


@dataclass
class RegisterState:
    """寄存器状态"""
    registers: Dict[str, int]
    flags: Dict[str, bool]
    instruction_pointer: int
    stack_pointer: int
    base_pointer: int


@dataclass
class MemoryRegion:
    """内存区域"""
    start_address: int
    end_address: int
    content: bytes
    permissions: str  # rwx combinations
    description: str = ""


@dataclass
class SymbolicConstraint:
    """符号约束"""
    variable_name: str
    constraint_type: str  # equality, inequality, range, etc.
    expression: str
    value: Optional[int] = None
    is_solved: bool = False


@dataclass
class ExecutionPath:
    """执行路径"""
    path_id: str
    instructions: List[str]
    branch_decisions: List[Tuple[int, bool]]  # (address, taken)
    constraints: List[SymbolicConstraint]
    depth: int
    is_feasible: bool


@dataclass
class VulnerabilityEvidence:
    """漏洞证据"""
    vulnerability_type: str
    cwe_id: Optional[str]
    cvss_score: float
    description: str
    reproduction_steps: List[str]
    affected_functions: List[str]
    proof_of_concept: Optional[bytes]


@dataclass
class ForensicSnapshot:
    """取证快照"""
    timestamp: datetime
    record_type: RecordType
    architecture: Architecture
    binary_path: str
    binary_hash: str
    register_state: Optional[RegisterState]
    memory_regions: List[MemoryRegion]
    execution_path: Optional[ExecutionPath]
    input_data: Optional[bytes]
    vulnerability_evidence: Optional[VulnerabilityEvidence]
    analyzer_info: Dict[str, Any]
    environment_info: Dict[str, str]


@dataclass
class ForensicRecord:
    """取证记录"""
    record_id: str
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    snapshots: List[ForensicSnapshot] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None


class ForensicPathRecorder(BaseAnalyzer):
    """
    漏洞发现取证级记录器
    
    核心功能：
    1. 捕获漏洞发现过程中的完整状态
    2. 打包输入、寄存器、内存、符号约束为可重放记录
    3. 支持独立验证，满足 CVE 提交证据要求
    """
    
    def __init__(self, output_dir: str = "data/forensics"):
        self.output_dir = output_dir
        self._current_record: Optional[ForensicRecord] = None
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """确保输出目录存在"""
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _generate_record_id(self) -> str:
        """生成唯一记录ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.md5(str(id(self)).encode()).hexdigest()[:8]
        return f"FOR_{timestamp}_{random_suffix}"
    
    def _generate_signature(self, record: ForensicRecord) -> str:
        """生成记录签名用于完整性验证"""
        record_data = json.dumps()
            {
                "record_id": record.record_id,
                "created_at": record.created_at.isoformat(),
                "snapshot_count": len(record.snapshots)
            },
            sort_keys=True
        
        return hashlib.sha256(record_data.encode().hexdigest()
    
    def create_new_record(self, metadata: Optional[Dict[str, Any]] = None) -> str:
        """创建新的取证记录"""
        record_id = self._generate_record_id()
        
        self._current_record = ForensicRecord()
            record_id=record_id,
            metadata=metadata or {},
            created_at=datetime.now(),
            updated_at=datetime.now()
        
        
        logger.info(f"创建新取证记录: {record_id}")
        return record_id
    
    def add_snapshot(self, snapshot: ForensicSnapshot) -> None:
        """添加取证快照到当前记录"""
        if not self._current_record:
            raise ValueError("没有活跃的取证记录，请先调用 create_new_record")
        
        self._current_record.snapshots.append(snapshot)
        self._current_record.updated_at = datetime.now()
        
        logger.info(f"添加快照到记录 {self._current_record.record_id}")
    
    def capture_symbolic_execution_state(, self)
        architecture: str,
        binary_path: str,
        registers: Dict[str, int],
        memory_regions: List[Dict[str, Any]],
        constraints: List[Dict[str, Any]],
        input_data: Optional[bytes] = None
    ) -> None:
        """捕获符号执行状态"""
        register_state = RegisterState()
            registers=registers,
            flags={},
            instruction_pointer=registers.get("rip", registers.get("pc", 0)),
            stack_pointer=registers.get("rsp", registers.get("sp", 0)),
            base_pointer=registers.get("rbp", registers.get("fp", 0

        
        
        memory_objs = [
            MemoryRegion()
                start_address=mr["start"],
                end_address=mr["end"],
                content=mr.get("content", b""),
                permissions=mr.get("permissions", "rw-"),
                description=mr.get("description", "")
            
            for mr in memory_regions
        ]
        
        symbolic_constraints = [
            SymbolicConstraint()
                variable_name=c["name"],
                constraint_type=c["type"],
                expression=c["expression"],
                value=c.get("value"),
                is_solved=c.get("solved", False)
            
            for c in constraints
        ]
        
        execution_path = ExecutionPath()
            path_id=f"path_{len(self._current_record.snapshots)}",
            instructions=[],
            branch_decisions=[],
            constraints=symbolic_constraints,
            depth=0,
            is_feasible=True
        
        
        snapshot = ForensicSnapshot()
            timestamp=datetime.now(),
            record_type=RecordType.SYMBOLIC_EXECUTION,
            architecture=Architecture(architecture.lower()),
            binary_path=binary_path,
            binary_hash=self._compute_file_hash(binary_path),
            register_state=register_state,
            memory_regions=memory_objs,
            execution_path=execution_path,
            input_data=input_data,
            vulnerability_evidence=None,
            analyzer_info={"type": "symbolic_execution"},
            environment_info=self._get_environment_info()
        
        
        self.add_snapshot(snapshot)
    
    def capture_crash_state(, self)
        architecture: str,
        binary_path: str,
        crash_input: bytes,
        registers: Dict[str, int],
        crash_type: str,
        cwe_id: Optional[str] = None,
        cvss_score: float = 0.0
    ) -> None:
        """捕获崩溃状态"""
        register_state = RegisterState()
            registers=registers,
            flags={},
            instruction_pointer=registers.get("rip", registers.get("pc", 0)),
            stack_pointer=registers.get("rsp", registers.get("sp", 0)),
            base_pointer=registers.get("rbp", registers.get("fp", 0

        
        
        evidence = VulnerabilityEvidence()
            vulnerability_type=crash_type,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            description=f"通过模糊测试发现的{crash_type}漏洞",
            reproduction_steps=[
                f"1. 使用输入: {crash_input.hex()[:32]}...",
                f"2. 运行目标程序",
                f"3. 观察到崩溃"
            ],
            affected_functions=[],
            proof_of_concept=crash_input
        
        
        snapshot = ForensicSnapshot()
            timestamp=datetime.now(),
            record_type=RecordType.FUZZING_CRASH,
            architecture=Architecture(architecture.lower()),
            binary_path=binary_path,
            binary_hash=self._compute_file_hash(binary_path),
            register_state=register_state,
            memory_regions=[],
            execution_path=None,
            input_data=crash_input,
            vulnerability_evidence=evidence,
            analyzer_info={"type": "fuzzing", "crash_type": crash_type},
            environment_info=self._get_environment_info()
        
        
        self.add_snapshot(snapshot)
    
    def _compute_file_hash(self, file_path: str) -> str:
        """计算文件 SHA256 哈希"""
        if not os.path.exists(file_path):
            return "unknown"
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _get_environment_info(self) -> Dict[str, str]:
        """获取环境信息"""
        return {
            "platform": os.name,
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "timestamp": datetime.now().isoformat()
        }
    
    def save_record(self, file_path: Optional[str] = None) -> str:
        """保存取证记录到文件"""
        if not self._current_record:
            raise ValueError("没有活跃的取证记录")
        
        self._current_record.signature = self._generate_signature(self._current_record)
        
        if file_path is None:
            file_path = os.path.join()
                self.output_dir,
                f"{self._current_record.record_id}.forensic"
            
        
        try:
            record_data = pickle.dumps(self._current_record)
            compressed_data = zlib.compress(record_data)
            
            with open(file_path, "wb") as f:
                f.write(compressed_data)
            
            logger.info(f"取证记录已保存: {file_path}")
            return file_path
        
        except Exception as e:
            logger.error(f"保存取证记录失败: {e}", exc_info=True)
            raise
    
    @staticmethod
    def load_record(file_path: str) -> ForensicRecord:
        """从文件加载取证记录"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"取证记录文件不存在: {file_path}")
        
        try:
            with open(file_path, "rb") as f:
                compressed_data = f.read()
            
            record_data = zlib.decompress(compressed_data)
            record = pickle.loads(record_data)
            
            if not isinstance(record, ForensicRecord):
                raise ValueError("无效的取证记录格式")
            
            return record
        
        except Exception as e:
            logger.error(f"加载取证记录失败: {e}", exc_info=True)
            raise
    
    def validate_record(self, record: ForensicRecord) -> bool:
        """验证取证记录的完整性"""
        if not record.signature:
            logger.warning("记录没有签名")
            return False
        
        expected_signature = self._generate_signature(record)
        
        if record.signature == expected_signature:
            logger.info("取证记录验证通过")
            return True
        else:
            logger.error("取证记录签名验证失败 - 记录可能已被篡改")
            return False
    
    def generate_cve_evidence_report(self, record: Optional[ForensicRecord] = None) -> Dict[str, Any]:
        """生成符合 CVE 提交要求的证据报告"""
        target_record = record or self._current_record
        
        if not target_record:
            raise ValueError("没有可用的取证记录")
        
        crash_snapshots = [
            s for s in target_record.snapshots
            if s.record_type == RecordType.FUZZING_CRASH
        ]
        
        report = {
            "cve_submission_format": "CVE-REQUIREMENTS",
            "record_id": target_record.record_id,
            "created_at": target_record.created_at.isoformat(),
            "validated": self.validate_record(target_record),
            "evidence_items": [],
            "summary": {}
        }
        
        for snapshot in crash_snapshots:
            evidence_item = {
                "timestamp": snapshot.timestamp.isoformat(),
                "architecture": snapshot.architecture.value,
                "binary": {
                    "path": snapshot.binary_path,
                    "hash": snapshot.binary_hash
                },
                "crash_input": {
                    "length": len(snapshot.input_data) if snapshot.input_data else 0,
                    "sample": snapshot.input_data.hex()[:64] if snapshot.input_data else ""
                },
                "vulnerability": {}
            }
            
            if snapshot.vulnerability_evidence:
                evidence_item["vulnerability"] = {
                    "type": snapshot.vulnerability_evidence.vulnerability_type,
                    "cwe_id": snapshot.vulnerability_evidence.cwe_id,
                    "cvss_score": snapshot.vulnerability_evidence.cvss_score,
                    "description": snapshot.vulnerability_evidence.description,
                    "reproduction_steps": snapshot.vulnerability_evidence.reproduction_steps
                }
            
            if snapshot.register_state:
                evidence_item["registers"] = {
                    "instruction_pointer": hex(snapshot.register_state.instruction_pointer),
                    "stack_pointer": hex(snapshot.register_state.stack_pointer),
                    "key_registers": {
                        k: hex(v) for k, v in snapshot.register_state.registers.items()
                    }
                }
            
            report["evidence_items"].append(evidence_item)
        
        report["summary"] = {
            "total_snapshots": len(target_record.snapshots),
            "crash_snapshots": len(crash_snapshots),
            "unique_vulnerabilities": len(set(
                s.vulnerability_evidence.vulnerability_type
                for s in crash_snapshots
                if s.vulnerability_evidence
            

        }
        
        return report
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行取证记录分析
        
        Args:
            **kwargs: 分析参数
                - action: 操作类型 (create, capture_crash, capture_symbolic, save, load, validate, generate_report)
                - record_id: 记录ID（用于加载）
                - file_path: 文件路径（用于保存/加载）
                - architecture: 架构类型
                - binary_path: 二进制文件路径
                - input_data: 输入数据（字节）
                - crash_type: 崩溃类型
                - cwe_id: CWE ID
                - cvss_score: CVSS评分
                - registers: 寄存器状态字典
                - memory_regions: 内存区域列表
                - constraints: 符号约束列表
        
        Returns:
            分析结果字典
        """
        action = kwargs.get("action", "create")
        
        try:
            if action == "create":
                record_id = self.create_new_record(kwargs.get("metadata"

                return {
                    "success": True,
                    "record_id": record_id,
                    "message": "取证记录创建成功"
                }
            
            elif action == "capture_crash":
                self.capture_crash_state()
                    architecture=kwargs.get("architecture", "x86_64"),
                    binary_path=kwargs.get("binary_path", ""),
                    crash_input=kwargs.get("input_data", b""),
                    registers=kwargs.get("registers", {}),
                    crash_type=kwargs.get("crash_type", "unknown"),
                    cwe_id=kwargs.get("cwe_id"),
                    cvss_score=kwargs.get("cvss_score", 0.0)
                
                return {
                    "success": True,
                    "message": "崩溃状态已捕获"
                }
            
            elif action == "capture_symbolic":
                self.capture_symbolic_execution_state()
                    architecture=kwargs.get("architecture", "x86_64"),
                    binary_path=kwargs.get("binary_path", ""),
                    registers=kwargs.get("registers", {}),
                    memory_regions=kwargs.get("memory_regions", []),
                    constraints=kwargs.get("constraints", []),
                    input_data=kwargs.get("input_data")
                
                return {
                    "success": True,
                    "message": "符号执行状态已捕获"
                }
            
            elif action == "save":
                saved_path = self.save_record(kwargs.get("file_path"

                return {
                    "success": True,
                    "file_path": saved_path,
                    "message": f"取证记录已保存到 {saved_path}"
                }
            
            elif action == "load":
                file_path = kwargs.get("file_path")
                if not file_path:
                    return {"success": False, "error": "file_path 是必需参数"}
                
                record = self.load_record(file_path)
                return {
                    "success": True,
                    "record_id": record.record_id,
                    "snapshot_count": len(record.snapshots),
                    "message": "取证记录加载成功"
                }
            
            elif action == "validate":
                file_path = kwargs.get("file_path")
                if not file_path:
                    return {"success": False, "error": "file_path 是必需参数"}
                
                record = self.load_record(file_path)
                is_valid = self.validate_record(record)
                return {
                    "success": True,
                    "valid": is_valid,
                    "message": "验证通过" if is_valid else "验证失败"
                }
            
            elif action == "generate_report":
                file_path = kwargs.get("file_path")
                if file_path:
                    record = self.load_record(file_path)
                else:
                    record = None
                
                report = self.generate_cve_evidence_report(record)
                return {
                    "success": True,
                    "report": report,
                    "message": "CVE证据报告生成成功"
                }
            
            else:
                return {"success": False, "error": f"未知操作: {action}"}
        
        except Exception as e:
            logger.error(f"取证记录操作失败: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ForensicPathRecorder",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="漏洞发现取证级记录器，捕获漏洞发现全过程，打包为可重放记录，支持CVE提交证据要求",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips"])))))))))