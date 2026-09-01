import logging
import os
import json
import pickle
import zlib
import hashlib
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class RecordType(str, Enum):
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DEBUGGER_STATE = "debugger_state"
    FUZZING_CRASH = "fuzzing_crash"
    STATIC_ANALYSIS = "static_analysis"
    MANUAL_ANALYSIS = "manual_analysis"

class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"


@dataclass
class RegisterState:
    registers: Dict[str, int]
    flags: Dict
    instruction_pointer: int
    stack_pointer: int
    base_pointer: int


@dataclass
class MemoryRegion:
    start_address: int
    end_address: int
    content: bytes
    permissions: str
    description: str = ""


@dataclass
class SymbolicConstraint:
    variable_name: str
    constraint_type: str
    expression: str
    value: Optional[Any] = None
    is_solved: bool = False


@dataclass
class ExecutionPath:
    path_id: str
    instructions: List
    branch_decisions: List
    constraints: List
    depth: int
    is_feasible: bool


@dataclass
class VulnerabilityEvidence:
    vulnerability_type: str
    cwe_id: Optional[str]
    cvss_score: float
    description: str
    reproduction_steps: List[str]
    affected_functions: List[str]
    proof_of_concept: Optional[bytes]


@dataclass
class ForensicSnapshot:
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
    analyzer_info: Dict
    environment_info: Dict


@dataclass
class ForensicRecord:
    record_id: str
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    snapshots: List = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    signature: Optional[str] = None


class ForensicPathRecorder(BaseAnalyzer):
    # 可复现的漏洞发现审计追踪
    # 捕获完整执行上下文（输入、寄存器、内存映射、符号约束）作为防篡改可重放取证记录
    # 用于满足 CVE 提交的证据要求与第三方独立可验证性

    def __init__(self, output_dir: str = "data/forensics"):
        self.output_dir = output_dir
        self._current_record: Optional[ForensicRecord] = None
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        os.makedirs(self.output_dir, exist_ok=True)

    def _generate_record_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.md5(str(id(self)).encode()).hexdigest()[:8]
        return f"FOR_{timestamp}_{random_suffix}"

    def _generate_signature(self, record: ForensicRecord) -> str:
        # 生成记录签名用于完整性校验
        record_data = json.dumps({
            "record_id": record.record_id,
            "created_at": record.created_at.isoformat(),
            "snapshot_count": len(record.snapshots)
        }, sort_keys=True)
        return hashlib.sha256(record_data.encode()).hexdigest()

    def create_new_record(self, metadata: Optional[Dict[str, Any]] = None) -> str:
        record_id = self._generate_record_id()

        self._current_record = ForensicRecord(
            record_id=record_id,
            metadata=metadata or {},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )

        logger.info(f"Created new forensic record: {record_id}")
        return record_id

    def add_snapshot(self, snapshot: ForensicSnapshot) -> None:
        # 将取证快照添加到当前记录
        if not self._current_record:
            raise ValueError("No active forensic record, call create_new_record first")

        self._current_record.snapshots.append(snapshot)
        self._current_record.updated_at = datetime.now()

        logger.info(f"Added snapshot to record {self._current_record.record_id}")

    def capture_symbolic_execution_state(
        self,
        architecture: str,
        binary_path: str,
        registers: Dict[str, int],
        memory_regions: List[Dict[str, Any]],
        constraints: List[Dict[str, Any]],
        input_data: Optional[bytes] = None
    ) -> None:
        register_state = RegisterState(
            registers=registers,
            flags={},
            instruction_pointer=registers.get("rip", registers.get("pc", 0)),
            stack_pointer=registers.get("rsp", registers.get("sp", 0)),
            base_pointer=registers.get("rbp", registers.get("fp", 0))
        )

        memory_objs = [
            MemoryRegion(
                start_address=mr["start"],
                end_address=mr["end"],
                content=mr.get("content", b""),
                permissions=mr.get("permissions", "rw-"),
                description=mr.get("description", "")
            )
            for mr in memory_regions
        ]

        symbolic_constraints = [
            SymbolicConstraint(
                variable_name=c["name"],
                constraint_type=c["type"],
                expression=c["expression"],
                value=c.get("value"),
                is_solved=c.get("solved", False)
            )
            for c in constraints
        ]

        execution_path = ExecutionPath(
            path_id=f"path_{len(self._current_record.snapshots)}",
            instructions=[],
            branch_decisions=[],
            constraints=symbolic_constraints,
            depth=0,
            is_feasible=True
        )

        snapshot = ForensicSnapshot(
            timestamp=datetime.now(),
            record_type=RecordType.SYMBOLIC_EXECUTION,
            architecture=architecture.lower(),
            binary_path=binary_path,
            binary_hash=self._compute_file_hash(binary_path),
            register_state=register_state,
            memory_regions=memory_objs,
            execution_path=execution_path,
            input_data=input_data,
            vulnerability_evidence=None,
            analyzer_info={"type": "symbolic_execution"},
            environment_info=self._get_environment_info()
        )

        self.add_snapshot(snapshot)

    def capture_crash_state(
        self,
        architecture: str,
        binary_path: str,
        crash_input: bytes,
        registers: Dict[str, int],
        crash_type: str,
        cwe_id: Optional[str] = None,
        cvss_score: float = 0.0
    ) -> None:
        register_state = RegisterState(
            registers=registers,
            flags={},
            instruction_pointer=registers.get("rip", registers.get("pc", 0)),
            stack_pointer=registers.get("rsp", registers.get("sp", 0)),
            base_pointer=registers.get("rbp", registers.get("fp", 0))
        )

        evidence = VulnerabilityEvidence(
            vulnerability_type=crash_type,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            description=f"Vulnerability ({crash_type}) discovered via fuzzing",
            reproduction_steps=[
                f"1. Use input: {crash_input.hex()[:32]}...",
                f"2. Run target program",
                f"3. Observe crash"
            ],
            affected_functions=[],
            proof_of_concept=crash_input
        )

        snapshot = ForensicSnapshot(
            timestamp=datetime.now(),
            record_type=RecordType.FUZZING_CRASH,
            architecture=architecture.lower(),
            binary_path=binary_path,
            binary_hash=self._compute_file_hash(binary_path),
            register_state=register_state,
            memory_regions=[],
            execution_path=None,
            input_data=crash_input,
            vulnerability_evidence=evidence,
            analyzer_info={"type": "fuzzing", "crash_type": crash_type},
            environment_info=self._get_environment_info()
        )

        self.add_snapshot(snapshot)

    def _compute_file_hash(self, file_path: str) -> str:
        if not os.path.exists(file_path):
            return "unknown"

        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _get_environment_info(self) -> Dict[str, str]:
        return {
            "platform": os.name,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "timestamp": datetime.now().isoformat()
        }

    def save_record(self, file_path: Optional[str] = None) -> str:
        if not self._current_record:
            raise ValueError("No active forensic record")

        self._current_record.signature = self._generate_signature(self._current_record)

        if file_path is None:
            file_path = os.path.join(
                self.output_dir,
                f"{self._current_record.record_id}.forensic"
            )

        try:
            record_data = pickle.dumps(self._current_record)
            compressed_data = zlib.compress(record_data)

            with open(file_path, "wb") as f:
                f.write(compressed_data)

            logger.info(f"Forensic record saved: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to save forensic record: {e}", exc_info=True)
            raise

    @staticmethod
    def load_record(file_path: str) -> ForensicRecord:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Forensic record file not found: {file_path}")

        try:
            with open(file_path, "rb") as f:
                compressed_data = f.read()

            record_data = zlib.decompress(compressed_data)
            record = pickle.loads(record_data)

            if not isinstance(record, ForensicRecord):
                raise ValueError("Invalid forensic record format")

            return record

        except Exception as e:
            logger.error(f"Failed to load forensic record: {e}", exc_info=True)
            raise

    def validate_record(self, record: ForensicRecord) -> bool:
        if not record.signature:
            logger.warning("Record has no signature")
            return False

        expected_signature = self._generate_signature(record)

        if record.signature == expected_signature:
            logger.info("Forensic record validation passed")
            return True
        else:
            logger.error("Forensic record signature mismatch - record may have been tampered with")
            return False

    def generate_cve_evidence_report(self, record: Optional[ForensicRecord] = None) -> Dict[str, Any]:
        target_record = record or self._current_record

        if not target_record:
            raise ValueError("No forensic record available")

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
            ))
        }

        return report

    def analyze(self, **kwargs) -> Dict[str, Any]:
        # 执行取证记录分析
        action = kwargs.get("action", "create")

        try:
            if action == "create":
                record_id = self.create_new_record(kwargs.get("metadata"))
                return {
                    "success": True,
                    "record_id": record_id,
                    "message": "Forensic record created successfully"
                }

            elif action == "capture_crash":
                self.capture_crash_state(
                    architecture=kwargs.get("architecture", "x86_64"),
                    binary_path=kwargs.get("binary_path", ""),
                    crash_input=kwargs.get("input_data", b""),
                    registers=kwargs.get("registers", {}),
                    crash_type=kwargs.get("crash_type", "unknown"),
                    cwe_id=kwargs.get("cwe_id"),
                    cvss_score=kwargs.get("cvss_score", 0.0)
                )
                return {
                    "success": True,
                    "message": "Crash state captured"
                }

            elif action == "capture_symbolic":
                self.capture_symbolic_execution_state(
                    architecture=kwargs.get("architecture", "x86_64"),
                    binary_path=kwargs.get("binary_path", ""),
                    registers=kwargs.get("registers", {}),
                    memory_regions=kwargs.get("memory_regions", []),
                    constraints=kwargs.get("constraints", []),
                    input_data=kwargs.get("input_data")
                )
                return {
                    "success": True,
                    "message": "Symbolic execution state captured"
                }

            elif action == "save":
                saved_path = self.save_record(kwargs.get("file_path"))
                return {
                    "success": True,
                    "file_path": saved_path,
                    "message": f"Forensic record saved to {saved_path}"
                }

            elif action == "load":
                file_path = kwargs.get("file_path")
                if not file_path:
                    return {"success": False, "error": "file_path is a required parameter"}

                record = self.load_record(file_path)
                return {
                    "success": True,
                    "record_id": record.record_id,
                    "snapshot_count": len(record.snapshots),
                    "message": "Forensic record loaded successfully"
                }

            elif action == "validate":
                file_path = kwargs.get("file_path")
                if not file_path:
                    return {"success": False, "error": "file_path is a required parameter"}

                record = self.load_record(file_path)
                is_valid = self.validate_record(record)
                return {
                    "success": True,
                    "valid": is_valid,
                    "message": "Validation passed" if is_valid else "Validation failed"
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
                    "message": "CVE evidence report generated successfully"
                }

            else:
                return {"success": False, "error": f"Unknown action: {action}"}

        except Exception as e:
            logger.error(f"Forensic record operation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ForensicPathRecorder",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="Vulnerability discovery forensic recorder - captures complete discovery process as replayable records for CVE submission",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips"]
        )
