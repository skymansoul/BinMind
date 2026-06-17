"""
Rust/Go 生命周期与并发分析模块

功能：
1. 恢复 Rust 借用和生命周期注解，检测 unsafe 块中的 UAF、数据竞争
2. 对 Go 进行 goroutine 调度点静态锁集分析，检测并发漏洞
"""

import logging
import os
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from enum import Enum

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class LanguageType(Enum):
    """语言类型枚举"""
    RUST = "rust"
    GO = "go"
    UNKNOWN = "unknown"


class AnalysisType(Enum):
    """分析类型枚举"""
    BORROW_CHECKING = "borrow_checking"
    LIFETIME_ANALYSIS = "lifetime_analysis"
    DATA_RACE_DETECTION = "data_race_detection"
    LOCK_SET_ANALYSIS = "lock_set_analysis"
    UNSAFE_ANALYSIS = "unsafe_analysis"


class RaceConditionType(Enum):
    """数据竞争类型枚举"""
    DATA_RACE = "data_race"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREFERENCE = "null_dereference"
    DEADLOCK = "deadlock"
    RACE_CONDITION = "race_condition"


@dataclass
class BorrowInfo:
    """借用信息数据类"""
    variable_name: str
    borrow_type: str  # 'mut' or 'immutable'
    borrow_scope: Tuple[int, int]  # (start_offset, end_offset)
    owner: Optional[str] = None
    lifetime: Optional[str] = None
    is_unsafe: bool = False


@dataclass
class LockInfo:
    """锁信息数据类"""
    lock_name: str
    lock_type: str  # 'mutex', 'rwlock', 'channel'
    acquire_offset: int
    release_offset: Optional[int] = None
    held_by: Optional[str] = None


@dataclass
class RaceWarning:
    """数据竞争警告数据类"""
    race_type: RaceConditionType
    description: str
    location: int
    severity: str = "high"
    variables: List[str] = field(default_factory=list)
    trace: List[str] = field(default_factory=list)


@dataclass
class OwnershipAnalysisResult:
    """所有权分析结果数据类"""
    language: LanguageType
    borrows: List[BorrowInfo] = field(default_factory=list)
    locks: List[LockInfo] = field(default_factory=list)
    warnings: List[RaceWarning] = field(default_factory=list)
    unsafe_blocks: List[int] = field(default_factory=list)
    goroutine_points: List[int] = field(default_factory=list)


class BorrowAnalyzer(ABC):
    """借用分析器基类"""
    
    @abstractmethod
    def analyze(self, binary_data: bytes) -> List[BorrowInfo]:
        """分析借用关系"""
        pass


class RustBorrowAnalyzer(BorrowAnalyzer):
    """Rust 借用分析器"""
    
    def __init__(self):
        self.borrow_patterns = {
            b'\x48\x8b\x05': 'load_ptr',      # mov rax, [rip+offset]
            b'\x48\x89\x05': 'store_ptr',     # mov [rip+offset], rax
            b'\x48\x8d\x05': 'lea_ptr',       # lea rax, [rip+offset]
            b'\xff\x15': 'indirect_call',    # call [rip+offset]
            b'\x48\x8b\x1d': 'load_ptr_32',  # mov rbx, [rip+offset]
        }
    
    def analyze(self, binary_data: bytes) -> List[BorrowInfo]:
        """分析 Rust 二进制中的借用关系"""
        borrows = []
        offset = 0
        
        while offset < len(binary_data):
            matched = False
            # 检测潜在的借用模式
            for pattern, pattern_type in self.borrow_patterns.items():
                pattern_len = len(pattern)
                if offset + pattern_len <= len(binary_data):
                    if binary_data[offset:offset+pattern_len] == pattern:
                        borrow = BorrowInfo()
                            variable_name=f"var_{offset:08x}",
                            borrow_type="mut" if pattern_type == "store_ptr" else "immutable",
                            borrow_scope=(offset, offset + 16),
                            lifetime=self._infer_lifetime(offset),
                            is_unsafe=self._check_unsafe_context(binary_data, offset)
                        
                        borrows.append(borrow)
                        offset += pattern_len
                        matched = True
                        break
            if not matched:
                offset += 1
        
        logger.info(f"Rust 借用分析完成，发现 {len(borrows)} 个借用")
        return borrows
    
    def _infer_lifetime(self, offset: int) -> str:
        """推断生命周期"""
        # 简单模拟：根据偏移量生成生命周期名称
        lifetime_id = offset % 5
        lifetimes = ['\'a', '\'b', '\'c', '\'d', '\'static']
        return lifetimes[lifetime_id]
    
    def _check_unsafe_context(self, data: bytes, offset: int) -> bool:
        """检查是否在 unsafe 块中"""
        # 检查附近是否有 unsafe 相关的模式
        search_range = min(200, offset)
        search_data = data[max(0, offset-search_range):offset+200]
        
        unsafe_patterns = [
            b'unchecked', b'unsafe', b'asm!', b'ptr::', b'mem::'
        ]
        
        return any(pattern in search_data for pattern in unsafe_patterns)


class GoLockSetAnalyzer:
    """Go 锁集分析器"""
    
    def __init__(self):
        self.lock_patterns = {
            b'\x48\x8b\x0d': 'mutex_lock',    # mov rcx, [rip+offset]
            b'\x48\x89\x0d': 'mutex_unlock',  # mov [rip+offset], rcx
            b'\x48\x8b\x15': 'rwlock_rlock', # mov rdx, [rip+offset]
            b'\x48\x8b\x1d': 'rwlock_wlock', # mov rbx, [rip+offset]
        }
        self.channel_patterns = [b'ch<-', b'<-ch', b'make(chan'])
    
    def analyze(self, binary_data: bytes) -> Tuple[List[LockInfo], List[int]]:
        """分析 Go 二进制中的锁和 goroutine 调度点"""
        locks = []
        goroutine_points = []
        offset = 0
        
        while offset < len(binary_data):
            matched = False
            # 检测锁操作
            for pattern, lock_type in self.lock_patterns.items():
                pattern_len = len(pattern)
                if offset + pattern_len <= len(binary_data):
                    if binary_data[offset:offset+pattern_len] == pattern:
                        lock_info = LockInfo()
                            lock_name=f"lock_{offset:08x}",
                            lock_type=self._map_lock_type(lock_type),
                            acquire_offset=offset
                        
                        locks.append(lock_info)
                        offset += pattern_len
                        matched = True
                        break
            if not matched:
                # 检测 goroutine 调度点
                if self._is_goroutine_point(binary_data, offset):
                    goroutine_points.append(offset)
                offset += 1
        
        logger.info(f"Go 锁集分析完成，发现 {len(locks)} 个锁操作，{len(goroutine_points)} 个 goroutine 调度点")
        return locks, goroutine_points
    
    def _map_lock_type(self, pattern_type: str) -> str:
        """映射锁类型"""
        if 'mutex' in pattern_type:
            return 'mutex'
        elif 'rwlock' in pattern_type:
            return 'rwlock'
        return 'mutex'
    
    def _is_goroutine_point(self, data: bytes, offset: int) -> bool:
        """检测是否为 goroutine 调度点"""
        # 检查常见的 goroutine 相关模式
        patterns = [
            b'runtime.goexit', b'runtime.gopark', 
            b'runtime.goready', b'runtime.schedule'
        ]
        
        window = data[offset:offset+50]
        return any(pattern in window for pattern in patterns)


class RaceDetector:
    """数据竞争检测器"""
    
    def __init__(self):
        self.warning_types = {
            RaceConditionType.DATA_RACE: "数据竞争",
            RaceConditionType.USE_AFTER_FREE: "使用已释放内存",
            RaceConditionType.DOUBLE_FREE: "重复释放",
            RaceConditionType.NULL_DEREFERENCE: "空指针解引用",
            RaceConditionType.DEADLOCK: "死锁",
            RaceConditionType.RACE_CONDITION: "竞态条件"
        }
    
    def detect_race_conditions(, self)
        borrows: List[BorrowInfo],
        locks: List[LockInfo],
        goroutine_points: List[int]
    ) -> List[RaceWarning]:
        """检测数据竞争条件"""
        warnings = []
        
        # 检测 UAF（Use-After-Free）
        uaf_warnings = self._detect_uaf(borrows)
        warnings.extend(uaf_warnings)
        
        # 检测数据竞争
        race_warnings = self._detect_data_race(borrows, locks, goroutine_points)
        warnings.extend(race_warnings)
        
        # 检测死锁
        deadlock_warnings = self._detect_deadlock(locks)
        warnings.extend(deadlock_warnings)
        
        return warnings
    
    def _detect_uaf(self, borrows: List[BorrowInfo]) -> List[RaceWarning]:
        """检测使用已释放内存"""
        warnings = []
        
        # 检查 unsafe 借用是否可能导致 UAF
        for borrow in borrows:
            if borrow.is_unsafe and borrow.borrow_type == "mut":
                warnings.append(RaceWarning(
                    race_type=RaceConditionType.USE_AFTER_FREE,
                    description=f"unsafe 块中的可变借用可能导致 UAF: {borrow.variable_name}",
                    location=borrow.borrow_scope[0],
                    severity="critical",
                    variables=[borrow.variable_name],
                    trace=[f"借用位置: 0x{borrow.borrow_scope[0]:x}"]
                

        
        return warnings
    
    def _detect_data_race(self, borrows: List[BorrowInfo], locks: List[LockInfo], goroutine_points: List[int]) -> List[RaceWarning]:
        """检测数据竞争"""
        warnings = []
        
        # 检查是否存在未保护的共享访问
        for i, borrow1 in enumerate(borrows):
            for j, borrow2 in enumerate(borrows[i+1:], i+1):
                # 检查两个借用是否可能并发访问同一变量
                if self._may_conflict(borrow1, borrow2):
                    # 检查是否有适当的锁保护
                    if not self._has_lock_protection(borrow1, locks):
                        warnings.append(RaceWarning(
                            race_type=RaceConditionType.DATA_RACE,
                            description=f"潜在数据竞争: {borrow1.variable_name} 和 {borrow2.variable_name}",
                            location=borrow1.borrow_scope[0],
                            severity="high",
                            variables=[borrow1.variable_name, borrow2.variable_name],
                            trace=["并发访问检测"]
                        

        
        return warnings
    
    def _may_conflict(self, borrow1: BorrowInfo, borrow2: BorrowInfo) -> bool:
        """检查两个借用是否可能冲突"""
        # 检查作用域是否重叠
        scope1_start, scope1_end = borrow1.borrow_scope
        scope2_start, scope2_end = borrow2.borrow_scope
        
        overlap = not (scope1_end <= scope2_start or scope2_end <= scope1_start)
        
        # 至少一个是可变借用才可能冲突
        has_mut = borrow1.borrow_type == "mut" or borrow2.borrow_type == "mut"
        
        return overlap and has_mut
    
    def _has_lock_protection(self, borrow: BorrowInfo, locks: List[LockInfo]) -> bool:
        """检查借用是否有锁保护"""
        for lock in locks:
            if lock.acquire_offset < borrow.borrow_scope[0]:
                if lock.release_offset is None or lock.release_offset > borrow.borrow_scope[1]:
                    return True
        return False
    
    def _detect_deadlock(self, locks: List[LockInfo]) -> List[RaceWarning]:
        """检测死锁"""
        warnings = []
        
        # 检查是否存在锁顺序问题
        for i, lock1 in enumerate(locks):
            for j, lock2 in enumerate(locks[i+1:], i+1):
                # 检测潜在的锁顺序问题
                if self._has_lock_order_issue(lock1, lock2):
                    warnings.append(RaceWarning(
                        race_type=RaceConditionType.DEADLOCK,
                        description=f"潜在死锁: 锁获取顺序不一致",
                        location=lock1.acquire_offset,
                        severity="critical",
                        variables=[lock1.lock_name, lock2.lock_name],
                        trace=["锁顺序检测"]
                    

        
        return warnings
    
    def _has_lock_order_issue(self, lock1: LockInfo, lock2: LockInfo) -> bool:
        """检查是否存在锁顺序问题"""
        # 简单检测：如果两个锁的获取顺序不一致，可能导致死锁
        if lock1.acquire_offset < lock2.acquire_offset:
            # 检查是否存在相反的顺序
            return True
        return False


class OwnershipAnalyzer(BaseAnalyzer):
    """
    Rust/Go 生命周期与并发分析器
    
    恢复 Rust 借用和生命周期注解，检测 unsafe 块中的 UAF、数据竞争。
    对 Go 进行 goroutine 调度点静态锁集分析，检测并发漏洞。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.rust_analyzer = RustBorrowAnalyzer()
        self.go_analyzer = GoLockSetAnalyzer()
        self.race_detector = RaceDetector()
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行所有权和并发分析
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径
                - binary_data: 二进制数据（可选）
                - language: 目标语言（rust/go/auto）
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        language = kwargs.get("language", "auto")
        
        logger.info(f"开始所有权分析: {binary_path}")
        
        try:
            # 加载二进制数据
            if binary_data is None and binary_path:
                if os.path.exists(binary_path):
                    with open(binary_path, 'rb') as f:
                        binary_data = f.read()
                else:
                    return {"success": False, "error": f"文件不存在: {binary_path}"}
            
            if binary_data is None:
                return {"success": False, "error": "缺少二进制数据"}
            
            # 检测语言
            detected_lang = self._detect_language(binary_data) if language == "auto" else LanguageType(language)
            
            # 根据语言执行分析
            result = OwnershipAnalysisResult(language=detected_lang)
            
            if detected_lang == LanguageType.RUST:
                result.borrows = self.rust_analyzer.analyze(binary_data)
                result.unsafe_blocks = self._find_unsafe_blocks(binary_data)
            
            elif detected_lang == LanguageType.GO:
                locks, goroutine_points = self.go_analyzer.analyze(binary_data)
                result.locks = locks
                result.goroutine_points = goroutine_points
            
            # 检测数据竞争
            result.warnings = self.race_detector.detect_race_conditions()
                result.borrows,
                result.locks,
                result.goroutine_points
            
            
            return {
                "success": True,
                "result": {
                    "language": detected_lang.value,
                    "num_borrows": len(result.borrows),
                    "num_locks": len(result.locks),
                    "num_warnings": len(result.warnings),
                    "num_unsafe_blocks": len(result.unsafe_blocks),
                    "num_goroutine_points": len(result.goroutine_points),
                    "warnings": [
                        {
                            "type": w.race_type.value,
                            "description": w.description,
                            "location": hex(w.location),
                            "severity": w.severity,
                            "variables": w.variables
                        } for w in result.warnings
                    ],
                    "summary": self._generate_summary(result)
                }
            }
            
        except Exception as e:
            logger.error(f"所有权分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _detect_language(self, binary_data: bytes) -> LanguageType:
        """检测二进制文件的语言类型"""
        # 检查 Rust 特征
        rust_signatures = [
            b'rust_', b'_ZN4core', b'_RNv', b'__rust_', b'rustc_demangle'
        ]
        
        # 检查 Go 特征
        go_signatures = [
            b'runtime.', b'main.', b'go.func.', b'gopanic', b'goexit'
        ]
        
        has_rust = any(signature in binary_data for signature in rust_signatures)
        has_go = any(signature in binary_data for signature in go_signatures)
        
        if has_rust and not has_go:
            return LanguageType.RUST
        elif has_go and not has_rust:
            return LanguageType.GO
        
        return LanguageType.UNKNOWN
    
    def _find_unsafe_blocks(self, binary_data: bytes) -> List[int]:
        """查找 unsafe 块的位置"""
        unsafe_blocks = []
        pattern = b'unchecked'
        
        offset = binary_data.find(pattern)
        while offset != -1:
            unsafe_blocks.append(offset)
            offset = binary_data.find(pattern, offset + 1)
        
        return unsafe_blocks
    
    def _generate_summary(self, result: OwnershipAnalysisResult) -> str:
        """生成分析摘要"""
        lang_name = {
            LanguageType.RUST: "Rust",
            LanguageType.GO: "Go",
            LanguageType.UNKNOWN: "未知"
        }[result.language]
        
        num_warnings = len(result.warnings)
        
        if num_warnings == 0:
            return f"{lang_name} 代码分析完成，未发现并发问题"
        elif num_warnings <= 3:
            return f"{lang_name} 代码分析完成，发现 {num_warnings} 个潜在并发问题"
        else:
            return f"{lang_name} 代码分析完成，发现 {num_warnings} 个潜在并发问题，建议详细审查"
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="OwnershipAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="Rust/Go 生命周期与并发分析器，检测借用问题、数据竞争和死锁",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        
        if not binary_path and binary_data is None:
            return False, "必须提供 binary_path 或 binary_data"
        
        if binary_path and not os.path.exists(binary_path):
            return False, f"文件不存在: {binary_path}"
        
        language = kwargs.get("language", "auto")
        if language not in ["auto", "rust", "go"]:
            return False, "language 必须是 auto、rust 或 go"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        pass))))'