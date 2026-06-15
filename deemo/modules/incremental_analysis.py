"""
多阶段分析缓存与增量分析模块

对同一二进制文件多次执行分析时，自动识别未发生变化的函数和模块，复用之前的分析结果。
"""

import os
import json
import logging
import hashlib
import sqlite3
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

try:
    from config import Config
except ImportError:
    class Config:
        INCREMENTAL_ANALYSIS_CACHE_DIR = "data/incremental_cache"
        LOG_LEVEL = "INFO"
        CACHE_VALIDITY_DAYS = 30


logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL, "INFO"))
logger = logging.getLogger(__name__)


class CacheStatus(Enum):
    """缓存状态枚举"""
    VALID = "valid"
    INVALIDATED = "invalidated"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"


class CacheInvalidationReason(Enum):
    """缓存失效原因枚举"""
    ANALYSIS_OPTIONS_CHANGED = "analysis_options_changed"
    BINARY_MODIFIED = "binary_modified"
    CACHE_EXPIRED = "cache_expired"
    MANUAL_INVALIDATION = "manual_invalidation"
    FORMAT_CHANGE = "format_change"


@dataclass
class FunctionCacheEntry:
    """函数缓存条目"""
    function_name: str
    function_address: int
    semantic_hash: str
    analysis_result: Dict[str, Any]
    analysis_timestamp: str
    binary_hash: str
    analysis_options: Dict[str, Any]
    status: CacheStatus = CacheStatus.VALID
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_name": self.function_name,
            "function_address": hex(self.function_address),
            "semantic_hash": self.semantic_hash,
            "analysis_result": self.analysis_result,
            "analysis_timestamp": self.analysis_timestamp,
            "binary_hash": self.binary_hash,
            "analysis_options": self.analysis_options,
            "status": self.status.value
        }


@dataclass
class BinaryCacheEntry:
    """二进制缓存条目"""
    binary_path: str
    binary_hash: str
    functions: List[int]  # 函数地址列表
    cache_timestamp: str
    version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "binary_hash": self.binary_hash,
            "functions": [hex(f) for f in self.functions],
            "cache_timestamp": self.cache_timestamp,
            "version": self.version
        }


@dataclass
class IncrementalAnalysisResult:
    """增量分析结果"""
    binary_path: str
    total_functions: int
    cached_functions: int
    new_functions: int
    modified_functions: int
    skipped_functions: int
    analysis_duration: float
    cache_hits: int
    cache_misses: int
    timestamp: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "total_functions": self.total_functions,
            "cached_functions": self.cached_functions,
            "new_functions": self.new_functions,
            "modified_functions": self.modified_functions,
            "skipped_functions": self.skipped_functions,
            "analysis_duration": self.analysis_duration,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "timestamp": self.timestamp
        }


class IncrementalAnalysisCache:
    """
    增量分析缓存管理器
    
    管理二进制分析结果的缓存，支持增量分析。
    """
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        初始化缓存管理器
        
        Args:
            cache_dir: 缓存目录
        """
        self.cache_dir = Path(cache_dir or Config.INCREMENTAL_ANALYSIS_CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化数据库
        self._init_database()
        
        logger.info(f"增量分析缓存初始化，缓存目录: {self.cache_dir}")
    
    def _init_database(self) -> None:
        """初始化缓存数据库"""
        db_path = self.cache_dir / "analysis_cache.db"
        
        self.conn = sqlite3.connect(str(db_path))
        self.cursor = self.conn.cursor()
        
        # 创建表
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS binary_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_path TEXT UNIQUE,
                binary_hash TEXT,
                functions TEXT,
                cache_timestamp TEXT,
                version TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS function_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                function_address INTEGER UNIQUE,
                function_name TEXT,
                semantic_hash TEXT,
                analysis_result TEXT,
                analysis_timestamp TEXT,
                binary_hash TEXT,
                analysis_options TEXT,
                status TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_path TEXT,
                timestamp TEXT,
                event_type TEXT,
                reason TEXT,
                details TEXT
            )
        ''')
        
        self.conn.commit()
    
    def compute_binary_hash(self, binary_path: str) -> str:
        """
        计算二进制文件的哈希值
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            文件哈希值
        """
        hasher = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def compute_semantic_hash(self, pseudocode: str) -> str:
        """
        计算语义哈希（基于反编译伪代码）
        
        Args:
            pseudocode: 反编译的伪代码
            
        Returns:
            语义哈希值
        """
        # 归一化伪代码：去除空白、注释等无关信息
        normalized = self._normalize_pseudocode(pseudocode)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def _normalize_pseudocode(self, pseudocode: str) -> str:
        """
        归一化伪代码
        
        Args:
            pseudocode: 原始伪代码
            
        Returns:
            归一化后的伪代码
        """
        lines = pseudocode.split('\n')
        normalized_lines = []
        
        for line in lines:
            # 去除注释
            if '//' in line:
                line = line[:line.index('//')]
            if '/*' in line:
                line = line[:line.index('/*')]
            
            # 去除多余空白
            line = line.strip()
            
            if line:
                normalized_lines.append(line)
        
        return '\n'.join(normalized_lines)
    
    def get_binary_cache(self, binary_path: str) -> Optional[BinaryCacheEntry]:
        """
        获取二进制缓存条目
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            BinaryCacheEntry或None
        """
        self.cursor.execute('''
            SELECT binary_hash, functions, cache_timestamp, version
            FROM binary_cache WHERE binary_path = ?
        ''', (binary_path,))
        
        row = self.cursor.fetchone()
        if not row:
            return None
        
        return BinaryCacheEntry(
            binary_path=binary_path,
            binary_hash=row[0],
            functions=[int(f, 16) for f in json.loads(row[1])],
            cache_timestamp=row[2],
            version=row[3]
        )
    
    def save_binary_cache(self, entry: BinaryCacheEntry) -> None:
        """
        保存二进制缓存条目
        
        Args:
            entry: BinaryCacheEntry对象
        """
        functions_json = json.dumps([f for f in entry.functions])
        
        self.cursor.execute('''
            INSERT OR REPLACE INTO binary_cache
            (binary_path, binary_hash, functions, cache_timestamp, version)
            VALUES (?, ?, ?, ?, ?)
        ''', (entry.binary_path, entry.binary_hash, functions_json, 
              entry.cache_timestamp, entry.version))
        
        self.conn.commit()
    
    def get_function_cache(self, function_address: int) -> Optional[FunctionCacheEntry]:
        """
        获取函数缓存条目
        
        Args:
            function_address: 函数地址
            
        Returns:
            FunctionCacheEntry或None
        """
        self.cursor.execute('''
            SELECT function_name, semantic_hash, analysis_result, 
                   analysis_timestamp, binary_hash, analysis_options, status
            FROM function_cache WHERE function_address = ?
        ''', (function_address,))
        
        row = self.cursor.fetchone()
        if not row:
            return None
        
        return FunctionCacheEntry(
            function_name=row[0],
            function_address=function_address,
            semantic_hash=row[1],
            analysis_result=json.loads(row[2]),
            analysis_timestamp=row[3],
            binary_hash=row[4],
            analysis_options=json.loads(row[5]),
            status=CacheStatus(row[6])
        )
    
    def save_function_cache(self, entry: FunctionCacheEntry) -> None:
        """
        保存函数缓存条目
        
        Args:
            entry: FunctionCacheEntry对象
        """
        self.cursor.execute('''
            INSERT OR REPLACE INTO function_cache
            (function_address, function_name, semantic_hash, analysis_result,
             analysis_timestamp, binary_hash, analysis_options, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (entry.function_address, entry.function_name, entry.semantic_hash,
              json.dumps(entry.analysis_result), entry.analysis_timestamp,
              entry.binary_hash, json.dumps(entry.analysis_options), entry.status.value))
        
        self.conn.commit()
    
    def invalidate_cache(self, binary_path: Optional[str] = None, 
                        reason: CacheInvalidationReason = CacheInvalidationReason.MANUAL_INVALIDATION) -> None:
        """
        失效缓存
        
        Args:
            binary_path: 二进制路径（可选，为空则失效所有）
            reason: 失效原因
        """
        if binary_path:
            # 失效特定二进制的缓存
            self.cursor.execute('''
                UPDATE function_cache SET status = ?
                WHERE binary_hash = (SELECT binary_hash FROM binary_cache WHERE binary_path = ?)
            ''', (CacheStatus.INVALIDATED.value, binary_path))
            
            self.cursor.execute('''
                DELETE FROM binary_cache WHERE binary_path = ?
            ''', (binary_path,))
            
            self._log_history(binary_path, "invalidation", reason.value, "binary-specific")
        else:
            # 失效所有缓存
            self.cursor.execute('''
                UPDATE function_cache SET status = ?
            ''', (CacheStatus.INVALIDATED.value,))
            
            self.cursor.execute('''
                DELETE FROM binary_cache
            ''')
            
            self._log_history("ALL", "invalidation", reason.value, "all")
        
        self.conn.commit()
        logger.info(f"缓存已失效: {binary_path or 'all'}, 原因: {reason.value}")
    
    def _log_history(self, binary_path: str, event_type: str, reason: str, details: str) -> None:
        """
        记录缓存历史
        
        Args:
            binary_path: 二进制路径
            event_type: 事件类型
            reason: 原因
            details: 详细信息
        """
        self.cursor.execute('''
            INSERT INTO cache_history (binary_path, timestamp, event_type, reason, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (binary_path, datetime.now().isoformat(), event_type, reason, details))
        
        self.conn.commit()
    
    def is_cache_valid(self, binary_path: str, current_hash: str) -> bool:
        """
        检查缓存是否有效
        
        Args:
            binary_path: 二进制路径
            current_hash: 当前二进制哈希
            
        Returns:
            True如果缓存有效
        """
        entry = self.get_binary_cache(binary_path)
        if not entry:
            return False
        
        # 检查哈希是否匹配
        if entry.binary_hash != current_hash:
            return False
        
        # 检查是否过期
        cache_time = datetime.fromisoformat(entry.cache_timestamp)
        now = datetime.now()
        age_days = (now - cache_time).days
        
        if age_days > Config.CACHE_VALIDITY_DAYS:
            return False
        
        return True
    
    def analyze_incrementally(
        self,
        binary_path: str,
        functions: List[Dict[str, Any]],
        analysis_options: Dict[str, Any],
        analysis_func
    ) -> IncrementalAnalysisResult:
        """
        执行增量分析
        
        Args:
            binary_path: 二进制路径
            functions: 函数列表（包含地址和伪代码）
            analysis_options: 分析选项
            analysis_func: 分析函数（接受函数信息，返回分析结果）
            
        Returns:
            IncrementalAnalysisResult对象
        """
        start_time = datetime.now()
        timestamp = start_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # 计算当前二进制哈希
        current_hash = self.compute_binary_hash(binary_path)
        
        # 获取缓存
        binary_cache = self.get_binary_cache(binary_path)
        
        # 统计变量
        total_functions = len(functions)
        cached_functions = 0
        new_functions = 0
        modified_functions = 0
        skipped_functions = 0
        cache_hits = 0
        cache_misses = 0
        
        # 分析结果存储
        all_results = {}
        
        for func in functions:
            func_addr = func["address"]
            func_name = func.get("name", f"sub_{func_addr:x}")
            pseudocode = func.get("pseudocode", "")
            
            # 计算语义哈希
            semantic_hash = self.compute_semantic_hash(pseudocode)
            
            # 检查函数缓存
            func_cache = self.get_function_cache(func_addr)
            
            if func_cache and func_cache.status == CacheStatus.VALID:
                # 检查分析选项是否变化
                if func_cache.analysis_options != analysis_options:
                    # 选项变化，需要重新分析
                    cache_misses += 1
                    modified_functions += 1
                    result = analysis_func(func)
                elif func_cache.semantic_hash == semantic_hash:
                    # 语义相同，使用缓存
                    cache_hits += 1
                    cached_functions += 1
                    result = func_cache.analysis_result
                    skipped_functions += 1
                else:
                    # 语义变化，重新分析
                    cache_misses += 1
                    modified_functions += 1
                    result = analysis_func(func)
            else:
                # 无缓存，新函数
                cache_misses += 1
                new_functions += 1
                result = analysis_func(func)
            
            # 保存结果到缓存
            cache_entry = FunctionCacheEntry(
                function_name=func_name,
                function_address=func_addr,
                semantic_hash=semantic_hash,
                analysis_result=result,
                analysis_timestamp=datetime.now().isoformat(),
                binary_hash=current_hash,
                analysis_options=analysis_options,
                status=CacheStatus.VALID
            )
            self.save_function_cache(cache_entry)
            
            all_results[func_addr] = result
        
        # 更新二进制缓存
        binary_entry = BinaryCacheEntry(
            binary_path=binary_path,
            binary_hash=current_hash,
            functions=[f["address"] for f in functions],
            cache_timestamp=datetime.now().isoformat()
        )
        self.save_binary_cache(binary_entry)
        
        # 计算分析时长
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result = IncrementalAnalysisResult(
            binary_path=binary_path,
            total_functions=total_functions,
            cached_functions=cached_functions,
            new_functions=new_functions,
            modified_functions=modified_functions,
            skipped_functions=skipped_functions,
            analysis_duration=duration,
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            timestamp=timestamp
        )
        
        logger.info(f"增量分析完成: {cached_functions} 缓存命中, {new_functions} 新函数, {modified_functions} 修改")
        return result
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            统计信息字典
        """
        # 统计函数缓存
        self.cursor.execute('''
            SELECT status, COUNT(*) FROM function_cache GROUP BY status
        ''')
        status_counts = {row[0]: row[1] for row in self.cursor.fetchall()}
        
        # 统计二进制缓存数量
        self.cursor.execute('''
            SELECT COUNT(*) FROM binary_cache
        ''')
        binary_count = self.cursor.fetchone()[0]
        
        # 统计历史记录
        self.cursor.execute('''
            SELECT COUNT(*) FROM cache_history
        ''')
        history_count = self.cursor.fetchone()[0]
        
        return {
            "function_cache_count": sum(status_counts.values()),
            "binary_cache_count": binary_count,
            "history_count": history_count,
            "status_distribution": status_counts
        }
    
    def generate_report(self, result: IncrementalAnalysisResult) -> str:
        """
        生成增量分析报告
        
        Args:
            result: 增量分析结果
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# 增量分析报告",
            "",
            f"**分析时间**: {result.timestamp}",
            f"**目标文件**: {result.binary_path}",
            "",
            "## 分析摘要",
            "",
            "| 指标 | 数量 |",
            "|------|------|",
            f"| 总函数数 | {result.total_functions} |",
            f"| 缓存命中 | {result.cached_functions} |",
            f"| 新函数 | {result.new_functions} |",
            f"| 修改函数 | {result.modified_functions} |",
            f"| 跳过分析 | {result.skipped_functions} |",
            f"| 分析时长 | {result.analysis_duration:.2f}s |",
            "",
            "## 缓存统计",
            "",
            f"- 缓存命中率: {(result.cache_hits / (result.cache_hits + result.cache_misses) * 100):.1f}%" if (result.cache_hits + result.cache_misses) > 0 else "- 无数据",
            f"- 缓存失效率: {(result.cache_misses / (result.cache_hits + result.cache_misses) * 100):.1f}%" if (result.cache_hits + result.cache_misses) > 0 else "- 无数据",
            "",
            "## 性能改进",
            "",
        ]
        
        # 估算时间节省
        if result.skipped_functions > 0 and result.total_functions > 0:
            time_saved_ratio = result.skipped_functions / result.total_functions
            report_lines.append(f"- 跳过了 {result.skipped_functions} 个函数的重新分析")
            report_lines.append(f"- 预计节省时间: {(time_saved_ratio * 100):.1f}%")
        
        report_lines.append("")
        
        return "\n".join(report_lines)
    
    def save_result(self, result: IncrementalAnalysisResult, filename: Optional[str] = None) -> str:
        """
        保存增量分析结果
        
        Args:
            result: 增量分析结果
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"incremental_{timestamp}"
        
        # 保存JSON结果
        json_path = self.cache_dir / f"{filename}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 保存报告
        report_path = self.cache_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(result))
        
        logger.info(f"增量分析结果已保存: {json_path}")
        return str(json_path)
    
    def close(self) -> None:
        """关闭数据库连接"""
        self.conn.close()


if __name__ == "__main__":
    # 示例用法
    import sys
    
    cache = IncrementalAnalysisCache()
    
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        
        # 模拟函数列表
        functions = [
            {"address": 0x401000, "name": "main", "pseudocode": "int main() { return 0; }"},
            {"address": 0x401050, "name": "func1", "pseudocode": "void func1() { printf(\"hello\"); }"},
            {"address": 0x401100, "name": "func2", "pseudocode": "int func2(int x) { return x + 1; }"},
        ]
        
        # 模拟分析函数
        def mock_analysis(func):
            return {
                "function_name": func["name"],
                "analysis": "completed",
                "vulnerabilities": []
            }
        
        # 执行增量分析
        result = cache.analyze_incrementally(
            binary_path,
            functions,
            {"analysis_level": "full"},
            mock_analysis
        )
        
        cache.save_result(result)
        
        print(f"增量分析完成!")
        print(f"总函数: {result.total_functions}")
        print(f"缓存命中: {result.cached_functions}")
        print(f"新函数: {result.new_functions}")
        print(f"分析时长: {result.analysis_duration:.2f}s")
        
        cache.close()
    else:
        print("用法: python incremental_analysis.py <二进制文件路径>")