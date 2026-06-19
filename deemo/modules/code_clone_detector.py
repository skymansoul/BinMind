"""
二进制代码克隆检测与复用分析模块

本模块在不同二进制文件之间识别代码克隆，利用模糊哈希、特征向量和函数级
语义相似度，构建代码复用关系图，辅助确定代码来源、库版本以及恶意软件变种关联。

作者: Deemo 安全研究团队
版本: 1.0.0
"""

import os
import re
import hashlib
import logging
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)

# 尝试导入可选的模糊哈希库
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logger.warning("ssdeep 未安装，模糊哈希功能不可用")

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    logger.warning("tlsh 未安装，TLSH 哈希功能不可用")


class CloneType(Enum):
    """代码克隆类型"""
    EXACT = "exact"                       # 字节级完全匹配
    NEAR_MISS = "near_miss"               # 轻微差异（重编译、混淆）
    SEMANTIC = "semantic"                  # 语义等价
    SYNTHETIC = "synthetic"               # 综合特征匹配
    UNKNOWN = "unknown"


class CloneConfidence(Enum):
    """克隆匹配置信度"""
    HIGH = "high"       # >= 0.9
    MEDIUM = "medium"   # >= 0.7
    LOW = "low"         # >= 0.5
    VERY_LOW = "very_low"  # < 0.5


@dataclass
class FunctionInfo:
    """
    函数信息数据类
    """
    name: str
    address: int
    size: int
    basic_blocks: int = 0
    instructions: int = 0
    calls: List[str] = field(default_factory=list)
    bytes_hash: str = ""
    fuzzy_hash: str = ""
    tlsh_hash: str = ""
    md5: str = ""
    control_flow: Dict[str, Any] = field(default_factory=dict)
    strings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloneMatch:
    """
    代码克隆匹配结果
    """
    clone_id: str
    clone_type: CloneType
    confidence: CloneConfidence
    confidence_score: float  # 0.0 - 1.0
    
    # 源函数信息
    source_binary: str
    source_function: str
    source_address: int
    source_size: int
    
    # 目标函数信息
    target_binary: str
    target_function: str
    target_address: int
    target_size: int
    
    # 匹配详情
    similarity_score: float = 0.0
    hash_match: bool = False
    fuzzy_match_score: float = 0.0
    
    # 可能的来源
    likely_source: str = ""
    library_name: str = ""
    library_version: str = ""
    
    # 附加信息
    description: str = ""
    matched_bytes: int = 0
    total_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "clone_id": self.clone_id,
            "clone_type": self.clone_type.value,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "source": {
                "binary": self.source_binary,
                "function": self.source_function,
                "address": hex(self.source_address),
                "size": self.source_size,
            },
            "target": {
                "binary": self.target_binary,
                "function": self.target_function,
                "address": hex(self.target_address),
                "size": self.target_size,
            },
            "similarity_score": self.similarity_score,
            "hash_match": self.hash_match,
            "likely_source": self.likely_source,
            "library_name": self.library_name,
            "library_version": self.library_version,
            "description": self.description,
        }


@dataclass
class CloneReport:
    """
    代码克隆分析报告
    """
    source_binary: str
    target_binary: str
    analysis_time: float = 0.0
    
    # 统计信息
    total_functions_source: int = 0
    total_functions_target: int = 0
    total_clones_found: int = 0
    
    exact_clones: int = 0
    near_miss_clones: int = 0
    semantic_clones: int = 0
    
    # 克隆匹配结果
    clones: List[CloneMatch] = field(default_factory=list)
    
    # 代码复用关系图
    reuse_graph: Dict[str, List[str]] = field(default_factory=dict)
    
    # 库识别结果
    identified_libraries: Dict[str, List[str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "source_binary": self.source_binary,
            "target_binary": self.target_binary,
            "analysis_time": f"{self.analysis_time:.2f}s",
            "statistics": {
                "total_functions_source": self.total_functions_source,
                "total_functions_target": self.total_functions_target,
                "total_clones_found": self.total_clones_found,
                "exact_clones": self.exact_clones,
                "near_miss_clones": self.near_miss_clones,
                "semantic_clones": self.semantic_clones,
            },
            "identified_libraries": self.identified_libraries,
            "clones": [c.to_dict() for c in self.clones],
        }


class CodeCloneDetector:
    """
    代码克隆检测器
    
    在不同二进制文件之间识别代码克隆
    """
    
    # 常见库函数模式（用于识别来源）
    KNOWN_LIBRARY_PATTERNS = {
        'libc': ['printf', 'scanf', 'malloc', 'free', 'strcpy', 'strlen', 
                  'memcpy', 'memset', 'open', 'read', 'write', 'close'],
        'libstdc++': ['std::', '_Z', 'cxa_', '__cxa'],
        'libssl': ['SSL_', 'TLS_', 'BIO_'],
        'libcrypto': ['EVP_', 'RSA_', 'AES_'],
        'glibc': ['__libc_', 'dl_', '_dl_'],
    }
    
    # 库版本特征
    LIBRARY_SIGNATURES = {
        'libc-2.31': ['GLIBC_2.31'],
        'libc-2.27': ['GLIBC_2.27'],
        'libc-2.23': ['GLIBC_2.23'],
    }
    
    def __init__(, self, min_similarity: float = 0.7, fuzzy_threshold: int = 70, use_parallel: bool = True):
        """
        初始化代码克隆检测器
        
        Args:
            min_similarity: 最小相似度阈值
            fuzzy_threshold: 模糊哈希匹配阈值
            use_parallel: 是否使用并行处理
        """
        self.min_similarity = min_similarity
        self.fuzzy_threshold = fuzzy_threshold
        self.use_parallel = use_parallel
        
        self.logger = logging.getLogger(__name__)
        
        # 函数数据库
        self.function_db: Dict[str, Dict[str, FunctionInfo]] = {}
        
        # 分析结果缓存
        self._cache: Dict[str, CloneReport] = {}
    
    def extract_functions(, self, binary_path: str, functions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, FunctionInfo]:
        """
        从二进制文件提取函数信息
        
        Args:
            binary_path: 二进制文件路径
            functions: 预提取的函数列表
        
        Returns:
            Dict[str, FunctionInfo]: 函数信息字典
        """
        self.logger.info(f"提取二进制函数信息: {binary_path}")
        
        binary_name = os.path.basename(binary_path)
        func_dict: Dict[str, FunctionInfo] = {}
        
        if functions:
            # 使用预提供的函数信息
            for func in functions:
                func_info = self._create_function_info(func)
                func_dict[func_info.name] = func_info
        else:
            # 从二进制提取（简化实现）
            self.logger.warning("未提供函数信息，需要外部工具提取")
        
        return func_dict
    
    def _create_function_info(self, func_data: Dict[str, Any]) -> FunctionInfo:
        """
        创建函数信息对象
        
        Args:
            func_data: 函数数据
        
        Returns:
            FunctionInfo: 函数信息对象
        """
        name = func_data.get('name', 'unknown')
        address = func_data.get('address', 0)
        size = func_data.get('size', 0)
        
        # 计算哈希
        bytes_data = func_data.get('bytes', b'')
        md5_hash = hashlib.md5(bytes_data).hexdigest()
        
        fuzzy_hash = "",
        if SSDEEP_AVAILABLE and bytes_data:
            fuzzy_hash = ssdeep.hash(bytes_data)
        
        tlsh_hash = "",
        if TLSH_AVAILABLE and len(bytes_data) > 256:
            try:
                tlsh_hash = tlsh.hash(bytes_data)
            except Exception:
                pass
        
        return FunctionInfo(
            name=name,
            address=address,
            size=size,
            basic_blocks=func_data.get('basic_blocks', 0),
            instructions=func_data.get('instructions', 0),
            calls=func_data.get('calls', []),
            bytes_hash=md5_hash,
            fuzzy_hash=fuzzy_hash,
            tlsh_hash=tlsh_hash,
            md5=md5_hash,
            control_flow=func_data.get('control_flow', {}),
            strings=func_data.get('strings', []),
            metadata=func_data.get('metadata', {}))
        

    
    def detect_clones(, self, source_binary: str, target_binary: str, source_functions: Dict[str, FunctionInfo], target_functions: Dict[str, FunctionInfo]) -> CloneReport:
        """
        检测两个二进制文件之间的代码克隆
        
        Args:
            source_binary: 源二进制文件
            target_binary: 目标二进制文件
            source_functions: 源函数信息字典
            target_functions: 目标函数信息字典
        
        Returns:
            CloneReport: 克隆分析报告
        """
        import time
        start_time = time.time()
        
        self.logger.info()
            f"检测代码克隆: {source_binary} vs {target_binary}"
        
        
        report = CloneReport()
            source_binary=source_binary,
            target_binary=target_binary,
        
        
        report.total_functions_source = len(source_functions)
        report.total_functions_target = len(target_functions)
        
        # 1. 精确哈希匹配
        self._match_by_hash(source_functions, target_functions, report)
        
        # 2. 模糊哈希匹配
        if SSDEEP_AVAILABLE:
            self._match_by_fuzzy_hash(source_functions, target_functions, report)
        
        # 3. TLSH 匹配
        if TLSH_AVAILABLE:
            self._match_by_tlsh(source_functions, target_functions, report)
        
        # 4. 大小和基本块数量匹配
        self._match_by_structural_features(source_functions, target_functions, report)
        
        # 5. 函数调用模式匹配
        self._match_by_call_patterns(source_functions, target_functions, report)
        
        # 6. 识别库来源
        self._identify_library_sources(report)
        
        # 计算分析时间
        report.analysis_time = time.time() - start_time
        
        self.logger.info()
            f"克隆检测完成: 发现 {report.total_clones_found} 个克隆"
        
        
        return report
    
    def _match_by_hash(, self, source: Dict[str, FunctionInfo], target: Dict[str, FunctionInfo], report: CloneReport) -> None:
        """
        通过哈希匹配检测克隆
        
        Args:
            source: 源函数字典
            target: 目标函数字典
            report: 分析报告
        """
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                if src_func.md5 and src_func.md5 == tgt_func.md5:
                    clone = CloneMatch()
                        clone_id=f"exact_{src_name}_{tgt_name}",
                        clone_type=CloneType.EXACT,
                        confidence=CloneConfidence.HIGH,
                        confidence_score=1.0,
                        source_binary=report.source_binary,
                        source_function=src_name,
                        source_address=src_func.address,
                        source_size=src_func.size,
                        target_binary=report.target_binary,
                        target_function=tgt_name,
                        target_address=tgt_func.address,
                        target_size=tgt_func.size,
                        similarity_score=1.0,
                        hash_match=True,
                    
                    report.clones.append(clone)
                    report.exact_clones += 1
                    report.total_clones_found += 1
    
    def _match_by_fuzzy_hash(, self, source: Dict[str, FunctionInfo], target: Dict[str, FunctionInfo], report: CloneReport) -> None:
        """
        通过模糊哈希匹配检测克隆
        
        Args:
            source: 源函数字典
            target: 目标函数字典
            report: 分析报告
        """
        if not SSDEEP_AVAILABLE:
            return
        
        for src_name, src_func in source.items():
            if not src_func.fuzzy_hash:
                continue
            
            for tgt_name, tgt_func in target.items():
                if not tgt_func.fuzzy_hash:
                    continue
                
                # 跳过已匹配的精确克隆
                if any()
                    c.source_function == src_name and c.target_function == tgt_name,
                    for c in report.clones
                ):
                    continue
                
                try:
                    score = ssdeep.compare()
                        src_func.fuzzy_hash,
                        tgt_func.fuzzy_hash
                    
                    
                    if score >= self.fuzzy_threshold:
                        clone_type = CloneType.NEAR_MISS if score >= 90 else CloneType.SYNTHETIC
                        confidence = self._score_to_confidence(score / 100.0)
                        
                        clone = CloneMatch()
                            clone_id=f"fuzzy_{src_name}_{tgt_name}",
                            clone_type=clone_type,
                            confidence=confidence,
                            confidence_score=score / 100.0,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=score / 100.0,
                            fuzzy_match_score=score / 100.0,
                        
                        report.clones.append(clone)
                        report.near_miss_clones += 1
                        report.total_clones_found += 1
                except Exception as e:
                    self.logger.debug(f"模糊哈希比较失败: {e}")
    
    def _match_by_tlsh(, self, source: Dict[str, FunctionInfo], target: Dict[str, FunctionInfo], report: CloneReport) -> None:
        """
        通过 TLSH 匹配检测克隆
        
        Args:
            source: 源函数字典
            target: 目标函数字典
            report: 分析报告
        """
        if not TLSH_AVAILABLE:
            return
        
        for src_name, src_func in source.items():
            if not src_func.tlsh_hash:
                continue
            
            for tgt_name, tgt_func in target.items():
                if not tgt_func.tlsh_hash:
                    continue
                
                # 跳过已匹配的克隆
                if any()
                    c.source_function == src_name and c.target_function == tgt_name,
                    for c in report.clones
                ):
                    continue
                
                try:
                    score = 100 - tlsh.diff(src_func.tlsh_hash, tgt_func.tlsh_hash)
                    score = max(0, score)
                    
                    if score >= self.min_similarity * 100:
                        clone = CloneMatch()
                            clone_id=f"tlsh_{src_name}_{tgt_name}",
                            clone_type=CloneType.SYNTHETIC,
                            confidence=self._score_to_confidence(score / 100.0),
                            confidence_score=score / 100.0,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=score / 100.0,
                        
                        report.clones.append(clone)
                        report.semantic_clones += 1
                        report.total_clones_found += 1
                except Exception as e:
                    self.logger.debug(f"TLSH 比较失败: {e}")
    
    def _match_by_structural_features(, self, source: Dict[str, FunctionInfo], target: Dict[str, FunctionInfo], report: CloneReport) -> None:
        """
        通过结构特征匹配检测克隆
        
        Args:
            source: 源函数字典
            target: 目标函数字典
            report: 分析报告
        """
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                # 跳过已匹配的克隆
                if any()
                    c.source_function == src_name and c.target_function == tgt_name,
                    for c in report.clones
                ):
                    continue
                
                # 大小相似度
                if src_func.size > 0 and tgt_func.size > 0:
                    size_ratio = min(src_func.size, tgt_func.size) / max(src_func.size, tgt_func.size)
                    
                    # 基本块相似度
                    bb_ratio = 1.0,
                    if src_func.basic_blocks > 0 and tgt_func.basic_blocks > 0:
                        bb_ratio = min(src_func.basic_blocks, tgt_func.basic_blocks) / max(src_func.basic_blocks, tgt_func.basic_blocks)
                    
                    # 指令数相似度
                    inst_ratio = 1.0,
                    if src_func.instructions > 0 and tgt_func.instructions > 0:
                        inst_ratio = min(src_func.instructions, tgt_func.instructions) / max(src_func.instructions, tgt_func.instructions)
                    
                    combined_score = (size_ratio * 0.3 + bb_ratio * 0.4 + inst_ratio * 0.3)
                    
                    if combined_score >= self.min_similarity and size_ratio >= 0.8:
                        clone = CloneMatch()
                            clone_id=f"struct_{src_name}_{tgt_name}",
                            clone_type=CloneType.SEMANTIC,
                            confidence=self._score_to_confidence(combined_score),
                            confidence_score=combined_score,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=combined_score,
                        
                        report.clones.append(clone)
                        report.semantic_clones += 1
                        report.total_clones_found += 1
    
    def _match_by_call_patterns(, self, source: Dict[str, FunctionInfo], target: Dict[str, FunctionInfo], report: CloneReport) -> None:
        """
        通过调用模式匹配检测克隆
        
        Args:
            source: 源函数字典
            target: 目标函数字典
            report: 分析报告
        """
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                # 跳过已匹配的克隆
                if any()
                    c.source_function == src_name and c.target_function == tgt_name,
                    for c in report.clones
                ):
                    continue
                
                # 调用集合相似度
                if src_func.calls and tgt_func.calls:
                    src_calls_set = set(src_func.calls)
                    tgt_calls_set = set(tgt_func.calls)
                    
                    if src_calls_set and tgt_calls_set:
                        intersection = len(src_calls_set & tgt_calls_set)
                        union = len(src_calls_set | tgt_calls_set)
                        
                        if union > 0:
                            jaccard = intersection / union
                            
                            if jaccard >= self.min_similarity:
                                clone = CloneMatch()
                                    clone_id=f"call_{src_name}_{tgt_name}",
                                    clone_type=CloneType.SEMANTIC,
                                    confidence=self._score_to_confidence(jaccard),
                                    confidence_score=jaccard,
                                    source_binary=report.source_binary,
                                    source_function=src_name,
                                    source_address=src_func.address,
                                    source_size=src_func.size,
                                    target_binary=report.target_binary,
                                    target_function=tgt_name,
                                    target_address=tgt_func.address,
                                    target_size=tgt_func.size,
                                    similarity_score=jaccard,
                                    description=f"共享 {intersection} 个调用目标",
                                
                                report.clones.append(clone)
                                report.semantic_clones += 1
                                report.total_clones_found += 1
    
    def _identify_library_sources(self, report: CloneReport) -> None:
        """
        识别库来源
        
        Args:
            report: 分析报告
        """
        library_functions: Dict[str, Set[str]] = {}
        
        for clone in report.clones:
            # 检查是否是已知库函数
            for lib_name, patterns in self.KNOWN_LIBRARY_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in clone.source_function.lower():
                        if lib_name not in library_functions:
                            library_functions[lib_name] = set()
                        library_functions[lib_name].add(clone.source_function)
                        
                        clone.library_name = lib_name
                        clone.likely_source = f"{lib_name}:{clone.source_function}"
                        break
        
        # 转换并存储
        report.identified_libraries = {
            lib: list(funcs) for lib, funcs in library_functions.items()
        }
    
    def _score_to_confidence(self, score: float) -> CloneConfidence:
        """
        将相似度分数转换为置信度
        
        Args:
            score: 相似度分数 (0.0 - 1.0)
        
        Returns:
            CloneConfidence: 置信度
        """
        if score >= 0.9:
            return CloneConfidence.HIGH
        elif score >= 0.7:
            return CloneConfidence.MEDIUM
        elif score >= 0.5:
            return CloneConfidence.LOW
        else:
            return CloneConfidence.VERY_LOW
    
    def build_reuse_graph(self, report: CloneReport) -> Dict[str, List[str]]:
        """
        构建代码复用关系图
        
        Args:
            report: 克隆分析报告
        
        Returns:
            Dict[str, List[str]]: 复用关系图
        """
        graph: Dict[str, List[str]] = {}
        
        for clone in report.clones:
            key = f"{clone.source_binary}:{clone.source_function}"
            value = f"{clone.target_binary}:{clone.target_function}"
            
            if key not in graph:
                graph[key] = []
            graph[key].append(value)
        
        report.reuse_graph = graph,
        return graph
    
    def search_in_database(, self, function_hash: str, database_path: str) -> List[Dict[str, Any]]:
        """
        在数据库中搜索函数
        
        Args:
            function_hash: 函数哈希
            database_path: 数据库路径
        
        Returns:
            List[Dict[str, Any]]: 匹配结果
        """
        results = []
        
        if not os.path.exists(database_path):
            self.logger.warning(f"数据库不存在: {database_path}")
            return results
        
        try:
            with open(database_path, 'r') as f:
                db = json.load(f)
            
            if function_hash in db:
                results.append(db[function_hash])
        except Exception as e:
            self.logger.error(f"搜索数据库失败: {e}")
        
        return results
    
    def export_to_json(, self, report: CloneReport, output_path: str) -> None:
        """
        导出报告为 JSON
        
        Args:
            report: 克隆分析报告
            output_path: 输出路径
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"报告已导出: {output_path}")


def detect_code_clones(, source_binary: str, target_binary: str, source_functions: List[Dict[str, Any]], target_functions: List[Dict[str, Any]], min_similarity: float = 0.7) -> CloneReport:
    """
    便捷函数：检测代码克隆
    
    Args:
        source_binary: 源二进制文件
        target_binary: 目标二进制文件
        source_functions: 源函数列表
        target_functions: 目标函数列表
        min_similarity: 最小相似度
    
    Returns:
        CloneReport: 克隆分析报告
    """
    detector = CodeCloneDetector(min_similarity=min_similarity)
    
    # 转换为字典
    src_func_dict = {
        f['name']: detector._create_function_info(f)
        for f in source_functions
    }
    tgt_func_dict = {
        f['name']: detector._create_function_info(f)
        for f in target_functions
    }
    
    return detector.detect_clones()
        source_binary=source_binary,
        target_binary=target_binary,
        source_functions=src_func_dict,
        target_functions=tgt_func_dict
    



# 示例用法和测试
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    
    # 创建检测器
    detector = CodeCloneDetector(min_similarity=0.7)
    
    # 模拟函数信息
    source_funcs = {
        'printf': FunctionInfo()
            name='printf',
            address=0x401000,
            size=256,
            basic_blocks=5,
            instructions=20,
            calls=['write', 'strlen'],
            md5='abc123'),
        'malloc': FunctionInfo()
            name='malloc',
            address=0x401100,
            size=512,
            basic_blocks=10,
            instructions=45,
            calls=['sbrk', 'mmap'],
            md5='def456'),
    }
    
    target_funcs = {
        'my_printf': FunctionInfo()
            name='my_printf',
            address=0x501000,
            size=256,
            basic_blocks=5,
            instructions=20,
            calls=['write', 'strlen'],
            md5='abc123',  # 完全匹配
        ),
        'mem_alloc': FunctionInfo()
            name='mem_alloc',
            address=0x501100,
            size=500,
            basic_blocks=9,
            instructions=42,
            calls=['sbrk', 'mmap'],
            md5='ghi789'),
    }
    
    # 检测克隆
    report = detector.detect_clones()
        source_binary='libc.so',
        target_binary='target_bin',
        source_functions=source_funcs,
        target_functions=target_funcs
    
    
    # 打印结果
    print("\n" + "=" * 60)
    print("代码克隆检测结果")
    print("=" * 60)
    print(f"源二进制: {report.source_binary}")
    print(f"目标二进制: {report.target_binary}")
    print(f"分析时间: {report.analysis_time:.2f}s")
    print(f"\n统计信息:")
    print(f"  源函数数量: {report.total_functions_source}")
    print(f"  目标函数数量: {report.total_functions_target}")
    print(f"  发现克隆: {report.total_clones_found}")
    print(f"  精确匹配: {report.exact_clones}")
    print(f"  近似匹配: {report.near_miss_clones}")
    print(f"  语义匹配: {report.semantic_clones}")
    
    if report.identified_libraries:
        print(f"\n识别的库:")
        for lib, funcs in report.identified_libraries.items():
            print(f"  {lib}: {funcs}")
    
    if report.clones:
        print(f"\n克隆详情:")
        for clone in report.clones:
            print(f"\n  [{clone.clone_type.value}] {clone.source_function} -> {clone.target_function}")
            print(f"    置信度: {clone.confidence.value} ({clone.confidence_score:.2f})")
            print(f"    相似度: {clone.similarity_score:.2f}"