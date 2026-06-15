"""
二进制签名与代码同源性分析模块

功能:
    1. 为二进制文件生成多维度签名（模糊哈希、语义特征向量、函数级相似度）
    2. 基于签名进行大规模同源搜索
    3. 辅助确定二进制是否属于已知恶意软件家族或与已知样本共享代码
    4. 与威胁情报关联
"""

import os
import json
import logging
import hashlib
import struct
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import Counter

logger = logging.getLogger(__name__)

# 检查 ssdeep 是否可用
SSDEEP_AVAILABLE = False
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
    logger.info("ssdeep 库已加载，模糊哈希功能可用")
except ImportError:
    logger.warning("ssdeep 未安装，模糊哈希功能不可用。安装命令: pip install ssdeep")

# 检查 tlsh 是否可用
TLSH_AVAILABLE = False
try:
    import tlsh
    TLSH_AVAILABLE = True
    logger.info("tlsh 库已加载，TLSH 模糊哈希功能可用")
except ImportError:
    logger.warning("tlsh 未安装，TLSH 模糊哈希功能不可用。安装命令: pip install py-tlsh")

# 检查 numpy 是否可用
NUMPY_AVAILABLE = False
try:
    import numpy as np
    NUMPY_AVAILABLE = True
    logger.info("numpy 库已加载，向量计算功能可用")
except ImportError:
    logger.warning("numpy 未安装，向量计算功能受限")


@dataclass
class BinarySignature:
    """
    二进制签名信息
    """
    binary_path: str
    binary_name: str
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    ssdeep_hash: str = ""
    tlsh_hash: str = ""
    import_hash: str = ""
    export_hash: str = ""
    section_hash: str = ""
    function_count: int = 0
    function_signatures: List[Dict[str, Any]] = field(default_factory=list)
    cfg_signature: str = ""
    call_graph_signature: str = ""
    semantic_vector: List[float] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HomologyMatch:
    """
    同源匹配结果
    """
    matched_binary: str
    matched_signature_id: int
    similarity_score: float
    match_type: str  # 'ssdeep', 'tlsh', 'import_hash', 'semantic', 'combined'
    matched_functions: List[str] = field(default_factory=list)
    matched_strings: List[str] = field(default_factory=list)
    malware_family: str = ""
    threat_level: str = ""
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class BinarySigner:
    """
    二进制签名生成器
    
    为二进制文件生成多维度签名，用于同源性分析和威胁检测。
    """
    
    # 最小文件大小（用于 TLSH）
    TLSH_MIN_SIZE = 256
    
    # 函数特征向量维度
    VECTOR_DIM = 128
    
    def __init__(
        self,
        db_path: str = None,
        use_ssdeep: bool = True,
        use_tlsh: bool = True,
        use_semantic: bool = True
    ):
        """
        初始化二进制签名生成器
        
        Args:
            db_path: 签名数据库路径
            use_ssdeep: 是否使用 ssdeep
            use_tlsh: 是否使用 tlsh
            use_semantic: 是否使用语义向量
        """
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'data', 'signatures.db')
        self.use_ssdeep = use_ssdeep and SSDEEP_AVAILABLE
        self.use_tlsh = use_tlsh and TLSH_AVAILABLE
        self.use_semantic = use_semantic and NUMPY_AVAILABLE
        
        # 初始化数据库
        self._init_db()
        
        logger.info(f"二进制签名生成器初始化完成，数据库: {self.db_path}")
    
    def _init_db(self) -> None:
        """
        初始化签名数据库
        """
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS binary_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_path TEXT,
                    binary_name TEXT,
                    sha256 TEXT UNIQUE,
                    sha1 TEXT,
                    md5 TEXT,
                    ssdeep_hash TEXT,
                    tlsh_hash TEXT,
                    import_hash TEXT,
                    export_hash TEXT,
                    section_hash TEXT,
                    function_count INTEGER,
                    function_signatures TEXT,
                    cfg_signature TEXT,
                    call_graph_signature TEXT,
                    semantic_vector TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    malware_family TEXT,
                    threat_level TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_sha256 ON binary_signatures(sha256);
                CREATE INDEX IF NOT EXISTS idx_ssdeep ON binary_signatures(ssdeep_hash);
                CREATE INDEX IF NOT EXISTS idx_tlsh ON binary_signatures(tlsh_hash);
                CREATE INDEX IF NOT EXISTS idx_import_hash ON binary_signatures(import_hash);
                CREATE INDEX IF NOT EXISTS idx_binary_name ON binary_signatures(binary_name);
                
                CREATE TABLE IF NOT EXISTS function_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id INTEGER,
                    function_name TEXT,
                    function_address TEXT,
                    function_size INTEGER,
                    function_hash TEXT,
                    feature_vector TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (signature_id) REFERENCES binary_signatures(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_func_sig ON function_signatures(signature_id);
                CREATE INDEX IF NOT EXISTS idx_func_hash ON function_signatures(function_hash);
            """)
            
            conn.commit()
            conn.close()
            
            logger.info(f"签名数据库初始化成功: {self.db_path}")
            
        except Exception as e:
            logger.error(f"初始化签名数据库失败: {e}")
    
    def _calculate_hashes(self, binary_path: str) -> Dict[str, str]:
        """
        计算标准哈希值
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            包含 SHA256、SHA1、MD5 的字典
        """
        hashes = {'sha256': '', 'sha1': '', 'md5': ''}
        
        if not os.path.exists(binary_path):
            return hashes
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            
        except Exception as e:
            logger.error(f"计算哈希失败: {binary_path} - {e}")
        
        return hashes
    
    def _calculate_ssdeep(self, binary_path: str) -> str:
        """
        计算 ssdeep 模糊哈希
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            ssdeep 哈希字符串
        """
        if not self.use_ssdeep:
            return ""
        
        try:
            return ssdeep.hash_from_file(binary_path)
        except Exception as e:
            logger.warning(f"计算 ssdeep 失败: {binary_path} - {e}")
            return ""
    
    def _calculate_tlsh(self, binary_path: str) -> str:
        """
        计算 TLSH 模糊哈希
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            TLSH 哈希字符串
        """
        if not self.use_tlsh:
            return ""
        
        try:
            file_size = os.path.getsize(binary_path)
            if file_size < self.TLSH_MIN_SIZE:
                logger.warning(f"文件太小，无法计算 TLSH: {binary_path} ({file_size} bytes)")
                return ""
            
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            return tlsh.hash(content)
            
        except Exception as e:
            logger.warning(f"计算 TLSH 失败: {binary_path} - {e}")
            return ""
    
    def _calculate_import_hash(self, binary_info: Dict[str, Any]) -> str:
        """
        计算导入函数哈希
        
        Args:
            binary_info: 二进制文件信息
            
        Returns:
            导入函数哈希字符串
        """
        imports = binary_info.get('imports', {})
        
        # 收集所有导入函数名
        import_list = []
        
        # 标准导入
        for lib, funcs in imports.items():
            if isinstance(funcs, list):
                for func in funcs:
                    if isinstance(func, str):
                        import_list.append(f"{lib}:{func}")
                    elif isinstance(func, dict):
                        import_list.append(f"{lib}:{func.get('name', '')}")
        
        # 危险函数
        dangerous_funcs = imports.get('dangerous_functions', [])
        for func in dangerous_funcs:
            import_list.append(f"dangerous:{func}")
        
        if not import_list:
            return ""
        
        # 排序并计算哈希
        import_list.sort()
        import_str = '|'.join(import_list)
        
        return hashlib.sha256(import_str.encode('utf-8')).hexdigest()[:32]
    
    def _calculate_section_hash(self, binary_info: Dict[str, Any]) -> str:
        """
        计算节区哈希
        
        Args:
            binary_info: 二进制文件信息
            
        Returns:
            节区哈希字符串
        """
        sections = binary_info.get('sections', [])
        
        if not sections:
            return ""
        
        # 收集节区信息
        section_info = []
        for section in sections:
            if isinstance(section, dict):
                name = section.get('name', '')
                size = section.get('size', 0)
                perms = section.get('permissions', '')
                section_info.append(f"{name}:{size}:{perms}")
        
        if not section_info:
            return ""
        
        section_info.sort()
        section_str = '|'.join(section_info)
        
        return hashlib.sha256(section_str.encode('utf-8')).hexdigest()[:32]
    
    def _extract_function_signatures(
        self,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        提取函数级签名
        
        Args:
            binary_info: 二进制文件信息
            decomp_results: 反编译结果
            
        Returns:
            函数签名列表
        """
        function_signatures = []
        
        # 从符号表提取
        symbols = binary_info.get('symbols', {})
        for func_name, addr in symbols.items():
            if isinstance(addr, dict):
                address = addr.get('address', 0)
                size = addr.get('size', 0)
            else:
                address = addr
                size = 0
            
            function_signatures.append({
                'name': func_name,
                'address': hex(address) if address else '',
                'size': size,
                'hash': hashlib.md5(func_name.encode('utf-8')).hexdigest()[:16]
            })
        
        # 从反编译结果提取特征向量
        if decomp_results:
            for result in decomp_results:
                func_name = result.get('function_name', '')
                pseudocode = result.get('pseudocode', '')
                
                if pseudocode:
                    # 生成简单的特征向量（基于伪代码）
                    feature_vector = self._generate_feature_vector(pseudocode)
                    
                    # 更新或添加函数签名
                    for sig in function_signatures:
                        if sig['name'] == func_name:
                            sig['feature_vector'] = feature_vector
                            sig['pseudocode_hash'] = hashlib.sha256(pseudocode.encode('utf-8')).hexdigest()[:16]
                            break
        
        return function_signatures
    
    def _generate_feature_vector(self, code: str) -> List[float]:
        """
        从代码生成特征向量
        
        Args:
            code: 代码字符串
            
        Returns:
            特征向量列表
        """
        if not self.use_semantic:
            return []
        
        # 简单的特征提取（基于代码特征）
        features = []
        
        # 关键词频率
        keywords = [
            'if', 'else', 'for', 'while', 'return', 'call', 'malloc', 'free',
            'strcpy', 'memcpy', 'sprintf', 'printf', 'scanf', 'read', 'write',
            'open', 'close', 'socket', 'connect', 'send', 'recv', 'exec', 'system'
        ]
        
        code_lower = code.lower()
        for keyword in keywords:
            count = code_lower.count(keyword)
            features.append(float(count))
        
        # 代码长度特征
        features.append(float(len(code)))
        features.append(float(len(code.split('\n'))))
        features.append(float(len(code.split())))
        
        # 特殊字符频率
        features.append(float(code.count('(')))
        features.append(float(code.count(')')))
        features.append(float(code.count('{')))
        features.append(float(code.count('}')))
        features.append(float(code.count('=')))
        features.append(float(code.count('+')))
        features.append(float(code.count('-')))
        
        # 填充到固定维度
        while len(features) < self.VECTOR_DIM:
            features.append(0.0)
        
        return features[:self.VECTOR_DIM]
    
    def generate_signature(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None
    ) -> BinarySignature:
        """
        生成二进制签名
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制文件信息
            decomp_results: 反编译结果
            
        Returns:
            二进制签名对象
        """
        binary_name = os.path.basename(binary_path)
        
        # 计算标准哈希
        hashes = self._calculate_hashes(binary_path)
        
        # 计算模糊哈希
        ssdeep_hash = self._calculate_ssdeep(binary_path)
        tlsh_hash = self._calculate_tlsh(binary_path)
        
        # 计算导入哈希
        import_hash = self._calculate_import_hash(binary_info)
        
        # 计算节区哈希
        section_hash = self._calculate_section_hash(binary_info)
        
        # 提取函数签名
        function_signatures = self._extract_function_signatures(binary_info, decomp_results)
        
        # 生成语义向量
        semantic_vector = []
        if self.use_semantic and decomp_results:
            # 合合所有伪代码的特征向量
            all_pseudocode = ' '.join(r.get('pseudocode', '') for r in decomp_results)
            semantic_vector = self._generate_feature_vector(all_pseudocode)
        
        # 构建签名
        signature = BinarySignature(
            binary_path=binary_path,
            binary_name=binary_name,
            sha256=hashes['sha256'],
            sha1=hashes['sha1'],
            md5=hashes['md5'],
            ssdeep_hash=ssdeep_hash,
            tlsh_hash=tlsh_hash,
            import_hash=import_hash,
            section_hash=section_hash,
            function_count=len(function_signatures),
            function_signatures=function_signatures,
            semantic_vector=semantic_vector,
            metadata={
                'architecture': binary_info.get('arch', ''),
                'bits': binary_info.get('bits', 0),
                'format': binary_info.get('format', ''),
            }
        )
        
        logger.info(f"生成二进制签名: {binary_name}, SHA256: {hashes['sha256'][:16]}...")
        return signature
    
    def save_signature(self, signature: BinarySignature) -> Optional[int]:
        """
        保存签名到数据库
        
        Args:
            signature: 二进制签名
            
        Returns:
            签名记录 ID
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO binary_signatures (
                    binary_path, binary_name, sha256, sha1, md5,
                    ssdeep_hash, tlsh_hash, import_hash, section_hash,
                    function_count, function_signatures, semantic_vector,
                    created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                signature.binary_path,
                signature.binary_name,
                signature.sha256,
                signature.sha1,
                signature.md5,
                signature.ssdeep_hash,
                signature.tlsh_hash,
                signature.import_hash,
                signature.section_hash,
                signature.function_count,
                json.dumps(signature.function_signatures),
                json.dumps(signature.semantic_vector),
                signature.created_at,
                json.dumps(signature.metadata)
            ))
            
            conn.commit()
            sig_id = cursor.lastrowid
            
            # 保存函数签名
            for func_sig in signature.function_signatures:
                cursor.execute("""
                    INSERT INTO function_signatures (
                        signature_id, function_name, function_address,
                        function_size, function_hash, feature_vector
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    sig_id,
                    func_sig.get('name', ''),
                    func_sig.get('address', ''),
                    func_sig.get('size', 0),
                    func_sig.get('hash', ''),
                    json.dumps(func_sig.get('feature_vector', []))
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"签名已保存到数据库，ID: {sig_id}")
            return sig_id
            
        except Exception as e:
            logger.error(f"保存签名失败: {e}")
            return None
    
    def get_signature_by_sha256(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        通过 SHA256 查询签名
        
        Args:
            sha256: SHA256 哈希值
            
        Returns:
            签名记录字典
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM binary_signatures WHERE sha256 = ?", (sha256,))
            row = cursor.fetchone()
            
            if row:
                columns = [desc[0] for desc in cursor.description]
                result = dict(zip(columns, row))
                
                # 解析 JSON 字段
                for key in ['function_signatures', 'semantic_vector', 'metadata']:
                    if result.get(key):
                        try:
                            result[key] = json.loads(result[key])
                        except:
                            pass
                
                conn.close()
                return result
            
            conn.close()
            return None
            
        except Exception as e:
            logger.error(f"查询签名失败: {e}")
            return None


class HomologySearcher:
    """
    同源搜索器
    
    基于多维度签名进行同源性搜索，识别相似二进制。
    """
    
    # 相似度阈值
    SSDEEP_THRESHOLD = 70  # ssdeep 相似度阈值
    TLSH_THRESHOLD = 100   # TLSH 距离阈值（越小越相似）
    SEMANTIC_THRESHOLD = 0.8  # 语义向量相似度阈值
    
    def __init__(
        self,
        db_path: str = None,
        vuln_db_path: str = None
    ):
        """
        初始化同源搜索器
        
        Args:
            db_path: 签名数据库路径
            vuln_db_path: 漏洞数据库路径（用于关联威胁情报）
        """
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'data', 'signatures.db')
        self.vuln_db_path = vuln_db_path
        
        logger.info(f"同源搜索器初始化完成，数据库: {self.db_path}")
    
    def _compare_ssdeep(self, hash1: str, hash2: str) -> int:
        """
        比较 ssdeep 哈希相似度
        
        Args:
            hash1: 第一个 ssdeep 哈希
            hash2: 第二个 ssdeep 哈希
            
        Returns:
            相似度分数 (0-100)
        """
        if not SSDEEP_AVAILABLE or not hash1 or not hash2:
            return 0
        
        try:
            return ssdeep.compare(hash1, hash2)
        except Exception as e:
            logger.warning(f"比较 ssdeep 失败: {e}")
            return 0
    
    def _compare_tlsh(self, hash1: str, hash2: str) -> int:
        """
        比较 TLSH 哈希距离
        
        Args:
            hash1: 第一个 TLSH 哈希
            hash2: 第二个 TLSH 哈希
            
        Returns:
            TLSH 距离（越小越相似）
        """
        if not TLSH_AVAILABLE or not hash1 or not hash2:
            return -1
        
        try:
            return tlsh.diff(hash1, hash2)
        except Exception as e:
            logger.warning(f"比较 TLSH 失败: {e}")
            return -1
    
    def _compare_vectors(
        self,
        vec1: List[float],
        vec2: List[float]
    ) -> float:
        """
        比较向量余弦相似度
        
        Args:
            vec1: 第一个向量
            vec2: 第二个向量
            
        Returns:
            余弦相似度 (0-1)
        """
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        
        if NUMPY_AVAILABLE:
            try:
                v1 = np.array(vec1)
                v2 = np.array(vec2)
                
                dot_product = np.dot(v1, v2)
                norm1 = np.linalg.norm(v1)
                norm2 = np.linalg.norm(v2)
                
                if norm1 == 0 or norm2 == 0:
                    return 0.0
                
                return float(dot_product / (norm1 * norm2))
            except Exception as e:
                logger.warning(f"numpy 计算失败: {e}")
        
        # 手动计算
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = (sum(a * a for a in vec1)) ** 0.5
        norm2 = (sum(b * b for b in vec2)) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def search_by_ssdeep(
        self,
        ssdeep_hash: str,
        threshold: int = None,
        limit: int = 10
    ) -> List[HomologyMatch]:
        """
        通过 ssdeep 搜索相似二进制
        
        Args:
            ssdeep_hash: ssdeep 哈希值
            threshold: 相似度阈值
            limit: 返回结果数量限制
            
        Returns:
            同源匹配结果列表
        """
        if not ssdeep_hash:
            return []
        
        threshold = threshold or self.SSDEEP_THRESHOLD
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM binary_signatures WHERE ssdeep_hash IS NOT NULL AND ssdeep_hash != ''")
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                
                other_hash = record.get('ssdeep_hash', '')
                if other_hash:
                    similarity = self._compare_ssdeep(ssdeep_hash, other_hash)
                    
                    if similarity >= threshold:
                        match = HomologyMatch(
                            matched_binary=record.get('binary_name', ''),
                            matched_signature_id=record.get('id', 0),
                            similarity_score=float(similarity) / 100.0,
                            match_type='ssdeep',
                            malware_family=record.get('malware_family', ''),
                            threat_level=record.get('threat_level', ''),
                            confidence=float(similarity) / 100.0,
                            details={'ssdeep_similarity': similarity}
                        )
                        results.append(match)
            
            conn.close()
            
            # 按相似度排序
            results.sort(key=lambda x: x.similarity_score, reverse=True)
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"ssdeep 搜索失败: {e}")
            return []
    
    def search_by_tlsh(
        self,
        tlsh_hash: str,
        threshold: int = None,
        limit: int = 10
    ) -> List[HomologyMatch]:
        """
        通过 TLSH 搜索相似二进制
        
        Args:
            tlsh_hash: TLSH 哈希值
            threshold: 距离阈值（越小越相似）
            limit: 返回结果数量限制
            
        Returns:
            同源匹配结果列表
        """
        if not tlsh_hash:
            return []
        
        threshold = threshold or self.TLSH_THRESHOLD
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM binary_signatures WHERE tlsh_hash IS NOT NULL AND tlsh_hash != ''")
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                
                other_hash = record.get('tlsh_hash', '')
                if other_hash:
                    distance = self._compare_tlsh(tlsh_hash, other_hash)
                    
                    if distance >= 0 and distance <= threshold:
                        # 将距离转换为相似度分数（距离越小，分数越高）
                        similarity = 1.0 - (distance / 300.0)  # TLSH 最大距离约 300
                        
                        match = HomologyMatch(
                            matched_binary=record.get('binary_name', ''),
                            matched_signature_id=record.get('id', 0),
                            similarity_score=max(0.0, similarity),
                            match_type='tlsh',
                            malware_family=record.get('malware_family', ''),
                            threat_level=record.get('threat_level', ''),
                            confidence=max(0.0, similarity),
                            details={'tlsh_distance': distance}
                        )
                        results.append(match)
            
            conn.close()
            
            # 按距离排序（距离越小越相似）
            results.sort(key=lambda x: x.details.get('tlsh_distance', 300))
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"TLSH 搜索失败: {e}")
            return []
    
    def search_by_import_hash(
        self,
        import_hash: str,
        limit: int = 10
    ) -> List[HomologyMatch]:
        """
        通过导入哈希搜索
        
        Args:
            import_hash: 导入哈希值
            limit: 返回结果数量限制
            
        Returns:
            同源匹配结果列表
        """
        if not import_hash:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM binary_signatures WHERE import_hash = ?", (import_hash,))
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                
                match = HomologyMatch(
                    matched_binary=record.get('binary_name', ''),
                    matched_signature_id=record.get('id', 0),
                    similarity_score=1.0,  # 完全匹配
                    match_type='import_hash',
                    malware_family=record.get('malware_family', ''),
                    threat_level=record.get('threat_level', ''),
                    confidence=1.0,
                    details={'import_hash_match': True}
                )
                results.append(match)
            
            conn.close()
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"导入哈希搜索失败: {e}")
            return []
    
    def search_by_semantic_vector(
        self,
        semantic_vector: List[float],
        threshold: float = None,
        limit: int = 10
    ) -> List[HomologyMatch]:
        """
        通过语义向量搜索
        
        Args:
            semantic_vector: 语义向量
            threshold: 相似度阈值
            limit: 返回结果数量限制
            
        Returns:
            同源匹配结果列表
        """
        if not semantic_vector:
            return []
        
        threshold = threshold or self.SEMANTIC_THRESHOLD
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM binary_signatures WHERE semantic_vector IS NOT NULL AND semantic_vector != ''")
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                columns = [desc[0] for desc in cursor.description]
                record = dict(zip(columns, row))
                
                other_vector_str = record.get('semantic_vector', '')
                if other_vector_str:
                    try:
                        other_vector = json.loads(other_vector_str)
                        similarity = self._compare_vectors(semantic_vector, other_vector)
                        
                        if similarity >= threshold:
                            match = HomologyMatch(
                                matched_binary=record.get('binary_name', ''),
                                matched_signature_id=record.get('id', 0),
                                similarity_score=similarity,
                                match_type='semantic',
                                malware_family=record.get('malware_family', ''),
                                threat_level=record.get('threat_level', ''),
                                confidence=similarity,
                                details={'cosine_similarity': similarity}
                            )
                            results.append(match)
                    except:
                        pass
            
            conn.close()
            
            # 按相似度排序
            results.sort(key=lambda x: x.similarity_score, reverse=True)
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"语义向量搜索失败: {e}")
            return []
    
    def comprehensive_search(
        self,
        signature: BinarySignature,
        ssdeep_threshold: int = None,
        tlsh_threshold: int = None,
        semantic_threshold: float = None,
        limit: int = 10
    ) -> List[HomologyMatch]:
        """
        综合同源搜索
        
        Args:
            signature: 二进制签名
            ssdeep_threshold: ssdeep 阈值
            tlsh_threshold: TLSH 阈值
            semantic_threshold: 语义阈值
            limit: 返回结果数量限制
            
        Returns:
            同源匹配结果列表
        """
        all_matches = {}
        
        # ssdeep 搜索
        if signature.ssdeep_hash:
            ssdeep_matches = self.search_by_ssdeep(
                signature.ssdeep_hash,
                threshold=ssdeep_threshold,
                limit=limit * 2
            )
            for match in ssdeep_matches:
                key = match.matched_binary
                if key not in all_matches:
                    all_matches[key] = match
                else:
                    # 合合分数
                    all_matches[key].similarity_score = max(
                        all_matches[key].similarity_score,
                        match.similarity_score
                    )
                    all_matches[key].match_type += '+ssdeep'
        
        # TLSH 搜索
        if signature.tlsh_hash:
            tlsh_matches = self.search_by_tlsh(
                signature.tlsh_hash,
                threshold=tlsh_threshold,
                limit=limit * 2
            )
            for match in tlsh_matches:
                key = match.matched_binary
                if key not in all_matches:
                    all_matches[key] = match
                else:
                    all_matches[key].similarity_score = max(
                        all_matches[key].similarity_score,
                        match.similarity_score
                    )
                    all_matches[key].match_type += '+tlsh'
        
        # 导入哈希搜索
        if signature.import_hash:
            import_matches = self.search_by_import_hash(
                signature.import_hash,
                limit=limit * 2
            )
            for match in import_matches:
                key = match.matched_binary
                if key not in all_matches:
                    all_matches[key] = match
                else:
                    all_matches[key].similarity_score = max(
                        all_matches[key].similarity_score,
                        match.similarity_score
                    )
                    all_matches[key].match_type += '+import'
        
        # 语义向量搜索
        if signature.semantic_vector:
            semantic_matches = self.search_by_semantic_vector(
                signature.semantic_vector,
                threshold=semantic_threshold,
                limit=limit * 2
            )
            for match in semantic_matches:
                key = match.matched_binary
                if key not in all_matches:
                    all_matches[key] = match
                else:
                    all_matches[key].similarity_score = max(
                        all_matches[key].similarity_score,
                        match.similarity_score
                    )
                    all_matches[key].match_type += '+semantic'
        
        # 按相似度排序
        results = sorted(
            all_matches.values(),
            key=lambda x: x.similarity_score,
            reverse=True
        )
        
        logger.info(f"综合同源搜索完成，找到 {len(results)} 个匹配")
        return results[:limit]
    
    def update_threat_intel(
        self,
        signature_id: int,
        malware_family: str,
        threat_level: str
    ) -> bool:
        """
        更新签名的威胁情报信息
        
        Args:
            signature_id: 签名 ID
            malware_family: 恶意软件家族
            threat_level: 威胁等级
            
        Returns:
            是否成功
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE binary_signatures
                SET malware_family = ?, threat_level = ?
                WHERE id = ?
            """, (malware_family, threat_level, signature_id))
            
            conn.commit()
            conn.close()
            
            logger.info(f"威胁情报已更新: ID={signature_id}, family={malware_family}, level={threat_level}")
            return True
            
        except Exception as e:
            logger.error(f"更新威胁情报失败: {e}")
            return False
    
    def get_search_summary(
        self,
        matches: List[HomologyMatch]
    ) -> Dict[str, Any]:
        """
        获取搜索结果摘要
        
        Args:
            matches: 匹配结果列表
            
        Returns:
            摘要信息字典
        """
        summary = {
            'total_matches': len(matches),
            'high_similarity_count': 0,
            'malware_families': [],
            'threat_levels': {},
            'match_types': {},
            'average_similarity': 0.0
        }
        
        if not matches:
            return summary
        
        total_similarity = 0.0
        families = set()
        
        for match in matches:
            total_similarity += match.similarity_score
            
            if match.similarity_score >= 0.8:
                summary['high_similarity_count'] += 1
            
            if match.malware_family:
                families.add(match.malware_family)
            
            level = match.threat_level or 'unknown'
            if level not in summary['threat_levels']:
                summary['threat_levels'][level] = 0
            summary['threat_levels'][level] += 1
            
            match_type = match.match_type
            if match_type not in summary['match_types']:
                summary['match_types'][match_type] = 0
            summary['match_types'][match_type] += 1
        
        summary['malware_families'] = list(families)
        summary['average_similarity'] = total_similarity / len(matches)
        
        return summary


def generate_binary_signature(
    binary_path: str,
    binary_info: Dict[str, Any],
    decomp_results: List[Dict[str, Any]] = None,
    save_to_db: bool = True
) -> BinarySignature:
    """
    生成二进制签名的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        binary_info: 二进制文件信息
        decomp_results: 反编译结果
        save_to_db: 是否保存到数据库
        
    Returns:
        二进制签名对象
    """
    signer = BinarySigner()
    signature = signer.generate_signature(binary_path, binary_info, decomp_results)
    
    if save_to_db:
        signer.save_signature(signature)
    
    return signature


def search_homology(
    signature: BinarySignature,
    limit: int = 10
) -> List[HomologyMatch]:
    """
    同源搜索的便捷函数
    
    Args:
        signature: 二进制签名
        limit: 返回结果数量限制
        
    Returns:
        同源匹配结果列表
    """
    searcher = HomologySearcher()
    return searcher.comprehensive_search(signature, limit=limit)