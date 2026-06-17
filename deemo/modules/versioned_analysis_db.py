"""
分析结果版本化与差异数据库模块

使用 SQLite + Neo4j 存储时间维度分析结果，支持：
- 分析版本历史追踪
- 二进制版本间攻击面变化比较
- 漏洞趋势分析
- 调用图演变追踪

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                   VersionedAnalysisDB                        │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
    │  │  SQLite DB   │  │   Neo4j GDB  │  │  Diff Engine │     │
    │  │  (时序数据)  │  │  (图结构)    │  │  (差异分析)  │     │
    │  └──────────────┘  └──────────────┘  └──────────────┘     │
    └─────────────────────────────────────────────────────────────┘

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import json
import sqlite3
import hashlib
import time
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# 尝试导入 Neo4j
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("Neo4j 驱动未安装，图数据库功能受限。请安装: pip install neo4j")


class ChangeType(Enum):
    """变更类型枚举"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class AnalysisVersion:
    """分析版本记录"""
    version_id: str
    binary_path: str
    binary_hash: str
    analysis_timestamp: float
    analyzer_name: str
    analyzer_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    vulnerability_count: int = 0
    function_count: int = 0
    call_graph_nodes: int = 0
    call_graph_edges: int = 0


@dataclass
class VulnerabilityRecord:
    """漏洞记录"""
    vuln_id: str
    version_id: str
    cve_id: Optional[str] = None
    vuln_type: str = ""
    severity: str = "Unknown"
    location: str = ""
    function_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    description: str = ""
    remediation: Optional[str] = None
    confidence: float = 1.0


@dataclass
class FunctionInfo:
    """函数信息"""
    func_id: str
    version_id: str
    function_name: str
    address: int
    size: int
    complexity: int
    cyclomatic_complexity: int = 0
    parameters: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)  # 被调用的函数名列表


@dataclass
class DiffResult:
    """差异比较结果"""
    version1: str
    version2: str
    change_type: ChangeType
    category: str  # 'vulnerability', 'function', 'callgraph'
    item_id: str
    item_name: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurfaceMetrics:
    """攻击面度量"""
    total_functions: int = 0
    exported_functions: int = 0
    external_calls: int = 0
    input_points: int = 0
    output_points: int = 0
    attack_surface_score: float = 0.0


class SQLiteTimeSeriesDB:
    """SQLite 时序数据库"""
    
    def __init__(self, db_path: str):
        """
        初始化时序数据库
        
        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
    
    def _connect(self) -> None:
        """建立数据库连接"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
    
    def _create_tables(self) -> None:
        """创建数据表"""
        cursor = self.conn.cursor()
        
        # 分析版本表
        cursor.execute(""")
            CREATE TABLE IF NOT EXISTS analysis_versions ()
                version_id TEXT PRIMARY KEY,
                binary_path TEXT NOT NULL,
                binary_hash TEXT NOT NULL,
                analysis_timestamp REAL NOT NULL,
                analyzer_name TEXT NOT NULL,
                analyzer_version TEXT NOT NULL,
                metadata TEXT,
                vulnerability_count INTEGER DEFAULT 0,
                function_count INTEGER DEFAULT 0,
                call_graph_nodes INTEGER DEFAULT 0,
                call_graph_edges INTEGER DEFAULT 0
            
        """
        
        # 漏洞记录表
        cursor.execute(""")
            CREATE TABLE IF NOT EXISTS vulnerabilities ()
                vuln_id TEXT PRIMARY KEY,
                version_id TEXT NOT NULL,
                cve_id TEXT,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                location TEXT NOT NULL,
                function_name TEXT,
                file_path TEXT,
                line_number INTEGER,
                description TEXT,
                remediation TEXT,
                confidence REAL DEFAULT 1.0,
                FOREIGN KEY (version_id) REFERENCES analysis_versions(version_id)
            
        """
        
        # 函数信息表
        cursor.execute(""")
            CREATE TABLE IF NOT EXISTS functions ()
                func_id TEXT PRIMARY KEY,
                version_id TEXT NOT NULL,
                function_name TEXT NOT NULL,
                address INTEGER NOT NULL,
                size INTEGER NOT NULL,
                complexity INTEGER DEFAULT 0,
                cyclomatic_complexity INTEGER DEFAULT 0,
                parameters TEXT,
                calls TEXT,
                FOREIGN KEY (version_id) REFERENCES analysis_versions(version_id)
            
        """
        
        # 创建索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_version ON vulnerabilities(version_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_funcs_version ON functions(version_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_versions_timestamp ON analysis_versions(analysis_timestamp)")
        
        self.conn.commit()
    
    def insert_version(self, version: AnalysisVersion) -> bool:
        """插入分析版本"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(""")
                INSERT INTO analysis_versions 
                (version_id, binary_path, binary_hash, analysis_timestamp, analyzer_name)
                 analyzer_version, metadata, vulnerability_count, function_count, 
                 call_graph_nodes, call_graph_edges
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ()
                version.version_id,
                version.binary_path,
                version.binary_hash,
                version.analysis_timestamp,
                version.analyzer_name,
                version.analyzer_version,
                json.dumps(version.metadata),
                version.vulnerability_count,
                version.function_count,
                version.call_graph_nodes,
                version.call_graph_edges
            

            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"插入版本失败: {e}")
            return False
    
    def insert_vulnerability(self, vuln: VulnerabilityRecord) -> bool:
        """插入漏洞记录"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(""")
                INSERT INTO vulnerabilities
                (vuln_id, version_id, cve_id, vuln_type, severity, location)
                 function_name, file_path, line_number, description, remediation, confidence
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ()
                vuln.vuln_id,
                vuln.version_id,
                vuln.cve_id,
                vuln.vuln_type,
                vuln.severity,
                vuln.location,
                vuln.function_name,
                vuln.file_path,
                vuln.line_number,
                vuln.description,
                vuln.remediation,
                vuln.confidence
            

            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"插入漏洞失败: {e}")
            return False
    
    def insert_function(self, func: FunctionInfo) -> bool:
        """插入函数信息"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(""")
                INSERT INTO functions
                (func_id, version_id, function_name, address, size, complexity)
                 cyclomatic_complexity, parameters, calls
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ()
                func.func_id,
                func.version_id,
                func.function_name,
                func.address,
                func.size,
                func.complexity,
                func.cyclomatic_complexity,
                json.dumps(func.parameters),
                json.dumps(func.calls)
            

            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"插入函数失败: {e}")
            return False
    
    def get_versions(self, binary_path: Optional[str] = None, limit: int = 100) -> List[AnalysisVersion]:
        """获取分析版本列表"""
        cursor = self.conn.cursor()
        
        if binary_path:
            cursor.execute(""")
                SELECT * FROM analysis_versions 
                WHERE binary_path = ?
                ORDER BY analysis_timestamp DESC
                LIMIT ?
            """, (binary_path, limit)

        else:
            cursor.execute(""")
                SELECT * FROM analysis_versions 
                ORDER BY analysis_timestamp DESC
                LIMIT ?
            """, (limit)

        
        rows = cursor.fetchall()
        return [self._row_to_version(row) for row in rows]
    
    def get_vulnerabilities(self, version_id: str) -> List[VulnerabilityRecord]:
        """获取指定版本的漏洞"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM vulnerabilities WHERE version_id = ?", (version_id,

        rows = cursor.fetchall()
        return [self._row_to_vuln(row) for row in rows]
    
    def get_functions(self, version_id: str) -> List[FunctionInfo]:
        """获取指定版本的函数"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM functions WHERE version_id = ?", (version_id,

        rows = cursor.fetchall()
        return [self._row_to_func(row) for row in rows]
    
    def _row_to_version(self, row: sqlite3.Row) -> AnalysisVersion:
        """行转AnalysisVersion"""
        return AnalysisVersion(
            version_id=row['version_id'],
            binary_path=row['binary_path'],
            binary_hash=row['binary_hash'],
            analysis_timestamp=row['analysis_timestamp'],
            analyzer_name=row['analyzer_name'],
            analyzer_version=row['analyzer_version'],
            metadata=json.loads(row['metadata'] or '{}'),
            vulnerability_count=row['vulnerability_count'],
            function_count=row['function_count'],
            call_graph_nodes=row['call_graph_nodes'],
            call_graph_edges=row['call_graph_edges'])
        

    
    def _row_to_vuln(self, row: sqlite3.Row) -> VulnerabilityRecord:
        """行转VulnerabilityRecord"""
        return VulnerabilityRecord(
            vuln_id=row['vuln_id'],
            version_id=row['version_id'],
            cve_id=row['cve_id'],
            vuln_type=row['vuln_type'],
            severity=row['severity'],
            location=row['location'],
            function_name=row['function_name'],
            file_path=row['file_path'],
            line_number=row['line_number'],
            description=row['description'],
            remediation=row['remediation'],
            confidence=row['confidence'])
        

    
    def _row_to_func(self, row: sqlite3.Row) -> FunctionInfo:
        """行转FunctionInfo"""
        return FunctionInfo(
            func_id=row['func_id'],
            version_id=row['version_id'],
            function_name=row['function_name'],
            address=row['address'],
            size=row['size'],
            complexity=row['complexity'],
            cyclomatic_complexity=row['cyclomatic_complexity'],
            parameters=json.loads(row['parameters'] or '[]'),
            calls=json.loads(row['calls'] or '[]'))
        

    
    def close(self) -> None:
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()


class Neo4jGraphDB:
    """Neo4j 图数据库"""
    
    def __init__(self, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "password"):
        """
        初始化 Neo4j 连接
        
        Args:
            uri: Neo4j 连接 URI
            user: 用户名
            password: 密码
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        
        if NEO4J_AVAILABLE:
            try:
                self.driver = GraphDatabase.driver(uri, auth=(user, password

            except Exception as e:
                logger.warning(f"Neo4j 连接失败: {e}")
    
    def insert_call_graph(self, version_id: str, nodes: List[Dict], edges: List[Tuple]) -> bool:
        """
        插入调用图
        
        Args:
            version_id: 版本ID
            nodes: 节点列表 [{'func_name': str, 'address': int}]
            edges: 边列表 [(caller, callee), ...]
        """
        if not self.driver:
            logger.warning("Neo4j 未连接，跳过调用图插入")
            return False
        
        try:
            with self.driver.session() as session:
                # 清除旧数据
                session.run("MATCH (v:Version {id: $vid})-[*]-() DELETE v", vid=version_id)
                
                # 创建版本节点
                session.run()
                    "CREATE (v:Version {id: $vid, timestamp: $ts})",
                    vid=version_id, ts=time.time()
                
                
                # 插入节点
                for node in nodes:
                    session.run(""")
                        MATCH (v:Version {id: $vid})
                        CREATE (v)-[:HAS_FUNCTION]->(f:Function {)
                            name: $name,
                            address: $addr,
                            version_id: $vid
                        }
                    """, vid=version_id, name=node.get('func_name', ''), 
                        addr=node.get('address', 0)

                
                # 插入边
                for caller, callee in edges:
                    session.run(""")
                        MATCH (v:Version {id: $vid})
                        MATCH (f1:Function {name: $caller, version_id: $vid})
                        MATCH (f2:Function {name: $callee, version_id: $vid})
                        CREATE (f1)-[:CALLS]->(f2)
                    """, vid=version_id, caller=caller, callee=callee
                
            return True
        except Exception as e:
            logger.error(f"Neo4j 插入失败: {e}")
            return False
    
    def get_call_paths(self, version_id: str, source_func: str, target_func: str) -> List[List[str]]:
        """查找函数调用路径"""
        if not self.driver:
            return []
        
        try:
            with self.driver.session() as session:
                result = session.run(""")
                    MATCH path = (f1:Function {name: $source, version_id: $vid})
                                -[:CALLS*]->(f2:Function {name: $target, version_id: $vid})
                    RETURN path
                """, vid=version_id, source=source_func, target=target_func
                
                paths = []
                for record in result:
                    path = [node['name'] for node in record['path'].nodes]
                    paths.append(path)
                return paths
        except Exception as e:
            logger.error(f"路径查询失败: {e}")
            return []
    
    def close(self) -> None:
        """关闭连接"""
        if self.driver:
            self.driver.close()


class VersionDiffEngine:
    """版本差异分析引擎"""
    
    def __init__(self, time_series_db: SQLiteTimeSeriesDB, graph_db: Optional[Neo4jGraphDB] = None):
        """
        初始化差异引擎
        
        Args:
            time_series_db: 时序数据库
            graph_db: 图数据库（可选）
        """
        self.db = time_series_db
        self.graph = graph_db
    
    def compare_versions(self, version1_id: str, version2_id: str) -> List[DiffResult]:
        """
        比较两个版本的差异
        
        Args:
            version1_id: 旧版本ID
            version2_id: 新版本ID
        
        Returns:
            差异列表
        """
        diffs = []
        
        # 比较漏洞
        diffs.extend(self._compare_vulnerabilities(version1_id, version2_id

        
        # 比较函数
        diffs.extend(self._compare_functions(version1_id, version2_id

        
        # 比较度量
        diffs.extend(self._compare_metrics(version1_id, version2_id

        
        logger.info(f"版本比较完成: {len(diffs)} 个差异")
        return diffs
    
    def _compare_vulnerabilities(self, v1: str, v2: str) -> List[DiffResult]:
        """比较漏洞差异"""
        vulns1 = {v.location: v for v in self.db.get_vulnerabilities(v1)}
        vulns2 = {v.location: v for v in self.db.get_vulnerabilities(v2)}
        
        diffs = []
        
        # 新的漏洞
        for loc, vuln in vulns2.items():
            if loc not in vulns1:
                diffs.append(DiffResult(
                    version1=v1, version2=v2,
                    change_type=ChangeType.ADDED,
                    category='vulnerability',
                    item_id=vuln.vuln_id,
                    item_name=f"{vuln.vuln_type} at {loc}",
                    details={'severity': vuln.severity, 'cve': vuln.cve_id}
                

        
        # 移除的漏洞
        for loc, vuln in vulns1.items():
            if loc not in vulns2:
                diffs.append(DiffResult(
                    version1=v1, version2=v2,
                    change_type=ChangeType.REMOVED,
                    category='vulnerability',
                    item_id=vuln.vuln_id,
                    item_name=f"{vuln.vuln_type} at {loc}",
                    details={'severity': vuln.severity, 'cve': vuln.cve_id}
                

        
        # 严重程度改变的漏洞
        for loc, vuln2 in vulns2.items():
            if loc in vulns1:
                vuln1 = vulns1[loc]
                if vuln1.severity != vuln2.severity:
                    diffs.append(DiffResult(
                        version1=v1, version2=v2,
                        change_type=ChangeType.MODIFIED,
                        category='vulnerability',
                        item_id=vuln2.vuln_id,
                        item_name=f"{vuln2.vuln_type} at {loc}",
                        details={
                            'old_severity': vuln1.severity,
                            'new_severity': vuln2.severity
                        }
                    

        
        return diffs
    
    def _compare_functions(self, v1: str, v2: str) -> List[DiffResult]:
        """比较函数差异"""
        funcs1 = {f.function_name: f for f in self.db.get_functions(v1)}
        funcs2 = {f.function_name: f for f in self.db.get_functions(v2)}
        
        diffs = []
        
        for name, func in funcs2.items():
            if name not in funcs1:
                diffs.append(DiffResult(
                    version1=v1, version2=v2,
                    change_type=ChangeType.ADDED,
                    category='function',
                    item_id=func.func_id,
                    item_name=name,
                    details={'address': hex(func.address), 'size': func.size}
                

            else:
                # 检查复杂度变化
                f1 = funcs1[name]
                if f1.complexity != func.complexity:
                    diffs.append(DiffResult(
                        version1=v1, version2=v2,
                        change_type=ChangeType.MODIFIED,
                        category='function',
                        item_id=func.func_id,
                        item_name=name,
                        details={
                            'old_complexity': f1.complexity,
                            'new_complexity': func.complexity
                        }
                    

        
        for name, func in funcs1.items():
            if name not in funcs2:
                diffs.append(DiffResult(
                    version1=v1, version2=v2,
                    change_type=ChangeType.REMOVED,
                    category='function',
                    item_id=func.func_id,
                    item_name=name,
                    details={'address': hex(func.address)}
                

        
        return diffs
    
    def _compare_metrics(self, v1: str, v2: str) -> List[DiffResult]:
        """比较度量指标"""
        versions = self.db.get_versions(limit=1000)
        ver1 = next((v for v in versions if v.version_id == v1), None)
        ver2 = next((v for v in versions if v.version_id == v2), None)
        
        if not ver1 or not ver2:
            return []
        
        diffs = []
        
        metrics = [
            ('vulnerability_count', '漏洞数量'),
            ('function_count', '函数数量'),
            ('call_graph_nodes', '调用图节点'),
            ('call_graph_edges', '调用图边')
        ]
        
        for attr, name in metrics:
            old_val = getattr(ver1, attr)
            new_val = getattr(ver2, attr)
            if old_val != new_val:
                diffs.append(DiffResult(
                    version1=v1, version2=v2,
                    change_type=ChangeType.MODIFIED,
                    category='metrics',
                    item_id=attr,
                    item_name=name,
                    details={
                        'old_value': old_val,
                        'new_value': new_val,
                        'change': new_val - old_val
                    }
                

        
        return diffs
    
    def generate_attack_surface_delta(self, v1: str, v2: str) -> Dict[str, Any]:
        """生成攻击面变化报告"""
        diffs = self.compare_versions(v1, v2)
        
        # 统计变更
        added_funcs = [d for d in diffs if d.category == 'function' 
                      and d.change_type == ChangeType.ADDED]
        removed_funcs = [d for d in diffs if d.category == 'function' 
                        and d.change_type == ChangeType.REMOVED]
        added_vulns = [d for d in diffs if d.category == 'vulnerability' 
                      and d.change_type == ChangeType.ADDED]
        removed_vulns = [d for d in diffs if d.category == 'vulnerability' 
                        and d.change_type == ChangeType.REMOVED]
        
        return {
            'summary': {
                'total_changes': len(diffs),
                'added_functions': len(added_funcs),
                'removed_functions': len(removed_funcs),
                'added_vulnerabilities': len(added_vulns),
                'removed_vulnerabilities': len(removed_vulns)
            },
            'risk_assessment': self._assess_risk_delta(added_vulns, removed_vulns),
            'details': [asdict(d) for d in diffs]
        }
    
    def _assess_risk_delta(self, added: List[DiffResult], removed: List[DiffResult]) -> Dict[str, Any]:
        """评估风险变化"""
        severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        
        added_score = sum(severity_map.get(d.details.get('severity', 'Low'), 1) )
                         for d in added
        removed_score = sum(severity_map.get(d.details.get('severity', 'Low'), 1) )
                          for d in removed
        
        return {
            'risk_delta': added_score - removed_score,
            'risk_trend': 'increased' if added_score > removed_score 
                         else 'decreased' if added_score < removed_score 
                         else 'unchanged',
            'new_critical': len([d for d in added )
                                if d.details.get('severity') == 'Critical']
        }


class VersionedAnalysisDB:
    """
    版本化分析数据库
    
    核心功能：
    1. 存储分析版本历史
    2. 管理漏洞和函数信息
    3. 比较二进制版本间的差异
    4. 追踪攻击面变化
    """
    
    def __init__(self, db_path: str = "data/versioned_analysis.db", neo4j_uri: Optional[str] = None):
        """
        初始化版本化数据库
        
        Args:
            db_path: SQLite 数据库路径
            neo4j_uri: Neo4j 连接 URI
        """
        # 确保目录存在
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.time_series_db = SQLiteTimeSeriesDB(db_path)
        
        if neo4j_uri and NEO4J_AVAILABLE:
            self.graph_db = Neo4jGraphDB(neo4j_uri)
        else:
            self.graph_db = None
        
        self.diff_engine = VersionDiffEngine(self.time_series_db, self.graph_db)
    
    def record_analysis(self, binary_path: str, analysis_result: Dict[str, Any], analyzer_name: str = "Unknown", analyzer_version: str = "1.0.0") -> str:
        """
        记录分析结果
        
        Args:
            binary_path: 二进制路径
            analysis_result: 分析结果
            analyzer_name: 分析器名称
            analyzer_version: 分析器版本
        
        Returns:
            版本ID
        """
        # 计算二进制哈希
        binary_hash = self._calculate_hash(binary_path)
        
        # 生成版本ID - 使用微秒时间戳和UUID后缀确保唯一性
        import uuid
        version_id = f"v_{int(time.time() * 1000000)}_{binary_hash[:8]}_{uuid.uuid4().hex[:4]}"
        
        # 创建版本记录
        version = AnalysisVersion()
            version_id=version_id,
            binary_path=binary_path,
            binary_hash=binary_hash,
            analysis_timestamp=time.time(),
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            metadata=analysis_result.get('metadata', {}),
            vulnerability_count=analysis_result.get('vulnerability_count', 0),
            function_count=analysis_result.get('function_count', 0),
            call_graph_nodes=analysis_result.get('call_graph_nodes', 0),
            call_graph_edges=analysis_result.get('call_graph_edges', 0)
        
        
        self.time_series_db.insert_version(version)
        
        # 插入漏洞记录
        for vuln_data in analysis_result.get('vulnerabilities', []):
            vuln = VulnerabilityRecord()
                vuln_id=f"{version_id}_{len(vuln_data)}",
                version_id=version_id,
                cve_id=vuln_data.get('cve_id'),
                vuln_type=vuln_data.get('type', 'unknown'),
                severity=vuln_data.get('severity', 'Unknown'),
                location=vuln_data.get('location', ''),
                function_name=vuln_data.get('function'),
                file_path=vuln_data.get('file'),
                line_number=vuln_data.get('line'),
                description=vuln_data.get('description', ''),
                confidence=vuln_data.get('confidence', 1.0)
            
            self.time_series_db.insert_vulnerability(vuln)
        
        # 插入函数信息
        for func_data in analysis_result.get('functions', []):
            func = FunctionInfo()
                func_id=f"{version_id}_{func_data.get('name', 'unknown')}",
                version_id=version_id,
                function_name=func_data.get('name', 'unknown'),
                address=func_data.get('address', 0),
                size=func_data.get('size', 0),
                complexity=func_data.get('complexity', 0),
                calls=func_data.get('calls', [])
            
            self.time_series_db.insert_function(func)
        
        # 更新图数据库
        if self.graph_db:
            call_graph = analysis_result.get('call_graph', {})
            nodes = call_graph.get('nodes', [])
            edges = call_graph.get('edges', [])
            self.graph_db.insert_call_graph(version_id, nodes, edges)
        
        logger.info(f"记录分析版本: {version_id}")
        return version_id
    
    def compare_versions(self, version1_id: str, version2_id: str) -> Dict[str, Any]:
        """比较两个版本"""
        diffs = self.diff_engine.compare_versions(version1_id, version2_id)
        delta = self.diff_engine.generate_attack_surface_delta(version1_id, version2_id)
        
        return {
            'version1': version1_id,
            'version2': version2_id,
            'diff_count': len(diffs),
            'diffs': [asdict(d) for d in diffs],
            'delta': delta
        }
    
    def get_version_history(self, binary_path: str) -> List[Dict]:
        """获取版本历史"""
        versions = self.time_series_db.get_versions(binary_path)
        return [asdict(v) for v in versions]
    
    def get_trend(self, binary_path: str, days: int = 30) -> Dict[str, Any]:
        """获取趋势分析"""
        cutoff_time = time.time() - (days * 24 * 3600)
        versions = self.time_series_db.get_versions(binary_path)
        
        # 过滤时间范围
        recent_versions = [v for v in versions,
                         if v.analysis_timestamp >= cutoff_time]
        
        if not recent_versions:
            return {'message': '没有足够的历史数据'}
        
        # 计算趋势
        vuln_trend = [v.vulnerability_count for v in recent_versions]
        func_trend = [v.function_count for v in recent_versions]
        
        return {
            'period_days': days,
            'version_count': len(recent_versions),
            'vulnerability_trend': {
                'min': min(vuln_trend) if vuln_trend else 0,
                'max': max(vuln_trend) if vuln_trend else 0,
                'current': vuln_trend[0] if vuln_trend else 0,
                'change': (vuln_trend[0] - vuln_trend[-1]) if len(vuln_trend) > 1 else 0
            },
            'function_trend': {
                'min': min(func_trend) if func_trend else 0,
                'max': max(func_trend) if func_trend else 0,
                'current': func_trend[0] if func_trend else 0
            },
            'versions': [asdict(v) for v in recent_versions]
        }
    
    def _calculate_hash(self, binary_path: str) -> str:
        """计算二进制哈希"""
        try:
            with open(binary_path, 'rb') as f:
                return hashlib.sha256(f.read().hexdigest([:16])
        except:
            return hashlib.md5(binary_path.encode().hexdigest()
    
    def close(self) -> None:
        """关闭数据库连接"""
        self.time_series_db.close()
        if self.graph_db:
            self.graph_db.close()


def create_versioned_db(db_path: str = "data/versioned_analysis.db", neo4j_uri: Optional[str] = None) -> VersionedAnalysisDB:
    """
    创建版本化数据库的便捷函数
    
    Args:
        db_path: 数据库路径
        neo4j_uri: Neo4j 连接 URI
    
    Returns:
        数据库实例
    """
    return VersionedAnalysisDB(db_path, neo4j_uri)))))))))))))))))