import sqlite3
import os
import json
import logging
import hashlib
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import uuid

from config import Config, ensure_directories

logger = logging.getLogger(__name__)



_LEGACY_MODE = False  # 保留

VECTOR_STORAGE_AVAILABLE = False
try:
    import numpy as np
    VECTOR_STORAGE_AVAILABLE = True
except ImportError:
    pass

FAISS_AVAILABLE = False
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    pass

PSYCOPG2_AVAILABLE = False
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    try:
        import psycopg2 as psycopg2
        PSYCOPG2_AVAILABLE = True
    except ImportError:
        pass


class VulnerabilityDatabaseCore:
    """
    本地漏洞数据库——核心CRUD与生命周期管理

    功能:
    1. 存储成功的漏洞分析结果和利用脚本
        4. 向量存储和语义搜索（可选 FAISS 加速）
        5. 外部漏洞数据库集成（CVE/Exploit-DB）
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_type TEXT NOT NULL,
        binary_name TEXT,
        binary_format TEXT,
        architecture TEXT,
        bits INTEGER,
        function_name TEXT,
        pseudocode_hash TEXT,
        pseudocode_snippet TEXT,
        exploit_script TEXT,
        dangerous_functions TEXT,
        checksec TEXT,
        symbols TEXT,
        severity TEXT,
        description TEXT,
        notes TEXT,
        call_graph_summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(vulnerability_type);
    CREATE INDEX IF NOT EXISTS idx_binary_format ON vulnerabilities(binary_format);
    CREATE INDEX IF NOT EXISTS idx_architecture ON vulnerabilities(architecture);
    CREATE INDEX IF NOT EXISTS idx_function_name ON vulnerabilities(function_name);
    CREATE INDEX IF NOT EXISTS idx_pseudocode_hash ON vulnerabilities(pseudocode_hash);

    CREATE TABLE IF NOT EXISTS code_embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vuln_id INTEGER,
        embedding TEXT,
        model_name TEXT,
        vector_dim INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    );

    CREATE INDEX IF NOT EXISTS idx_embedding_vuln ON code_embeddings(vuln_id);

    CREATE TABLE IF NOT EXISTS external_cve_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE,
        binary_hash TEXT,
        binary_name TEXT,
        cve_data TEXT,
        source TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_cve_id ON external_cve_cache(cve_id);
    CREATE INDEX IF NOT EXISTS idx_cve_binary ON external_cve_cache(binary_hash);
    """

    POSTGRES_SCHEMA = """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id SERIAL PRIMARY KEY,
        vulnerability_type TEXT NOT NULL,
        binary_name TEXT,
        binary_format TEXT,
        architecture TEXT,
        bits INTEGER,
        function_name TEXT,
        pseudocode_hash TEXT,
        pseudocode_snippet TEXT,
        exploit_script TEXT,
        dangerous_functions TEXT,
        checksec TEXT,
        symbols TEXT,
        severity TEXT,
        description TEXT,
        notes TEXT,
        call_graph_summary TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(vulnerability_type);
    CREATE INDEX IF NOT EXISTS idx_binary_format ON vulnerabilities(binary_format);
    CREATE INDEX IF NOT EXISTS idx_architecture ON vulnerabilities(architecture);
    CREATE INDEX IF NOT EXISTS idx_function_name ON vulnerabilities(function_name);
    CREATE INDEX IF NOT EXISTS idx_pseudocode_hash ON vulnerabilities(pseudocode_hash);

    CREATE TABLE IF NOT EXISTS code_embeddings (
        id SERIAL PRIMARY KEY,
        vuln_id INTEGER,
        embedding TEXT,
        model_name TEXT,
        vector_dim INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    );

    CREATE INDEX IF NOT EXISTS idx_embedding_vuln ON code_embeddings(vuln_id);

    CREATE TABLE IF NOT EXISTS external_cve_cache (
        id SERIAL PRIMARY KEY,
        cve_id TEXT UNIQUE,
        binary_hash TEXT,
        binary_name TEXT,
        cve_data TEXT,
        source TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_cve_id ON external_cve_cache(cve_id);
    CREATE INDEX IF NOT EXISTS idx_cve_binary ON external_cve_cache(binary_hash);
    """

    DANGEROUS_FUNCTION_COMBOS = {
        ('gets', 'strcpy'): {'score': 100, 'note': '经典缓冲区溢出组合'},
        ('scanf', '%s'): {'score': 95, 'note': 'scanf 无边界读取'},
        ('read', 'strcpy'): {'score': 90, 'note': 'read + strcpy 组合'},
        ('sprintf', 'strcat'): {'score': 85, 'note': '格式化字符串溢出'},
        ('gets', 'memcpy'): {'score': 80, 'note': 'gets + memcpy'},
        ('strcpy', 'strcat'): {'score': 75, 'note': '字符串操作组合'},
        ('system', 'gets'): {'score': 95, 'note': '直接命令执行风险'},
        ('popen', 'sprintf'): {'score': 90, 'note': '命令注入风险'},
        ('malloc', 'memcpy'): {'score': 60, 'note': '堆溢出风险'},
        ('free', 'malloc'): {'score': 50, 'note': 'UAF 风险'},
    }

# legacy scoring (pre-v2.1)
    # def _legacy_danger_score(funcs):
    #     score_map = {'gets': 30, 'strcpy': 20, 'system': 40}
    #     raw = sum(score_map.get(f, 5) for f in funcs)
    #     return min(raw, 150)
# end legacy

    def __init__(self, db_path: str = None):
        """
        初始化漏洞数据库连接与表结构

        Args:
            db_path: 数据库路径
        """
        self.db_type = Config.DB_TYPE
        self.db_path = db_path
        self.connection = None

        logger.info(f"数据库类型: {self.db_type}")

        if self.db_type == 'postgres':
            logger.info(f"尝试连接 PostgreSQL: {Config.POSTGRES_HOST}:{Config.POSTGRES_PORT}/{Config.POSTGRES_DB}")
            if not Config.POSTGRES_PASSWORD:
                logger.warning("POSTGRES_PASSWORD 未设置，PostgreSQL 连接可能失败")
            self._init_postgres()
        else:
            if db_path is None:
                db_path = Config.DB_PATH
            self.db_path = db_path
            logger.info(f"使用 SQLite 数据库: {self.db_path}")
            self._ensure_db_directory()
            self._init_db()

    def _ensure_db_directory(self):
        """
        确保数据库目录存在
        """
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
                logger.info(f"创建数据库目录: {db_dir}")
            except Exception as e:
                logger.error(f"创建数据库目录失败: {e}")

    def _init_db(self):
        """
        初始化 SQLite 数据库连接和表结构
        """
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            cursor = self.connection.cursor()
            cursor.executescript(self.SCHEMA)
            self.connection.commit()
            logger.info(f"漏洞数据库初始化成功: {self.db_path}")
        except Exception as e:
            logger.error(f"初始化 SQLite 数据库失败: {e}")
            self.connection = None

    def _init_postgres(self):
        """
        初始化 PostgreSQL 数据库连接和表结构
        如果连接失败，自动回退到 SQLite
        """
        if not PSYCOPG2_AVAILABLE:
            logger.warning("psycopg2 未安装，无法连接 PostgreSQL")
            logger.warning("正在回退到 SQLite 数据库...")
            self.db_type = 'sqlite'
            if self.db_path is None:
                self.db_path = Config.DB_PATH
            logger.info(f"使用 SQLite 数据库: {self.db_path}")
            self._ensure_db_directory()
            self._init_db()
            return

        try:
            connection_params = {
                'host': Config.POSTGRES_HOST,
                'port': Config.POSTGRES_PORT,
                'user': Config.POSTGRES_USER,
                'dbname': Config.POSTGRES_DB,
            }
            if Config.POSTGRES_PASSWORD:
                connection_params['password'] = Config.POSTGRES_PASSWORD

            self.connection = psycopg2.connect(**connection_params)
            self.connection.autocommit = True
            cursor = self.connection.cursor()
            cursor.execute(self.POSTGRES_SCHEMA)
            logger.info("PostgreSQL 数据库初始化成功")
            logger.info(f"已连接: {Config.POSTGRES_HOST}:{Config.POSTGRES_PORT}/{Config.POSTGRES_DB}")
        except Exception as e:
            logger.error(f"连接 PostgreSQL 失败: {e}")
            logger.warning("正在回退到 SQLite 数据库...")
            self.db_type = 'sqlite'
            if self.db_path is None:
                self.db_path = Config.DB_PATH
            logger.info(f"使用 SQLite 数据库: {self.db_path}")
            self._ensure_db_directory()
            self._init_db()

    def _hash_pseudocode(self, pseudocode: str) -> str:
        """
        生成伪代码的哈希值（用于相似性匹配

        Args:
            pseudocode: 伪代码字符串

        Returns:
            MD5 哈希值
        """
        if not pseudocode:
            return ""

        normalized = ''.join(c.lower() for c in pseudocode if c.isalnum())
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()

    def add_vulnerability(
        self,
        vulnerability_type: str,
        binary_name: str,
        binary_format: str,
        architecture: str,
        bits: int,
        function_name: str,
        pseudocode: str = "",
        exploit_script: str = "",
        dangerous_functions: List[str] = None,
        checksec: Dict[str, Any] = None,
        symbols: Dict[str, int] = None,
        severity: str = "Medium",
        description: str = "",
        notes: str = "",
        call_graph_summary: Dict[str, Any] = None
    ) -> Optional[int]:
        """
        添加漏洞记录到数据库

        Args:
            vulnerability_type: 漏洞类型
            binary_name: 二进制文件名
            binary_format: 文件格式 (ELF/PE/MACH-O)
            architecture: 架构 (amd64, i386 等)
            bits: 位数 (32/64)
            function_name: 受影响的函数名
            pseudocode: 伪代码
            exploit_script: 利用脚本
            dangerous_functions: 危险函数列表
            checksec: 保护机制信息
            symbols: 符号表
            severity: 严重程度
            description: 漏洞描述
            notes: 额外说明
            call_graph_summary: 调用图摘要

        Returns:
            新记录的 ID，失败返回 None
        """
        if not self.connection:
            logger.error("数据库未初始化失败")
            return None

        try:
            pseudocode_hash = self._hash_pseudocode(pseudocode)

            dangerous_functions_json = json.dumps(dangerous_functions or [], ensure_ascii=False)
            checksec_json = json.dumps(checksec or {}, ensure_ascii=False)
            symbols_json = json.dumps(symbols or {}, ensure_ascii=False)
            call_graph_json = json.dumps(call_graph_summary or {}, ensure_ascii=False)

            cursor = self.connection.cursor()

            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    vulnerability_type, binary_name, binary_format, architecture, bits,
                    function_name, pseudocode_hash, pseudocode_snippet,
                    exploit_script, dangerous_functions, checksec, symbols,
                    severity, description, notes, call_graph_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vulnerability_type, binary_name, binary_format, architecture, bits,
                    function_name, pseudocode_hash, pseudocode[:2000],
                    exploit_script, dangerous_functions_json, checksec_json, symbols_json,
                    severity, description, notes, call_graph_json
                )
            )

            self.connection.commit()
            new_id = cursor.lastrowid
            logger.info(f"添加漏洞记录成功，ID: {new_id}")
            return new_id

        except Exception as e:
            logger.error(f"添加漏洞记录失败: {e}")
            return None

    def get_by_id(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        """
        按 ID 获取漏洞记录

        Args:
            vuln_id: 漏洞 ID

        Returns:
            漏洞记录字典，不存在返回 None
        """
        if not self.connection:
            return None

        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_dict(row)
            return None
        except Exception as e:
            logger.error(f"按 ID 获取漏洞记录失败: {e}")
            return None

    def get_all(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        获取所有漏洞记录

        Args:
            limit: 返回结果数量限制
            offset: 偏移量

        Returns:
            漏洞记录列表
        """
        if not self.connection:
            return []

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )

            results = []
            for row in cursor.fetchall():
                results.append(self._row_to_dict(row))

            return results
        except Exception as e:
            logger.error(f"获取所有漏洞记录失败: {e}")
            return []

    def update_vulnerability(
        self,
        vuln_id: int,
        **kwargs
    ) -> bool:
        """
        更新漏洞记录

        Args:
            vuln_id: 漏洞 ID
            **kwargs: 要更新的字段

        Returns:
            是否成功
        """
        if not self.connection:
            return False

        try:
            allowed_fields = [
                'vulnerability_type', 'binary_name', 'binary_format',
                'architecture', 'bits', 'function_name',
                'pseudocode_snippet', 'exploit_script',
                'dangerous_functions', 'checksec', 'symbols',
                'severity', 'description', 'notes'
            ]

            update_fields = []
            params = []

            for key, value in kwargs.items():
                if key in allowed_fields:
                    if key in ['dangerous_functions', 'checksec', 'symbols']:
                        value = json.dumps(value, ensure_ascii=False)
                    update_fields.append(f"{key} = ?")
                    params.append(value)

            if not update_fields:
                return False

            update_fields.append("updated_at = CURRENT_TIMESTAMP")
            params.append(vuln_id)

            cursor = self.connection.cursor()
            cursor.execute(
                f"UPDATE vulnerabilities SET {', '.join(update_fields)} WHERE id = ?",
                tuple(params)
            )
            self.connection.commit()

            logger.info(f"更新漏洞记录成功，ID: {vuln_id}")
            return True
        except Exception as e:
            logger.error(f"更新漏洞记录失败: {e}")
            return False

    def delete_vulnerability(self, vuln_id: int) -> bool:
        """
        删除漏洞记录

        Args:
            vuln_id: 漏洞 ID

        Returns:
            是否成功
        """
        if not self.connection:
            return False

        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
            self.connection.commit()
            logger.info(f"删除漏洞记录成功，ID: {vuln_id}")
            return True
        except Exception as e:
            logger.error(f"删除漏洞记录失败: {e}")
            return False

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """
        将数据库行转换为字典

        Args:
            row: 数据库行

        Returns:
            字典形式的漏洞记录
        """
        result = dict(row)

        for key in ['dangerous_functions', 'checksec', 'symbols']:
            if result.get(key):
                try:
                    result[key] = json.loads(result[key])
                except (json.JSONDecodeError, TypeError):
                    pass

        return result

    def close(self):
        """
        关闭数据库连接
        """
        if self.connection:
            try:
                self.connection.close()
                self.connection = None
                logger.info("数据库连接已关闭")
            except Exception as e:
                logger.error(f"关闭数据库连接失败: {e}")

    def __del__(self):
        """
        析构函数，确保关闭连接
        """
        self.close()

    def add_code_embedding(
        self,
        vuln_id: int,
        embedding: List[float],
        model_name: str = 'default'
    ) -> Optional[int]:
        """
        添加代码嵌入向量到数据库

        Args:
            vuln_id: 漏洞记录 ID
            embedding: 嵌入向量列表
            model_name: 使用的嵌入模型名称

        Returns:
            新记录的 ID
        """
        if not self.connection:
            return None

        if not VECTOR_STORAGE_AVAILABLE:
            logger.warning("numpy 不可用，无法存储向量")
            return None

        try:
            embedding_json = json.dumps(embedding)
            vector_dim = len(embedding)

            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT INTO code_embeddings (vuln_id, embedding, model_name, vector_dim)
                VALUES (?, ?, ?, ?)
                """,
                (vuln_id, embedding_json, model_name, vector_dim)
            )

            self.connection.commit()
            new_id = cursor.lastrowid
            logger.info(f"添加代码嵌入向量成功，ID: {new_id}, 维度: {vector_dim}")
            return new_id

        except Exception as e:
            logger.error(f"添加代码嵌入失败: {e}")
            return None

    def cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """
        计算两个向量的余弦相似度

        Args:
            vec1: 向量 1
            vec2: 向量 2

        Returns:
            余弦相似度 (0-1)
        """
        if not VECTOR_STORAGE_AVAILABLE:
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            norm1 = (sum(a * a for a in vec1)) ** 0.5
            norm2 = (sum(b * b for b in vec2)) ** 0.5
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return dot_product / (norm1 * norm2)

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
            logger.debug(f"余弦相似度计算失败: {e}")
            return 0.0

    def semantic_search(
        self,
        query_embedding: List[float],
        limit: int = 10,
        min_similarity: float = 0.7,
        model_name: str = None
    ) -> List[Dict[str, Any]]:
        """
        基于嵌入向量的语义搜索

        Args:
            query_embedding: 查询向量
            limit: 返回结果数量限制
            min_similarity: 最小相似度阈值
            model_name: 模型名称过滤（可选）

        Returns:
            按相似度排序的结果列表
        """
        if not self.connection:
            return []

        try:
            cursor = self.connection.cursor()

            if model_name:
                cursor.execute(
                    """
                    SELECT ce.*, v.* FROM code_embeddings ce
                    JOIN vulnerabilities v ON ce.vuln_id = v.id
                    WHERE ce.model_name = ?
                    """,
                    (model_name,)
                )
            else:
                cursor.execute(
                    """
                    SELECT ce.*, v.* FROM code_embeddings ce
                    JOIN vulnerabilities v ON ce.vuln_id = v.id
                    """
                )

            results = []
            for row in cursor.fetchall():
                try:
                    embedding = json.loads(row['embedding'])
                    similarity = self.cosine_similarity(query_embedding, embedding)

                    if similarity >= min_similarity:
                        vuln_record = self._row_to_dict(row)
                        vuln_record['similarity'] = similarity
                        vuln_record['embedding_model'] = row['model_name']
                        results.append(vuln_record)
                except Exception as e:
                    logger.debug(f"解析嵌入向量失败: {e}")
                    continue

            results.sort(key=lambda x: x['similarity'], reverse=True)

            logger.info(f"语义搜索完成: 找到 {len(results)} 个匹配（阈值: {min_similarity}）")
            return results[:limit]

        except Exception as e:
            logger.error(f"语义搜索失败: {e}")
            return []

    def export_database(self, export_path: str) -> bool:
        """
        导出数据库到 JSON 文件

        Args:
            export_path: 导出文件路径

        Returns:
            是否成功
        """
        try:
            all_records = self.get_all(limit=10000)

            export_data = {
                'export_time': datetime.now().isoformat(),
                'version': '1.0',
                'records': all_records
            }

            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)

            logger.info(f"导出数据库成功: {export_path}")
            return True
        except Exception as e:
            logger.error(f"导出数据库失败: {e}")
            return False

    def import_database(self, import_path: str, merge: bool = True) -> int:
        """
        从 JSON 文件导入数据库

        Args:
            import_path: 导入文件路径
            merge: 是否合并导入（True）或替换（False）

        Returns:
            导入的记录数
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)

            records = import_data.get('records', [])
            if not records:
                logger.warning("导入文件中没有记录")
                return 0

            if not merge:
                cursor = self.connection.cursor()
                cursor.execute("DELETE FROM vulnerabilities")
                self.connection.commit()

            imported_count = 0
            for record in records:
                dangerous_functions = record.get('dangerous_functions', [])
                if isinstance(dangerous_functions, str):
                    dangerous_functions = json.loads(dangerous_functions)

                checksec = record.get('checksec', {})
                if isinstance(checksec, str):
                    checksec = json.loads(checksec)

                symbols = record.get('symbols', {})
                if isinstance(symbols, str):
                    symbols = json.loads(symbols)

                vuln_id = self.add_vulnerability(
                    vulnerability_type=record.get('vulnerability_type', 'Unknown'),
                    binary_name=record.get('binary_name', ''),
                    binary_format=record.get('binary_format', 'Unknown'),
                    architecture=record.get('architecture', 'unknown'),
                    bits=record.get('bits', 0),
                    function_name=record.get('function_name', ''),
                    pseudocode=record.get('pseudocode_snippet', ''),
                    exploit_script=record.get('exploit_script', ''),
                    dangerous_functions=dangerous_functions,
                    checksec=checksec,
                    symbols=symbols,
                    severity=record.get('severity', 'Medium'),
                    description=record.get('description', ''),
                    notes=record.get('notes', '')
                )

                if vuln_id:
                    imported_count += 1

            logger.info(f"导入数据库成功: {imported_count} 条记录")
            return imported_count
        except Exception as e:
            logger.error(f"导入数据库失败: {e}")
            return 0

    def export_vulnerability_features(
        self,
        vuln_id: int,
        export_path: str = None
    ) -> Optional[str]:
        """
        导出漏洞特征为 JSON

        Args:
            vuln_id: 漏洞 ID
            export_path: 导出路径（可选，默认返回 JSON 字符串）

        Returns:
            JSON 字符串或文件路径
        """
        if not self.connection:
            return None

        try:
            vuln = self.get_by_id(vuln_id)
            if not vuln:
                logger.error(f"漏洞记录不存在: {vuln_id}")
                return None

            features = {
                'vuln_id': vuln_id,
                'vulnerability_type': vuln.get('vulnerability_type'),
                'function_name': vuln.get('function_name'),
                'architecture': vuln.get('architecture'),
                'bits': vuln.get('bits'),
                'dangerous_functions': vuln.get('dangerous_functions', []),
                'pseudocode_hash': vuln.get('pseudocode_hash'),
                'checksec': vuln.get('checksec', {}),
                'severity': vuln.get('severity'),
                'exported_at': datetime.now().isoformat()
            }

            if vuln.get('call_graph_summary'):
                try:
                    features['call_graph_summary'] = json.loads(vuln['call_graph_summary'])
                except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                    features['call_graph_summary'] = vuln['call_graph_summary']

            features_json = json.dumps(features, ensure_ascii=False, indent=2)

            if export_path:
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write(features_json)
                logger.info(f"导出漏洞特征成功: {export_path}")
                return export_path

            return features_json

        except Exception as e:
            logger.error(f"导出漏洞特征失败: {e}")
            return None

    def query_external_cve_database(
        self,
        binary_name: str,
        binary_hash: str = None,
        use_cache: bool = True,
        timeout: int = 10
    ) -> List[Dict[str, Any]]:
        """
        查询外部CVE数据库（可选功能）

        Args:
            binary_name: 二进制文件名
            binary_hash: 二进制文件哈希（可选）
            use_cache: 是否使用本地缓存
            timeout: 请求超时时间

        Returns:
            CVE 记录列表
        """
        results = []

        if use_cache and self.connection and binary_hash:
            try:
                cursor = self.connection.cursor()
                cursor.execute(
                    """
                    SELECT cve_id, cve_data FROM external_cve_cache
                    WHERE binary_hash = ? OR binary_name = ?
                    ORDER BY created_at DESC
                    """,
                    (binary_hash, binary_name)
                )

                for row in cursor.fetchall():
                    try:
                        cve_data = json.loads(row['cve_data'])
                        cve_data['from_cache'] = True
                        results.append(cve_data)
                    except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                        continue

                if results:
                    logger.info(f"从缓存获取到 {len(results)} 个 CVE 记录")
                    return results
            except Exception as e:
                logger.debug(f"查询 CVE 缓存失败: {e}")

        try:
            import urllib.request
            import urllib.parse

            query_params = {
                'product': binary_name,
                'resultsPerPage': 10
            }

            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urllib.parse.urlencode(query_params)}"

            logger.info(f"查询 NVD CVE 数据库: {binary_name}")

            req = urllib.request.Request(
                nvd_url,
                headers={'User-Agent': 'deemo-vuln-scanner/1.0'}
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8'))

                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', '')

                    cve_record = {
                        'cve_id': cve_id,
                        'source': 'NVD',
                        'binary_name': binary_name,
                        'description': '',
                        'severity': '',
                        'published_date': '',
                        'from_cache': False
                    }

                    descriptions = cve.get('descriptions', [])
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            cve_record['description'] = desc.get('value', '')
                            break

                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cve_record['severity'] = cvss.get('baseSeverity', '')
                    elif 'cvssMetricV2' in metrics:
                        cvss = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cve_record['severity'] = 'High' if cvss.get('baseScore', 0) >= 7.0 else 'Medium'

                    cve_record['published_date'] = cve.get('published', '')

                    results.append(cve_record)

                    if self.connection and use_cache:
                        try:
                            cursor = self.connection.cursor()
                            cursor.execute(
                                """
                                INSERT OR IGNORE INTO external_cve_cache
                                (cve_id, binary_hash, binary_name, cve_data, source)
                                VALUES (?, ?, ?, ?, ?)
                                """,
                                (
                                    cve_id,
                                    binary_hash or '',
                                    binary_name,
                                    json.dumps(cve_record),
                                    'NVD'
                                )
                            )
                            self.connection.commit()
                        except Exception as e:
                            logger.debug(f"缓存 CVE 记录失败: {e}")

                logger.info(f"从 NVD 获取到 {len(results)} 个 CVE 记录")

        except Exception as e:
            logger.warning(f"查询外部 CVE 数据库失败: {e}")
            logger.info("提示: 这是可选功能，需要网络连接和 NVD API 访问")

        return results

    def query_exploit_db(
        self,
        search_term: str,
        use_cache: bool = True,
        timeout: int = 10
    ) -> List[Dict[str, Any]]:
        """
        查询 Exploit-DB（可选功能）

        Args:
            search_term: 搜索关键词
            use_cache: 是否使用缓存
            timeout: 请求超时

        Returns:
            Exploit-DB 记录列表
        """
        results = []

        try:
            import urllib.request
            import urllib.parse

            logger.info(f"查询 Exploit-DB: {search_term}")

            search_url = f"https://www.exploit-db.com/search?q={urllib.parse.quote(search_term)}"

            req = urllib.request.Request(
                search_url,
                headers={
                    'User-Agent': 'deemo-vuln-scanner/1.0',
                    'Accept': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = response.read()

                try:
                    parsed = json.loads(data.decode('utf-8'))
                    if isinstance(parsed, dict) and 'data' in parsed:
                        for item in parsed['data'][:10]:
                            results.append({
                                'id': item.get('id'),
                                'title': item.get('description', ''),
                                'platform': item.get('platform', ''),
                                'type': item.get('type', ''),
                                'source': 'Exploit-DB'
                            })
                except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                    pass

                if not results:
                    logger.info("Exploit-DB API 格式可能已变更，使用离线模式")

        except Exception as e:
            logger.debug(f"查询 Exploit-DB 失败: {e}")

        return results

    def jaccard_similarity(
        self,
        set1: List[str],
        set2: List[str]
    ) -> float:
        """
        计算两个集合的 Jaccard 相似度

        Jaccard 相似度 = |A ∩ B| / |A ∪ B|

        Args:
            set1: 第一个集合
            set2: 第二个集合

        Returns:
            0.0 到 1.0 之间的相似度值
        """
        if not set1 or not set2:
            return 0.0

        s1 = set(set1)
        s2 = set(set2)

        union = s1 | s2
        if not union:
            return 0.0

        intersection = s1 & s2

        return len(intersection) / len(union)

    def calculate_dangerous_function_score(
        self,
        dangerous_functions: List[str],
        vulnerability_type: str = None
    ) -> Dict[str, Any]:
        """
        基于危险函数组合计算模糊搜索评分

        Args:
            dangerous_functions: 危险函数列表
            vulnerability_type: 漏洞类型（可选）

        Returns:
            包含评分和匹配信息的字典
        """
        if not dangerous_functions:
            return {'score': 0, 'matches': [], 'notes': []}

        func_set = set(dangerous_functions)
        score = 0
        matches = []
        notes = []

        for combo, info in self.DANGEROUS_FUNCTION_COMBOS.items():
            if set(combo).issubset(func_set):
                score += info['score']
                matches.append(combo)
                notes.append(f"组合 {combo}: {info['note']} (+{info['score']})")

        for func in dangerous_functions:
            if func in ['gets', 'scanf', 'sprintf', 'vsprintf']:
                score += 20
            elif func in ['strcpy', 'strcat', 'memcpy']:
                score += 15
            elif func in ['system', 'execve', 'popen']:
                score += 30
            elif func in ['read', 'fread']:
                score += 10

        vuln_type_scores = {
            'Buffer Overflow': 50,
            'Stack Overflow': 45,
            'Format String': 40,
            'Use After Free': 35,
            'Double Free': 35,
            'Command Injection': 55,
            'SQL Injection': 40,
            'Integer Overflow': 25,
        }

        if vulnerability_type:
            for vt, bonus in vuln_type_scores.items():
                if vt.lower() in vulnerability_type.lower():
                    score += bonus
                    notes.append(f"漏洞类型匹配: {vt} (+{bonus})")
                    break

        score = min(score, 200)

        return {
            'score': score,
            'matches': matches,
            'notes': notes,
            'risk_level': self._score_to_risk(score)
        }

    def _score_to_risk(self, score: int) -> str:
        # 将分数转换为风险等级
        if score >= 150:
            return 'Critical'
        elif score >= 100:
            return 'High'
        elif score >= 50:
            return 'Medium'
        else:
            return 'Low'

    def generate_call_graph_summary(
        self,
        function_name: str,
        dangerous_functions: List[str] = None,
        call_depth: int = 3
    ) -> Dict[str, Any]:
        """
        生成调用图摘要（用于导出 JSON）

        Args:
            function_name: 函数名
            dangerous_functions: 危险函数列表
            call_depth: 调用深度

        Returns:
            调用图摘要字典
        """
        summary = {
            'function_name': function_name,
            'call_depth': call_depth,
            'dangerous_functions': dangerous_functions or [],
            'has_dangerous_calls': bool(dangerous_functions),
            'generated_at': datetime.now().isoformat()
        }

        if dangerous_functions:
            summary['risk_assessment'] = self.calculate_dangerous_function_score(
                dangerous_functions
            )

        return summary

    def query_osv(
        self,
        package_name: str = None,
        commit_hash: str = None,
        vuln_id: str = None,
        use_cache: bool = True,
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """
        查询 OSV (Open Source Vulnerabilities) 数据库

        OSV是Google维护的开源漏洞数据库，包含Linux发行版、
        npm、PyPI、Go、Rust 等生态系统的漏洞信息。

        Args:
            package_name: 包名（如 'openssl', 'python-requests'）
            commit_hash: 提交哈希（用于精确匹配）
            vuln_id: 漏洞 ID（如 'CVE-2023-12345', 'GHSA-xxxx-xxxx'）
            use_cache: 是否使用本地缓存
            timeout: 请求超时时间（秒）

        Returns:
            OSV 漏洞记录列表
        """
        logger.info(f"[VulnDB] 查询 OSV 数据库: package={package_name}, vuln_id={vuln_id}")

        results = []

        cache_key = None
        if use_cache and self.connection:
            cache_key_parts = []
            if package_name:
                cache_key_parts.append(f"pkg:{package_name}")
            if commit_hash:
                cache_key_parts.append(f"commit:{commit_hash}")
            if vuln_id:
                cache_key_parts.append(f"id:{vuln_id}")

            if cache_key_parts:
                cache_key = hashlib.md5("|".join(cache_key_parts).encode()).hexdigest()
                cached = self._get_external_cache('osv', cache_key)
                if cached:
                    logger.info(f"[VulnDB] OSV 缓存命中: {len(cached)} 条记录")
                    return cached

        try:
            import urllib.request
            import urllib.error

            base_url = "https://api.osv.dev/v1"
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'deemo-vuln-scanner/1.0'
            }

            if vuln_id:
                url = f"{base_url}/vulns/{vuln_id}"
                logger.debug(f"[VulnDB] OSV 查询 URL: {url}")

                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    processed = self._process_osv_vuln(data)
                    if processed:
                        results.append(processed)

            elif package_name or commit_hash:
                url = f"{base_url}/query"
                query_body = {}

                if commit_hash:
                    query_body['commit'] = commit_hash
                elif package_name:
                    query_body['package'] = {
                        'name': package_name,
                        'ecosystem': '*'
                    }

                logger.debug(f"[VulnDB] OSV 查询 Body: {query_body}")

                req = urllib.request.Request(
                    url,
                    data=json.dumps(query_body).encode('utf-8'),
                    headers=headers
                )

                with urllib.request.urlopen(req, timeout=timeout) as response:
                    data = json.loads(response.read().decode('utf-8'))

                    for vuln in data.get('vulns', []):
                        processed = self._process_osv_vuln(vuln)
                        if processed:
                            results.append(processed)

            if use_cache and self.connection and cache_key and results:
                self._save_external_cache('osv', cache_key, results)

            logger.info(f"[VulnDB] OSV 查询完成: {len(results)} 条记录")

        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.info(f"[VulnDB] OSV: 未找到记录")
            else:
                logger.warning(f"[VulnDB] OSV 查询 HTTP 错误: {e.code}")
        except Exception as e:
            logger.warning(f"[VulnDB] OSV 查询失败: {e}")

        return results

    def _process_osv_vuln(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        处理 OSV 漏洞数据，标准化格式
        """
        if not vuln_data:
            return None

        vuln_id = vuln_data.get('id', '')

        severity = 'Unknown'
        severity_score = None
        for affected in vuln_data.get('affected', []):
            for severity_entry in affected.get('severity', []):
                if severity_entry.get('type') == 'CVSS_V3':
                    try:
                        cvss_data = severity_entry.get('score', '')
                        for part in cvss_data.split('/'):
                            if part.startswith('SCORE:'):
                                severity_score = float(part.split(':')[1])
                                if severity_score >= 9.0:
                                    severity = 'Critical'
                                elif severity_score >= 7.0:
                                    severity = 'High'
                                elif severity_score >= 4.0:
                                    severity = 'Medium'
                                else:
                                    severity = 'Low'
                    except (ValueError, IndexError):  # 修复: bare except → ValueError
                        pass
                    break
            if severity != 'Unknown':
                break

        aliases = vuln_data.get('aliases', [])
        cve_ids = [a for a in aliases if a.startswith('CVE-')]
        ghsa_ids = [a for a in aliases if a.startswith('GHSA-')]

        description = ''
        for desc in vuln_data.get('details', ''):
            description = vuln_data.get('details', '')
            break

        return {
            'vuln_id': vuln_id,
            'source': 'OSV',
            'title': vuln_data.get('summary', vuln_id),
            'description': description[:2000] if description else '',
            'severity': severity,
            'cvss_score': severity_score,
            'published': vuln_data.get('published', ''),
            'modified': vuln_data.get('modified', ''),
            'cve_ids': cve_ids,
            'ghsa_ids': ghsa_ids,
            'references': [
                {'type': ref.get('type'), 'url': ref.get('url')}
                for ref in vuln_data.get('references', [])
            ],
            'affected_packages': [
                {
                    'name': affected.get('package', {}).get('name', ''),
                    'ecosystem': affected.get('package', {}).get('ecosystem', ''),
                    'ranges': affected.get('ranges', [])
                }
                for affected in vuln_data.get('affected', [])
            ],
            'raw_data': vuln_data
        }

    def query_gh_advisory(
        self,
        package_name: str = None,
        ecosystem: str = None,
        ghsa_id: str = None,
        cve_id: str = None,
        use_cache: bool = True,
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """
        查询 GitHub Advisory Database

        GitHub Advisory 数据库包含 npm、PyPI、Maven、NuGet 等
        生态系统的安全漏洞信息。

        Args:
            package_name: 包名
            ecosystem: 生态系统（npm, pypi, maven, nuget, go, rust）
            ghsa_id: GHSA 漏洞 ID（如 'GHSA-xxxx-xxxx-xxxx'）
            cve_id: CVE ID
            use_cache: 是否使用本地缓存
            timeout: 请求超时时间（秒）

        Returns:
            GitHub Advisory 漏洞记录列表
        """
        logger.info(f"[VulnDB] 查询 GitHub Advisory: package={package_name}, ghsa={ghsa_id}, cve={cve_id}")

        results = []

        cache_key = None
        if use_cache and self.connection:
            cache_key_parts = []
            if package_name:
                cache_key_parts.append(f"pkg:{package_name}")
            if ecosystem:
                cache_key_parts.append(f"eco:{ecosystem}")
            if ghsa_id:
                cache_key_parts.append(f"ghsa:{ghsa_id}")
            if cve_id:
                cache_key_parts.append(f"cve:{cve_id}")

            if cache_key_parts:
                cache_key = hashlib.md5("|".join(cache_key_parts).encode()).hexdigest()
                cached = self._get_external_cache('ghadvisory', cache_key)
                if cached:
                    logger.info(f"[VulnDB] GitHub Advisory 缓存命中: {len(cached)} 条记录")
                    return cached

        try:
            import urllib.request
            import urllib.error

            base_url = "https://api.github.com/advisories"
            query_params = {}

            if ghsa_id:
                query_params['ghsa_id'] = ghsa_id
            if cve_id:
                query_params['cve_id'] = cve_id
            if package_name:
                query_params['package'] = package_name
            if ecosystem:
                query_params['ecosystem'] = ecosystem.lower()

            query_params['per_page'] = 20
            query_params['sort'] = 'published'
            query_params['direction'] = 'desc'

            import urllib.parse
            query_string = urllib.parse.urlencode(query_params)
            url = f"{base_url}?{query_string}"

            headers = {
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'deemo-vuln-scanner/1.0',
                'X-GitHub-Api-Version': '2022-11-28'
            }

            logger.debug(f"[VulnDB] GitHub Advisory URL: {url}")

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode('utf-8'))

                if isinstance(data, list):
                    for advisory in data:
                        processed = self._process_gh_advisory(advisory)
                        if processed:
                            results.append(processed)
                elif isinstance(data, dict):
                    processed = self._process_gh_advisory(data)
                    if processed:
                        results.append(processed)

            if use_cache and self.connection and cache_key and results:
                self._save_external_cache('ghadvisory', cache_key, results)

            logger.info(f"[VulnDB] GitHub Advisory 查询完成: {len(results)} 条记录")

        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.warning(f"[VulnDB] GitHub API 限流，请稍后重试或设置 GITHUB_TOKEN")
            elif e.code == 404:
                logger.info(f"[VulnDB] GitHub Advisory: 未找到记录")
            else:
                logger.warning(f"[VulnDB] GitHub Advisory HTTP 错误: {e.code}")
        except Exception as e:
            logger.warning(f"[VulnDB] GitHub Advisory 查询失败: {e}")

        return results

    def _process_gh_advisory(self, advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        处理 GitHub Advisory 数据，标准化格式
        """
        if not advisory:
            return None

        ghsa_id = advisory.get('ghsa_id', '')
        severity = advisory.get('severity', 'Unknown')

        cvss = advisory.get('cvss', {})
        cvss_score = cvss.get('score') if isinstance(cvss, dict) else None

        cves = []
        identifiers = advisory.get('identifiers', [])
        for ident in identifiers:
            if ident.get('type') == 'CVE':
                cves.append(ident.get('value', ''))

        return {
            'vuln_id': ghsa_id,
            'source': 'GitHub Advisory',
            'title': advisory.get('summary', ghsa_id),
            'description': advisory.get('description', '')[:2000],
            'severity': severity,
            'cvss_score': cvss_score,
            'cvss_vector': cvss.get('vector_string') if isinstance(cvss, dict) else '',
            'published': advisory.get('published_at', ''),
            'updated': advisory.get('updated_at', ''),
            'cve_ids': cves,
            'ghsa_id': ghsa_id,
            'references': advisory.get('references', []),
            'vulnerabilities': [
                {
                    'package': v.get('package', {}).get('name', ''),
                    'ecosystem': v.get('package', {}).get('ecosystem', ''),
                    'vulnerable_version_range': v.get('vulnerable_version_range', ''),
                    'patched_versions': v.get('patched_versions', ''),
                    'first_patched_version': v.get('first_patched_version', '')
                }
                for v in advisory.get('vulnerabilities', [])
            ],
            'cwes': advisory.get('cwes', []),
            'raw_data': advisory
        }

    def _process_vuldb_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """处理 VulDB API 返回条目，标准化为统一漏洞记录结构。

        VulDB 原始条目嵌套在 'source' 键下；输出与 _process_osv_vuln、
        _process_gh_advisory 保持同构，便于上层统一消费。
        """
        if not entry or not isinstance(entry, dict):
            return None

        src = entry.get('source')
        if not isinstance(src, dict):
            src = entry

        vuln_id = str(src.get('id', ''))

        cve_ids = []
        cve = src.get('cve')
        if isinstance(cve, dict) and cve.get('id'):
            cve_ids.append(cve['id'])

        risk = src.get('risk')
        severity = risk.get('name', 'Unknown') if isinstance(risk, dict) else 'Unknown'

        cvss = src.get('cvss')
        cvss_score = cvss.get('score') if isinstance(cvss, dict) else None

        product = src.get('product')
        if isinstance(product, dict):
            vendor = product.get('vendor')
            vendor_name = vendor.get('name', '') if isinstance(vendor, dict) else ''
            product_name = product.get('name', '') or ''
            product_version = product.get('version', '') or ''
        else:
            vendor_name = product_name = product_version = ''

        date = src.get('date')
        last_modified = date.get('last_modified', '') if isinstance(date, dict) else ''

        return {
            'vuln_id': vuln_id,
            'source': 'VulDB',
            'title': src.get('title', '') or '',
            'description': (src.get('advisory', '') or '')[:2000],
            'severity': severity,
            'cvss_score': cvss_score,
            'cve_ids': cve_ids,
            'vuldb_link': src.get('vuldb_link', '') or '',
            'published': None,
            'updated': last_modified,
            'product': {
                'vendor': vendor_name,
                'name': product_name,
                'version': product_version,
            },
            'raw_data': entry,
        }

    def _validate_external_query_params(self, **kwargs) -> Dict[str, Any]:
        """校验外部漏洞源查询参数并清洗注入风险。

        返回 {'valid': bool, 'sanitized': dict, 'errors': [str]}。
        - cve_id: 必须匹配 CVE-\\d{4}-\\d{4,7} 格式
        - package_name / binary_name: 去除路径分隔符与危险字符；
          含路径穿越片段直接判为非法
        """
        sanitized: Dict[str, Any] = {}
        errors: List[str] = []

        cve_id = kwargs.get('cve_id')
        if cve_id:
            if re.match(r'^CVE-\d{4}-\d{4,7}$', str(cve_id)):
                sanitized['cve_id'] = str(cve_id)
            else:
                errors.append(f'非法 CVE ID: {cve_id}')

        for field in ('package_name', 'binary_name'):
            value = kwargs.get(field)
            if not value:
                continue
            cleaned = re.sub(r'[;|&<>`\s/\\\\]', '', str(value))
            if '..' in str(value) or str(value).startswith('/'):
                errors.append(f'{field} 含路径穿越片段')
            sanitized[field] = cleaned

        return {
            'valid': not errors,
            'sanitized': sanitized or dict(kwargs),
            'errors': errors,
        }

    def query_all_external(
        self,
        package_name: str = None,
        cve_id: str = None,
        binary_name: str = None,
        use_cache: bool = True,
        deduplicate: bool = True
    ) -> Dict[str, Any]:
        """
        综合查询所有外部漏洞数据源

        数据源包括：
        - NVD (现有)
        - Exploit-DB (现有)
        - OSV (新增)
        - GitHub Advisory (新增)

        Args:
            package_name: 包名
            cve_id: CVE ID
            binary_name: 二进制文件名
            use_cache: 是否使用缓存
            deduplicate: 是否去重

        Returns:
            包含各数据源结果和合并结果的字典
        """
        logger.info(f"[VulnDB] 综合外部漏洞查询: pkg={package_name}, cve={cve_id}")

        results = {
            'nvd': [],
            'exploit_db': [],
            'osv': [],
            'github_advisory': [],
            'combined': [],
            'stats': {
                'total': 0,
                'unique': 0,
                'by_source': {}
            }
        }

        search_terms = []
        if package_name:
            search_terms.append(package_name)
        if binary_name:
            search_terms.append(binary_name)

        main_term = search_terms[0] if search_terms else None

        if main_term:
            try:
                results['nvd'] = self.query_external_cve_database(
                    binary_name=main_term,
                    use_cache=use_cache
                )
            except Exception as e:
                logger.debug(f"[VulnDB] NVD 查询失败: {e}")

        if main_term:
            try:
                results['exploit_db'] = self.query_exploit_db(
                    search_term=main_term,
                    use_cache=use_cache
                )
            except Exception as e:
                logger.debug(f"[VulnDB] Exploit-DB 查询失败: {e}")

        if package_name or cve_id:
            try:
                osv_params = {}
                if package_name:
                    osv_params['package_name'] = package_name
                if cve_id:
                    osv_params['vuln_id'] = cve_id
                results['osv'] = self.query_osv(
                    **osv_params,
                    use_cache=use_cache
                )
            except Exception as e:
                logger.debug(f"[VulnDB] OSV 查询失败: {e}")

        if package_name or cve_id:
            try:
                gh_params = {}
                if package_name:
                    gh_params['package_name'] = package_name
                if cve_id and cve_id.startswith('CVE-'):
                    gh_params['cve_id'] = cve_id
                if gh_params:
                    results['github_advisory'] = self.query_gh_advisory(
                        **gh_params,
                        use_cache=use_cache
                    )
            except Exception as e:
                logger.debug(f"[VulnDB] GitHub Advisory 查询失败: {e}")

        all_records = []

        for item in results['nvd']:
            all_records.append({
                **item,
                '_source': 'nvd',
                '_id': item.get('cve_id', '')
            })

        for item in results['exploit_db']:
            all_records.append({
                **item,
                '_source': 'exploit_db',
                '_id': str(item.get('id', ''))
            })

        for item in results['osv']:
            all_records.append({
                **item,
                '_source': 'osv',
                '_id': item.get('vuln_id', '')
            })

        for item in results['github_advisory']:
            all_records.append({
                **item,
                '_source': 'ghadvisory',
                '_id': item.get('vuln_id', '')
            })

        results['stats']['total'] = len(all_records)
        results['stats']['by_source'] = {
            'nvd': len(results['nvd']),
            'exploit_db': len(results['exploit_db']),
            'osv': len(results['osv']),
            'github_advisory': len(results['github_advisory'])
        }

        if deduplicate:
            seen_ids = set()
            combined = []

            priority_order = ['nvd', 'ghadvisory', 'osv', 'exploit_db']
            all_records_sorted = sorted(
                all_records,
                key=lambda x: priority_order.index(x.get('_source', 'exploit_db'))
            )

            for record in all_records_sorted:
                record_id = record.get('_id', '')
                cve_ids = record.get('cve_ids', [])

                identifiers = {record_id}
                identifiers.update(cve_ids)

                is_duplicate = False
                for ident in identifiers:
                    if ident and ident in seen_ids:
                        is_duplicate = True
                        break

                if not is_duplicate:
                    combined.append(record)
                    for ident in identifiers:
                        if ident:
                            seen_ids.add(ident)

            results['combined'] = self._sort_vulns_by_severity(combined)
            results['stats']['unique'] = len(results['combined'])
        else:
            results['combined'] = self._sort_vulns_by_severity(all_records)
            results['stats']['unique'] = len(all_records)

        logger.info(
            f"[VulnDB] 综合查询完成: "
            f"总计={results['stats']['total']}, "
            f"去重后={results['stats']['unique']}"
        )

        return results

    def _sort_vulns_by_severity(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        按严重程度对漏洞进行排序
        """
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}

        def get_sort_key(v: Dict[str, Any]) -> Tuple[int, float]:
            sev = v.get('severity', 'Unknown')
            score = v.get('cvss_score') or v.get('cvss', {}).get('score', 0)
            return (severity_order.get(sev, 0), -float(score or 0))

        return sorted(vulns, key=get_sort_key, reverse=True)

    def _get_external_cache(
        self,
        source: str,
        cache_key: str
    ) -> Optional[List[Dict[str, Any]]]:
        """
        从外部缓存表获取缓存数据
        """
        if not self.connection:
            return None

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                SELECT cve_data FROM external_cve_cache
                WHERE cve_id = ? AND source = ?
                """,
                (cache_key, source)
            )

            row = cursor.fetchone()
            if row:
                try:
                    return json.loads(row['cve_data'])
                except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                    return None
        except Exception as e:
            logger.debug(f"[VulnDB] 读取缓存失败: {e}")

        return None

    def _save_external_cache(
        self,
        source: str,
        cache_key: str,
        data: List[Dict[str, Any]]
    ) -> bool:
        """
        保存数据到外部缓存表
        """
        if not self.connection:
            return False

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO external_cve_cache
                (cve_id, cve_data, source)
                VALUES (?, ?, ?)
                """,
                (
                    cache_key,
                    json.dumps(data, ensure_ascii=False),
                    source
                )
            )
            self.connection.commit()
            return True
        except Exception as e:
            logger.debug(f"[VulnDB] 保存缓存失败: {e}")
            return False

    def clear_external_cache(self, source: str = None) -> int:
        """
        清除外部 API 缓存

        Args:
            source: 指定数据源清除，None 清除所有

        Returns:
            清除的记录数
        """
        if not self.connection:
            return 0

        try:
            cursor = self.connection.cursor()

            if source:
                cursor.execute("DELETE FROM external_cve_cache WHERE source = ?", (source,))
            else:
                cursor.execute("DELETE FROM external_cve_cache")

            self.connection.commit()
            deleted = cursor.rowcount

            logger.info(f"[VulnDB] 清除外部缓存: {deleted} 条记录")
            return deleted
        except Exception as e:
            logger.error(f"[VulnDB] 清除缓存失败: {e}")
            return 0
