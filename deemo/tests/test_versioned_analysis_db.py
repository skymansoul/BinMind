"""
分析结果版本化与差异数据库测试
"""

import pytest
import tempfile
import os
import time
from modules.versioned_analysis_db import (
    VersionedAnalysisDB,
    SQLiteTimeSeriesDB,
    AnalysisVersion,
    VulnerabilityRecord,
    FunctionInfo,
    ChangeType,
    VersionDiffEngine
)


class TestSQLiteTimeSeriesDB:
    """时序数据库测试"""
    
    @pytest.fixture
    def db(self):
        """创建测试数据库"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        db = SQLiteTimeSeriesDB(db_path)
        yield db
        
        db.close()
        os.unlink(db_path)
    
    def test_insert_version(self, db):
        """测试插入版本"""
        version = AnalysisVersion(
            version_id="test_v1",
            binary_path="/test/binary",
            binary_hash="abcd1234",
            analysis_timestamp=time.time(),
            analyzer_name="test_analyzer",
            analyzer_version="1.0",
            vulnerability_count=5,
            function_count=100
        )
        
        success = db.insert_version(version)
        
        assert success is True
        
        versions = db.get_versions()
        assert len(versions) == 1
        assert versions[0].version_id == "test_v1"
    
    def test_insert_vulnerability(self, db):
        """测试插入漏洞"""
        vuln = VulnerabilityRecord(
            vuln_id="vuln_1",
            version_id="test_v1",
            cve_id="CVE-2023-0001",
            vuln_type="buffer_overflow",
            severity="HIGH",
            location="main.c:100",
            description="Buffer overflow detected"
        )
        
        success = db.insert_vulnerability(vuln)
        
        assert success is True
    
    def test_get_versions(self, db):
        """测试获取版本"""
        for i in range(3):
            version = AnalysisVersion(
                version_id=f"v{i}",
                binary_path="/test/binary",
                binary_hash="hash",
                analysis_timestamp=time.time() - i * 1000,
                analyzer_name="test",
                analyzer_version="1.0"
            )
            db.insert_version(version)
        
        versions = db.get_versions(limit=2)
        
        assert len(versions) == 2


class TestVersionDiffEngine:
    """版本差异引擎测试"""
    
    @pytest.fixture
    def db(self):
        """创建测试数据库"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        db = SQLiteTimeSeriesDB(db_path)
        yield db
        
        db.close()
        os.unlink(db_path)
    
    @pytest.fixture
    def diff_engine(self, db):
        """创建差异引擎"""
        return VersionDiffEngine(db)
    
    def test_compare_versions(self, db, diff_engine):
        """测试版本比较"""
        # 插入版本1
        v1 = AnalysisVersion(
            version_id="v1",
            binary_path="/test/binary",
            binary_hash="hash1",
            analysis_timestamp=time.time() - 1000,
            analyzer_name="test",
            analyzer_version="1.0",
            vulnerability_count=5
        )
        db.insert_version(v1)
        
        # 插入版本2
        v2 = AnalysisVersion(
            version_id="v2",
            binary_path="/test/binary",
            binary_hash="hash2",
            analysis_timestamp=time.time(),
            analyzer_name="test",
            analyzer_version="1.0",
            vulnerability_count=7
        )
        db.insert_version(v2)
        
        diffs = diff_engine.compare_versions("v1", "v2")
        
        assert len(diffs) > 0


class TestVersionedAnalysisDB:
    """版本化数据库测试"""
    
    @pytest.fixture
    def db(self):
        """创建测试数据库"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        vdb = VersionedAnalysisDB(db_path)
        yield vdb
        
        vdb.close()
        os.unlink(db_path)
    
    def test_record_analysis(self, db):
        """测试记录分析结果"""
        analysis_result = {
            'metadata': {'compiler': 'gcc'},
            'vulnerability_count': 3,
            'function_count': 50,
            'call_graph_nodes': 100,
            'call_graph_edges': 200,
            'vulnerabilities': [
                {
                    'type': 'buffer_overflow',
                    'severity': 'HIGH',
                    'location': 'main.c:50',
                    'function': 'process_input',
                    'description': 'Potential buffer overflow'
                }
            ],
            'functions': [
                {
                    'name': 'main',
                    'address': 0x1000,
                    'size': 100,
                    'complexity': 5
                }
            ]
        }
        
        version_id = db.record_analysis(
            "/test/binary",
            analysis_result,
            "test_analyzer",
            "1.0"
        )
        
        assert version_id is not None
        assert version_id.startswith('v_')
    
    def test_get_version_history(self, db):
        """测试获取版本历史"""
        # 记录多次分析
        for i in range(3):
            db.record_analysis(
                "/test/binary",
                {'vulnerability_count': i, 'function_count': 10},
                "test"
            )
        
        history = db.get_version_history("/test/binary")
        
        assert len(history) == 3
    
    def test_compare_versions(self, db):
        """测试比较版本"""
        # 记录两次分析
        db.record_analysis("/test/binary", {
            'vulnerability_count': 5,
            'function_count': 10
        }, "test")
        
        time.sleep(0.1)
        
        db.record_analysis("/test/binary", {
            'vulnerability_count': 7,
            'function_count': 12
        }, "test")
        
        history = db.get_version_history("/test/binary")
        
        if len(history) >= 2:
            result = db.compare_versions(
                history[1]['version_id'],
                history[0]['version_id']
            )
            
            assert 'diff_count' in result
            assert 'delta' in result
