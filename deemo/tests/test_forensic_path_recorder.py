"""
测试漏洞发现取证级记录模块
"""

import pytest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.forensic_path_recorder import ForensicPathRecorder


class TestForensicPathRecorder:
    """取证记录器测试类"""
    
    @classmethod
    def setup_class(cls):
        """测试类初始化"""
        cls.temp_dir = tempfile.mkdtemp()
        cls.recorder = ForensicPathRecorder(output_dir=cls.temp_dir)
        
        cls.test_binary = tempfile.NamedTemporaryFile(
            suffix=".bin", delete=False, dir=cls.temp_dir
        )
        cls.test_binary.write(b"test_binary_content")
        cls.test_binary.close()
    
    @classmethod
    def teardown_class(cls):
        """测试类清理"""
        os.unlink(cls.test_binary.name)
        for root, dirs, files in os.walk(cls.temp_dir, topdown=False):
            for file in files:
                os.unlink(os.path.join(root, file))
            for dir in dirs:
                os.rmdir(os.path.join(root, dir))
        os.rmdir(cls.temp_dir)
    
    def test_create_and_save_record(self):
        """测试创建并保存取证记录"""
        result = self.recorder.analyze(action="create")
        assert result["success"] is True
        assert "record_id" in result
        
        result = self.recorder.analyze(
            action="capture_crash",
            architecture="x86_64",
            binary_path=self.test_binary.name,
            input_data=b"A" * 100,
            registers={"rip": 0x401000, "rsp": 0x7fffffff, "rbp": 0x7ffffffe},
            crash_type="buffer_overflow",
            cwe_id="CWE-120",
            cvss_score=9.8
        )
        assert result["success"] is True
        
        result = self.recorder.analyze(action="save")
        assert result["success"] is True
        assert "file_path" in result
        assert os.path.exists(result["file_path"])
    
    def test_load_and_validate_record(self):
        """测试加载并验证取证记录"""
        self.recorder.create_new_record()
        self.recorder.capture_crash_state(
            architecture="x86",
            binary_path=self.test_binary.name,
            crash_input=b"test_crash_input",
            registers={"eip": 0x8048000, "esp": 0xbffff000},
            crash_type="use_after_free",
            cwe_id="CWE-416",
            cvss_score=7.8
        )
        saved_path = self.recorder.save_record()
        
        result = self.recorder.analyze(action="validate", file_path=saved_path)
        assert result["success"] is True
        assert result["valid"] is True
    
    def test_generate_cve_report(self):
        """测试生成 CVE 证据报告"""
        self.recorder.create_new_record()
        self.recorder.capture_crash_state(
            architecture="arm",
            binary_path=self.test_binary.name,
            crash_input=b"A" * 512,
            registers={"pc": 0x10000, "sp": 0xffff0000},
            crash_type="stack_overflow",
            cwe_id="CWE-121",
            cvss_score=9.0
        )
        
        result = self.recorder.analyze(action="generate_report")
        assert result["success"] is True
        assert "report" in result
        
        report = result["report"]
        assert report["cve_submission_format"] == "CVE-REQUIREMENTS"
        assert "evidence_items" in report
        assert len(report["evidence_items"]) > 0
        assert "summary" in report
    
    def test_capture_symbolic_execution(self):
        """测试捕获符号执行状态"""
        self.recorder.create_new_record()
        
        memory_regions = [
            {"start": 0x1000, "end": 0x2000, "permissions": "r-x", "description": "code"},
            {"start": 0x2000, "end": 0x3000, "permissions": "rw-", "description": "data"}
        ]
        
        constraints = [
            {"name": "input_len", "type": "equality", "expression": "input_len == 100"},
            {"name": "input_byte", "type": "range", "expression": "input_byte[0] < 0x80"}
        ]
        
        result = self.recorder.analyze(
            action="capture_symbolic",
            architecture="x86_64",
            binary_path=self.test_binary.name,
            registers={"rip": 0x400000, "rsp": 0x7ffff000, "rbp": 0x7ffff080},
            memory_regions=memory_regions,
            constraints=constraints,
            input_data=b"test_input"
        )
        
        assert result["success"] is True
    
    def test_load_invalid_file(self):
        """测试加载无效文件"""
        invalid_path = os.path.join(self.temp_dir, "invalid.forensic")
        with open(invalid_path, "w") as f:
            f.write("not a valid forensic record")
        
        result = self.recorder.analyze(action="load", file_path=invalid_path)
        assert result["success"] is False
    
    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = ForensicPathRecorder.get_metadata()
        
        assert metadata.name == "ForensicPathRecorder"
        assert metadata.type.value == "utility"
        assert metadata.version == "1.0.0"
        assert "取证级记录" in metadata.description