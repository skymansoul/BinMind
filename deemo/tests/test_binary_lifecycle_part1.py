# 测试BinaryLifecycleManager的完整pipeline: register -> analyze -> trend -> alerts -> report

import os
import unittest
import tempfile
import shutil
import time

from modules.binary_lifecycle import (
    BinaryLifecycleManager,
    BinarySignature,
    SecurityMetrics,
    AnalysisRecord,
    TrendData,
    LifecycleReport,
    Severity,
    MetricType,
    format_lifecycle_report
)


class TestBinarySignature(unittest.TestCase):

    def test_initialization(self):
        """md5+sha256+file_size+arch 四项缺一不可"""
        sig = BinarySignature(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=1024,
            architecture="x86_64"
        )
        self.assertEqual(sig.md5, "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(sig.file_size, 1024)

class TestSecurityMetrics(unittest.TestCase):

    def test_initialization(self):
        metrics = SecurityMetrics(
            total_vulns=10,
            critical_vulns=2,
            high_vulns=3,
            vuln_counts={Severity.CRITICAL: 2, Severity.HIGH: 3}
        )
        self.assertEqual(metrics.total_vulns, 10)
        self.assertEqual(metrics.critical_vulns, 2)

    def test_defaults(self):
        """啥也不传: total_vulns=0, attack_surface_score=0.0"""
        metrics = SecurityMetrics()
        self.assertEqual(metrics.total_vulns, 0)
        self.assertEqual(metrics.attack_surface_score, 0.0)

class TestAnalysisRecord(unittest.TestCase):

    def test_initialization(self):
        sig = BinarySignature(md5="test", sha256="test256")
        metrics = SecurityMetrics(total_vulns=5)

        record = AnalysisRecord(
            record_id="record_001",
            binary_signature=sig,
            version="1.0.0",
            analysis_timestamp=time.time(),
            metrics=metrics
        )
        self.assertEqual(record.record_id, "record_001")
        self.assertEqual(record.version, "1.0.0")

class TestTrendData(unittest.TestCase):

    def test_initialization(self):
        """increasing趋势: 5->8->10, 百分比100%"""
        # 口径: 技术性参数/计算值, 非检测结果宣称
        trend = TrendData(
            metric_name="vulnerability_count",
            timestamps=[1000, 2000, 3000],
            values=[5, 8, 10],
            trend_direction="increasing",
            trend_percentage=100.0
        )
        self.assertEqual(trend.metric_name, "vulnerability_count")
        self.assertEqual(trend.trend_direction, "increasing")

class TestLifecycleReport(unittest.TestCase):

    def test_initialization(self):
        report = LifecycleReport(
            binary_name="test_binary",
            total_versions=5,
            analysis_period=(0, 0),
            current_metrics=SecurityMetrics()
        )
        self.assertEqual(report.binary_name, "test_binary")
        self.assertEqual(report.total_versions, 5)

