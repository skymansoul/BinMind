#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
二进制生命周期管理模块单元测试
"""

import unittest
import sys
import os
import tempfile
import shutil
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    """BinarySignature测试类"""

    def test_initialization(self):
        """测试初始化"""
        sig = BinarySignature(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=1024,
            architecture="x86_64"
        )

        self.assertEqual(sig.md5, "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(sig.file_size, 1024)


class TestSecurityMetrics(unittest.TestCase):
    """SecurityMetrics测试类"""

    def test_initialization(self):
        """测试初始化"""
        metrics = SecurityMetrics(
            total_vulns=10,
            critical_vulns=2,
            high_vulns=3,
            vuln_counts={Severity.CRITICAL: 2, Severity.HIGH: 3}
        )

        self.assertEqual(metrics.total_vulns, 10)
        self.assertEqual(metrics.critical_vulns, 2)

    def test_defaults(self):
        """测试默认值"""
        metrics = SecurityMetrics()

        self.assertEqual(metrics.total_vulns, 0)
        self.assertEqual(metrics.attack_surface_score, 0.0)


class TestAnalysisRecord(unittest.TestCase):
    """AnalysisRecord测试类"""

    def test_initialization(self):
        """测试初始化"""
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
    """TrendData测试类"""

    def test_initialization(self):
        """测试初始化"""
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
    """LifecycleReport测试类"""

    def test_initialization(self):
        """测试初始化"""
        report = LifecycleReport(
            binary_name="test_binary",
            total_versions=5,
            analysis_period=(1000.0, 5000.0),
            current_metrics=SecurityMetrics()
        )

        self.assertEqual(report.binary_name, "test_binary")
        self.assertEqual(report.total_versions, 5)


class TestBinaryLifecycleManager(unittest.TestCase):
    """BinaryLifecycleManager测试类"""

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.manager = BinaryLifecycleManager(data_dir=self.temp_dir)

    def tearDown(self):
        """清理测试环境"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """测试初始化"""
        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager.data_dir, self.temp_dir)

    def test_compute_signature(self):
        """测试签名计算"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            temp_path = f.name

        try:
            sig = self.manager._compute_signature(temp_path)

            self.assertIsNotNone(sig)
            self.assertEqual(sig.md5, "d41d8cd98f00b204e9800998ecf8427e")  # 空数据的MD5
        finally:
            os.unlink(temp_path)

    def test_generate_record_id(self):
        """测试记录ID生成"""
        sig = BinarySignature(sha256="test_sha256")
        record_id = self.manager._generate_record_id(sig, "1.0.0")

        self.assertIsInstance(record_id, str)
        self.assertEqual(len(record_id), 16)

    def test_register_binary(self):
        """测试二进制注册"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            sha = self.manager.register_binary(temp_path, "test_binary")

            self.assertIsInstance(sha, str)
            self.assertIn(sha, self.manager.binary_index)
        finally:
            os.unlink(temp_path)

    def test_add_analysis_record(self):
        """测试添加分析记录"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            metrics = SecurityMetrics(
                total_vulns=10,
                critical_vulns=2,
                high_vulns=3,
                attack_surface_score=65.0,
                hardening_score=70.0
            )

            record = self.manager.add_analysis_record(
                binary_path=temp_path,
                binary_name="test_binary",
                version="1.0.0",
                metrics=metrics,
                metadata={"analyzer": "test"}
            )

            self.assertIsInstance(record, AnalysisRecord)
            self.assertEqual(record.version, "1.0.0")
        finally:
            os.unlink(temp_path)

    def test_load_records_empty(self):
        """测试加载空记录"""
        records = self.manager.load_records("nonexistent_signature")

        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 0)

    def test_compute_trends_insufficient_data(self):
        """测试数据不足时的趋势计算"""
        trends = self.manager.compute_trends("test_signature")

        self.assertIsInstance(trends, list)

    def test_compute_trends_with_data(self):
        """测试有数据时的趋势计算"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            # 添加多条记录
            for i in range(3):
                metrics = SecurityMetrics(
                    total_vulns=5 + i,
                    attack_surface_score=60.0 + i * 5,
                    hardening_score=70.0 - i * 5
                )
                self.manager.add_analysis_record(
                    binary_path=temp_path,
                    binary_name="trend_test",
                    version=f"1.0.{i}",
                    metrics=metrics
                )

            # 获取签名
            sig = self.manager._compute_signature(temp_path)

            trends = self.manager.compute_trends(sig.sha256)

            self.assertIsInstance(trends, list)
        finally:
            os.unlink(temp_path)

    def test_analyze_trend_direction(self):
        """测试趋势方向分析"""
        # 上升趋势
        direction, pct = self.manager._analyze_trend_direction([10, 20, 30])
        self.assertEqual(direction, "increasing")

        # 下降趋势
        direction, pct = self.manager._analyze_trend_direction([30, 20, 10])
        self.assertEqual(direction, "decreasing")

        # 稳定
        direction, pct = self.manager._analyze_trend_direction([10, 11, 10])
        self.assertEqual(direction, "stable")

    def test_generate_alerts_no_records(self):
        """测试无记录时告警生成"""
        alerts = self.manager.generate_alerts("test_signature")

        self.assertIsInstance(alerts, list)

    def test_generate_alerts_with_data(self):
        """测试有数据时告警生成"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            # 添加两条记录，一条漏洞更多
            metrics1 = SecurityMetrics(total_vulns=5, critical_vulns=1)
            self.manager.add_analysis_record(
                binary_path=temp_path,
                binary_name="alert_test",
                version="1.0.0",
                metrics=metrics1
            )

            metrics2 = SecurityMetrics(total_vulns=10, critical_vulns=3)
            self.manager.add_analysis_record(
                binary_path=temp_path,
                binary_name="alert_test",
                version="1.0.1",
                metrics=metrics2
            )

            sig = self.manager._compute_signature(temp_path)
            alerts = self.manager.generate_alerts(sig.sha256)

            self.assertIsInstance(alerts, list)
        finally:
            os.unlink(temp_path)

    def test_calculate_maturity_score_no_records(self):
        """测试无记录时成熟度计算"""
        score = self.manager.calculate_maturity_score([])

        self.assertEqual(score, 0.0)

    def test_calculate_maturity_score_with_records(self):
        """测试有记录时成熟度计算"""
        sig = BinarySignature()
        metrics = SecurityMetrics(
            total_vulns=5,
            critical_vulns=1,
            hardening_score=80.0,
            attack_surface_score=30.0
        )

        record = AnalysisRecord(
            record_id="test",
            binary_signature=sig,
            version="1.0.0",
            analysis_timestamp=time.time(),
            metrics=metrics
        )

        score = self.manager.calculate_maturity_score([record])

        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 100.0)

    def test_generate_report_no_records(self):
        """测试无记录时报告生成"""
        report = self.manager.generate_report("nonexistent")

        self.assertEqual(report.total_versions, 0)
        self.assertIn("没有找到分析记录", report.alerts)

    def test_generate_report_with_records(self):
        """测试有记录时报告生成"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            metrics = SecurityMetrics(
                total_vulns=10,
                critical_vulns=2,
                attack_surface_score=65.0,
                hardening_score=70.0
            )

            self.manager.add_analysis_record(
                binary_path=temp_path,
                binary_name="report_test",
                version="1.0.0",
                metrics=metrics
            )

            sig = self.manager._compute_signature(temp_path)
            report = self.manager.generate_report(sig.sha256)

            self.assertEqual(report.binary_name, "report_test")
            self.assertGreater(report.total_versions, 0)
        finally:
            os.unlink(temp_path)

    def test_generate_recommendations(self):
        """测试建议生成"""
        records = []
        trends = []
        alerts = ["漏洞数增加: +5"]

        recommendations = self.manager._generate_recommendations(records, trends, alerts)

        self.assertIsInstance(recommendations, list)

    def test_export_report_json(self):
        """测试JSON导出"""
        report = LifecycleReport(
            binary_name="export_test",
            total_versions=1,
            analysis_period=(1000.0, 2000.0),
            current_metrics=SecurityMetrics()
        )

        temp_file = os.path.join(self.temp_dir, "report.json")
        success = self.manager.export_report_json(report, temp_file)

        self.assertTrue(success)
        self.assertTrue(os.path.exists(temp_file))

    def test_export_trend_csv_no_data(self):
        """测试无数据时CSV导出"""
        temp_file = os.path.join(self.temp_dir, "trends.csv")
        success = self.manager.export_trend_csv("nonexistent", temp_file)

        self.assertFalse(success)


class TestSeverity(unittest.TestCase):
    """Severity枚举测试"""

    def test_severity_values(self):
        """测试严重性等级"""
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")


class TestMetricType(unittest.TestCase):
    """MetricType枚举测试"""

    def test_metric_types(self):
        """测试指标类型"""
        self.assertEqual(MetricType.VULN_COUNT.value, "vulnerability_count")
        self.assertEqual(MetricType.ATTACK_SURFACE.value, "attack_surface")
        self.assertEqual(MetricType.HARDENING.value, "hardening_score")


class TestHelperFunctions(unittest.TestCase):
    """辅助函数测试"""

    def test_format_lifecycle_report(self):
        """测试报告格式化"""
        report = LifecycleReport(
            binary_name="format_test",
            total_versions=3,
            analysis_period=(1000.0, 5000.0),
            current_metrics=SecurityMetrics(
                total_vulns=10,
                critical_vulns=2,
                high_vulns=3,
                hardening_score=75.0
            ),
            maturity_score=85.0,
            recommendations=["保持当前安全实践"]
        )

        report_str = format_lifecycle_report(report)

        self.assertIn("format_test", report_str)
        self.assertIn("安全成熟度评分", report_str)


if __name__ == '__main__':
    unittest.main()
