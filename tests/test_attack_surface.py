
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import importlib.util

# 直接导入模块，避免通过 __init__.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接加载模块
module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'attack_surface.py')
spec = importlib.util.spec_from_file_location('attack_surface', module_path)
attack_surface = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attack_surface)

AttackSurfaceMapper = attack_surface.AttackSurfaceMapper
AttackSurfaceReport = attack_surface.AttackSurfaceReport
AttackSurfaceType = attack_surface.AttackSurfaceType
RiskLevel = attack_surface.RiskLevel


class TestAttackSurfaceMapper(unittest.TestCase):

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试文件
        self.temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.temp_file.write(b'\x7fELF\x02\x01\x01\x00')
        self.temp_file.close()

        # 创建包含网络相关字符串的测试文件
        self.network_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        network_content = b'bind listen accept recvfrom 192.168.1.1:8080 http://example.com'
        self.network_file.write(network_content)
        self.network_file.close()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
        if os.path.exists(self.network_file.name):
            os.unlink(self.network_file.name)

    def test_invalid_path(self):
        """测试无效路径"""
        mapper = AttackSurfaceMapper('/nonexistent/path/to/binary')
        result = mapper.analyze()
        self.assertFalse(result.analysis_success)
        self.assertIn('无效的文件路径', result.error_message)

    def test_empty_binary(self):
        """测试空文件"""
        mapper = AttackSurfaceMapper(self.temp_file.name)
        result = mapper.analyze()
        self.assertTrue(result.analysis_success)

    def test_network_interface_detection(self):
        mapper = AttackSurfaceMapper(self.network_file.name)
        result = mapper.analyze()

        self.assertTrue(result.analysis_success)

        # 检查是否检测到网络相关攻击面
        network_points = [p for p in result.surface_points
                          if p.surface_type == AttackSurfaceType.NETWORK_INTERFACE]
        self.assertGreaterEqual(len(network_points), 1)

    def test_file_operation_detection(self):
        file_content = b'/etc/config.txt /var/log/app.log C:\\Windows\\System32'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(file_content)
            test_path = f.name

        try:
            mapper = AttackSurfaceMapper(test_path)
            result = mapper.analyze()

            file_ops = [p for p in result.surface_points
                        if p.surface_type == AttackSurfaceType.FILE_OPERATION]
            self.assertGreaterEqual(len(file_ops), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_rpc_interface_detection(self):
        """测试RPC接口检测"""
        rpc_content = b'RpcServerRegister RpcServerListen grpc_initialize'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(rpc_content)
            test_path = f.name

        try:
            mapper = AttackSurfaceMapper(test_path)
            result = mapper.analyze()

            rpc_points = [p for p in result.surface_points
                          if p.surface_type == AttackSurfaceType.RPC_INTERFACE]
            self.assertGreaterEqual(len(rpc_points), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_risk_calculation(self):
        """测试风险计算"""
        mapper = AttackSurfaceMapper(self.network_file.name)
        result = mapper.analyze()

        self.assertTrue(result.analysis_success)

        # 检查风险评分是否在有效范围内
        for point in result.surface_points:
            self.assertGreaterEqual(point.risk_score, 0.0)
            self.assertLessEqual(point.risk_score, 100.0)

    def test_generate_report(self):
        """测试报告生成"""
        mapper = AttackSurfaceMapper(self.network_file.name)
        report_content = mapper.generate_report()

        self.assertIsNotNone(report_content)
        self.assertIn('攻击面分析报告', report_content)
        self.assertIn('目标文件', report_content)

    def test_report_to_dict(self):
        """测试报告转换为字典"""
        mapper = AttackSurfaceMapper(self.network_file.name)
        result = mapper.analyze()

        dict_result = result.to_dict()

        self.assertIn('binary_path', dict_result)
        self.assertIn('surface_points', dict_result)
        self.assertIn('high_risk_count', dict_result)
        self.assertIn('analysis_success', dict_result)



if __name__ == '__main__':
    unittest.main()
