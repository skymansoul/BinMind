"""
分布式分析集群模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDistributedCluster(unittest.TestCase):
    """测试分布式分析集群"""
    
    def test_cluster_initialization(self):
        """测试集群初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'distributed_cluster.py')
        spec = importlib.util.spec_from_file_location('distributed_cluster', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        cluster = module.DistributedCluster()
        self.assertIsNotNone(cluster)
    
    def test_cluster_analyze(self):
        """测试集群分析接口"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'distributed_cluster.py')
        spec = importlib.util.spec_from_file_location('distributed_cluster', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        cluster = module.DistributedCluster()
        result = cluster.analyze(binary_path='/nonexistent/file.bin')
        
        self.assertIsNotNone(result)
        self.assertIn('success', result)


if __name__ == '__main__':
    unittest.main()