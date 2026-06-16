"""
精确虚表恢复模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestPreciseVTableRecovery(unittest.TestCase):
    """测试精确虚表恢复"""
    
    def test_recoverer_initialization(self):
        """测试恢复器初始化"""
        from modules.precise_vtable_recovery import PreciseVTableRecovery
        
        recoverer = PreciseVTableRecovery('/path/to/binary')
        self.assertIsNotNone(recoverer)
    
    def test_recover_vtables(self):
        """测试虚表恢复"""
        from modules.precise_vtable_recovery import PreciseVTableRecovery
        
        recoverer = PreciseVTableRecovery('/path/to/binary')
        result = recoverer.recover_vtables()
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
