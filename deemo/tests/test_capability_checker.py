"""
符号执行权限/能力模型违规检测模块测试
"""

import pytest
from modules.capability_checker import CapabilityChecker, Capability, Component, IPCInterface, CapabilityLevel


class TestCapabilityChecker:
    """能力检查器测试类"""
    
    def test_analyze_basic(self):
        """测试基本分析功能"""
        checker = CapabilityChecker()
        
        capabilities = [
            {'name': 'android.permission.ACCESS_FINE_LOCATION', 'level': 'high'},
            {'name': 'android.permission.INTERNET', 'level': 'low'},
            {'name': 'android.permission.SYSTEM_ALERT_WINDOW', 'level': 'system'},
        ]
        
        components = [
            {
                'name': 'com.example.app.MainActivity',
                'capabilities': ['android.permission.INTERNET'],
                'interfaces': ['com.example.service.LocationService'],
                'security_level': 'low'
            },
            {
                'name': 'com.example.service.LocationService',
                'capabilities': ['android.permission.ACCESS_FINE_LOCATION'],
                'security_level': 'high'
            }
        ]
        
        interfaces = [
            {
                'name': 'com.example.service.LocationService',
                'provider': 'com.example.service.LocationService',
                'required_capabilities': ['android.permission.ACCESS_FINE_LOCATION'],
                'exposed_capabilities': ['android.permission.ACCESS_FINE_LOCATION'],
                'ipc_type': 'binder'
            }
        ]
        
        result = checker.analyze(
            binary_path='/system/framework/framework.jar',
            ipc_type='binder',
            capabilities=capabilities,
            components=components,
            interfaces=interfaces
        )
        
        assert result['success'] is True
        assert 'violations' in result
        assert 'summary' in result
    
    def test_check_capability_violation(self):
        """测试能力违规检测"""
        checker = CapabilityChecker()
        
        # 设置能力模型
        checker.graph.capabilities['high_cap'] = Capability(
            name='high_cap',
            level=CapabilityLevel.HIGH
        )
        
        source = Component(
            name='low_component',
            capabilities={'low_cap'},
            security_level=CapabilityLevel.LOW
        )
        
        iface = IPCInterface(
            name='high_interface',
            provider='high_component',
            required_capabilities={'high_cap'},
            exposed_capabilities={'high_cap'}
        )
        
        target = Component(
            name='high_component',
            capabilities={'high_cap'},
            security_level=CapabilityLevel.HIGH
        )
        
        violation = checker._check_capability_violation(source, iface, target)
        
        assert violation is not None
        assert 'high_cap' in violation.missing_capabilities
    
    def test_calculate_exploitability(self):
        """测试可利用性计算"""
        checker = CapabilityChecker()
        
        exploitability = checker._calculate_exploitability(
            missing_caps={'cap1', 'cap2'},
            has_escalation=True
        )
        
        assert 0.0 <= exploitability <= 1.0
        assert exploitability > 0.5
    
    def test_find_privilege_escalation(self):
        """测试权限提升路径查找"""
        checker = CapabilityChecker()
        
        # 设置测试数据
        checker.graph.nodes['low_comp'] = Component(
            name='low_comp',
            capabilities={'basic'},
            interfaces=['high_iface'],
            security_level=CapabilityLevel.LOW
        )
        
        checker.graph.nodes['high_comp'] = Component(
            name='high_comp',
            capabilities={'admin'},
            security_level=CapabilityLevel.HIGH
        )
        
        checker.graph.interfaces['high_iface'] = IPCInterface(
            name='high_iface',
            provider='high_comp',
            exposed_capabilities={'admin'}
        )
        
        violations = checker._find_privilege_escalation_paths()
        
        assert isinstance(violations, list)
    
    def test_metadata(self):
        """测试元数据获取"""
        metadata = CapabilityChecker.get_metadata()
        
        assert metadata.name == "CapabilityChecker"
        assert metadata.type.value == "vulnerability_detector"


class TestCapabilityLevel:
    """权限级别测试类"""
    
    def test_level_hierarchy(self):
        """测试权限级别层次"""
        levels = [CapabilityLevel.NONE, CapabilityLevel.LOW, 
                  CapabilityLevel.MEDIUM, CapabilityLevel.HIGH, 
                  CapabilityLevel.SYSTEM]
        
        for i in range(len(levels) - 1):
            assert levels[i].value < levels[i+1].value