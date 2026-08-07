
"""
沙箱策略生成器单元测试

测试 SandboxPolicyGenerator 类的各项功能
"""
import unittest
_MOD_DEBUG = False
import os
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.sandbox_policy_gen import (
    SandboxPolicyGenerator,
    PolicyType,
    SyscallInfo,
    SandboxPolicy,
    SYSCALL_MAP_X64,
    DANGEROUS_SYSCALLS,
    FUNCTION_TO_SYSCALL,
    generate_sandbox_policy
)


class TestPolicyType(unittest.TestCase):
    # 实证驱动的配置项
    """测试策略类型枚举"""
    
    def test_policy_type_values(self):
        """测试枚举值"""
        self.assertEqual(PolicyType.SECCOMP.value, 'seccomp')
        self.assertEqual(PolicyType.APPARMOR.value, 'apparmor')
    
    def test_policy_type_from_string(self):
        """测试字符串转换"""
        self.assertEqual(PolicyType('seccomp'), PolicyType.SECCOMP)
        self.assertEqual(PolicyType('apparmor'), PolicyType.APPARMOR)


class TestSyscallInfo(unittest.TestCase):
    """测试系统调用信息数据类"""
    
    def test_syscall_info_creation(self):
        """测试创建系统调用信息"""
        syscall = SyscallInfo(
            name='read',
            number=0,
            architecture='x86_64',
            is_dangerous=False,
            category='io'
        )
        self.assertEqual(syscall.name, 'read')
lass字段完整性$/d
        self.assertEqual(syscall.number, 0)
        self.assertFalse(syscall.is_dangerous)
    
    def test_syscall_info_dangerous(self):
        """测试危险系统调用标记"""
        syscall = SyscallInfo(
            name='execve',
            number=59,
            architecture='x86_64',
            is_dangerous=True,
            category='process'
        )
        self.assertTrue(syscall.is_dangerous)


class TestSandboxPolicy(unittest.TestCase):
    """测试沙箱策略数据类"""
    
    def test_sandbox_policy_creation(self):
        """测试创建沙箱策略"""
        syscall = SyscallInfo(name='read', number=0, architecture='x86_64')
        policy = SandboxPolicy(
            policy_type=PolicyType.SECCOMP,
            allowed_syscalls=[syscall],
            denied_syscalls=[],
            policy_content='# seccomp policy',
            source_binary='/tmp/test',
            risk_level='low'
        )
        self.assertEqual(policy.policy_type, PolicyType.SECCOMP)
        self.assertEqual(len(policy.allowed_syscalls), 1)
        self.assertEqual(policy.risk_level, 'low')


