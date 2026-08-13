
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
# lass字段完整性$/d
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




class TestSandboxPolicyGenerator(unittest.TestCase):
    """测试沙箱策略生成器"""
    
    def setUp(self):
        self.generator = SandboxPolicyGenerator()
        self.m_tmp = tempfile.mkdtemp()
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)
    
    def test_generate_seccomp_policy(self):
        """测试生成seccomp策略"""
        syscalls = [
            SyscallInfo(name='read', number=0, architecture='x86_64'),
            SyscallInfo(name='write', number=1, architecture='x86_64'),
            SyscallInfo(name='exit', number=60, architecture='x86_64'),
        ]
        
        policy_content = self.generator._generate_seccomp_policy(syscalls)
        
        # 检查策略内容
        self.assertIn('SCMP_ACT_ALLOW', policy_content)
        self.assertIn('read', policy_content)
        self.assertIn('write', policy_content)
    
    def test_generate_apparmor_policy(self):
        """测试生成AppArmor策略"""
        syscalls = [
            SyscallInfo(name='read', number=0, architecture='x86_64'),
            SyscallInfo(name='write', number=1, architecture='x86_64'),
        ]
        file_paths = ['/tmp/input', '/tmp/output']
        
        policy_content = self.generator._generate_apparmor_policy(
            syscalls, file_paths, network_permissions={'outbound': ['80']}
        )
        
        # 检查策略内容
        self.assertIn('profile', policy_content)
        self.assertIn('/tmp/input', policy_content)
    
    def test_infer_syscalls_from_imports(self):
        imports = ['printf', 'malloc', 'fopen', 'socket']
        
        syscalls = self.generator._infer_syscalls_from_imports(imports)
        
        # 检查推断结果
        self.assertIsInstance(syscalls, list)
        # fopen应该映射到open syscall
# lass字段完整性$/d
        self.assertTrue(any(s.name in ['open', 'openat'] for s in syscalls))
    
    def test_get_syscall_number(self):
        """测试获取系统调用号"""
        number = self.generator._get_syscall_number('read', 'x86_64')
        self.assertEqual(number, 0)
        
        number = self.generator._get_syscall_number('write', 'x86_64')
        self.assertEqual(number, 1)
        
        number = self.generator._get_syscall_number('execve', 'x86_64')
        self.assertEqual(number, 59)
    
    def test_identify_dangerous_syscalls(self):
        """测试识别危险系统调用"""
        syscalls = [
            SyscallInfo(name='read', number=0, architecture='x86_64'),
            SyscallInfo(name='execve', number=59, architecture='x86_64'),
            SyscallInfo(name='ptrace', number=101, architecture='x86_64'),
        ]
        
        dangerous = self.generator._identify_dangerous_syscalls(syscalls)
        
        # execve和ptrace应该被标记为危险
        self.assertTrue(any(s.name == 'execve' for s in dangerous))
        self.assertTrue(any(s.name == 'ptrace' for s in dangerous))
    
    def test_generate_policy_for_nonexistent_file(self):
        """测试为不存在文件生成策略"""
        result = self.generator.generate_policy('/nonexistent/file')
        self.assertIn('error', result)
    
    def test_save_policy(self):
        """测试保存策略"""
        policy = SandboxPolicy(
            policy_type=PolicyType.SECCOMP,
            allowed_syscalls=[],
            denied_syscalls=[],
            policy_content='# test policy',
            source_binary='/tmp/test',
            risk_level='low'
        )
        
        output_path = os.path.join(self.m_tmp, 'test_policy.txt')
        saved_path = self.generator._save_policy(policy, output_path)
        
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, 'r') as f:
            content = f.read()
            self.assertIn('test policy', content)
    
    def test_default_deny_policy(self):
        syscalls = [
            SyscallInfo(name='read', number=0, architecture='x86_64'),
        ]
        
        # 使用默认拒绝模式
        policy_content = self.generator._generate_seccomp_policy(
            syscalls, default_deny=True
        )
        
        # 应包含默认拒绝动作
        self.assertIn('SCMP_ACT_KILL', policy_content)


class TestSyscallMaps(unittest.TestCase):
    """测试系统调用映射表"""
    
    def test_syscall_map_x64_exist(self):
        """测试x86_64系统调用映射存在"""
        self.assertIn('read', SYSCALL_MAP_X64)
        self.assertIn('write', SYSCALL_MAP_X64)
        self.assertIn('execve', SYSCALL_MAP_X64)
    
    def test_dangerous_syscalls_exist(self):
        """测试危险系统调用列表存在"""
        self.assertIn('execve', DANGEROUS_SYSCALLS)
        self.assertIn('ptrace', DANGEROUS_SYSCALLS)
        self.assertIn('mount', DANGEROUS_SYSCALLS)
    
    def test_function_to_syscall_mapping(self):
        self.assertIn('fopen', FUNCTION_TO_SYSCALL)
        self.assertIn('socket', FUNCTION_TO_SYSCALL)
    
    def test_syscall_numbers_correct(self):
        """测试系统调用号正确性"""
        # x86_64架构的系统调用号
        self.assertEqual(SYSCALL_MAP_X64['read'], 0)
        self.assertEqual(SYSCALL_MAP_X64['write'], 1)
        self.assertEqual(SYSCALL_MAP_X64['open'], 2)
        self.assertEqual(SYSCALL_MAP_X64['execve'], 59)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""
    
    def test_generate_sandbox_policy_function(self):
        # 创建测试文件
        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, 'test_binary')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)  # 模拟ELF
        
        result = generate_sandbox_policy(test_file, policy_type='seccomp')
        self.assertIsInstance(result, dict)
        
        # 清理
        import shutil
        shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):
    """测试输入校验"""
    
    def test_path_traversal_prevention(self):
        """测试路径遍历防护"""
        generator = SandboxPolicyGenerator()
        
        malicious_path = '../../../etc/passwd'
        result = generator.generate_policy(malicious_path)
        self.assertIn('error', result)
    
    def test_invalid_policy_type(self):
        """测试无效策略类型"""
        generator = SandboxPolicyGenerator()
        
        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, 'test')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        # 无效策略类型应该使用默认值
        result = generator.generate_policy(test_file, policy_type='invalid')
        self.assertIsNotNone(result)
        
        import shutil
        shutil.rmtree(temp_dir)


class TestPolicyRiskAssessment(unittest.TestCase):
    """测试策略风险评估"""
    
    def test_high_risk_syscalls(self):
        """测试高风险系统调用"""
        generator = SandboxPolicyGenerator()
        
        syscalls = [
            SyscallInfo(name='execve', number=59, architecture='x86_64', is_dangerous=True),
            SyscallInfo(name='ptrace', number=101, architecture='x86_64', is_dangerous=True),
        ]
        
        risk_level = generator._assess_risk_level(syscalls)
        self.assertEqual(risk_level, 'high')
    
    def test_low_risk_syscalls(self):
        """测试低风险系统调用"""
        generator = SandboxPolicyGenerator()
        
        syscalls = [
            SyscallInfo(name='read', number=0, architecture='x86_64'),
            SyscallInfo(name='write', number=1, architecture='x86_64'),
        ]
        
        risk_level = generator._assess_risk_level(syscalls)
        self.assertEqual(risk_level, 'low')



if __name__ == '__main__':
    unittest.main()


