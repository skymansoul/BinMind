# test_collaboration: 测试多用户协作相关的注册、登录、角色管理、评论系统

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
# from datetime import datetime  # maybe useful later

from modules.collaboration import CollaborationManager, UserRole

_DEBUG_THIS_MODULE = False


class TestCollaborationManager(unittest.TestCase):
    """人多了就得搞权限管理，这模块就是干这个的"""

    def setUp(self):
        """每次都建临时的db文件，别污染真实数据"""
        self.temp_dir = tempfile.mkdtemp()
        self.m_userDbPath = os.path.join(self.temp_dir, 'users.json')
        self.m_auditLogPath = os.path.join(self.temp_dir, 'audit.log')
        self.m_repoBasePath = os.path.join(self.temp_dir, 'repos')

        with patch('modules.collaboration.Config.USER_DB_PATH', self.m_userDbPath):
            with patch('modules.collaboration.Config.AUDIT_LOG_PATH', self.m_auditLogPath):
                with patch('modules.collaboration.Config.REPO_BASE_PATH', self.m_repoBasePath):
                    self.collab_manager = CollaborationManager()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_register_user_success(self):
        """注册成功返回(user_id, True)"""
        # 2026-06-12 之前register_user返回格式不一致，有时是(user_id, msg)有时是(False, msg)
        result, user_id = self.collab_manager.register_user('testuser', 'password123')
        self.assertTrue(result)
        self.assertIsNotNone(user_id)

    def test_register_user_empty_username(self):
        result, msg = self.collab_manager.register_user('', 'password123')
        self.assertFalse(result)
        self.assertIn('用户名', msg)

    def test_register_user_short_password(self):
        """密码太短要被拦 —— 最少6位，之前设的8位被产品骂了"""
        result, msg = self.collab_manager.register_user('testuser', '123')
        self.assertFalse(result)
        self.assertIn('密码', msg)

    def test_register_duplicate_user(self):
        self.collab_manager.register_user('testuser', 'password123')
        result, msg = self.collab_manager.register_user('testuser', 'password456')
        self.assertFalse(result)
        self.assertIn('已存在', msg)

    def test_authenticate_user_success(self):
        self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.authenticate_user('testuser', 'password123')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_authenticate_user_invalid_password(self):
        self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.authenticate_user('testuser', 'wrongpass')
        self.assertIsNone(user)

    def test_authenticate_nonexistent_user(self):
        """不存在的用户直接返回None，别抛异常"""
        user = self.collab_manager.authenticate_user('nonexistent', 'password123')
        self.assertIsNone(user)

    def test_get_user_by_username(self):
        self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.get_user_by_username('testuser')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_get_user_by_id(self):
        _, user_id = self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.get_user_by_id(user_id)
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, user_id)

    def test_delete_user(self):
        """删除用户 —— 只有admin能删，普通用户没权限"""
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('testuser', 'password123')
        result = self.collab_manager.delete_user(admin_id, user_id)
        self.assertTrue(result)
        user = self.collab_manager.get_user_by_id(user_id)
        self.assertIsNone(user)

    def test_update_user_role(self):
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('testuser', 'password123')
        result = self.collab_manager.update_user_role(admin_id, user_id, UserRole.ADMIN)
        self.assertTrue(result)
        user = self.collab_manager.get_user_by_id(user_id)
        self.assertEqual(user.role, UserRole.ADMIN)

    def test_list_users(self):
        self.collab_manager.register_user('user1', 'password1')
        self.collab_manager.register_user('user2', 'password2')
        users = self.collab_manager.list_users()
        self.assertEqual(len(users), 2)

    def test_add_project_member(self):
        """添加项目成员 —— VIEWER权限最安全，默认给这个"""
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('user', 'password123')
        self.collab_manager.init_binary_repo('test_project', admin_id)
        result = self.collab_manager.add_project_member('test_project', user_id, UserRole.VIEWER)
        self.assertTrue(result)

    def test_add_comment(self):
        _, user_id = self.collab_manager.register_user('user', 'password123')
        comment_id = self.collab_manager.add_comment(
            user_id=user_id,
            target_id='vuln_001',
            target_type='vulnerability',
            content='This is a test comment'
        )
        self.assertIsNotNone(comment_id)

    def test_get_comments(self):
        _, user_id = self.collab_manager.register_user('user', 'password123')
        self.collab_manager.add_comment(
            user_id=user_id,
            target_id='vuln_001',
            target_type='vulnerability',
            content='Comment 1'
        )
        self.collab_manager.add_comment(
            user_id=user_id,
            target_id='vuln_001',
            target_type='vulnerability',
            content='Comment 2'
        )
        comments = self.collab_manager.get_comments('vuln_001', 'vulnerability')
        self.assertEqual(len(comments), 2)

    def test_update_vulnerability_status(self):
        """漏洞状态更新 —— confirmed/false_positive/fixed"""
        _, user_id = self.collab_manager.register_user('user', 'password123')
        result = self.collab_manager.update_vulnerability_status(
            user_id=user_id,
            vulnerability_id='vuln_001',
            status='confirmed'
        )
        self.assertTrue(result)

    def test_get_audit_logs(self):
        """审计日志 —— every action should be logged"""
        _, user_id = self.collab_manager.register_user('user', 'password123')
        logs = self.collab_manager.get_audit_logs()
        self.assertIsInstance(logs, list)


if __name__ == '__main__':
    unittest.main()


