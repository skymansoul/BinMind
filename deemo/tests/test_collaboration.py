import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from modules.collaboration import CollaborationManager, UserRole


class TestCollaborationManager(unittest.TestCase):
    """
    CollaborationManager 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        self.user_db_path = os.path.join(self.temp_dir, 'users.json')
        self.audit_log_path = os.path.join(self.temp_dir, 'audit.log')
        self.repo_base_path = os.path.join(self.temp_dir, 'repos')

        with patch('modules.collaboration.Config.USER_DB_PATH', self.user_db_path):
            with patch('modules.collaboration.Config.AUDIT_LOG_PATH', self.audit_log_path):
                with patch('modules.collaboration.Config.REPO_BASE_PATH', self.repo_base_path):
                    self.collab_manager = CollaborationManager()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_register_user_success(self):
        """测试用户注册成功"""
        result, user_id = self.collab_manager.register_user('testuser', 'password123')
        self.assertTrue(result)
        self.assertIsNotNone(user_id)

    def test_register_user_empty_username(self):
        """测试注册空用户名"""
        result, msg = self.collab_manager.register_user('', 'password123')
        self.assertFalse(result)
        self.assertIn('用户名', msg)

    def test_register_user_short_password(self):
        """测试注册短密码"""
        result, msg = self.collab_manager.register_user('testuser', '123')
        self.assertFalse(result)
        self.assertIn('密码', msg)

    def test_register_duplicate_user(self):
        """测试注册重复用户名"""
        self.collab_manager.register_user('testuser', 'password123')
        result, msg = self.collab_manager.register_user('testuser', 'password456')
        self.assertFalse(result)
        self.assertIn('已存在', msg)

    def test_authenticate_user_success(self):
        """测试用户认证成功"""
        self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.authenticate_user('testuser', 'password123')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_authenticate_user_invalid_password(self):
        """测试认证密码错误"""
        self.collab_manager.register_user('testuser', 'password123')
        user = self.collab_manager.authenticate_user('testuser', 'wrongpass')
        self.assertIsNone(user)

    def test_authenticate_nonexistent_user(self):
        """测试认证不存在的用户"""
        user = self.collab_manager.authenticate_user('nonexistent', 'password123')
        self.assertIsNone(user)

    def test_get_user_by_username(self):
        """测试通过用户名获取用户"""
        self.collab_manager.register_user('testuser', 'password123')

        user = self.collab_manager.get_user_by_username('testuser')
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')

    def test_get_user_by_id(self):
        """测试通过用户 ID 获取用户"""
        _, user_id = self.collab_manager.register_user('testuser', 'password123')

        user = self.collab_manager.get_user_by_id(user_id)
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, user_id)

    def test_delete_user(self):
        """测试删除用户"""
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('testuser', 'password123')

        result = self.collab_manager.delete_user(admin_id, user_id)
        self.assertTrue(result)

        user = self.collab_manager.get_user_by_id(user_id)
        self.assertIsNone(user)

    def test_update_user_role(self):
        """测试更新用户角色"""
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('testuser', 'password123')

        result = self.collab_manager.update_user_role(admin_id, user_id, UserRole.ADMIN)
        self.assertTrue(result)

        user = self.collab_manager.get_user_by_id(user_id)
        self.assertEqual(user.role, UserRole.ADMIN)

    def test_list_users(self):
        """测试获取用户列表"""
        self.collab_manager.register_user('user1', 'password1')
        self.collab_manager.register_user('user2', 'password2')

        users = self.collab_manager.list_users()
        self.assertEqual(len(users), 2)

    def test_add_project_member(self):
        """测试添加项目成员"""
        _, admin_id = self.collab_manager.register_user('admin', 'password123', UserRole.ADMIN)
        _, user_id = self.collab_manager.register_user('user', 'password123')

        # 需要先初始化仓库
        self.collab_manager.init_binary_repo('test_project', admin_id)
        result = self.collab_manager.add_project_member('test_project', user_id, UserRole.VIEWER)

        self.assertTrue(result)

    def test_add_comment(self):
        """测试添加评论"""
        _, user_id = self.collab_manager.register_user('user', 'password123')

        comment_id = self.collab_manager.add_comment(
            user_id=user_id,
            target_id='vuln_001',
            target_type='vulnerability',
            content='This is a test comment'
        )

        self.assertIsNotNone(comment_id)

    def test_get_comments(self):
        """测试获取评论列表"""
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
        """测试更新漏洞状态"""
        _, user_id = self.collab_manager.register_user('user', 'password123')

        result = self.collab_manager.update_vulnerability_status(
            user_id=user_id,
            vulnerability_id='vuln_001',
            status='confirmed'
        )

        self.assertTrue(result)

    def test_get_audit_logs(self):
        """测试获取审计日志"""
        _, user_id = self.collab_manager.register_user('user', 'password123')

        logs = self.collab_manager.get_audit_logs()
        self.assertIsInstance(logs, list)


if __name__ == '__main__':
    unittest.main()