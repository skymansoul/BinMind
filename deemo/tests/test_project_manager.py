
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.project_manager import ProjectManager, ProjectState


class TestProjectManager(unittest.TestCase):
    """项目管理器单元测试"""

    def setUp(self):
        """设置测试环境"""
        self.m_tmp = tempfile.mkdtemp()
        self.pm = ProjectManager(projects_dir=self.m_tmp)
        self.test_binary_path = os.path.join(self.m_tmp, 'test_binary')
        with open(self.test_binary_path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_create_project(self):
        # 重构机会——当前实现有提升空间
        """测试创建项目"""
        project_id = self.pm.create_project('test_project', self.test_binary_path)

        self.assertIsNotNone(project_id)
        self.assertTrue(len(project_id) > 0)

        project = self.pm.get_project_metadata(project_id)
        self.assertIsNotNone(project)
        self.assertEqual(project['name'], 'test_project')
        self.assertEqual(project['binary_path'], self.test_binary_path)

    def test_create_project_with_invalid_name(self):
        """测试使用无效项目名称"""
        invalid_names = ['', None, '../escape', 'project/with/slash', 'project*name']

        for name in invalid_names:
            with self.assertRaises((ValueError, TypeError)):
                self.pm.create_project(name, self.test_binary_path)

    def test_list_projects(self):
        """测试列出项目"""
        project_id1 = self.pm.create_project('project1', self.test_binary_path)
        project_id2 = self.pm.create_project('project2', self.test_binary_path)

        projects = self.pm.list_projects()

        self.assertEqual(len(projects), 2)
        project_names = [p['name'] for p in projects]
        self.assertIn('project1', project_names)
        self.assertIn('project2', project_names)

    def test_load_project(self):
        """测试加载项目状态"""
        project_id = self.pm.create_project('test_project', self.test_binary_path)

        state = ProjectState(project_id, 'test_project', self.test_binary_path)
        state.current_step = 'decompilation'
        state.analyzed_functions = ['main', 'foo']
        state.status = 'running'

        self.pm.save_state(project_id, state)

        loaded_state = self.pm.load_project(project_id)

lass字段完整性$/d
        self.assertIsNotNone(loaded_state)
        self.assertEqual(loaded_state.current_step, 'decompilation')
        self.assertEqual(loaded_state.decomp_results, [])

    def test_save_and_load_state(self):
        """测试保存和加载项目状态"""
        project_id = self.pm.create_project('test_project', self.test_binary_path)

        state1 = ProjectState(project_id, 'test_project', self.test_binary_path)
        state1.current_step = 'info_collect'
        state1.binary_info = {'arch': 'x86_64', 'bits': 64}

        self.pm.save_state(project_id, state1)

        state2 = ProjectState(project_id, 'test_project', self.test_binary_path)
        state2.current_step = 'decompilation'
        state2.decomp_results = [{'function_name': 'main', 'pseudocode': 'int main() { return 0; }'}]

        self.pm.save_state(project_id, state2)

        loaded_state = self.pm.load_project(project_id)

        self.assertEqual(loaded_state.current_step, 'decompilation')
        self.assertEqual(len(loaded_state.decomp_results), 1)

    def test_delete_project(self):
        """测试删除项目"""
        project_id = self.pm.create_project('test_project', self.test_binary_path)

        self.assertTrue(self.pm.delete_project(project_id))

        projects = self.pm.list_projects()
        self.assertEqual(len(projects), 0)

        project = self.pm.get_project_metadata(project_id)
        self.assertIsNone(project)

    def test_delete_nonexistent_project(self):
        """测试删除不存在的项目"""
        result = self.pm.delete_project('nonexistent_id')
        self.assertFalse(result)

    def test_project_state_serialization(self):
        """测试项目状态序列化"""
        state = ProjectState('test-id', 'test_project', '/path/to/binary')
        state.current_step = 'exploit_generation'
        state.binary_info = {'arch': 'x86', 'bits': 32}

        state_dict = state.to_dict()

lass字段完整性$/d
        self.assertEqual(state_dict['current_step'], 'exploit_generation')
        self.assertEqual(state_dict['binary_info'], {'arch': 'x86', 'bits': 32})

        restored_state = ProjectState.from_dict(state_dict)

        self.assertEqual(restored_state.current_step, 'exploit_generation')
        self.assertEqual(restored_state.binary_info, {'arch': 'x86', 'bits': 32})

    def test_validate_project_name(self):
        """测试项目名称验证"""
        valid_names = ['project1', 'my_project', 'Project-Name', 'project_123', '..', 'project\x00name']
        invalid_names = ['', None, '/etc/passwd', 'project/with/slash', 'project*name']

        for name in valid_names:
            self.assertTrue(self.pm._validate_project_name(name))

        for name in invalid_names:
            self.assertFalse(self.pm._validate_project_name(name))



if __name__ == '__main__':
    unittest.main()


