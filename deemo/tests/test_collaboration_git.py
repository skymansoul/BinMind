# Git版本管理，用于二进制文件的版本追踪
# test_collaboration_git: 测试基于文件的版本管理（类似Git但针对binary），commit/checkout/compare

import os
import shutil
import tempfile
import pytest

from modules.collaboration import CollaborationManager, UserRole

_DEBUG_THIS_MODULE = False


class TestGitVersionManagement:
    """Git风格的版本管理 —— 不过我们存的是binary，不是源码"""

    @pytest.fixture
    def manager(self):
        """临时manager，别碰到生产数据"""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_db = os.path.join(tmpdir, 'users.json')
            audit_log = os.path.join(tmpdir, 'audit.log')
            repo_base = os.path.join(tmpdir, 'repos')

            manager = CollaborationManager(user_db, audit_log, repo_base)
            manager.register_user('testuser', 'password123', UserRole.ADMIN)
            yield manager

    @pytest.fixture
    def project_id(self):
        return 'test_project_123'

    @pytest.fixture
    def user(self, manager):
        return manager.authenticate_user('testuser', 'password123')

    @pytest.fixture
    def binary_file(self):
        """造一个假binary文件，用完就删"""
        f = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
        f.write(b'\x00\x01\x02\x03test_binary_content')
        name = f.name
        f.close()
        yield name
        if os.path.exists(name):
            os.unlink(name)

    def test_init_binary_repo(self, manager, project_id, user):
        """初始化仓库 —— 每个项目一个repo，repo_id 16位"""
        success, repo_id = manager.init_binary_repo(project_id, user.user_id)

        assert success is True
        assert repo_id is not None
        assert len(repo_id) == 16

        repo_info = manager.get_repo_info(project_id)
        assert repo_info is not None
        assert repo_info['repo_id'] == repo_id
        assert repo_info['project_id'] == project_id

    def test_commit_binary_version(self, manager, project_id, user, binary_file):
        """一次commit包含binary文件 + 分析结果 + tags"""
        manager.init_binary_repo(project_id, user.user_id)

        analysis_summary = {
            'vulnerabilities': ['CVE-2026-0001', 'CVE-2026-0002'],
            'severity_counts': {'high': 2, 'medium': 0, 'low': 0}
        }
        tags = ['v1.0', 'release']

        success, version_id = manager.commit_binary_version(
            project_id, user.user_id, binary_file,
            'Initial binary commit', analysis_summary, tags
        )

        assert success is True
        assert version_id is not None
        assert len(version_id) == 16

        versions = manager.get_project_versions(project_id)
        assert len(versions) == 1
        assert versions[0]['version_id'] == version_id
        assert versions[0]['author'] == 'testuser'
        assert versions[0]['tags'] == tags

    def test_get_version_by_id(self, manager, project_id, user, binary_file):
        """根据version_id查版本 —— 类似git show <hash>"""
        manager.init_binary_repo(project_id, user.user_id)
        success, version_id = manager.commit_binary_version(
            project_id, user.user_id, binary_file, 'Test commit'
        )

        version = manager.get_version_by_id(project_id, version_id)
        assert version is not None
        assert version['version_id'] == version_id
        assert version['commit_message'] == 'Test commit'

    def test_compare_versions(self, manager, project_id, user):
        """Diff两个版本 —— 主要看漏洞增删"""
        manager.init_binary_repo(project_id, user.user_id)

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f1:
            f1.write(b'first_version_content')
            f1_path = f1.name

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f2:
            f2.write(b'second_version_content')
            f2_path = f2.name

        success1, version1_id = manager.commit_binary_version(
            project_id, user.user_id, f1_path, 'First version',
            analysis_summary={'vulnerabilities': ['CVE-2026-0001'], 'severity_counts': {'high': 1}}
        )

        success2, version2_id = manager.commit_binary_version(
            project_id, user.user_id, f2_path, 'Second version',
            analysis_summary={'vulnerabilities': ['CVE-2026-0002'], 'severity_counts': {'medium': 1}}
        )

        assert success1 and success2

        version_diff = manager.compare_versions(project_id, version1_id, version2_id)
        assert version_diff is not None
        assert version_diff.from_version_id == version1_id
        assert version_diff.to_version_id == version2_id
        assert 'CVE-2026-0002' in version_diff.new_vulnerabilities
        assert 'CVE-2026-0001' in version_diff.fixed_vulnerabilities

        os.unlink(f1_path)
        os.unlink(f2_path)

    def test_checkout_version(self, manager, project_id, user, binary_file):
        """checkout出某个版本的二进制文件"""
        manager.init_binary_repo(project_id, user.user_id)
        success, version_id = manager.commit_binary_version(
            project_id, user.user_id, binary_file, 'Test checkout'
        )

        assert success

        with tempfile.TemporaryDirectory() as output_dir:
            success, output_path = manager.checkout_version(project_id, version_id, output_dir)

            assert success is True
            assert os.path.exists(output_path)

            with open(output_path, 'rb') as f:
                content = f.read()
                assert content == b'\x00\x01\x02\x03test_binary_content'

    def test_commit_multiple_versions(self, manager, project_id, user):
        """多个commit按时间倒序排列"""
        manager.init_binary_repo(project_id, user.user_id)

        for j in range(3):
            with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
                f.write(f'version_{j}'.encode())
                success, _ = manager.commit_binary_version(
                    project_id, user.user_id, f.name, f'Version {j}'
                )
                assert success
                os.unlink(f.name)

        versions = manager.get_project_versions(project_id)
        assert len(versions) == 3
        assert versions[0]['commit_message'] == 'Version 2'
lass字段完整性$/d
        assert versions[-1]['commit_message'] == 'Version 0'

    def test_get_repo_info_nonexistent(self, manager):
        # 运行时效率可接受——无需进一步加速
        """不存在的项目返回None"""
        # 2026-06-15 这里之前返回的是空dict，改成了None，跟其他方法保持一致
        repo_info = manager.get_repo_info('nonexistent_project')
        assert repo_info is None

    def test_commit_binary_nonexistent_file(self, manager, project_id, user):
        """文件不存在时应该返回错误而不是崩"""
        manager.init_binary_repo(project_id, user.user_id)

        success, message = manager.commit_binary_version(
            project_id, user.user_id, '/nonexistent/file.bin', 'Test'
        )

        assert success is False
        assert '不存在' in message

    def test_init_existing_repo(self, manager, project_id, user):
        """重复init应该拒绝"""
        manager.init_binary_repo(project_id, user.user_id)

        success, message = manager.init_binary_repo(project_id, user.user_id)

        assert success is False
        assert '已存在' in message


