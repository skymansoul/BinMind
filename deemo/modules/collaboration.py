import os
import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass
class User:
    """用户数据类"""
    user_id: str
    username: str
    password_hash: str
    role: UserRole
    created_at: str
    last_login_at: Optional[str] = None


@dataclass
class ProjectMember:
    """项目成员"""
    user_id: str
    username: str
    role: UserRole
    joined_at: str


@dataclass
class AuditLogEntry:
    """审计日志条目"""
    timestamp: str
    user_id: str
    username: str
    action: str
    target_id: str
    target_type: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None


@dataclass
class Comment:
    """注释"""
    comment_id: str
    user_id: str
    username: str
    target_id: str
    target_type: str
    content: str
    created_at: str


@dataclass
class VulnerabilityStatus:
    """漏洞状态"""
    vulnerability_id: str
    status: str
    updated_by: str
    updated_at: str
    comment: Optional[str] = None


@dataclass
class GitRepository:
    """Git仓库配置"""
    repo_id: str
    project_id: str
    repo_path: str
    remote_url: Optional[str] = None
    initialized_at: str = ""
    last_commit_hash: Optional[str] = None


@dataclass
class BinaryVersion:
    """二进制版本信息"""
    version_id: str
    project_id: str
    binary_hash: str
    commit_hash: str
    commit_message: str
    author: str
    timestamp: str
    analysis_summary: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


@dataclass
class VersionDiff:
    """版本差异信息"""
    project_id: str
    from_version_id: str
    to_version_id: str
    from_commit: str
    to_commit: str
    changed_functions: List[str]
    new_vulnerabilities: List[str]
    fixed_vulnerabilities: List[str]
    severity_changes: List[Dict[str, Any]]


class CollaborationManager:
    """
    多用户协作与审计追踪模块
    
    核心功能：
    1. 用户管理（注册、登录、角色管理）
    2. 项目协作（多人加入、权限控制）
    3. 审计追踪（操作日志记录）
    4. 注释与漏洞状态管理
    5. Git-based 二进制版本管理
    """
    
    def __init__(self, user_db_path: str = None, audit_log_path: str = None, repo_base_path: str = None):
        """
        初始化协作管理器
        
        Args:
            user_db_path: 用户数据库文件路径
            audit_log_path: 审计日志文件路径
            repo_base_path: Git仓库基础路径
        """
        self.user_db_path = user_db_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'users.json'
        )
        self.audit_log_path = audit_log_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'audit.log'
        )
        self.repo_base_path = repo_base_path or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'repos'
        )
        
        os.makedirs(os.path.dirname(self.user_db_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        os.makedirs(self.repo_base_path, exist_ok=True)
        
        self._users: Dict[str, User] = {}
        self._project_members: Dict[str, List[ProjectMember]] = {}
        self._comments: Dict[str, List[Comment]] = {}
        self._vuln_status: Dict[str, VulnerabilityStatus] = {}
        
        self._git_repos: Dict[str, GitRepository] = {}
        self._binary_versions: Dict[str, List[BinaryVersion]] = {}
        
        self._load_users()
        self._load_git_repos()
        logger.info(f"CollaborationManager 初始化完成，已加载 {len(self._users)} 个用户")
    
    def _load_users(self):
        """加载用户数据"""
        if os.path.exists(self.user_db_path):
            try:
                with open(self.user_db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for user_id, user_data in data.items():
                        self._users[user_id] = User(
                            user_id=user_id,
                            username=user_data['username'],
                            password_hash=user_data['password_hash'],
                            role=UserRole(user_data['role']),
                            created_at=user_data['created_at'],
                            last_login_at=user_data.get('last_login_at')
                        )
            except Exception as e:
                logger.error(f"加载用户数据失败: {e}")
    
    def _save_users(self):
        """保存用户数据"""
        try:
            data = {}
            for user_id, user in self._users.items():
                data[user_id] = {
                    'username': user.username,
                    'password_hash': user.password_hash,
                    'role': user.role.value,
                    'created_at': user.created_at,
                    'last_login_at': user.last_login_at
                }
            
            with open(self.user_db_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"保存用户数据失败: {e}")
    
    def _hash_password(self, password: str) -> str:
        """哈希密码"""
        try:
            import bcrypt
            return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        except ImportError:
            logger.warning("bcrypt 未安装，使用简单哈希")
            return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def _verify_password(self, password: str, hash_value: str) -> bool:
        """验证密码"""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), hash_value.encode('utf-8'))
        except ImportError:
            logger.warning("bcrypt 未安装，使用简单哈希验证")
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hash_value
    
    def register_user(self, username: str, password: str, role: UserRole = UserRole.VIEWER) -> Tuple[bool, str]:
        """
        注册新用户
        
        Args:
            username: 用户名
            password: 密码
            role: 用户角色
            
        Returns:
            (success, message/user_id)
        """
        if not username or not password:
            return False, "用户名和密码不能为空"
        
        if len(username) < 3 or len(username) > 50:
            return False, "用户名长度必须在3-50个字符之间"
        
        if len(password) < 6:
            return False, "密码长度至少为6个字符"
        
        if any(user.username == username for user in self._users.values()):
            return False, "用户名已存在"
        
        user_id = hashlib.md5(username.encode('utf-8')).hexdigest()[:16]
        
        user = User(
            user_id=user_id,
            username=username,
            password_hash=self._hash_password(password),
            role=role,
            created_at=datetime.now().isoformat()
        )
        
        self._users[user_id] = user
        self._save_users()
        
        self._log_audit(user_id, username, 'USER_CREATE', user_id, 'user', {
            'username': username,
            'role': role.value
        })
        
        logger.info(f"用户注册成功: {username}")
        return True, user_id
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        验证用户身份
        
        Args:
            username: 用户名
            password: 密码
            
        Returns:
            用户对象，如果验证失败返回 None
        """
        for user in self._users.values():
            if user.username == username:
                if self._verify_password(password, user.password_hash):
                    user.last_login_at = datetime.now().isoformat()
                    self._save_users()
                    
                    self._log_audit(user.user_id, username, 'USER_LOGIN', user.user_id, 'user', {})
                    
                    logger.info(f"用户登录成功: {username}")
                    return user
        
        logger.warning(f"登录失败: 用户名或密码错误: {username}")
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """根据用户ID获取用户"""
        return self._users.get(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """根据用户名获取用户"""
        for user in self._users.values():
            if user.username == username:
                return user
        return None
    
    def list_users(self) -> List[Dict[str, Any]]:
        """列出所有用户（脱敏）"""
        result = []
        for user in self._users.values():
            result.append({
                'user_id': user.user_id,
                'username': user.username,
                'role': user.role.value,
                'created_at': user.created_at,
                'last_login_at': user.last_login_at
            })
        return result
    
    def update_user_role(self, admin_id: str, user_id: str, new_role: UserRole) -> bool:
        """
        更新用户角色（需要管理员权限）
        
        Args:
            admin_id: 管理员用户ID
            user_id: 目标用户ID
            new_role: 新角色
            
        Returns:
            True 如果成功
        """
        admin = self._users.get(admin_id)
        if not admin or admin.role != UserRole.ADMIN:
            logger.warning(f"非管理员尝试修改用户角色: {admin_id}")
            return False
        
        user = self._users.get(user_id)
        if not user:
            return False
        
        old_role = user.role
        user.role = new_role
        self._save_users()
        
        self._log_audit(admin_id, admin.username, 'USER_UPDATE_ROLE', user_id, 'user', {
            'old_role': old_role.value,
            'new_role': new_role.value
        })
        
        logger.info(f"用户角色更新: {user.username} {old_role.value} -> {new_role.value}")
        return True
    
    def delete_user(self, admin_id: str, user_id: str) -> bool:
        """
        删除用户（需要管理员权限）
        
        Args:
            admin_id: 管理员用户ID
            user_id: 目标用户ID
            
        Returns:
            True 如果成功
        """
        admin = self._users.get(admin_id)
        if not admin or admin.role != UserRole.ADMIN:
            logger.warning(f"非管理员尝试删除用户: {admin_id}")
            return False
        
        user = self._users.get(user_id)
        if not user:
            return False
        
        username = user.username
        del self._users[user_id]
        self._save_users()
        
        self._log_audit(admin_id, admin.username, 'USER_DELETE', user_id, 'user', {
            'username': username
        })
        
        logger.info(f"用户已删除: {username}")
        return True
    
    def add_project_member(self, project_id: str, user_id: str, role: UserRole = UserRole.VIEWER) -> bool:
        """
        添加项目成员
        
        Args:
            project_id: 项目ID
            user_id: 用户ID
            role: 项目内角色
            
        Returns:
            True 如果成功
        """
        user = self._users.get(user_id)
        if not user:
            return False
        
        if project_id not in self._project_members:
            self._project_members[project_id] = []
        
        # 检查是否已加入
        for member in self._project_members[project_id]:
            if member.user_id == user_id:
                return False
        
        member = ProjectMember(
            user_id=user_id,
            username=user.username,
            role=role,
            joined_at=datetime.now().isoformat()
        )
        
        self._project_members[project_id].append(member)
        
        self._log_audit(user_id, user.username, 'PROJECT_JOIN', project_id, 'project', {
            'role': role.value
        })
        
        logger.info(f"用户 {user.username} 加入项目 {project_id}")
        return True
    
    def remove_project_member(self, admin_id: str, project_id: str, user_id: str) -> bool:
        """
        移除项目成员
        
        Args:
            admin_id: 管理员/项目所有者ID
            project_id: 项目ID
            user_id: 用户ID
            
        Returns:
            True 如果成功
        """
        admin = self._users.get(admin_id)
        if not admin:
            return False
        
        if project_id not in self._project_members:
            return False
        
        members = self._project_members[project_id]
        for i, member in enumerate(members):
            if member.user_id == user_id:
                del members[i]
                
                self._log_audit(admin_id, admin.username, 'PROJECT_REMOVE', project_id, 'project', {
                    'removed_user_id': user_id,
                    'removed_username': member.username
                })
                
                logger.info(f"用户 {member.username} 已从项目 {project_id} 移除")
                return True
        
        return False
    
    def get_project_members(self, project_id: str) -> List[Dict[str, Any]]:
        """获取项目成员列表"""
        if project_id not in self._project_members:
            return []
        
        result = []
        for member in self._project_members[project_id]:
            result.append({
                'user_id': member.user_id,
                'username': member.username,
                'role': member.role.value,
                'joined_at': member.joined_at
            })
        return result
    
    def check_project_permission(self, user_id: str, project_id: str, required_role: UserRole = UserRole.VIEWER) -> bool:
        """
        检查用户在项目中的权限
        
        Args:
            user_id: 用户ID
            project_id: 项目ID
            required_role: 所需角色（VIEWER < ANALYST < ADMIN）
            
        Returns:
            True 如果有权限
        """
        if project_id not in self._project_members:
            return False
        
        role_order = {UserRole.VIEWER: 1, UserRole.ANALYST: 2, UserRole.ADMIN: 3}
        
        for member in self._project_members[project_id]:
            if member.user_id == user_id:
                return role_order.get(member.role, 0) >= role_order.get(required_role, 0)
        
        return False
    
    def _log_audit(self, user_id: str, username: str, action: str, target_id: str, target_type: str, details: Dict[str, Any]):
        """
        记录审计日志
        
        Args:
            user_id: 用户ID
            username: 用户名
            action: 动作类型
            target_id: 目标对象ID
            target_type: 目标对象类型
            details: 详细信息
        """
        log_entry = AuditLogEntry(
            timestamp=datetime.now().isoformat(),
            user_id=user_id,
            username=username,
            action=action,
            target_id=target_id,
            target_type=target_type,
            details=details
        )
        
        log_line = json.dumps({
            'timestamp': log_entry.timestamp,
            'user_id': log_entry.user_id,
            'username': log_entry.username,
            'action': log_entry.action,
            'target_id': log_entry.target_id,
            'target_type': log_entry.target_type,
            'details': log_entry.details
        })
        
        try:
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')
        except Exception as e:
            logger.error(f"写入审计日志失败: {e}")
        
        logger.info(f"[审计] {username}({user_id}) {action} {target_type} {target_id}")
    
    def get_audit_logs(self, user_id: str = None, action: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        获取审计日志
        
        Args:
            user_id: 按用户ID过滤（管理员可用）
            action: 按动作类型过滤
            limit: 返回数量限制
            
        Returns:
            日志列表
        """
        logs = []
        
        if os.path.exists(self.audit_log_path):
            try:
                with open(self.audit_log_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            
                            if user_id and entry.get('user_id') != user_id:
                                continue
                            if action and entry.get('action') != action:
                                continue
                            
                            logs.append(entry)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"读取审计日志失败: {e}")
        
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return logs[:limit]
    
    def add_comment(self, user_id: str, target_id: str, target_type: str, content: str) -> str:
        """
        添加注释
        
        Args:
            user_id: 用户ID
            target_id: 目标对象ID（漏洞ID或函数地址）
            target_type: 目标类型（vulnerability/function）
            content: 注释内容
            
        Returns:
            注释ID
        """
        user = self._users.get(user_id)
        if not user:
            raise ValueError("用户不存在")
        
        if not content.strip():
            raise ValueError("注释内容不能为空")
        
        comment_id = hashlib.md5(f"{user_id}{target_id}{datetime.now()}".encode('utf-8')).hexdigest()[:16]
        
        comment = Comment(
            comment_id=comment_id,
            user_id=user_id,
            username=user.username,
            target_id=target_id,
            target_type=target_type,
            content=content,
            created_at=datetime.now().isoformat()
        )
        
        key = f"{target_type}:{target_id}"
        if key not in self._comments:
            self._comments[key] = []
        self._comments[key].append(comment)
        
        self._log_audit(user_id, user.username, 'COMMENT_ADD', target_id, target_type, {
            'comment_id': comment_id,
            'content_length': len(content)
        })
        
        logger.info(f"用户 {user.username} 添加注释到 {target_type} {target_id}")
        return comment_id
    
    def get_comments(self, target_id: str, target_type: str) -> List[Dict[str, Any]]:
        """获取目标对象的所有注释"""
        key = f"{target_type}:{target_id}"
        if key not in self._comments:
            return []
        
        result = []
        for comment in self._comments[key]:
            result.append({
                'comment_id': comment.comment_id,
                'user_id': comment.user_id,
                'username': comment.username,
                'content': comment.content,
                'created_at': comment.created_at
            })
        
        return result
    
    def update_vulnerability_status(self, user_id: str, vulnerability_id: str, status: str, comment: str = None) -> bool:
        """
        更新漏洞状态
        
        Args:
            user_id: 用户ID
            vulnerability_id: 漏洞ID
            status: 新状态（confirmed/false_positive/fixed/rejected）
            comment: 状态变更原因
            
        Returns:
            True 如果成功
        """
        user = self._users.get(user_id)
        if not user:
            return False
        
        valid_statuses = ['confirmed', 'false_positive', 'fixed', 'rejected']
        if status not in valid_statuses:
            return False
        
        vuln_status = VulnerabilityStatus(
            vulnerability_id=vulnerability_id,
            status=status,
            updated_by=user.username,
            updated_at=datetime.now().isoformat(),
            comment=comment
        )
        
        self._vuln_status[vulnerability_id] = vuln_status
        
        self._log_audit(user_id, user.username, 'VULN_STATUS_UPDATE', vulnerability_id, 'vulnerability', {
            'status': status,
            'comment': comment
        })
        
        logger.info(f"用户 {user.username} 更新漏洞 {vulnerability_id} 状态为 {status}")
        return True
    
    def get_vulnerability_status(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """获取漏洞状态"""
        vuln_status = self._vuln_status.get(vulnerability_id)
        if not vuln_status:
            return None
        
        return {
            'vulnerability_id': vuln_status.vulnerability_id,
            'status': vuln_status.status,
            'updated_by': vuln_status.updated_by,
            'updated_at': vuln_status.updated_at,
            'comment': vuln_status.comment
        }
    
    # ==================== Git 版本管理方法 ====================
    
    def _load_git_repos(self):
        """加载Git仓库配置"""
        repos_file = os.path.join(self.repo_base_path, 'repos.json')
        if os.path.exists(repos_file):
            try:
                with open(repos_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for repo_id, repo_data in data.items():
                        self._git_repos[repo_id] = GitRepository(
                            repo_id=repo_id,
                            project_id=repo_data['project_id'],
                            repo_path=repo_data['repo_path'],
                            remote_url=repo_data.get('remote_url'),
                            initialized_at=repo_data.get('initialized_at', ''),
                            last_commit_hash=repo_data.get('last_commit_hash')
                        )
            except Exception as e:
                logger.error(f"加载Git仓库配置失败: {e}")
    
    def _save_git_repos(self):
        """保存Git仓库配置"""
        repos_file = os.path.join(self.repo_base_path, 'repos.json')
        try:
            data = {}
            for repo_id, repo in self._git_repos.items():
                data[repo_id] = {
                    'repo_id': repo.repo_id,
                    'project_id': repo.project_id,
                    'repo_path': repo.repo_path,
                    'remote_url': repo.remote_url,
                    'initialized_at': repo.initialized_at,
                    'last_commit_hash': repo.last_commit_hash
                }
            
            with open(repos_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"保存Git仓库配置失败: {e}")
    
    def _load_binary_versions(self):
        """加载二进制版本信息"""
        versions_file = os.path.join(self.repo_base_path, 'versions.json')
        if os.path.exists(versions_file):
            try:
                with open(versions_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for project_id, versions in data.items():
                        self._binary_versions[project_id] = []
                        for version_data in versions:
                            self._binary_versions[project_id].append(BinaryVersion(
                                version_id=version_data['version_id'],
                                project_id=version_data['project_id'],
                                binary_hash=version_data['binary_hash'],
                                commit_hash=version_data['commit_hash'],
                                commit_message=version_data['commit_message'],
                                author=version_data['author'],
                                timestamp=version_data['timestamp'],
                                analysis_summary=version_data.get('analysis_summary'),
                                tags=version_data.get('tags')
                            ))
            except Exception as e:
                logger.error(f"加载二进制版本信息失败: {e}")
    
    def _save_binary_versions(self):
        """保存二进制版本信息"""
        versions_file = os.path.join(self.repo_base_path, 'versions.json')
        try:
            data = {}
            for project_id, versions in self._binary_versions.items():
                data[project_id] = []
                for version in versions:
                    data[project_id].append({
                        'version_id': version.version_id,
                        'project_id': version.project_id,
                        'binary_hash': version.binary_hash,
                        'commit_hash': version.commit_hash,
                        'commit_message': version.commit_message,
                        'author': version.author,
                        'timestamp': version.timestamp,
                        'analysis_summary': version.analysis_summary,
                        'tags': version.tags
                    })
            
            with open(versions_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"保存二进制版本信息失败: {e}")
    
    def init_binary_repo(self, project_id: str, user_id: str, remote_url: str = None) -> Tuple[bool, str]:
        """
        初始化项目的二进制文件Git仓库
        
        Args:
            project_id: 项目ID
            user_id: 用户ID
            remote_url: 远程仓库URL（可选）
            
        Returns:
            (success, message/repo_id)
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装，请先安装: pip install gitpython")
            return False, "gitpython 未安装"
        
        user = self._users.get(user_id)
        if not user:
            return False, "用户不存在"
        
        repo_id = hashlib.md5(f"{project_id}{user_id}{datetime.now()}".encode('utf-8')).hexdigest()[:16]
        repo_path = os.path.join(self.repo_base_path, project_id, repo_id)
        
        if os.path.exists(repo_path):
            return False, "仓库已存在"
        
        os.makedirs(repo_path, exist_ok=True)
        
        try:
            repo = git.Repo.init(repo_path)
            
            gitignore_content = """*.log
*.tmp
*.pyc
__pycache__/
results/
*.so
*.dll
*.dylib
*.exe
"""
            with open(os.path.join(repo_path, '.gitignore'), 'w') as f:
                f.write(gitignore_content)
            
            repo.index.add(['.gitignore'])
            repo.index.commit('Initial commit: binary analysis repository')
            
            if remote_url:
                repo.create_remote('origin', remote_url)
            
            git_repo = GitRepository(
                repo_id=repo_id,
                project_id=project_id,
                repo_path=repo_path,
                remote_url=remote_url,
                initialized_at=datetime.now().isoformat(),
                last_commit_hash=repo.head.commit.hexsha
            )
            
            self._git_repos[repo_id] = git_repo
            self._save_git_repos()
            
            self._log_audit(user_id, user.username, 'REPO_INIT', project_id, 'project', {
                'repo_id': repo_id,
                'repo_path': repo_path,
                'remote_url': remote_url
            })
            
            logger.info(f"项目 {project_id} 二进制仓库初始化成功: {repo_path}")
            return True, repo_id
        
        except Exception as e:
            logger.error(f"初始化二进制仓库失败: {e}")
            return False, str(e)
    
    def commit_binary_version(self, project_id: str, user_id: str, binary_path: str, 
                            commit_message: str, analysis_summary: Dict[str, Any] = None,
                            tags: List[str] = None) -> Tuple[bool, str]:
        """
        提交二进制文件新版本到Git仓库
        
        Args:
            project_id: 项目ID
            user_id: 用户ID
            binary_path: 二进制文件路径
            commit_message: 提交消息
            analysis_summary: 分析摘要（可选）
            tags: 版本标签（可选）
            
        Returns:
            (success, message/version_id)
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装")
            return False, "gitpython 未安装"
        
        user = self._users.get(user_id)
        if not user:
            return False, "用户不存在"
        
        if not os.path.exists(binary_path):
            return False, "二进制文件不存在"
        
        repo = None
        repo_id = None
        for rid, r in self._git_repos.items():
            if r.project_id == project_id:
                repo_id = rid
                if os.path.exists(r.repo_path):
                    repo = git.Repo(r.repo_path)
                break
        
        if not repo:
            return False, "项目仓库未初始化"
        
        try:
            binary_name = os.path.basename(binary_path)
            dest_path = os.path.join(repo.working_dir, binary_name)
            import shutil
            shutil.copy2(binary_path, dest_path)
            
            with open(binary_path, 'rb') as f:
                binary_hash = hashlib.sha256(f.read()).hexdigest()
            
            repo.index.add([binary_name])
            commit = repo.index.commit(commit_message)
            
            self._git_repos[repo_id].last_commit_hash = commit.hexsha
            self._save_git_repos()
            
            version_id = hashlib.md5(f"{project_id}{binary_hash}{datetime.now()}".encode('utf-8')).hexdigest()[:16]
            
            binary_version = BinaryVersion(
                version_id=version_id,
                project_id=project_id,
                binary_hash=binary_hash,
                commit_hash=commit.hexsha,
                commit_message=commit_message,
                author=user.username,
                timestamp=datetime.now().isoformat(),
                analysis_summary=analysis_summary,
                tags=tags
            )
            
            if project_id not in self._binary_versions:
                self._binary_versions[project_id] = []
            self._binary_versions[project_id].append(binary_version)
            self._save_binary_versions()
            
            self._log_audit(user_id, user.username, 'VERSION_COMMIT', project_id, 'project', {
                'version_id': version_id,
                'binary_name': binary_name,
                'binary_hash': binary_hash,
                'commit_hash': commit.hexsha
            })
            
            logger.info(f"二进制版本提交成功: {version_id}")
            return True, version_id
        
        except Exception as e:
            logger.error(f"提交二进制版本失败: {e}")
            return False, str(e)
    
    def get_project_versions(self, project_id: str) -> List[Dict[str, Any]]:
        """
        获取项目的所有二进制版本
        
        Args:
            project_id: 项目ID
            
        Returns:
            版本列表
        """
        versions = self._binary_versions.get(project_id, [])
        result = []
        for version in versions:
            result.append({
                'version_id': version.version_id,
                'binary_hash': version.binary_hash,
                'commit_hash': version.commit_hash,
                'commit_message': version.commit_message,
                'author': version.author,
                'timestamp': version.timestamp,
                'analysis_summary': version.analysis_summary,
                'tags': version.tags
            })
        return sorted(result, key=lambda x: x['timestamp'], reverse=True)
    
    def get_version_by_id(self, project_id: str, version_id: str) -> Optional[Dict[str, Any]]:
        """
        根据版本ID获取版本信息
        
        Args:
            project_id: 项目ID
            version_id: 版本ID
            
        Returns:
            版本信息，如果不存在返回None
        """
        versions = self._binary_versions.get(project_id, [])
        for version in versions:
            if version.version_id == version_id:
                return {
                    'version_id': version.version_id,
                    'binary_hash': version.binary_hash,
                    'commit_hash': version.commit_hash,
                    'commit_message': version.commit_message,
                    'author': version.author,
                    'timestamp': version.timestamp,
                    'analysis_summary': version.analysis_summary,
                    'tags': version.tags
                }
        return None
    
    def compare_versions(self, project_id: str, from_version_id: str, to_version_id: str) -> Optional[VersionDiff]:
        """
        比较两个版本之间的差异
        
        Args:
            project_id: 项目ID
            from_version_id: 起始版本ID
            to_version_id: 目标版本ID
            
        Returns:
            版本差异信息，如果版本不存在返回None
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装")
            return None
        
        versions = self._binary_versions.get(project_id, [])
        from_version = None
        to_version = None
        
        for v in versions:
            if v.version_id == from_version_id:
                from_version = v
            if v.version_id == to_version_id:
                to_version = v
        
        if not from_version or not to_version:
            return None
        
        repo = None
        for rid, r in self._git_repos.items():
            if r.project_id == project_id and os.path.exists(r.repo_path):
                repo = git.Repo(r.repo_path)
                break
        
        if not repo:
            return None
        
        try:
            diff = repo.git.diff(f"{from_version.commit_hash}..{to_version.commit_hash}", '--name-only')
            changed_files = [f for f in diff.split('\n') if f.strip()]
            
            changed_functions = []
            for f in changed_files:
                if f.endswith(('.so', '.dll', '.dylib', '.exe')):
                    changed_functions.append(f)
            
            new_vulns = []
            fixed_vulns = []
            severity_changes = []
            
            if from_version.analysis_summary and to_version.analysis_summary:
                from_vulns = set(from_version.analysis_summary.get('vulnerabilities', []))
                to_vulns = set(to_version.analysis_summary.get('vulnerabilities', []))
                
                new_vulns = list(to_vulns - from_vulns)
                fixed_vulns = list(from_vulns - to_vulns)
                
                from_severity = from_version.analysis_summary.get('severity_counts', {})
                to_severity = to_version.analysis_summary.get('severity_counts', {})
                
                for sev in ['critical', 'high', 'medium', 'low']:
                    diff_count = to_severity.get(sev, 0) - from_severity.get(sev, 0)
                    if diff_count != 0:
                        severity_changes.append({
                            'severity': sev,
                            'change': diff_count,
                            'from': from_severity.get(sev, 0),
                            'to': to_severity.get(sev, 0)
                        })
            
            return VersionDiff(
                project_id=project_id,
                from_version_id=from_version_id,
                to_version_id=to_version_id,
                from_commit=from_version.commit_hash,
                to_commit=to_version.commit_hash,
                changed_functions=changed_functions,
                new_vulnerabilities=new_vulns,
                fixed_vulnerabilities=fixed_vulns,
                severity_changes=severity_changes
            )
        
        except Exception as e:
            logger.error(f"比较版本差异失败: {e}")
            return None
    
    def checkout_version(self, project_id: str, version_id: str, output_path: str) -> Tuple[bool, str]:
        """
        检出指定版本的二进制文件
        
        Args:
            project_id: 项目ID
            version_id: 版本ID
            output_path: 输出路径
            
        Returns:
            (success, message/output_file_path)
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装")
            return False, "gitpython 未安装"
        
        versions = self._binary_versions.get(project_id, [])
        version = None
        
        for v in versions:
            if v.version_id == version_id:
                version = v
                break
        
        if not version:
            return False, "版本不存在"
        
        repo = None
        for rid, r in self._git_repos.items():
            if r.project_id == project_id and os.path.exists(r.repo_path):
                repo = git.Repo(r.repo_path)
                break
        
        if not repo:
            return False, "仓库不存在"
        
        try:
            repo.git.checkout(version.commit_hash)
            
            binary_files = [f for f in os.listdir(repo.working_dir) 
                          if not f.startswith('.') and os.path.isfile(os.path.join(repo.working_dir, f))]
            
            if not binary_files:
                return False, "未找到二进制文件"
            
            binary_name = binary_files[0]
            source_path = os.path.join(repo.working_dir, binary_name)
            dest_path = os.path.join(output_path, binary_name)
            
            import shutil
            os.makedirs(output_path, exist_ok=True)
            shutil.copy2(source_path, dest_path)
            
            repo.git.checkout('main')
            
            logger.info(f"版本 {version_id} 检出成功: {dest_path}")
            return True, dest_path
        
        except Exception as e:
            logger.error(f"检出版本失败: {e}")
            return False, str(e)
    
    def pull_from_remote(self, project_id: str, user_id: str) -> Tuple[bool, str]:
        """
        从远程仓库拉取最新版本
        
        Args:
            project_id: 项目ID
            user_id: 用户ID
            
        Returns:
            (success, message)
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装")
            return False, "gitpython 未安装"
        
        user = self._users.get(user_id)
        if not user:
            return False, "用户不存在"
        
        repo = None
        repo_id = None
        for rid, r in self._git_repos.items():
            if r.project_id == project_id and r.remote_url and os.path.exists(r.repo_path):
                repo = git.Repo(r.repo_path)
                repo_id = rid
                break
        
        if not repo:
            return False, "远程仓库未配置"
        
        try:
            origin = repo.remote('origin')
            origin.pull()
            
            self._git_repos[repo_id].last_commit_hash = repo.head.commit.hexsha
            self._save_git_repos()
            
            self._log_audit(user_id, user.username, 'REPO_PULL', project_id, 'project', {
                'commit_hash': repo.head.commit.hexsha
            })
            
            logger.info(f"项目 {project_id} 从远程拉取成功")
            return True, f"拉取成功，最新提交: {repo.head.commit.hexsha}"
        
        except Exception as e:
            logger.error(f"从远程拉取失败: {e}")
            return False, str(e)
    
    def push_to_remote(self, project_id: str, user_id: str) -> Tuple[bool, str]:
        """
        推送本地提交到远程仓库
        
        Args:
            project_id: 项目ID
            user_id: 用户ID
            
        Returns:
            (success, message)
        """
        try:
            import git
        except ImportError:
            logger.error("gitpython 未安装")
            return False, "gitpython 未安装"
        
        user = self._users.get(user_id)
        if not user:
            return False, "用户不存在"
        
        repo = None
        repo_id = None
        for rid, r in self._git_repos.items():
            if r.project_id == project_id and r.remote_url and os.path.exists(r.repo_path):
                repo = git.Repo(r.repo_path)
                repo_id = rid
                break
        
        if not repo:
            return False, "远程仓库未配置"
        
        try:
            origin = repo.remote('origin')
            origin.push()
            
            self._log_audit(user_id, user.username, 'REPO_PUSH', project_id, 'project', {
                'commit_hash': repo.head.commit.hexsha
            })
            
            logger.info(f"项目 {project_id} 推送到远程成功")
            return True, f"推送成功"
        
        except Exception as e:
            logger.error(f"推送到远程失败: {e}")
            return False, str(e)
    
    def get_repo_info(self, project_id: str) -> Optional[Dict[str, Any]]:
        """
        获取项目仓库信息
        
        Args:
            project_id: 项目ID
            
        Returns:
            仓库信息，如果不存在返回None
        """
        for repo in self._git_repos.values():
            if repo.project_id == project_id:
                return {
                    'repo_id': repo.repo_id,
                    'project_id': repo.project_id,
                    'repo_path': repo.repo_path,
                    'remote_url': repo.remote_url,
                    'initialized_at': repo.initialized_at,
                    'last_commit_hash': repo.last_commit_hash
                }
        return None


def get_collaboration_manager() -> CollaborationManager:
    """
    获取全局协作管理器实例
    
    Returns:
        CollaborationManager 实例
    """
    global _collaboration_manager
    if _collaboration_manager is None:
        _collaboration_manager = CollaborationManager()
    return _collaboration_manager


# 全局协作管理器实例
_collaboration_manager = None
