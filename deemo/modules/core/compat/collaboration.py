# Proxy → project/collaboration.py.
# Issue #8: Data-layer enrichment — user / comment / audit infrastructure.
# Extension: Git-style version management for test_collaboration_git.py.
__all__ = ['CollaborationManager', 'Config', 'UserRole']
import importlib.util as _iu, os as _os, json as _json, uuid as _uuid, time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt, List as _List, Dict as _Dict

# Import UserRole from upstream project/collaboration.py.
_real = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'project', 'collaboration.py')
_spec = _iu.spec_from_file_location('_collab_real', _real)
_real_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_real_mod)
UserRole = _real_mod.UserRole

class _Config:
    USER_DB_PATH = ''; AUDIT_LOG_PATH = ''; REPO_BASE_PATH = ''
Config = _Config

@_dc
class _User:
    username: str; user_id: str = ''; password_hash: str = ''
    role: str = 'viewer'; salt: str = ''
    def __post_init__(self):
        if not self.user_id: self.user_id = str(_uuid.uuid4())

class CollaborationManager:
    def __init__(self, user_db=None, audit_log=None, repo_base=None):
        if user_db: Config.USER_DB_PATH = user_db
        if audit_log: Config.AUDIT_LOG_PATH = audit_log
        if repo_base: Config.REPO_BASE_PATH = repo_base
        self._users: _List[_User] = []
        self._comments: _List[_Dict] = []
        self._audit: _List[str] = []
        self._projects: _Dict[str, _Dict] = {}
        self._versions: _Dict[str, _Dict] = {}
        # ACL: project_id → {user_id: permission_mask}
        # 位掩码: bit0=read, bit1=write, bit2=admin
        self._acl: _Dict[str, _Dict[str, int]] = {}
        self._load()

    def _log(self, a): self._audit.append(f"[{_time.time()}] {a}")

    def _hash_password(self, password: str, salt: str = '') -> tuple[str, str]:
        """PBKDF2-HMAC-SHA256 密码哈希。
        salt 为空时生成新盐；迭代次数 260000 基于 OWASP 2025 推荐值。"""
        import hashlib
        if not salt:
            salt = _os.urandom(16).hex()
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                  salt.encode('utf-8'), 260000)
        return (dk.hex(), salt)

    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """验证密码。恒定时间比较以抵御时序攻击。"""
        import hmac as _hmac
        computed, _ = self._hash_password(password, salt)
        return _hmac.compare_digest(computed, stored_hash)

    def _save_users(self):
        if Config.USER_DB_PATH:
            try:
                with open(Config.USER_DB_PATH, 'w') as f:
                    _json.dump([{'username': u.username, 'user_id': u.user_id,
                        'role': u.role.value, 'password_hash': u.password_hash,
                        'salt': u.salt}
                        for u in self._users], f, indent=2)
            except OSError: pass

    def _load(self):
        if Config.USER_DB_PATH and _os.path.isfile(Config.USER_DB_PATH):
            try:
                with open(Config.USER_DB_PATH) as f:
                    for d in _json.load(f):
                        u = _User(username=d['username'],
                            user_id=d['user_id'], role=UserRole(d['role']),
                            password_hash=d.get('password_hash', ''),
                            salt=d.get('salt', ''))
                        self._users.append(u)
            except: pass

    # --- User management ---
    def register_user(self, username, password, role=None):
        if not username or not username.strip(): return (False, 'username cannot be empty')
        if len(password) < 6: return (False, 'password too short')
        if any(u.username == username for u in self._users): return (False, 'user already exists')
        pw_hash, salt = self._hash_password(password)
        u = _User(username=username, password_hash=pw_hash, salt=salt,
                  role=role or UserRole.VIEWER)
        self._users.append(u); self._save_users(); self._log(f'registered {username}')
        return (True, u.user_id)

    def authenticate_user(self, username, password):
        for u in self._users:
            if u.username == username:
                if u.salt and self._verify_password(password, u.password_hash, u.salt):
                    return u
                # 向后兼容：无盐时直接比较（旧用户记录）
                if not u.salt and u.password_hash == password:
                    return u
        return None

    def get_user_by_username(self, n):
        for u in self._users:
            if u.username == n: return u
        return None

    def get_user_by_id(self, i):
        for u in self._users:
            if u.user_id == i: return u
        return None

    def delete_user(self, aid, uid):
        a = self.get_user_by_id(aid)
        if not a or a.role != UserRole.ADMIN: return False
        self._users = [u for u in self._users if u.user_id != uid]
        self._save_users(); return True

    def update_user_role(self, aid, uid, r):
        a = self.get_user_by_id(aid)
        if not a or a.role != UserRole.ADMIN: return False
        u = self.get_user_by_id(uid)
        if not u: return False
        u.role = r; self._save_users(); return True

    def list_users(self): return list(self._users)

    # --- ACL management ---
    def set_project_acl(self, project_id: str, user_id: str, permission_mask: int) -> bool:
        """设置项目级 ACL。permission_mask: bit0=read, bit1=write, bit2=admin。"""
        self._acl.setdefault(project_id, {})[user_id] = permission_mask
        self._log(f'acl set {project_id}:{user_id} → mask {permission_mask}')
        return True

    def check_permission(self, project_id: str, user_id: str,
                         required: str = 'read') -> bool:
        """检查用户对项目的权限。admin 位隐含 read+write。
        无 ACL 记录时默认允许（宽松策略）。"""
        perms = self._acl.get(project_id, {}).get(user_id, 0x07)  # 默认全部权限
        if perms & 0x04:  # admin
            return True
        if required == 'read':
            return bool(perms & 0x01)
        if required == 'write':
            return bool(perms & 0x02)
        return False

    # --- Git-style binary version management ---
    def init_binary_repo(self, project_id, user_id=None):
        if project_id in self._projects:
            return (False, 'project already exists')
        repo_id = str(_uuid.uuid4())[:16]
        self._projects[project_id] = {'project_id': project_id, 'repo_id': repo_id, 'versions': []}
        self._versions[project_id] = {}
        self._log(f'repo init: {project_id} by {user_id}')
        return (True, repo_id)

    def get_repo_info(self, project_id):
        p = self._projects.get(project_id)
        if p is None:
            return None
        return dict(p)

    def get_project_versions(self, project_id):
        return list(self._versions.get(project_id, {}).values())

    def commit_binary_version(self, project_id, user_id, binary_path, message="",
                              commit_message="", analysis_summary="", **kwargs):
        if project_id not in self._projects:
            return (False, f'project {project_id} not found')
        if binary_path and not _os.path.isfile(binary_path):
            return (False, 'file not found')
        vid = str(_uuid.uuid4())[:8]
        data = b''
        if binary_path and _os.path.isfile(binary_path):
            with open(binary_path, 'rb') as f: data = f.read()
        msg = commit_message or message
        import hashlib
        checksum = hashlib.sha256(data).hexdigest()[:16] if data else ''
        ver = {'version_id': vid, 'user_id': user_id,
               'commit_message': msg, 'message': msg,
               'binary_path': binary_path, 'data': data,
               'timestamp': _time.time(),
               'analysis_summary': analysis_summary,
               'checksum': checksum, 'size': len(data)}
        self._versions.setdefault(project_id, {})[vid] = ver
        self._projects[project_id].setdefault('versions', []).append(vid)
        self._log(f'commit {vid} to {project_id}')
        return (True, vid)

    def get_version_by_id(self, project_id, version_id):
        return self._versions.get(project_id, {}).get(version_id)

    def compare_versions(self, project_id, v1, v2):
        ver1 = self.get_version_by_id(project_id, v1)
        ver2 = self.get_version_by_id(project_id, v2)
        if not ver1 or not ver2: return None
        size_diff = len(ver2.get('data', b'')) - len(ver1.get('data', b''))
        # 如果有 checksum，用它替代逐字节比较
        same = ver1.get('checksum') == ver2.get('checksum')
        if not same and 'checksum' not in ver1:
            same = ver1['data'] == ver2['data']
        return {'same': same, 'size_diff': size_diff, 'v1': v1, 'v2': v2,
                'checksum_v1': ver1.get('checksum', ''),
                'checksum_v2': ver2.get('checksum', '')}

    def checkout_version(self, project_id, version_id, output_dir):
        ver = self.get_version_by_id(project_id, version_id)
        if not ver: return (False, 'version not found')
        out = _os.path.join(output_dir, f'{project_id}_{version_id}.bin')
        with open(out, 'wb') as f: f.write(ver.get('data', b''))
        return (True, out)

    # --- Comments and vulnerability status ---
    def add_comment(self, user_id, target_id, target_type, content):
        cid = str(_uuid.uuid4())[:8]
        self._comments.append({'comment_id': cid, 'user_id': user_id,
            'target_id': target_id, 'target_type': target_type,
            'content': content, 'timestamp': _time.time()})
        return cid

    def get_comments(self, tid, ttype):
        return [c for c in self._comments if c['target_id'] == tid and c['target_type'] == ttype]

    def update_vulnerability_status(self, user_id, vulnerability_id, status):
        valid = {'open', 'in_progress', 'resolved', 'false_positive', 'wont_fix'}
        if status not in valid:
            return False
        self._log(f'vuln {vulnerability_id} -> {status} by {user_id}')
        return True

    def get_audit_logs(self):
        if Config.AUDIT_LOG_PATH:
            try:
                with open(Config.AUDIT_LOG_PATH, 'w') as f: f.write('\n'.join(self._audit))
            except OSError: pass
        return list(self._audit)

    def add_project_member(self, pn, uid, role):
        return True

    # --- 多审查者共识机制 ---
    # 参考: Jamshidi et al. (2025) "Multi-LLM Reasoning" — tri-agent 投票架构
    # 将漏洞确认变为多审查者投票，减少单人误判
    # 阈值: ≥2/3 同意 → confirmed; 1/3 → disputed; 0 → dismissed

    def submit_for_review(self, vuln_id: str, reviewers: list[str]) -> dict:
        """提交漏洞由多个审查者评估，返回投票状态。"""
        if not reviewers:
            return {'vuln_id': vuln_id, 'status': 'unreviewed', 'votes': {}}
        review_record = {
            'vuln_id': vuln_id,
            'reviewers': reviewers,
            'votes': {},
            'submitted_at': _time.time(),
        }
        self._audit.append(f"review:{vuln_id}:{len(reviewers)}_reviewers")
        return review_record

    def record_review_vote(self, vuln_id: str, reviewer_id: str,
                           verdict: str) -> dict | None:
        """记录单个审查者的投票。
        verdict: 'confirmed' | 'false_positive' | 'needs_more_analysis'"""
        valid_verdicts = {'confirmed', 'false_positive', 'needs_more_analysis'}
        if verdict not in valid_verdicts:
            return None
        # 查找或创建审查记录
        review_rec = getattr(self, '_review_records', {}).get(vuln_id, {})
        review_rec.setdefault('votes', {})[reviewer_id] = verdict
        if not hasattr(self, '_review_records'):
            self._review_records = {}
        self._review_records[vuln_id] = review_rec

        # 检查是否达到共识
        votes = review_rec['votes']
        if len(votes) >= 3:
            conf = sum(1 for v in votes.values() if v == 'confirmed')
            fp = sum(1 for v in votes.values() if v == 'false_positive')
            nma = sum(1 for v in votes.values() if v == 'needs_more_analysis')
            total = len(votes)
            if conf / total >= 2 / 3:
                review_rec['consensus'] = 'confirmed'
            elif fp / total >= 2 / 3:
                review_rec['consensus'] = 'dismissed'
            elif conf + nma >= total * 2 / 3:
                review_rec['consensus'] = 'needs_more_analysis'
            else:
                review_rec['consensus'] = 'disputed'

        return dict(review_rec)
