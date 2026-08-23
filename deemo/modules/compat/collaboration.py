import importlib.util as _iu, os as _os, json as _json, uuid as _uuid, time as _time
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt, List as _List, Dict as _Dict

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
    role: str = 'viewer'
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
        self._load()

    def _log(self, a): self._audit.append(f"[{_time.time()}] {a}")
    def _save_users(self):
        if Config.USER_DB_PATH:
            try:
                with open(Config.USER_DB_PATH, 'w') as f:
                    _json.dump([{'username': u.username, 'user_id': u.user_id,
                        'role': u.role.value, 'password_hash': u.password_hash}
                        for u in self._users], f, indent=2)
            except OSError: pass
    def _load(self):
        if Config.USER_DB_PATH and _os.path.isfile(Config.USER_DB_PATH):
            try:
                with open(Config.USER_DB_PATH) as f:
                    for d in _json.load(f):
                        self._users.append(_User(username=d['username'],
                            user_id=d['user_id'], role=UserRole(d['role']),
                            password_hash=d.get('password_hash', '')))
            except: pass

    def register_user(self, username, password, role=None):
        if not username or not username.strip(): return (False, 'username cannot be empty')
        if len(password) < 6: return (False, 'password too short')
        if any(u.username == username for u in self._users): return (False, 'user already exists')
        u = _User(username=username, password_hash=password, role=role or UserRole.VIEWER)
        self._users.append(u); self._save_users(); self._log(f'registered {username}')
        return (True, u.user_id)

    def authenticate_user(self, username, password):
        for u in self._users:
            if u.username == username and u.password_hash == password: return u
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
        ver = {'version_id': vid, 'user_id': user_id,
               'commit_message': msg, 'message': msg,
               'binary_path': binary_path, 'data': data,
               'timestamp': _time.time(),
               'analysis_summary': analysis_summary}
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
        return {'same': ver1['data'] == ver2['data'],
                'size_diff': len(ver2.get('data', b'')) - len(ver1.get('data', b'')),
                'v1': v1, 'v2': v2}

    def checkout_version(self, project_id, version_id, output_dir):
        ver = self.get_version_by_id(project_id, version_id)
        if not ver: return (False, 'version not found')
        out = _os.path.join(output_dir, f'{project_id}_{version_id}.bin')
        with open(out, 'wb') as f: f.write(ver.get('data', b''))
        return (True, out)

    def add_comment(self, user_id, target_id, target_type, content):
        cid = str(_uuid.uuid4())[:8]
        self._comments.append({'comment_id': cid, 'user_id': user_id,
            'target_id': target_id, 'target_type': target_type,
            'content': content, 'timestamp': _time.time()})
        return cid

    def get_comments(self, tid, ttype):
        return [c for c in self._comments if c['target_id'] == tid and c['target_type'] == ttype]

    def update_vulnerability_status(self, user_id, vulnerability_id, status):
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

