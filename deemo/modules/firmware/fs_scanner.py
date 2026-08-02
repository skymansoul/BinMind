# 2026-07-20
# 文件系统扫描器 — 权限审计/SUID二进制/硬编码凭证/不安全配置
# 2026-07 新增: cronjob后门检测 + capabilities审计 + /etc writable检查

import os
import stat as st
import re

_KNOWN_SAFE_SUID = {
    "sudo", "passwd", "ping", "ping6", "su", "newgrp", "mount", "umount",
    "fusermount", "chsh", "chfn", "gpasswd", "pkexec", "unix_chkpwd",
    "bwrap", "ssh-keysign", "wall", "write", "chage", "expiry",
    "bsd-excl", "crontab", "at", "Xorg.wrap",
}

_CRON_DIRS = ["etc/crontabs", "etc/cron.d", "var/spool/cron/crontabs",
              "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly"]
_SUS_CRON_CMDS = [
    (re.compile(rb'(?:wget|curl|tftp|ftpget)\s+.*\|\s*(?:sh|bash|ash)'), "pipe-to-shell"),
    (re.compile(rb'(?:nc|netcat|ncat)\s+-[eEl]\s+'), "netcat-backconnect"),
    (re.compile(rb'/dev/tcp/'), "bash-reverse-shell"),
    (re.compile(rb'/tmp/\w*(?:backdoor|bd|shell|bind|rev)'), "suspicious-tmp-binary"),
]

_DANGEROUS_CAPABILITIES = {
    "cap_sys_admin": "允许任意挂载/卸载和大量管理员操作",
    "cap_sys_ptrace": "允许 ptrace 任意进程", "cap_sys_module": "允许加载/卸载内核模块",
    "cap_sys_rawio": "允许直接 I/O 端口访问", "cap_net_admin": "允许网络接口管理",
    "cap_net_raw": "允许原始套接字", "cap_dac_override": "绕过所有 DAC 权限检查",
    "cap_dac_read_search": "绕过文件读和目录搜索权限",
}


class FSScanner:

    def scan_world_writable(self, root_path: str) -> list[dict]:
        _results = []
        for _dirpath, _dirnames, _filenames in os.walk(root_path, followlinks=False):
            for _fn in _filenames:
                _fp = os.path.join(_dirpath, _fn)
                try:
                    _mode = os.lstat(_fp).st_mode
                except OSError:
                    continue
                if _mode & 0o002:
                    _results.append({"path": _fp, "relative_path": os.path.relpath(_fp, root_path),
                                     "permissions": oct(_mode & 0o777), "type": "world_writable",
                                     "severity": "HIGH", "finding": f"全局可写文件: {_fn}",
                                     "recommendation": "移除 other write 权限: chmod o-w"})
        return _results

    def scan_suid_sgid(self, root_path: str) -> list[dict]:
        _results = []
        for _dirpath, _dirnames, _filenames in os.walk(root_path, followlinks=False):
            for _fn in _filenames:
                _fp = os.path.join(_dirpath, _fn)
                try:
                    _mode = os.lstat(_fp).st_mode
                except OSError:
                    continue
                _is_suid = bool(_mode & st.S_ISUID); _is_sgid = bool(_mode & st.S_ISGID)
                if not _is_suid and not _is_sgid:
                    continue
                _is_known_safe = _fn in _KNOWN_SAFE_SUID
                _sev = "LOW" if _is_known_safe else "HIGH"
                _flags = []
                if _is_suid:
                    _flags.append("SUID")
                if _is_sgid:
                    _flags.append("SGID")
                _results.append({"path": _fp, "relative_path": os.path.relpath(_fp, root_path),
                                 "permissions": oct(_mode & 0o777), "flags": "|".join(_flags),
                                 "type": "suid_sgid", "severity": _sev, "known_safe": _is_known_safe,
                                 "finding": f"{'/'.join(_flags)} 二进制: {_fn}",
                                 "recommendation": ("白名单中的系统二进制" if _is_known_safe
                                                    else f"检查是否必要")})
        return _results

    def scan_hardcoded_credentials(self, root_path: str) -> list[dict]:
        _patterns = [("password\\s*=\\s*[\"\\']?[^\"'\\s]+", "password="),
                     ("passwd\\s*=\\s*[\"\\']?[^\"'\\s]+", "passwd="),
                     ("pwd\\s*=\\s*[\"\\']?[^\"'\\s]+", "pwd="),
                     ("secret\\s*=\\s*[\"\\']?[^\"'\\s]+", "secret="),
                     ("api_key\\s*=\\s*[\"\\']?[^\"'\\s]+", "api_key="),
                     ("token\\s*=\\s*[\"\\']?[^\"'\\s]+", "token="),
                     ("-----BEGIN.*PRIVATE KEY-----", "PRIVATE KEY")]
        _results = []
        _text_exts = {".conf", ".cfg", ".ini", ".json", ".xml", ".yml", ".yaml",
                      ".txt", ".sh", ".bash", ".py", ".pl", ".php", ".lua",
                      ".env", ".toml", ".service", ".socket", ".target"}
        for _dirpath, _dirnames, _filenames in os.walk(root_path, followlinks=False):
            for _fn in _filenames:
                _fp = os.path.join(_dirpath, _fn)
                _ext = os.path.splitext(_fn)[1].lower()
                if _ext not in _text_exts and _fn not in {"shadow", "passwd", "group", "hosts",
                                                          "fstab", "inittab", "rc.local", "profile",
                                                          "environment"}:
                    continue
                try:
                    _size = os.path.getsize(_fp)
                    if _size > 1048576:
                        continue
                except OSError:
                    continue
                _matched = self._grep_file(_fp, _patterns)
                _results.extend(_matched)
        return _results

    def _grep_file(self, filepath: str, patterns: list) -> list[dict]:
        _hits = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as _f:
                _content = _f.read(8192)
        except Exception:
            return _hits
        if "\x00" in _content[:256]:
            return _hits
        for _regex, _label in patterns:
            for _m in re.finditer(_regex, _content, re.IGNORECASE):
                _line_no = _content[:_m.start()].count("\n") + 1
                _snippet = _m.group(0)[:100]
                _hits.append({"path": filepath, "relative_path": os.path.relpath(filepath, "/"),
                              "line": _line_no, "pattern": _label, "snippet": _snippet,
                              "type": "hardcoded_credential",
                              "severity": "CRITICAL" if "PRIVATE KEY" in _label else "HIGH",
                              "finding": f"硬编码凭证 ({_label}): {filepath}:{_line_no}",
                              "recommendation": "使用环境变量或密钥管理服务替代硬编码凭证"})
        return _hits

    def scan_cron_backdoors(self, root_path: str) -> list[dict]:
        _results = []
        for _cron_rel in _CRON_DIRS:
            _cron_path = os.path.join(root_path, _cron_rel)
            if not os.path.isdir(_cron_path):
                continue
            for _fn in os.listdir(_cron_path):
                _fp = os.path.join(_cron_path, _fn)
                if not os.path.isfile(_fp):
                    continue
                try:
                    with open(_fp, 'rb') as _f:
                        _chunk = _f.read(8192)
                except OSError:
                    continue
                for _pat, _type in _SUS_CRON_CMDS:
                    if _pat.search(_chunk):
                        _results.append({"path": _fp, "relative_path": os.path.relpath(_fp, root_path),
                                         "pattern_type": _type, "type": "cron_backdoor",
                                         "severity": "CRITICAL",
                                         "finding": f"Cron 可疑命令 ({_type}): {os.path.basename(_fp)}",
                                         "recommendation": "审查 cron 条目来源"})
        return _results

    def scan_capabilities(self, root_path: str) -> list[dict]:
        _results = []
        import subprocess
        for _dirpath, _dirnames, _filenames in os.walk(root_path, followlinks=False):
            for _fn in _filenames:
                _fp = os.path.join(_dirpath, _fn)
                try:
                    _mode = os.lstat(_fp).st_mode
                except OSError:
                    continue
                if not (_mode & st.S_IXUSR):
                    continue
                try:
                    _out = subprocess.run(['getcap', _fp], capture_output=True, text=True, timeout=5)
                    _caps = _out.stdout.strip()
                except Exception:
                    continue
                if not _caps:
                    continue
                _has_dangerous = any(cap in _caps.lower() for cap in _DANGEROUS_CAPABILITIES)
                _dlist = [c for c in _DANGEROUS_CAPABILITIES if c in _caps.lower()]
                _results.append({"path": _fp, "relative_path": os.path.relpath(_fp, root_path),
                                 "capabilities": _caps, "dangerous": _dlist, "type": "capability",
                                 "severity": "HIGH" if _has_dangerous else "LOW",
                                 "finding": f"Capabilities 设置: {_fn} ({_caps})",
                                 "recommendation": "审查并移除不必要的 capabilities" if _has_dangerous else "检查最小权限"})
        return _results

    def scan_insecure_permissions(self, root_path: str) -> list[dict]:
        _results = []
        _sensitive = {"etc/shadow": (0o000, "密码影子文件"), "etc/shadow-": (0o000, "密码影子备份"),
                      "etc/gshadow": (0o000, "组影子文件"), "etc/passwd": (0o644, "用户数据库")}
        _ssh_patterns = [("id_rsa", 0o600), ("id_ecdsa", 0o600), ("id_ed25519", 0o600),
                         ("id_dsa", 0o600), ("authorized_keys", 0o600)]
        for _rel, (_max_perm, _desc) in _sensitive.items():
            _fp = os.path.join(root_path, _rel)
            if not os.path.exists(_fp):
                continue
            try:
                _mode = os.stat(_fp).st_mode; _perm = _mode & 0o777
                if _perm > _max_perm:
                    _results.append({"path": _fp, "relative_path": _rel, "permissions": oct(_perm),
                                     "expected_max": oct(_max_perm), "type": "insecure_permission",
                                     "severity": "HIGH",
                                     "finding": f"{_rel} 权限过于宽松: {oct(_perm)} (≤ {oct(_max_perm)})",
                                     "recommendation": f"chmod {oct(_max_perm)} {_rel}"})
            except OSError:
                pass
        for _dirpath, _dirnames, _filenames in os.walk(root_path, followlinks=False):
            for _fn in _filenames:
                for _keyname, _max in _ssh_patterns:
                    if _fn == _keyname:
                        _fp = os.path.join(_dirpath, _fn)
                        try:
                            _mode = os.stat(_fp).st_mode; _perm = _mode & 0o777
                            if _perm > _max:
                                _results.append({"path": _fp, "relative_path": os.path.relpath(_fp, root_path),
                                                 "permissions": oct(_perm), "expected_max": oct(_max),
                                                 "type": "insecure_permission", "severity": "CRITICAL",
                                                 "finding": f"SSH密钥权限不安全: {_fn} ({oct(_perm)})",
                                                 "recommendation": f"chmod {oct(_max)} {_fn}"})
                        except OSError:
                            pass
        _etc_path = os.path.join(root_path, "etc")
        if os.path.isdir(_etc_path):
            try:
                _etc_mode = os.stat(_etc_path).st_mode
                if _etc_mode & 0o002:
                    _results.append({"path": _etc_path, "relative_path": "etc",
                                     "permissions": oct(_etc_mode & 0o777), "type": "insecure_permission",
                                     "severity": "CRITICAL",
                                     "finding": "/etc 全局可写 — 攻击者可修改系统配置",
                                     "recommendation": "chmod 755 /etc"})
            except OSError:
                pass
        return _results

    def scan_all(self, root_path: str) -> list[dict]:
        _all = []
        _all.extend(self.scan_world_writable(root_path))
        _all.extend(self.scan_suid_sgid(root_path))
        _all.extend(self.scan_hardcoded_credentials(root_path))
        _all.extend(self.scan_insecure_permissions(root_path))
        _all.extend(self.scan_cron_backdoors(root_path))
        return _all
