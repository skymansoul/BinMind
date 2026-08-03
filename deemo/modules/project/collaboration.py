from __future__ import annotations
"""Git协作层: repo init/stage/commit/diff生成/porcelain状态解析."""
from typing import Dict, List, Optional, Any
import subprocess as sp, os, time, logging, shutil
from pathlib import Path
from enum import Enum as _Enum
from contextlib import suppress

logger = logging.getLogger(__name__)
class UserRole(_Enum): ADMIN = "admin"; ANALYST = "analyst"; VIEWER = "viewer"
class DiffHunk:
    def __init__(self, os=0, oc=0, ns=0, nc=0, lines=None): self.old_start = os; self.old_count = oc; self.new_start = ns; self.new_count = nc; self.lines = lines or []

class CollaborationManager:
    _PROTECTED = frozenset({"main", "master", "release", "production"})
    def __init__(self, repo_root=None):
        self.root = Path(repo_root) if repo_root else Path.cwd(); self.users: list = []; self._wt: Dict[str, Path] = {}

    # 用户注册
    def add_user(self, u, r): self.users.append({"name": u, "role": r, "added": time.time()})
    def register_user(self, u, role="analyst"):
        try: r = UserRole(role)
        except ValueError: r = UserRole.VIEWER
        self.add_user(u, r); return True
    def authenticate_user(self, u, **_): return any(x["name"] == u for x in self.users)

    # git操作
    def is_git_repo(self): return (self.root / ".git").is_dir()
    def _run(self, *args, capture=True, check=False):
        cmd = []
        for a in args:
            if isinstance(a, (list, tuple)): cmd.extend(str(x) for x in a)
            else: cmd.append(str(a))
        kw: Dict[str, Any] = {'cwd': str(self.root)}
        if capture: kw.update(stdout=sp.PIPE, stderr=sp.PIPE, text=True)
        try: return sp.run(cmd, check=check, **kw)
        except FileNotFoundError: logger.error("git not found on PATH"); return None

    def init(self, branch="main"):
        self.root.mkdir(parents=True, exist_ok=True)
        if (r := self._run("git", "init", "-b", branch)) and r.returncode == 0: logger.info("initialized git repo at %s", self.root)

    def status(self):
        out: Dict[str, List[str]] = {"staged": [], "unstaged": [], "untracked": []}
        r = self._run("git", "status", "--porcelain")
        if r is None or r.returncode != 0: return out
        for line in r.stdout.splitlines():
            if not line.strip(): continue
            x, y, fp = line[0], line[1], line[3:].strip()
            if x in "MRC" or y in "MRC": out["staged"].append(fp)
            elif x in " ?" and y in "M D": out["unstaged"].append(fp)
            elif x == "?" and y == "?": out["untracked"].append(fp)
        return out

    def is_clean(self):
        s = self.status(); return not (s["staged"] or s["unstaged"] or s["untracked"])

    def stage(self, *paths): paths and self._run("git", "add", "--", *paths, capture=False)
    def unstage(self, *paths): paths and self._run("git", "reset", "HEAD", "--", *paths, capture=False)

    def commit(self, msg, an="", ae="", allow_empty=False):
        if not allow_empty and self.current_branch() in self._PROTECTED: logger.warning("拒绝在受保护分支上 commit"); return False
        cmd = ["git", "commit"]; allow_empty and cmd.append("--allow-empty"); cmd.extend(["-m", msg])
        env = {**os.environ, "GIT_AUTHOR_NAME": an, "GIT_AUTHOR_EMAIL": ae, "GIT_COMMITTER_NAME": an, "GIT_COMMITTER_EMAIL": ae} if an and ae else None
        with suppress(FileNotFoundError):
            kw: Dict[str, Any] = {'cwd': str(self.root), 'capture_output': True, 'text': True}
            if env: kw['env'] = env
            return sp.run(cmd, **kw).returncode == 0
        return False

    def diff(self, staged=False, target=None):
        cmd = ["git", "diff"]; staged and cmd.append("--cached"); target and cmd.append(str(target))
        r = self._run(*cmd); return r.stdout if r and r.returncode == 0 else ""
    def diff_branches(self, base, head="HEAD"):
        r = self._run("git", "diff", f"{base}..{head}"); return r.stdout if r and r.returncode == 0 else ""
    def log(self, n=20, oneline=False):
        cmd = ["git", "log", f"-n{n}"]; oneline and cmd.append("--oneline")
        r = self._run(*cmd); return r.stdout if r and r.returncode == 0 else ""
    def branch(self):
        r = self._run("git", "branch", "--list")
        return [b.strip().lstrip("* ") for b in r.stdout.splitlines() if b.strip()] if r and r.returncode == 0 else []
    def checkout(self, b): self._run("git", "checkout", b, capture=False)
    def current_branch(self):
        r = self._run("git", "rev-parse", "--abbrev-ref", "HEAD"); return r.stdout.strip() if r and r.returncode == 0 else None
    def pull(self, remote="origin", branch=None):
        cmd = ["git", "pull", remote]; branch and cmd.append(branch); self._run(*cmd, capture=False)
    def push(self, remote="origin", branch=None):
        cmd = ["git", "push", remote]; branch and cmd.append(branch); self._run(*cmd, capture=False)
    def get_diff_files(self, staged=False):
        raw = self.diff(staged=staged); files = []
        for line in raw.splitlines():
            if line.startswith("diff --git ") and len(parts := line.split()) >= 4: files.append(parts[3][2:])
        return files
    def stash_push(self, msg=""):
        cmd = ["git", "stash", "push", "--include-untracked"]; msg and cmd.extend(["-m", msg])
        r = self._run(*cmd); return r.stdout.strip() if r and r.returncode == 0 else None
    def stash_pop(self, idx=0):
        r = self._run("git", "stash", "pop", f"stash@{{{idx}}}"); return r is not None and r.returncode == 0
    def stash_list(self):
        r = self._run("git", "stash", "list"); return r.stdout.strip().splitlines() if r and r.returncode == 0 else []
    def blame(self, fp, sl=0, el=0):
        cmd = ["git", "blame", "--line-porcelain"]; sl and el and cmd.extend(["-L", f"{sl},{el}"]); cmd.append(fp)
        r = self._run(*cmd)
        if r is None or r.returncode != 0: return []
        entries, cur = [], {}
        for line in r.stdout.splitlines():
            if line.startswith("\t"): cur["content"] = line[1:]; entries.append(dict(cur)); cur = {}; continue
            if len(parts := line.split(" ", 1)) == 2: cur[parts[0]] = parts[1]
        return entries
    def create_worktree(self, name, base=None):
        wp = self.root / ".binmind" / "worktrees" / name
        if wp.exists(): logger.warning("worktree %s 已存在", name); self._wt[name] = wp; return wp
        cmd = ["git", "worktree", "add", str(wp)]; base and cmd.append(base)
        r = self._run(*cmd, capture=False)
        if r is None or r.returncode != 0: logger.error("创建 worktree %s 失败", name); return None
        self._wt[name] = wp; logger.info("worktree %s 已创建: %s", name, wp); return wp
    def remove_worktree(self, name, force=False):
        if (wp := self._wt.pop(name, None)) is None: return
        cmd = ["git", "worktree", "remove"]; force and cmd.append("--force"); cmd.append(str(wp))
        self._run(*cmd, capture=False); wp.exists() and shutil.rmtree(str(wp), ignore_errors=True)
    def list_worktrees(self):
        r = self._run("git", "worktree", "list")
        return [{"path": p[0], "branch": p[-1].strip("[]")} for line in r.stdout.strip().splitlines() if len(p := line.split()) >= 2] if r and r.returncode == 0 else []
    def prune_worktrees(self): self._run("git", "worktree", "prune", capture=False)
    def shallow_clone(self, url, target="", depth=50, branch=None):
        dest = target or self.root.name; cmd = ["git", "clone", "--depth", str(depth)]
        branch and cmd.extend(["-b", branch]); cmd.extend([url, dest])
        with suppress(FileNotFoundError):
            r = sp.run(cmd, cwd=str(self.root.parent), capture_output=True, text=True)
            if r.returncode == 0: logger.info("浅克隆成功: %s (depth=%d)", url, depth); return True
        return False
    def sparse_checkout(self, patterns):
        r = self._run("git", "sparse-checkout", "set", "--no-cone", *patterns); return r is not None and r.returncode == 0
    def tag(self, name, msg=""):
        cmd = ["git", "tag", "-a", name]; msg and cmd.extend(["-m", msg])
        r = self._run(*cmd, capture=False); return r is not None and r.returncode == 0

name: str = ""; module: str = ""
