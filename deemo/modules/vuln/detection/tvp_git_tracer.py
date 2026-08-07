# coding: utf-8
# 创建: 2026-05-17  |  Git提交追溯
# 修改: 2026-05-17  |  审计后补充文件头与错误处理
#
"""
Git提交溯源追踪器——从源码仓库提取漏洞相关提交的因果特征。

技术路径:
  1. git blame限定行范围 → 定位每行的引入提交
  2. 按提交聚合 + git log补充元数据 → 提取因果特征
  3. 产出ProvenanceHypothesis列表供贝叶斯引擎推断

关键优化:
  仅blame漏洞相关行（程序切片限定范围），避免全仓库线性扫描。
  作者经验计算限定在目标文件内——跨文件经验不可迁移。
"""

import os
import re
import math
import logging
import subprocess
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timezone

from .tvp_causal_types import ProvenanceHypothesis

_log = logging.getLogger(__name__)


def _run_git(repo: str, args: List[str], timeout: int = 30,
              retries: int = 2) -> Tuple[int, str, str]:
    """执行git命令——含重试机制与网络错误处理。

    瞬态错误(网络波动/锁文件竞争)自动重试。
    永久错误(仓库不存在/权限不足)立即返回。
    """
    last_error = ''
    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(
                ['git'] + args, cwd=repo, capture_output=True, text=True,
                timeout=timeout,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0',
                     'GIT_CONFIG_NOSYSTEM': '1'})
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            last_error = f'超时({timeout}s)'
            if attempt < retries:
                _log.debug('git %s 超时, 重试 %d/%d', args[0], attempt + 1, retries)
                timeout = int(timeout * 1.5)  # 指数退避
        except FileNotFoundError:
            return -2, '', 'git命令不可用'
        except OSError as e:
            last_error = str(e)
            if attempt < retries:
                _log.debug('git %s OS错误, 重试: %s', args[0], e)
    return -1, '', last_error


def _parse_iso_to_unix(iso_str: str) -> float:
    """ISO 8601→Unix时间戳"""
    iso_str = iso_str.strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S'):
        try:
            dt = datetime.strptime(iso_str.replace('Z', '+0000'), fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


class CommitFeatureExtractor:
    """提交特征提取器——blame + log + 因果特征计算。

    缓存策略:
      _author_file_history: (作者, 文件)→提交数，避免重复git log --author
      _file_total_commits: 文件→总提交数，跨函数共享
    """

    def __init__(self, repo_path: str):
        if not os.path.isdir(os.path.join(repo_path, '.git')):
            raise ValueError(f"非git仓库: {repo_path}")
        self._repo = repo_path
        self._author_file_history: Dict[Tuple[str, str], int] = {}
        self._file_total_commits: Dict[str, int] = {}
        self._file_lines: Dict[str, int] = {}

    def extract_commits_for_lines(self, file_path: str,
                                   start_line: int, end_line: int
                                   ) -> List[ProvenanceHypothesis]:
        """对指定行范围执行blame，返回候选提交假设列表。

        git blame --line-porcelain → 逐行解析 → 按提交聚合 → 补充元数据。
        """
        line_range = f"-L{start_line},{end_line}"
        retcode, stdout, _ = _run_git(
            self._repo,
            ['blame', '--line-porcelain', line_range, 'HEAD', '--', file_path],
            timeout=60)
        if retcode != 0:
            _log.debug("git blame失败: %s (行%d-%d)", file_path, start_line, end_line)
            return []

        # 解析porcelain输出——逐提交聚合行数与作者
        commit_data: Dict[str, Dict] = {}
        current = None
        for line in stdout.split('\n'):
            if not line.strip():
                continue
            if not line.startswith('\t') and not line.startswith(' '):
                parts = line.split()
                if parts and re.match(r'^[0-9a-f]{40}$', parts[0]):
                    current = parts[0]
                    commit_data.setdefault(current, {'lines': 0, 'authors': set()})
                    commit_data[current]['lines'] += 1
            elif line.startswith('author ') and current:
                commit_data[current]['authors'].add(line[7:].strip())
            elif line.startswith('author-time ') and current:
                commit_data[current]['timestamp'] = int(line[12:].strip())

        # 补充元数据并构造假设
        hypotheses = []
        for ch, data in commit_data.items():
            features = self._enrich(ch, file_path)
            if features is None:
                continue
            author = next(iter(data['authors']), 'unknown') if data['authors'] else 'unknown'
            h = ProvenanceHypothesis(
                commit_hash=ch, commit_timestamp=features['timestamp'],
                author_expertise=self._author_expertise(author, file_path),
                files_changed=features['files'], lines_added=features['added'],
                lines_removed=features['deleted'], code_churn=features['churn'],
                causal_path=features['path'])
            hypotheses.append(h)

        _log.info("文件%s行%d-%d: %d候选提交", file_path, start_line, end_line, len(hypotheses))
        return hypotheses

    def _enrich(self, commit_hash: str, file_path: str) -> Optional[Dict]:
        """提取提交元数据——numstat + 衍生因果特征"""
        retcode, stdout, _ = _run_git(
            self._repo,
            ['log', '--format=%H%n%aI%n%s%n%P', '--numstat', '--no-renames',
             f'{commit_hash}^!'],
            timeout=15)
        if retcode != 0:
            return None
        lines = stdout.strip().split('\n')
        if len(lines) < 5:
            return None

        timestamp = _parse_iso_to_unix(lines[1].strip())
        message = lines[2].strip()
        parents = lines[3].strip().split()
        is_merge = len(parents) > 1

        files_touched = []
        total_added = 0
        total_deleted = 0
        for line in lines[4:]:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            total_added += int(parts[0]) if parts[0] != '-' else 0
            total_deleted += int(parts[1]) if parts[1] != '-' else 0
            files_touched.append(parts[2])

        file_lines = self._get_file_lines(file_path)
        code_churn = min(1.0, (total_added + total_deleted) / max(file_lines, 1))
        causal_path = self._classify_path(is_merge, files_touched, message)

        return {'timestamp': timestamp, 'files': files_touched,
                'added': total_added, 'deleted': total_deleted,
                'churn': code_churn, 'path': causal_path}

    def _author_expertise(self, author: str, file_path: str) -> float:
        """作者在目标文件的经验量化——对数缩放。

        公式: 1 - exp(-0.3 × author_commits)
        5次提交≈0.78, 10次提交≈0.95。
        """
        cache_key = (author, file_path)
        if cache_key not in self._author_file_history:
            _, stdout, _ = _run_git(
                self._repo,
                ['log', '--oneline', '--author', author, 'HEAD', '--', file_path],
                timeout=20)
            self._author_file_history[cache_key] = (
                len(stdout.strip().split('\n')) if stdout.strip() else 0)

        return min(1.0, 1.0 - math.exp(-0.3 * self._author_file_history[cache_key]))

    def _get_file_lines(self, file_path: str) -> int:
        """文件当前行数——用于churn归一化"""
        if file_path in self._file_lines:
            return self._file_lines[file_path]
        try:
            with open(os.path.join(self._repo, file_path), 'r',
                      encoding='utf-8', errors='replace') as f:
                n = sum(1 for _ in f)
        except (FileNotFoundError, OSError):
            n = 100
        self._file_lines[file_path] = max(n, 1)
        return self._file_lines[file_path]

    @staticmethod
    def _classify_path(is_merge: bool, files: List[str], msg: str) -> str:
        """基于提交特征推测因果路径类型"""
        if is_merge:
            return 'merge_introduction'
        config_exts = {'.cfg', '.ini', '.toml', '.yaml', '.yml'}
        config_names = {'CMakeLists.txt', 'Makefile', 'setup.py', 'setup.cfg'}
        for f in files:
            bn = os.path.basename(f)
            if bn in config_names or any(f.endswith(ext) for ext in config_exts):
                return 'config_change'
        dep_kw = ('dependency', 'import', 'include', 'vendor', 'library')
        if any(kw in msg.lower() for kw in dep_kw):
            return 'dependency_change'
        return 'direct_modification'


class RepositoryTemporalAnalyzer:
    """仓库时态分析——文件年龄、提交频率、安全敏感标记。

    为贝叶斯模型提供根节点先验数据。
    """

    _SEC_PATTERNS = [
        r'auth', r'login', r'password', r'crypto', r'encrypt',
        r'decrypt', r'hash', r'sign', r'verify', r'token',
        r'serializ', r'deserializ', r'permission', r'sandbox', r'seccomp',
    ]

    def __init__(self, repo_path: str):
        self._repo = repo_path
        self._cache: Dict[str, float] = {}

    def get_file_age_days(self, file_path: str) -> float:
        """文件首次提交至今的天数"""
        key = f'age_{file_path}'
        if key in self._cache:
            return self._cache[key]
        _, stdout, _ = _run_git(
            self._repo,
            ['log', '--reverse', '--format=%aI', 'HEAD', '--', file_path],
            timeout=20)
        if not stdout.strip():
            return 365.0
        first_ts = _parse_iso_to_unix(stdout.strip().split('\n')[0])
        days = max(1.0, (datetime.now(timezone.utc).timestamp() - first_ts) / 86400.0)
        self._cache[key] = days
        return days

    def get_commit_freq_weekly(self, file_path: str) -> float:
        """最近90天周均提交数"""
        key = f'freq_{file_path}'
        if key in self._cache:
            return self._cache[key]
        since = datetime.now(timezone.utc).replace(
            day=max(1, datetime.now(timezone.utc).day - 90))
        _, stdout, _ = _run_git(
            self._repo,
            ['log', '--oneline', f'--since={since.strftime("%Y-%m-%d")}',
             'HEAD', '--', file_path],
            timeout=20)
        freq = (len(stdout.strip().split('\n')) if stdout.strip() else 0) / 12.86
        self._cache[key] = freq
        return freq

    def is_security_sensitive(self, file_path: str) -> bool:
        """路径模式匹配——安全敏感文件启发式判断"""
        import re
        path_l = file_path.lower()
        return any(re.search(p, path_l) for p in self._SEC_PATTERNS)


__all__ = [
    "CommitFeatureExtractor",
    "RepositoryTemporalAnalyzer",
]
