"""
样本管理器 —— CRUD mixin。

封装样本注册、检索、筛选、删除及 JSON 持久化，供 SampleManager 组合复用。
"""


import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .sample_manager_types import guess_format, infer_vuln_type

_log = logging.getLogger(__name__)


class _CrudMixin:
    """样本注册表的增删改查与持久化。"""

    db_path: str
    _samples: Dict[str, Dict[str, Any]]

    def register(
        self,
        binary_path: str,
        vuln_type: str = '',
        difficulty: str = '',
        source: str = '',
        tags: Optional[List[str]] = None,
        run_args: str = '',
        notes: str = '',
    ) -> str:
        """
        注册一个样本。

        Args:
            binary_path: 二进制文件路径
            vuln_type:   漏洞类型（如 stack-overflow, format-string）
            difficulty:  难度评估（easy/medium/hard/insane）
            source:      样本来源（CTF名称/CVE编号/课程名）
            tags:        标签列表
            run_args:    运行参数
            notes:       备注

        Returns:
            样本 ID（SHA256 哈希的前 16 字符）
        """
        abs_path = os.path.abspath(binary_path)
        if not os.path.isfile(abs_path):
            raise FileNotFoundError(f'not a file: {abs_path}')

        try:
            h = hashlib.sha256()
            with open(abs_path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sample_id = h.hexdigest()[:16]
        except OSError:
            sample_id = hashlib.sha256(abs_path.encode()).hexdigest()[:16]

        # 自动采集 checksec
        checksec = {}
        try:
            from core.checksec import detect_checksec
            checksec = detect_checksec(abs_path)
        except ImportError:
            pass

        # 自动推断漏洞类型
        if not vuln_type:
            vuln_type = infer_vuln_type(abs_path)

        entry = {
            'id': sample_id,
            'path': abs_path,
            'filename': os.path.basename(abs_path),
            'size_bytes': os.path.getsize(abs_path),
            'format': checksec.get('format', guess_format(abs_path)),
            'checksec': checksec,
            'vuln_type': vuln_type,
            'difficulty': difficulty,
            'source': source,
            'tags': tags or [],
            'run_args': run_args,
            'notes': notes,
            'registered_at': datetime.now().isoformat(),
        }

        self._samples[sample_id] = entry
        self._save()
        _log.info("Sample registered: %s (id=%s)", entry['filename'], sample_id)
        return sample_id

    def get(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """按 ID 检索样本。"""
        return self._samples.get(sample_id)

    def list_samples(
        self,
        vuln_type: str = '',
        difficulty: str = '',
        fmt: str = '',
        tag: str = '',
    ) -> List[Dict[str, Any]]:
        """列出满足筛选条件的样本。"""
        result = []
        for s in self._samples.values():
            if vuln_type and vuln_type not in s.get('vuln_type', ''):
                continue
            if difficulty and difficulty != s.get('difficulty', ''):
                continue
            if fmt and fmt != s.get('format', ''):
                continue
            if tag and tag not in s.get('tags', []):
                continue
            result.append(dict(s))
        result.sort(key=lambda s: s.get('registered_at', ''))
        return result

    def delete(self, sample_id: str) -> bool:
        """删除样本注册记录（不删除文件）。"""
        if sample_id in self._samples:
            del self._samples[sample_id]
            self._save()
            return True
        return False

    def _load(self) -> None:
        """从 JSON 文件加载样本数据库。"""
        if os.path.isfile(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self._samples = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                _log.warning("Sample DB load failed: %s, starting fresh", e)
                self._samples = {}

    def _save(self) -> None:
        """保存样本数据库到 JSON 文件。"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self._samples, f, indent=2, ensure_ascii=False)
