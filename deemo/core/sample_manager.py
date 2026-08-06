"""
Sample manager: binary sample registration, classification, batch checksec,
and metadata maintenance.

CRUD operations for the sample library, batch directory scanning, CSV/Markdown
export, and filtering by vuln type / arch / difficulty. Metadata persisted as JSON.

Integrates with experiment_tracker.py: registered samples serve as experiment
inputs, linked via sample_id.

References:
  - NIST SAMATE, "Test Case Suites"
  - CGC (DARPA Cyber Grand Challenge), "Challenge Binary Corpus"
"""

from __future__ import annotations

import csv
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 默认样本库路径
DEFAULT_SAMPLE_DB = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'data', 'samples.json'
)

# 样本库目录结构模板
SAMPLE_DIRS = {
    'ctf': 'CTF 竞赛样本',
    'teaching': '教学演示样本',
    'cve': '公开 CVE 漏洞样本',
}


class SampleManager:
    """
    样本管理器 —— 维护样本注册表和批量操作。

    用法:
        mgr = SampleManager()
        mgr.register('/path/to/vuln_binary', vuln_type='stack-overflow')
        mgr.batch_scan('/samples/ctf/')
        mgr.export_csv('samples.csv')
    """

    def __init__(self, db_path: str = DEFAULT_SAMPLE_DB):
        self.db_path = db_path
        self._samples: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ---- CRUD ----

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
        import hashlib

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
            vuln_type = _infer_vuln_type(abs_path)

        entry = {
            'id': sample_id,
            'path': abs_path,
            'filename': os.path.basename(abs_path),
            'size_bytes': os.path.getsize(abs_path),
            'format': checksec.get('format', _guess_format(abs_path)),
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

    # ---- 批量操作 ----

    def batch_scan(
        self,
        directory: str,
        recursive: bool = True,
        register: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        批量扫描目录中的二进制文件。

        Args:
            directory: 目录路径
            recursive: 是否递归扫描子目录
            register:  是否自动注册发现的样本

        Returns:
            发现的二进制摘要列表
        """
        if not os.path.isdir(directory):
            return []

        binaries = _find_binaries(directory, recursive)
        _log.info("Batch scan found %d binary(ies) in %s", len(binaries), directory)

        results = []
        for bpath in binaries:
            try:
                if register:
                    sample_id = self.register(bpath)
                    results.append(self.get(sample_id) or {})
                else:
                    results.append({
                        'path': bpath,
                        'filename': os.path.basename(bpath),
                        'format': _guess_format(bpath),
                    })
            except Exception as e:
                _log.debug("Batch scan skipping %s: %s", bpath, e)

        return results

    def export_csv(self, output_path: str) -> str:
        """导出样本清单为 CSV 文件。"""
        samples = self.list_samples()
        if not os.path.isabs(output_path):
            output_path = os.path.join(os.path.dirname(self.db_path), output_path)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Filename', 'Format', 'Arch', 'Bits',
                'Vuln Type', 'Difficulty', 'NX', 'PIE', 'Canary',
                'RELRO', 'FORTIFY', 'Source', 'Tags', 'Size (bytes)',
            ])
            for s in samples:
                cs = s.get('checksec', {})
                writer.writerow([
                    s['id'], s['filename'], s.get('format', ''),
                    cs.get('format', ''), cs.get('bits', ''),
                    s.get('vuln_type', ''), s.get('difficulty', ''),
                    cs.get('nx', ''), cs.get('pie', ''),
                    cs.get('canary', ''), cs.get('relro', ''),
                    cs.get('fortify', ''), s.get('source', ''),
                    ','.join(s.get('tags', [])), s.get('size_bytes', ''),
                ])

        _log.info("Exported %d samples to %s", len(samples), output_path)
        return output_path

    def export_markdown(self, output_path: str) -> str:
        """导出样本清单为 Markdown 文件。"""
        samples = self.list_samples()
        if not os.path.isabs(output_path):
            output_path = os.path.join(os.path.dirname(self.db_path), output_path)

        lines = [
            '# BinMind Sample Registry',
            f'',
            f'**Total:** {len(samples)} samples  ',
            f'**Exported:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ',
            f'',
            f'| ID | Filename | Arch | Vuln | Difficulty | Protections |',
            f'|----|----------|------|------|------------|-------------|',
        ]
        for s in samples:
            cs = s.get('checksec', {})
            prot = (
                f"{'N' if cs.get('nx') else 'n'} "
                f"{'P' if cs.get('pie') else 'p'} "
                f"{'C' if cs.get('canary') else 'c'} "
                f"{cs.get('relro', '?')[0].upper()}"
            )
            lines.append(
                f"| `{s['id'][:8]}` | {s['filename']} | "
                f"{cs.get('format', '?')} | {s.get('vuln_type', '-')} | "
                f"{s.get('difficulty', '-')} | {prot} |"
            )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

        return output_path

    def summary(self) -> Dict[str, Any]:
        """返回样本库的统计摘要。"""
        samples = self.list_samples()
        by_type: Dict[str, int] = {}
        by_difficulty: Dict[str, int] = {}
        by_format: Dict[str, int] = {}
        for s in samples:
            vt = s.get('vuln_type', 'unknown')
            df = s.get('difficulty', 'unknown')
            fm = s.get('format', 'unknown')
            by_type[vt] = by_type.get(vt, 0) + 1
            by_difficulty[df] = by_difficulty.get(df, 0) + 1
            by_format[fm] = by_format.get(fm, 0) + 1

        return {
            'total_samples': len(samples),
            'by_vuln_type': by_type,
            'by_difficulty': by_difficulty,
            'by_format': by_format,
        }

    # ---- 内部 ----

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


def _find_binaries(directory: str, recursive: bool) -> List[str]:
    """发现目录中的可执行二进制文件。"""
    binaries = []
    from core.binary_info import detect_format

    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath) and not fname.endswith(
                ('.py', '.c', '.cpp', '.h', '.txt', '.md', '.json', '.log')
            ):
                if detect_format(fpath) != 'unknown':
                    binaries.append(fpath)
        if not recursive:
            break

    return binaries


def _guess_format(path: str) -> str:
    """快速猜测文件格式。"""
    try:
        from core.binary_info import detect_format
        return detect_format(path)
    except Exception:
        return 'unknown'


def _infer_vuln_type(path: str) -> str:
    """从文件名推断漏洞类型。"""
    name = os.path.basename(path).lower()
    if 'stack' in name or 'bof' in name or 'overflow' in name:
        return 'stack-overflow'
    if 'fmt' in name or 'format' in name or 'fsb' in name:
        return 'format-string'
    if 'heap' in name or 'uaf' in name:
        return 'heap-corruption'
    if 'rop' in name:
        return 'code-reuse'
    if 'shellcode' in name:
        return 'shellcode-injection'
    return ''


def init_sample_directories(base_dir: str) -> Dict[str, str]:
    """初始化样本库目录结构。"""
    created = {}
    for dirname, description in SAMPLE_DIRS.items():
        dirpath = os.path.join(base_dir, dirname)
        os.makedirs(dirpath, exist_ok=True)
        readme_path = os.path.join(dirpath, 'README.md')
        if not os.path.exists(readme_path):
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(f'# {description}\n\n放置 {description} 的二进制文件。\n')
        created[dirname] = dirpath
    return created
