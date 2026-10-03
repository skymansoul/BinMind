"""
样本管理器 - 批量扫描与导出 mixin。

封装目录批量扫描、CSV/Markdown 导出及统计摘要，供 SampleManager 组合复用。
"""


import csv
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from .sample_manager_types import find_binaries, guess_format

_log = logging.getLogger(__name__)


class _BatchMixin:
    """批量操作与导出功能。"""

    db_path: str
    _samples: Dict[str, Dict[str, Any]]

    def batch_scan(
        self,
        directory: str,
        recursive: bool = True,
        register: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        批量扫描目录中的二进制文件, 返回发现的二进制摘要列表;
        register=True 时自动注册并回读完整记录。
        """
        if not os.path.isdir(directory):
            return []

        binaries = find_binaries(directory, recursive)
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
                        'format': guess_format(bpath),
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
