# 兼容性 alias: re-exports core.报告 under modules.报告
from core.report import *
from typing import Dict, Any
from typing import List, Optional
import json as _json
import os as _os


class ReportGenerator:
    """Accumulates step data produces analysis 报告"""

    def __init__(self, output_dir="./reports"):
        self.output_dir = output_dir
        self._steps = []

    def add_step_rp(self, name, data, result):
        self._steps.append({
            'name': name,
            'data': data,
            'result': result,
        })

    def generate_markdown_report_rp(self):
        lines = ["# Analysis Report", ""]
        for s in self._steps:
            lines.append(f"## {s['name']}")
            lines.append("")
            lines.append("```")
            lines.append(f"{s['result']}")
            lines.append("```")
            lines.append("")
        return "\n".join(lines)

    def generate_json_report_rp(self):
        return _json.dumps(self._steps, indent=2)

    def generate_report(self, findings, binary_info, output_format='markdown'):
        return write_report(findings, binary_info, output_format=output_format)

    def generate_markdown(self, findings, binary_info):
        return generate_markdown(findings, binary_info)

    def generate_json(self, findings, binary_info):
        return generate_json(findings, binary_info)

    def write_report_to_disk(self, findings, binary_info, output_format='markdown'):
        """将报告持久化到磁盘, 自动生成带时间戳的文件名，避免跨运行的路径冲突"""
        fmt = output_format or 'markdown'
        content = self.generate_report(findings, binary_info, output_format=fmt)
        try:
            _os.makedirs(self.output_dir, exist_ok=True)
            stamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')
            ext = 'md' if fmt == 'markdown' else 'json'
            fpath = _os.path.join(self.output_dir, f"analysis_report_{stamp}.{ext}")
            with open(fpath, 'w', encoding='utf-8') as fh:
                fh.write(content)
            return fpath
        except Exception:
            return None
