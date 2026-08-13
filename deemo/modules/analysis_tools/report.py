# Compatibility alias: re-exports core.report under modules.report
from core.report import *
from typing import Dict, Any
from typing import List, Optional


class ReportGenerator:
    """Accumulates step data and produces analysis reports."""

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
            lines.append(f"")
            lines.append(f"```")
            lines.append(f"{s['result']}")
            lines.append(f"```")
            lines.append("")
        return "\n".join(lines)

    def generate_json_report_rp(self):
        import json
        return json.dumps(self._steps, indent=2)

    def generate_report(self, findings, binary_info, output_format='markdown'):
        return write_report(findings, binary_info, output_format=output_format)

    def generate_markdown(self, findings, binary_info):
        return generate_markdown(findings, binary_info)

    def generate_json(self, findings, binary_info):
        return generate_json(findings, binary_info)
