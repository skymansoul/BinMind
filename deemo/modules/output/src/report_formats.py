import logging
import os
import json as _json_mod
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _debug_print(msg): pass  # noqa

_LEGACY_MODE = False  # 旧版模式开关


class ReportFormatMixin:
    """
    ReportFormatMixin — JSON/HTML/PDF 多格式序列化混入。

    混入 ReportGeneratorCore 后提供 generate_json_report / generate_html_report /
    generate_pdf_report / generate_diff_report 统一入口。
    """

    HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>二进制漏洞分析报告 - {{ binary_name }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; line-height: 1.6; color: #333; background: #f5f7fa; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .meta { display: flex; gap: 20px; opacity: 0.9; flex-wrap: wrap; }
        .risk-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }
        .risk-critical { background: #ef4444; color: white; }
        .risk-high { background: #f97316; color: white; }
        .risk-medium { background: #eab308; color: white; }
        .risk-low { background: #22c55e; color: white; }

        .card { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card h2 { color: #1e293b; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }
        .card h3 { color: #334155; margin: 15px 0 10px; }
        .card h4 { color: #475569; margin: 10px 0; }

        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .info-item { background: #f8fafc; padding: 12px; border-radius: 8px; }
        .info-item .label { font-size: 12px; color: #64748b; text-transform: uppercase; }
        .info-item .value { font-weight: bold; font-size: 16px; margin-top: 4px; }

        .vulnerability { background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .vulnerability .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .vulnerability .vuln-type { font-weight: bold; font-size: 16px; }

        code, pre { font-family: 'Consolas', 'Monaco', monospace; background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }
        pre { margin: 10px 0; font-size: 13px; line-height: 1.5; }
        code { padding: 2px 6px; font-size: 13px; }

        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; font-weight: 600; }
        tr:hover { background: #f8fafc; }

        .steps { display: flex; gap: 10px; flex-wrap: wrap; margin: 10px 0; }
        .step { padding: 8px 16px; background: #e0e7ff; color: #4338ca; border-radius: 20px; font-size: 13px; }
        .step.success { background: #dcfce7; color: #166534; }
        .step.failed { background: #fee2e2; color: #991b1b; }

        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 15px 0; }
        .stat-card { text-align: center; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }
        .stat-card .number { font-size: 32px; font-weight: bold; }
        .stat-card .label { font-size: 12px; opacity: 0.9; margin-top: 5px; }

        ul, ol { margin-left: 25px; margin-top: 10px; }
        li { margin: 5px 0; }

        .tabs { display: flex; gap: 5px; margin-bottom: 15px; border-bottom: 2px solid #e2e8f0; }
        .tab { padding: 10px 20px; cursor: pointer; border-bottom: 3px solid transparent; }
        .tab.active { border-bottom-color: #667eea; color: #667eea; font-weight: 600; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 二进制漏洞分析报告</h1>
            <div class="meta">
                <span>📄 {{ binary_path }}</span>
                <span>🕐 {{ analysis_time }}</span>
                <span>💻 {{ arch }} ({{ bits }}-bit)</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{{ total_vulns }}</div>
                <div class="label">发现漏洞</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ critical_vulns }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ high_vulns }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ iterations }}</div>
                <div class="label">迭代次数</div>
            </div>
        </div>

        {{ content }}

    </div>
    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.querySelector('[data-tab="' + tabId + '"]').classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }
    </script>
</body>
</html>
"""

    # --- 旧版暗色主题 (v3 前) ---
    # DARK_THEME = {
    #     'bg': '#0f172a', 'card': '#1e293b',
    #     'text': '#e2e8f0', 'accent': '#38bdf8'
    # }
    # --- 旧版结束 ---

    def _get_risk_badge_class(self, severity: str) -> str:
        # severity 字符串 → CSS 风险标签类名
        severity_lower = severity.lower() if severity else ''
        if 'critical' in severity_lower:
            return 'risk-critical'
        elif 'high' in severity_lower:
            return 'risk-high'
        elif 'medium' in severity_lower:
            return 'risk-medium'
        else:
            return 'risk-low'

    def generate_json_report_simple(self, output_path: str = None):
        """
        将已记录的步骤序列化为 JSON（轻量版）。

        Args:
            output_path: 输出文件路径

        Returns:
            JSON 字符串
        """
        import json
        report = {"steps": self.steps}
        json_str = json.dumps(report, indent=2)

        if output_path:
            self._ensure_output_dir()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info(f"JSON 报告已生成: {output_path}")

        return json_str

    def generate_json_report(
        self,
        binary_path: str = None,
        binary_info: Dict[str, Any] = None,
        decomp_results: List[Dict[str, Any]] = None,
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        output_path: str = None
    ):
        """
        完整 JSON 报告序列化（含 metadata + binary_info + 所有分析段）。

        无 binary_path 时退化为简单步骤 JSON。

        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制元信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            output_path: 输出路径

        Returns:
            JSON 字符串或写入路径
        """
        import json

        if binary_path is None:
            report = {"steps": self.steps}
            json_str = json.dumps(report, indent=2)

            if output_path:
                self._ensure_output_dir()
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                logger.info(f"JSON 报告已生成: {output_path}")

            return json_str

        report = {
            'metadata': {
                'binary_path': binary_path,
                'analysis_time': datetime.now().isoformat(),
                'steps': self.analysis_steps
            },
            'binary_info': binary_info,
            'decomp_analysis': decomp_results,
            'crash_analysis': crash_analysis,
            'exploit_result': exploit_result
        }

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(binary_path))[0]
            output_path = os.path.join(self.output_dir, f"report_{base_name}_{timestamp}.json")

        self._ensure_output_dir()
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"JSON 报告已生成: {output_path}")
        return output_path

    def generate_html_report(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        similar_vulns: List[Dict[str, Any]] = None,
        symbolic_result: Dict[str, Any] = None,
        output_path: str = None
    ) -> str:
        """
        基于 HTML_TEMPLATE 渲染完整可视化报告 (vis.js 图表 + Ghidra 脚本嵌入)。

        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制元信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            similar_vulns: 相似漏洞匹配
            symbolic_result: 符号执行结果
            output_path: 输出路径

        Returns:
            HTML 文件路径
        """
        logger.info("开始生成 HTML 报告...")

        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        cvss_summary = {'max_score': 0, 'avg_score': 0, 'count': 0}
        all_cvss_scores = []

        for result in decomp_results:
            vulns = result.get('analysis', {}).get('vulnerabilities', [])
            total_vulns += len(vulns)
            for vuln in vulns:
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    critical_vulns += 1
                elif severity == 'high':
                    high_vulns += 1

                cvss = self.calculate_cvss(vuln)
                vuln['cvss'] = cvss
                all_cvss_scores.append(cvss['base_score'])
                if cvss['base_score'] > cvss_summary['max_score']:
                    cvss_summary['max_score'] = cvss['base_score']
                cvss_summary['count'] += 1

        if cvss_summary['count'] > 0:
            cvss_summary['avg_score'] = round(sum(all_cvss_scores) / cvss_summary['count'], 1)

        iterations = len(exploit_result.get('iterations', [])) + 1 if exploit_result else 0

        content_parts = []

        content_parts.append('<div class="card">')
        content_parts.append('<h2>📋 二进制信息</h2>')
        content_parts.append('<div class="info-grid">')

        content_parts.append(f'<div class="info-item"><div class="label">文件路径</div><div class="value">{binary_path}</div></div>')
        content_parts.append(f'<div class="info-item"><div class="label">架构</div><div class="value">{binary_info.get("arch", "N/A")}</div></div>')
        content_parts.append(f'<div class="info-item"><div class="label">位数</div><div class="value">{binary_info.get("bits", "N/A")}-bit</div></div>')
        content_parts.append(f'<div class="info-item"><div class="label">格式</div><div class="value">{binary_info.get("binary_format", "N/A")}</div></div>')

        checksec = binary_info.get('checksec', {})
        if checksec:
            content_parts.append(f'<div class="info-item"><div class="label">NX</div><div class="value">{"✓" if checksec.get("NX") else "✗"}</div></div>')
            content_parts.append(f'<div class="info-item"><div class="label">PIE</div><div class="value">{"✓" if checksec.get("PIE") else "✗"}</div></div>')
            content_parts.append(f'<div class="info-item"><div class="label">Canary</div><div class="value">{"✓" if checksec.get("Canary") else "✗"}</div></div>')
            content_parts.append(f'<div class="info-item"><div class="label">RELRO</div><div class="value">{checksec.get("RELRO", "N/A")}</div></div>')

        if cvss_summary['count'] > 0:
            max_severity = self._get_severity_from_score(cvss_summary['max_score'])
            max_badge = self._get_risk_badge_class(max_severity)
            content_parts.append(f'<div class="info-item"><div class="label">CVSS 最高</div><div class="value"><span class="risk-badge {max_badge}">{cvss_summary["max_score"]}</span></div></div>')
            content_parts.append(f'<div class="info-item"><div class="label">CVSS 平均</div><div class="value">{cvss_summary["avg_score"]}</div></div>')

        content_parts.append('</div></div>')

        call_graph_html, cfg_html = self._generate_vis_js_graphs(
            binary_info, decomp_results, symbolic_result
        )
        content_parts.append(call_graph_html)
        content_parts.append(cfg_html)

        if decomp_results:
            content_parts.append('<div class="card">')
            content_parts.append('<h2>🔬 函数分析</h2>')

            for result in decomp_results:
                func_name = result.get('function_name', 'Unknown')
                analysis = result.get('analysis', {})
                vulns = analysis.get('vulnerabilities', [])

                content_parts.append(f'<h3>📌 {func_name}</h3>')

                if vulns:
                    for i, vuln in enumerate(vulns, 1):
                        severity = vuln.get('severity', 'Unknown')
                        badge_class = self._get_risk_badge_class(severity)
                        cvss = vuln.get('cvss', {})

                        content_parts.append(f'<div class="vulnerability">')
                        content_parts.append(f'<div class="vuln-header">')
                        content_parts.append(f'<span class="vuln-type">漏洞 {i}: {vuln.get("type", "Unknown")}</span>')
                        content_parts.append(f'<span class="risk-badge {badge_class}">{severity}</span>')
                        content_parts.append(f'</div>')
                        content_parts.append(f'<p><strong>位置:</strong> {vuln.get("location", "N/A")}</p>')
                        content_parts.append(f'<p><strong>描述:</strong> {vuln.get("description", "N/A")}</p>')
                        content_parts.append(f'<p><strong>利用方式:</strong> {vuln.get("exploitation", "N/A")}</p>')

                        if cvss:
                            content_parts.append(f'<p><strong>CVSS 3.1:</strong> <span class="risk-badge {badge_class}">{cvss.get("base_score", "N/A")}</span>')
                            if cvss.get('vector_string'):
                                content_parts.append(f' <code style="font-size:11px;">{cvss["vector_string"]}</code>')
                            content_parts.append(f'</p>')
                            if cvss.get('explanation'):
                                content_parts.append(f'<p style="font-size:12px;color:#64748b;">{cvss["explanation"]}</p>')

                        if vuln.get('code_snippet'):
                            content_parts.append(f'<pre>{vuln["code_snippet"]}</pre>')

                        content_parts.append(f'</div>')
                else:
                    content_parts.append('<p>✅ 未发现明显漏洞</p>')

                content_parts.append(f'<h4>📝 反编译代码</h4>')
                pseudocode = result.get('pseudocode', '')[:2000]
                content_parts.append(f'<pre>{pseudocode}</pre>')

            content_parts.append('</div>')

        if similar_vulns:
            content_parts.append('<div class="card">')
            content_parts.append('<h2>🔍 数据库相似漏洞</h2>')
            content_parts.append(f'<p>在漏洞数据库中发现 <strong>{len(similar_vulns)}</strong> 个相似漏洞记录</p>')

            if similar_vulns[:5]:
                content_parts.append('<table>')
                content_parts.append('<tr><th>类型</th><th>文件</th><th>严重程度</th><th>函数</th></tr>')
                for vuln in similar_vulns[:5]:
                    sev_badge = self._get_risk_badge_class(vuln.get('severity', 'Low'))
                    content_parts.append(f'<tr>')
                    content_parts.append(f'<td>{vuln.get("vulnerability_type", "N/A")}</td>')
                    content_parts.append(f'<td>{vuln.get("binary_name", "N/A")}</td>')
                    content_parts.append(f'<td><span class="risk-badge {sev_badge}">{vuln.get("severity", "N/A")}</span></td>')
                    content_parts.append(f'<td>{vuln.get("function_name", "N/A")}</td>')
                    content_parts.append(f'</tr>')
                content_parts.append('</table>')
            content_parts.append('</div>')

        if crash_analysis:
            content_parts.append('<div class="card">')
            content_parts.append('<h2>💥 崩溃分析</h2>')

            combined = crash_analysis.get('combined', {})
            if combined:
                content_parts.append(f'<p><strong>崩溃类型:</strong> {combined.get("crash_type", "Unknown")}</p>')
                content_parts.append(f'<p><strong>漏洞类型:</strong> {combined.get("vulnerability_type", "Unknown")}</p>')
                content_parts.append(f'<p><strong>可利用性:</strong> {combined.get("exploitability", "Unknown")}</p>')
                content_parts.append(f'<p><strong>利用难度:</strong> {combined.get("difficulty", "Unknown")}</p>')

                if combined.get('analysis'):
                    content_parts.append(f'<h4>详细分析</h4>')
                    content_parts.append(f'<p>{combined["analysis"]}</p>')

            content_parts.append('</div>')

        if exploit_result:
            content_parts.append('<div class="card">')
            content_parts.append('<h2>🚀 利用脚本生成</h2>')

            success = exploit_result.get('success', False)
            status_class = 'success' if success else 'failed'
            content_parts.append(f'<div class="steps">')
            content_parts.append(f'<span class="step {status_class}">最终状态: {"✅ 成功" if success else "❌ 失败"}</span>')
            content_parts.append(f'<span class="step">迭代次数: {iterations}</span>')
            content_parts.append(f'</div>')

            if exploit_result.get('script_path'):
                content_parts.append(f'<p><strong>脚本文件:</strong> <code>{exploit_result["script_path"]}</code></p>')

            if exploit_result.get('script_content'):
                content_parts.append('<h4>📜 最终脚本</h4>')
                script = exploit_result['script_content'][:3000]
                content_parts.append(f'<pre>{script}</pre>')

            content_parts.append('</div>')

        ghidra_script = self.generate_ghidra_script(binary_path, decomp_results, crash_analysis)
        ghidra_script_escaped = ghidra_script.replace('\\', '\\\\').replace('`', '\\`').replace('$', '\\$')
        ghidra_script_html = f'''
        <div class="card">
            <h2>🐉 Ghidra 集成</h2>
            <p>点击下方按钮下载可在 Ghidra 中运行的 Python 脚本，用于在 Ghidra 界面中标注漏洞位置。</p>
            <div class="button-group" style="margin-top:15px;display:flex;gap:10px;flex-wrap:wrap;">
                <button onclick="downloadGhidraScript()" style="padding:12px 24px;background:#7c3aed;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">
                    📥 下载 Ghidra 标注脚本
                </button>
                <button onclick="toggleGhidraScript()" style="padding:12px 24px;background:#64748b;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:14px;">
                    👁 查看脚本内容
                </button>
            </div>
            <div id="ghidraScriptContent" style="display:none;margin-top:15px;">
                <pre id="ghidraScriptPre" style="max-height:400px;overflow:auto;"></pre>
            </div>
        </div>
        <script>
        var ghidraScriptContent = `{ghidra_script_escaped}`;

        function downloadGhidraScript() {{
            var blob = new Blob([ghidraScriptContent], {{ type: 'text/plain' }});
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'deemo_ghidra_annotate_{os.path.splitext(os.path.basename(binary_path))[0]}.py';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }}

        function toggleGhidraScript() {{
            var el = document.getElementById('ghidraScriptContent');
            var pre = document.getElementById('ghidraScriptPre');
            if (el.style.display === 'none') {{
                pre.textContent = ghidraScriptContent;
                el.style.display = 'block';
            }} else {{
                el.style.display = 'none';
            }}
        }}
        </script>
        '''
        content_parts.append(ghidra_script_html)

        content = '\n'.join(content_parts)

        html_content = self.HTML_TEMPLATE
        html_content = html_content.replace('{{ binary_name }}', os.path.basename(binary_path))
        html_content = html_content.replace('{{ binary_path }}', binary_path)
        html_content = html_content.replace('{{ analysis_time }}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        html_content = html_content.replace('{{ arch }}', binary_info.get('arch', 'N/A'))
        html_content = html_content.replace('{{ bits }}', str(binary_info.get('bits', 'N/A')))
        html_content = html_content.replace('{{ total_vulns }}', str(total_vulns))
        html_content = html_content.replace('{{ critical_vulns }}', str(critical_vulns))
        html_content = html_content.replace('{{ high_vulns }}', str(high_vulns))
        html_content = html_content.replace('{{ iterations }}', str(iterations))
        html_content = html_content.replace('{{ content }}', content)

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(binary_path))[0]
            output_path = os.path.join(self.output_dir, f"report_{base_name}_{timestamp}.html")

        self._ensure_output_dir()
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML 报告已生成: {output_path}")
        return output_path

    # --- 增量差异报告 ---
    # 2025-07-18 16:05 追加，覆盖补丁前后/多轮 fuzz 差异比对

    def generate_diff_report(
        self,
        old_findings: List[Dict[str, Any]],
        new_findings: List[Dict[str, Any]],
        title: str = "增量分析差异报告",
        output_path: str = None
    ) -> str:
        """
        委托 report_differ 构造 Markdown 增量差异汇总。

        两次分析 finding 集合 → added/removed/changed/unchanged 分类。
        """
        from modules.output.src.report_differ import generate_diff_report as _gen_diff

        md_content = _gen_diff(old_findings, new_findings, title)

        if output_path:
            self._ensure_output_dir()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            logger.info(f"差异报告已生成: {output_path}")
            return output_path

        return md_content

    # --- SARIF v2.1.0 输出 ---
    # 2025-07-21 09:34 追加，对接 GitHub Code Scanning / GitLab SAST

    def generate_sarif_report(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        evidence_chains: Dict[str, Dict] = None,
        merkle_roots: Dict[str, str] = None,
        output_path: str = None
    ) -> Tuple[Dict, str]:
        """
        构造 SARIF v2.1.0 报告 (OASIS 静态分析交换标准)。

        可直接上传至 GitHub Code Scanning / GitLab SAST / Azure DevOps。
        返回 (sarif_obj, output_path)。

        evidence_chains + merkle_roots 嵌入 result.properties，
        供消费端独立校验分析过程的密码学完整性。
        """
        logger.info("开始生成 SARIF v2.1.0 报告...")

        from modules.output.src.sarif_output import generate_sarif, write_sarif_file

        sarif_obj = generate_sarif(
            binary_path=binary_path,
            binary_info=binary_info,
            decomp_results=decomp_results,
            crash_analysis=crash_analysis,
            exploit_result=exploit_result,
            evidence_chains=evidence_chains,
            merkle_roots=merkle_roots,
        )

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(binary_path))[0]
            output_path = os.path.join(self.output_dir, f"report_{base_name}_{timestamp}.sarif")

        self._ensure_output_dir()
        write_sarif_file(sarif_obj, output_path)

        logger.info(f"SARIF 报告已生成: {output_path}")
        return sarif_obj, output_path

    def generate_pdf_report(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        similar_vulns: List[Dict[str, Any]] = None,
        symbolic_result: Dict[str, Any] = None,
        output_path: str = None
    ) -> Dict[str, Any]:
        """
        HTML → PDF 转写 (weasyprint 优先，回落 pdfkit)。

        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制元信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            similar_vulns: 相似漏洞匹配
            symbolic_result: 符号执行结果
            output_path: 输出路径

        Returns:
            {success, pdf_path, html_path, method, error}
        """
        logger.info("开始生成 PDF 报告...")

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(binary_path))[0]
            output_path = os.path.join(self.output_dir, f"report_{base_name}_{timestamp}.pdf")

        result = {
            'success': False,
            'pdf_path': None,
            'html_path': None,
            'method': None,
            'error': None
        }

        html_path = output_path.replace('.pdf', '.html')
        self.generate_html_report(
            binary_path, binary_info, decomp_results,
            crash_analysis, exploit_result, similar_vulns, symbolic_result,
            output_path=html_path
        )
        result['html_path'] = html_path

        weasyprint_available = False
        pdfkit_available = False

        try:
            import weasyprint
            weasyprint_available = True
        except ImportError:
            pass

        try:
            import pdfkit
            pdfkit_available = True
        except ImportError:
            pass

        if weasyprint_available:
            try:
                logger.info("使用 weasyprint 生成 PDF...")
                result['method'] = 'weasyprint'

                html = weasyprint.HTML(html_path)
                html.write_pdf(output_path)

                result['success'] = True
                result['pdf_path'] = output_path
                logger.info(f"PDF 报告已生成 (weasyprint): {output_path}")
                return result

            except Exception as e:
                logger.warning(f"weasyprint 生成失败: {e}")
                result['error'] = str(e)

        if pdfkit_available and not result['success']:
            try:
                logger.info("使用 pdfkit 生成 PDF...")
                result['method'] = 'pdfkit'

                import pdfkit
                pdfkit.from_file(html_path, output_path)

                result['success'] = True
                result['pdf_path'] = output_path
                logger.info(f"PDF 报告已生成 (pdfkit): {output_path}")
                return result

            except Exception as e:
                logger.warning(f"pdfkit 生成失败: {e}")
                if not result['error']:
                    result['error'] = str(e)

        if not result['success']:
            logger.warning("PDF 生成库不可用，已降级为 HTML 报告")
            result['error'] = result['error'] or 'No PDF library available'
            result['warning'] = (
                "PDF 生成需要 weasyprint 或 pdfkit。请安装:\n"
                "  pip install weasyprint\n"
                "  或\n"
                "  pip install pdfkit (还需要安装 wkhtmltopdf)"
            )

        return result
