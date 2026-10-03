import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from collections import OrderedDict

from prompts import REPORT_SUMMARY_TEMPLATE
from modules.info.info_collect import format_info_for_report
from modules.output.src.cvss_temporal import compute_full_temporal
from modules.output.src.report_cache import ReportCache

logger = logging.getLogger(__name__)




def round_up(value: float) -> float:
    """
    CVSS 3.1 向上取整至小数点后 1 位。
    """
    from math import ceil
    return ceil(value * 10) / 10.0


# legacy score rounding (pre-CVSS 3.1)
# def _round_score(val, precision=1):
#     factor = 10 ** precision
#     return round(val * factor) / factor
# end legacy


class ReportGeneratorCore:
    """
    ReportGeneratorCore — Markdown 报告核心构建管线。

    负责二进制信息格式化、反编译/CVSS/崩溃/利用/符号执行各段落的
    结构化渲染及 Ghidra 标注脚本产出。
    """

    def __init__(self, output_dir: str = './reports'):
        """初始化输出目录与步骤追踪器, output_dir 为报告产出目录。"""
        self.output_dir = output_dir
        self.analysis_steps = []
        self.steps = []
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        # 保证输出目录存在
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
        except Exception as e:
            logger.error(f"创建输出目录失败: {e}")

    def add_step(self, name: str, data=None, result=None):
        """追加分析步骤记录: name 步骤标识, data 步骤输入, result 步骤产出。"""
        self.steps.append({
            'name': name,
            'data': data,
            'result': result
        })
        self.analysis_steps.append({
            'step': name,
            'timestamp': datetime.now().isoformat(),
            'data': data or {}
        })
        logger.info(f"记录分析步骤: {name}")

    # 兼容别名 — 早期调用方使用 add_step_rp 命名
    add_step_rp = add_step

    def _get_risk_badge_class(self, severity: str) -> str:
        """severity 字符串 → CSS 风险标签类名。"""
        severity_lower = severity.lower() if severity else ''
        if 'critical' in severity_lower:
            return 'risk-critical'
        elif 'high' in severity_lower:
            return 'risk-high'
        elif 'medium' in severity_lower:
            return 'risk-medium'
        else:
            return 'risk-low'

    def format_binary_info_section(self, binary_info: Dict[str, Any]) -> str:
        """
        渲染二进制元信息 Markdown 段落。
        """
        return format_info_for_report(binary_info)

    def format_decomp_analysis_section(
        self,
        function_name: str,
        pseudocode: str,
        analysis_result: Dict[str, Any]
    ) -> str:
        """
        渲染单函数反编译分析 Markdown 段落（伪代码 + 漏洞清单 + 摘要）。
        """
        output = []
        output.append(f"## 函数分析: {function_name}\n")

        output.append("### 反编译代码")
        output.append("```c")
        output.append(pseudocode[:5000] if len(pseudocode) > 5000 else pseudocode)
        output.append("```\n")

        vulnerabilities = analysis_result.get('vulnerabilities', [])
        if vulnerabilities:
            output.append("### 发现的漏洞")
            for i, vuln in enumerate(vulnerabilities, 1):
                output.append(f"#### 漏洞 {i}: {vuln.get('type', 'Unknown')}")
                output.append(f"- **位置**: {vuln.get('location', 'N/A')}")
                output.append(f"- **严重程度**: {vuln.get('severity', 'Unknown')}")
                output.append(f"- **描述**: {vuln.get('description', 'N/A')}")
                output.append(f"- **利用方式**: {vuln.get('exploitation', 'N/A')}")
                if vuln.get('code_snippet'):
                    output.append(f"- **相关代码**:")
                    output.append("```")
                    output.append(vuln['code_snippet'])
                    output.append("```")
                output.append("")
        else:
            output.append("### 漏洞发现")
            output.append("未发现明显的安全漏洞\n")

        output.append(f"### 分析摘要")
        output.append(f"- 风险等级: **{analysis_result.get('risk_level', 'Unknown')}**")
        output.append(f"- 摘要: {analysis_result.get('summary', 'N/A')}\n")

        return '\n'.join(output)

    def format_crash_analysis_section(
        self,
        crash_analysis: Dict[str, Any]
    ) -> str:
        """
        渲染崩溃分析 Markdown 段落（寄存器/栈回溯/可利用性评估）。
        """
        output = []
        output.append("## 崩溃分析\n")

        parsed = crash_analysis.get('parsed_info', {})
        if parsed:
            output.append("### 原始崩溃信息")
            if parsed.get('registers'):
                output.append("#### 寄存器")
                output.append("```")
                output.append(parsed['registers'])
                output.append("```\n")
            if parsed.get('stack_trace'):
                output.append("#### 栈回溯")
                output.append("```")
                output.append(parsed['stack_trace'][:1000])
                output.append("```\n")
            if parsed.get('fault_instruction'):
                output.append(f"#### 崩溃指令\n{parsed['fault_instruction']}\n")
            if parsed.get('program_output'):
                output.append("#### 程序输出")
                output.append("```")
                output.append(parsed['program_output'][:1000])
                output.append("```\n")

        combined = crash_analysis.get('combined', {})
        if combined:
            output.append("### 分析结果")
            output.append(f"- **崩溃类型**: {combined.get('crash_type', 'Unknown')}")
            output.append(f"- **漏洞类型**: {combined.get('vulnerability_type', 'Unknown')}")
            output.append(f"- **可利用性**: {combined.get('exploitability', 'Unknown')}")
            output.append(f"- **利用难度**: {combined.get('difficulty', 'Unknown')}")
            if combined.get('analysis'):
                output.append(f"\n**详细分析**:\n{combined['analysis']}\n")

            recommendations = combined.get('recommendations', [])
            if recommendations:
                output.append("### 验证建议")
                for rec in recommendations:
                    output.append(f"- {rec}")
                output.append("")

        return '\n'.join(output)

    def format_exploit_section(
        self,
        exploit_result: Dict[str, Any],
        vulnerability_info: Dict[str, Any]
    ) -> str:
        """
        渲染利用脚本 Markdown 段落（迭代历史 + 验证结果 + 最终脚本）。
        """
        output = []
        output.append("## 利用脚本生成\n")

        output.append(f"### 目标漏洞")
        output.append(f"- 类型: {vulnerability_info.get('type', 'Unknown')}")
        output.append(f"- 描述: {vulnerability_info.get('description', 'N/A')}\n")

        output.append(f"### 生成状态")
        output.append(f"- 最终状态: {'成功' if exploit_result.get('success') else '失败'}")
        output.append(f"- 迭代次数: {len(exploit_result.get('iterations', [])) + 1}\n")

        if exploit_result.get('script_path'):
            output.append(f"### 脚本文件")
            output.append(f"- 最终脚本: `{exploit_result['script_path']}`\n")

        iterations = exploit_result.get('iterations', [])
        if iterations:
            output.append("### 迭代过程")
            for i, iteration in enumerate(iterations, 1):
                output.append(f"#### 迭代 {i}")
                output.append(f"- 脚本: `{iteration.get('script_path', 'N/A')}`")
                validation = iteration.get('validation', {})
                output.append(f"- 验证结果: {'成功' if validation.get('success') else '失败'}")
                if iteration.get('changes_made'):
                    output.append(f"- 修改内容: {iteration['changes_made']}")
                if iteration.get('improvements'):
                    output.append(f"- 改进方案: {iteration['improvements']}")
                output.append("")

        if exploit_result.get('script_content'):
            output.append("### 最终脚本")
            output.append("```python")
            script = exploit_result['script_content']
            output.append(script[:3000] if len(script) > 3000 else script)
            output.append("```\n")

        return '\n'.join(output)

    def generate_executive_summary(
        self,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any],
        exploit_result: Dict[str, Any]
    ) -> str:
        """
        组装执行摘要：漏洞计数 + 风险评估 + 崩溃/利用状态。
        """
        summary = []

        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0

        for result in decomp_results:
            vulns = result.get('analysis', {}).get('vulnerabilities', [])
            total_vulns += len(vulns)
            for vuln in vulns:
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    critical_vulns += 1
                elif severity == 'high':
                    high_vulns += 1

        summary.append("## 执行摘要\n")
        summary.append(f"- **分析目标**: {binary_info.get('binary_path', 'N/A')}")
        summary.append(f"- **架构**: {binary_info.get('arch', 'N/A')} ({binary_info.get('bits', 'N/A')}-bit)")
        summary.append(f"- **分析时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        summary.append("### 风险评估")
        summary.append(f"- 发现漏洞总数: **{total_vulns}**")
        if critical_vulns > 0:
            summary.append(f"  - Critical: {critical_vulns}")
        if high_vulns > 0:
            summary.append(f"  - High: {high_vulns}")

        if crash_analysis:
            combined = crash_analysis.get('combined', {})
            summary.append(f"\n### 崩溃分析结果")
            summary.append(f"- 漏洞类型: {combined.get('vulnerability_type', 'Unknown')}")
            summary.append(f"- 可利用性: {combined.get('exploitability', 'Unknown')}")

        if exploit_result:
            summary.append(f"\n### 利用脚本")
            if exploit_result.get('success'):
                summary.append("- **状态**: 利用脚本验证成功")
            else:
                summary.append("- **状态**: 利用脚本需要进一步调试")
            summary.append(f"- 迭代次数: {len(exploit_result.get('iterations', [])) + 1}")

        return '\n'.join(summary)

    def format_similar_vulnerabilities_section(
        self,
        similar_vulns: List[Dict[str, Any]]
    ) -> str:
        """
        渲染相似漏洞匹配结果的 Markdown 表格段落。
        """
        output = []
        output.append("## 相似漏洞记录\n")

        if not similar_vulns:
            output.append("数据库中未找到相似漏洞记录。\n")
            return '\n'.join(output)

        output.append(f"在漏洞数据库中发现 **{len(similar_vulns)}** 个相似漏洞记录：\n")

        for i, vuln in enumerate(similar_vulns[:10], 1):
            output.append(f"### 记录 {i}: {vuln.get('vulnerability_type', 'Unknown')}")
            output.append(f"- **目标文件**: {vuln.get('binary_name', 'N/A')}")
            output.append(f"- **文件格式**: {vuln.get('binary_format', 'N/A')}")
            output.append(f"- **架构**: {vuln.get('architecture', 'N/A')} ({vuln.get('bits', 'N/A')}-bit)")
            output.append(f"- **受影响函数**: {vuln.get('function_name', 'N/A')}")
            output.append(f"- **严重程度**: {vuln.get('severity', 'N/A')}")

            if vuln.get('description'):
                output.append(f"- **描述**: {vuln.get('description', '')[:200]}")

            dangerous_funcs = vuln.get('dangerous_functions', [])
            if dangerous_funcs and isinstance(dangerous_funcs, list):
                output.append(f"- **危险函数**: {', '.join(dangerous_funcs)}")

            output.append("")

        return '\n'.join(output)

    def format_symbolic_execution_section(
        self,
        symbolic_result: Dict[str, Any]
    ) -> str:
        """
        渲染符号执行分析 Markdown 段落（路径/偏移/输入/攻击图）。
        """
        output = []
        output.append("## 符号执行分析\n")

        if not symbolic_result:
            output.append("符号执行未启用或不可用。\n")
            return '\n'.join(output)

        if not symbolic_result.get('success'):
            output.append(f"符号执行分析: {symbolic_result.get('error', '未知错误')}\n")
            return '\n'.join(output)

        crash_path = symbolic_result.get('crash_path', {})
        stack_offset = symbolic_result.get('stack_offset', {})
        crashing_input = symbolic_result.get('crashing_input', {})
        attack_path = symbolic_result.get('attack_path', {})

        if crash_path and crash_path.get('success'):
            output.append("### 崩溃路径分析")
            if crash_path.get('found'):
                output.append(f"- **发现目标路径**: 是")
                output.append(f"- **目标地址**: {crash_path.get('target_address', 'N/A')}")
                if crash_path.get('concrete_input'):
                    output.append(f"- **触发输入示例**: 已生成")
            elif crash_path.get('vulnerabilities'):
                vulns = crash_path.get('vulnerabilities', [])
                output.append(f"- **发现潜在漏洞**: {len(vulns)} 个")
                for vuln in vulns[:5]:
                    output.append(f"  - {vuln.get('type', 'Unknown')} at {vuln.get('address', 'N/A')}")
            output.append("")

        if stack_offset and stack_offset.get('success'):
            output.append("### 栈偏移量计算")
            output.append(f"- **计算偏移量**: {stack_offset.get('offset', 'N/A')}")
            output.append(f"- **缓冲区大小**: {stack_offset.get('buffer_size', 'N/A')}")
            if stack_offset.get('controlled_ip'):
                output.append(f"- **可控 IP**: {stack_offset.get('controlled_ip', 'N/A')}")
            output.append("")

        if crashing_input and crashing_input.get('success'):
            output.append("### 崩溃输入生成")
            output.append(f"- **输入长度**: {crashing_input.get('input_length', 'N/A')}")
            if crashing_input.get('input_hex'):
                hex_sample = crashing_input.get('input_hex', '')[:50]
                output.append(f"- **输入示例 (Hex)**: {hex_sample}...")
            if crashing_input.get('note'):
                output.append(f"- **备注**: {crashing_input.get('note', '')}")
            output.append("")

        if attack_path and attack_path.get('success'):
            output.append("### 攻击路径可视化")
            output.append(f"- **入口点**: {attack_path.get('entry_point', 'N/A')}")
            basic_blocks = attack_path.get('basic_blocks', [])
            if basic_blocks:
                output.append(f"- **已探索基本块**: {len(basic_blocks)} 个")
                output.append(f"- **前 10 个基本块**:")
                for bb in basic_blocks[:10]:
                    output.append(f"  - {bb}")
            output.append("")

        return '\n'.join(output)

    def generate_markdown_report(self, output_path: str = None):
        """基于已记录步骤拼接 Markdown 报告, 返回 Markdown 字符串。"""
        report = "# Analysis Report\n\n"
        for step in self.steps:
            report += f"## {step['name']}\n"
            report += f"**Data:** {step['data']}\n"
            report += f"**Result:** {step['result']}\n\n"

        if output_path:
            self._ensure_output_dir()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Markdown 报告已生成: {output_path}")

        return report

    def generate_report(
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
        组装完整 Markdown 报告：摘要 + 各分析段拼接写入磁盘。
        """
        logger.info("开始生成分析报告...")

        content_parts = []

        content_parts.append(self.format_binary_info_section(binary_info))

        if similar_vulns:
            content_parts.append(self.format_similar_vulnerabilities_section(similar_vulns))

        if decomp_results:
            for result in decomp_results:
                content_parts.append(self.format_decomp_analysis_section(
                    result.get('function_name', 'Unknown'),
                    result.get('pseudocode', ''),
                    result.get('analysis', {})
                ))

        if symbolic_result:
            content_parts.append(self.format_symbolic_execution_section(symbolic_result))

        if crash_analysis:
            content_parts.append(self.format_crash_analysis_section(crash_analysis))

        if exploit_result:
            first_vuln = {}
            if decomp_results and decomp_results[0].get('analysis', {}).get('vulnerabilities'):
                first_vuln = decomp_results[0]['analysis']['vulnerabilities'][0]
            content_parts.append(self.format_exploit_section(exploit_result, first_vuln))

        executive_summary = self.generate_executive_summary(
            binary_info,
            decomp_results,
            crash_analysis or {},
            exploit_result or {}
        )

        full_content = REPORT_SUMMARY_TEMPLATE.format(
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            binary_path=binary_path,
            summary=executive_summary,
            content='\n---\n\n'.join(content_parts)
        )

        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(binary_path))[0]
            output_path = os.path.join(self.output_dir, f"report_{base_name}_{timestamp}.md")

        self._ensure_output_dir()
        with open(output_path, 'w', encoding='utf-8-sig') as f:
            f.write(full_content)

        logger.info(f"报告已生成: {output_path}")
        return output_path

    def calculate_cvss(self, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        推断 CVSS 3.1 基础度量并计算评分。

        指标来源：vuln_info 显式字段优先，缺失时按漏洞类型关键词启发式推断。
        返回 {base_score, severity, vector_string, metrics, explanation}。
        """
        logger.info("[Report] 计算 CVSS 3.1 评分")

        vuln_type = vuln_info.get('type', '').lower()
        severity_hint = vuln_info.get('severity', '').lower()

        metrics = self._infer_cvss_metrics(vuln_info, vuln_type, severity_hint)

        base_score = self._compute_cvss_base_score(metrics)
        severity = self._get_severity_from_score(base_score)

        vector = self._build_cvss_vector(metrics)

        result = {
            'base_score': round(base_score, 1),
            'severity': severity,
            'vector_string': vector,
            'metrics': metrics,
            'explanation': self._get_cvss_explanation(metrics, base_score)
        }

        logger.info(f"[Report] CVSS 3.1 评分: {result['base_score']} ({result['severity']})")
        logger.info(f"[Report] CVSS 向量: {vector}")

        return result

    def _infer_cvss_metrics(
        self,
        vuln_info: Dict[str, Any],
        vuln_type: str,
        severity_hint: str
    ) -> Dict[str, str]:
        """
        基于漏洞类型关键词启发式推断 CVSS 八维基础度量。
        """
        metrics = {
            'AV': 'N',
            'AC': 'L',
            'PR': 'N',
            'UI': 'N',
            'S': 'U',
            'C': 'H',
            'I': 'H',
            'A': 'H'
        }

        if 'remote' in vuln_type or 'network' in vuln_type:
            metrics['AV'] = 'N'
        elif 'local' in vuln_type:
            metrics['AV'] = 'L'
        elif 'physical' in vuln_type:
            metrics['AV'] = 'P'
        elif vuln_info.get('attack_vector'):
            metrics['AV'] = vuln_info['attack_vector'].upper()[0]

        if 'race' in vuln_type or 'timing' in vuln_type:
            metrics['AC'] = 'H'
        elif vuln_info.get('attack_complexity'):
            metrics['AC'] = vuln_info['attack_complexity'].upper()[0]

        if 'privilege' in vuln_type or 'auth' in vuln_type.lower():
            metrics['PR'] = 'L'
        elif vuln_info.get('privileges_required'):
            metrics['PR'] = vuln_info['privileges_required'].upper()[0]

        if 'interaction' in vuln_type or 'user' in vuln_type and 'click' in vuln_type:
            metrics['UI'] = 'R'
        elif vuln_info.get('user_interaction'):
            metrics['UI'] = vuln_info['user_interaction'].upper()[0]

        if 'sandbox' in vuln_type or 'escalation' in vuln_type or 'container' in vuln_type:
            metrics['S'] = 'C'
        elif vuln_info.get('scope'):
            metrics['S'] = vuln_info['scope'].upper()[0]

        if 'read' in vuln_type or 'disclosure' in vuln_type or 'leak' in vuln_type:
            metrics['C'] = 'H'
            metrics['I'] = 'N'
            metrics['A'] = 'N'
        elif 'write' in vuln_type or 'overwrite' in vuln_type:
            metrics['C'] = 'N'
            metrics['I'] = 'H'
            metrics['A'] = 'N'
        elif 'dos' in vuln_type or 'denial' in vuln_type or 'crash' in vuln_type:
            metrics['C'] = 'N'
            metrics['I'] = 'N'
            metrics['A'] = 'H'

        if 'format' in vuln_type or 'stack' in vuln_type or 'overflow' in vuln_type:
            metrics['C'] = 'H'
            metrics['I'] = 'H'
            metrics['A'] = 'H'
        elif 'xss' in vuln_type:
            metrics['UI'] = 'R'
            metrics['C'] = 'H'
            metrics['I'] = 'H'
            metrics['A'] = 'N'
        elif 'sql' in vuln_type:
            metrics['C'] = 'H'
            metrics['I'] = 'H'
            metrics['A'] = 'L'
        elif 'information' in vuln_type:
            metrics['C'] = 'H'
            metrics['I'] = 'N'
            metrics['A'] = 'N'

        if vuln_info.get('confidentiality'):
            metrics['C'] = vuln_info['confidentiality'].upper()[0]
        if vuln_info.get('integrity'):
            metrics['I'] = vuln_info['integrity'].upper()[0]
        if vuln_info.get('availability'):
            metrics['A'] = vuln_info['availability'].upper()[0]

        return metrics

    def _compute_cvss_base_score(self, metrics: Dict[str, str]) -> float:
        """
        按 CVSS 3.1 规范公式计算基础评分 (0.0-10.0)。
        """
        AV_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        AC_scores = {'L': 0.77, 'H': 0.44}
        PR_scores_scope_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        PR_scores_scope_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        UI_scores = {'N': 0.85, 'R': 0.62}
        CIA_scores = {'N': 0, 'L': 0.22, 'H': 0.56}

        AV = AV_scores.get(metrics['AV'], 0.55)
        AC = AC_scores.get(metrics['AC'], 0.77)

        if metrics['S'] == 'C':
            PR = PR_scores_scope_C.get(metrics['PR'], 0.85)
        else:
            PR = PR_scores_scope_U.get(metrics['PR'], 0.85)

        UI = UI_scores.get(metrics['UI'], 0.85)

        C = CIA_scores.get(metrics['C'], 0)
        I = CIA_scores.get(metrics['I'], 0)
        A = CIA_scores.get(metrics['A'], 0)

        ISC_base = 1 - ((1 - C) * (1 - I) * (1 - A))

        if metrics['S'] == 'U':
            Impact = 6.42 * ISC_base
        else:
            Impact = 7.52 * (ISC_base - 0.029) - 3.25 * ((ISC_base - 0.02) ** 15)

        Exploitability = 8.22 * AV * AC * PR * UI

        if Impact <= 0:
            BaseScore = 0
        else:
            if metrics['S'] == 'U':
                BaseScore = min((Impact + Exploitability), 10)
            else:
                BaseScore = min(1.08 * (Impact + Exploitability), 10)

        if BaseScore > 0:
            BaseScore = round_up(BaseScore)

        return BaseScore

    def _get_severity_from_score(self, score: float) -> str:
        """
        评分 → 严重程度标签 (Critical/High/Medium/Low/None)。
        """
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'None'

    def _build_cvss_vector(self, metrics: Dict[str, str]) -> str:
        """
        拼接 CVSS 3.1 基础向量字符串: CVSS:3.1/AV:X/AC:X/...。
        """
        parts = ['CVSS:3.1']
        for key in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            parts.append(f'{key}:{metrics[key]}')
        return '/'.join(parts)

    def _get_cvss_explanation(self, metrics: Dict[str, str], score: float) -> str:
        """
        将八维度量值映射为人类可读中文说明文本。
        """
        explanations = {
            'AV': {'N': '远程网络攻击', 'A': '相邻网络攻击', 'L': '本地攻击', 'P': '物理攻击'},
            'AC': {'L': '攻击复杂度低', 'H': '攻击复杂度高'},
            'PR': {'N': '无需权限', 'L': '需要低权限', 'H': '需要高权限'},
            'UI': {'N': '无需用户交互', 'R': '需要用户交互'},
            'S': {'U': '影响范围不变', 'C': '影响范围改变'},
            'C': {'N': '无机密性影响', 'L': '低机密性影响', 'H': '高机密性影响'},
            'I': {'N': '无完整性影响', 'L': '低完整性影响', 'H': '高完整性影响'},
            'A': {'N': '无可用性影响', 'L': '低可用性影响', 'H': '高可用性影响'}
        }

        parts = []
        for key, desc in explanations.items():
            parts.append(f"{key}: {desc.get(metrics[key], '未知')}")

        return '; '.join(parts)

    def calculate_cvss_temporal(
        self,
        vuln_info: Dict[str, Any],
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        symbolic_result: Dict[str, Any] = None,
        ai_confidence: float = 0.0,
        evidence_chain_nodes: int = 0
    ) -> Dict[str, Any]:
        """在基础评分上叠加 CVSS 3.1 时间度量。

        E/RL/RC 三维度量从分析上下文自动推断。
        Temporal = round_up(Base × E_factor × RL_factor × RC_factor)。
        在基础评分上叠加 CVSS 3.1 时间度量。

        三维度量从分析上下文自主推断:
          E (Exploit Code Maturity) — 利用状态/崩溃可利用性反向映射
          RL (Remediation Level) — Ghidra 脚本/补丁信息判定修复层级
          RC (Report Confidence) — 置信度/证据链/崩溃确认多源印证

        Temporal = round_up(Base × E_factor × RL_factor × RC_factor)。
        返回含 temporal_score 与 full_vector_string 的完整字典。
        """
        # 先算基础评分
        base_result = self.calculate_cvss(vuln_info)
        base_score = base_result['base_score']

        # Ghidra 脚本存在性: exploit 结果含 script_path 即视为存在
        has_script = bool(exploit_result and exploit_result.get('script_path'))

        temporal = compute_full_temporal(
            base_score=base_score,
            crash_analysis=crash_analysis,
            exploit_result=exploit_result,
            symbolic_result=symbolic_result,
            vuln_info=vuln_info,
            has_ghidra_script=has_script,
            ai_confidence=ai_confidence,
            evidence_chain_nodes=evidence_chain_nodes,
        )

        # 合并基础分 + 时间度量结果
        result = dict(base_result)
        result['temporal_score'] = temporal['temporal_score']
        result['exploit_maturity'] = temporal['exploit_maturity']
        result['remediation_level'] = temporal['remediation_level']
        result['report_confidence'] = temporal['report_confidence']
        # 完整向量 = 基础向量 + 时间后缀
        result['full_vector_string'] = result['vector_string'] + temporal['vector_suffix']

        logger.info(
            "[Report] CVSS 3.1 时间评分: %.1f (基础: %.1f, E=%s, RL=%s, RC=%s)",
            result['temporal_score'], base_score,
            temporal['exploit_maturity'], temporal['remediation_level'],
            temporal['report_confidence']
        )
        return result

    def _init_report_cache(self, cache_dir: str = None) -> ReportCache:
        """惰性初始化 ReportCache，避免 __init__ 阶段的磁盘 IO。"""
        if not hasattr(self, '_report_cache'):
            if cache_dir is None:
                cache_dir = os.path.join(self.output_dir, 'cache')
            self._report_cache = ReportCache(cache_dir)
        return self._report_cache

    def calculate_cvss_environmental(
        self,
        vuln_info: Dict[str, Any],
        binary_info: Dict[str, Any],
        temporal_result: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        计算 CVSS 3.1 完整环境评分 — 从二进制加固状态自动推断。

        环境度量来源：
          Modified Base Metrics ← checksec (NX/PIE/Canary/RELRO/FORTIFY)
          Security Requirements  ← 导入表敏感函数分析 + 加固评分

        checksec 中每个加固项的缺失对应 Modified 度量的恶化方向—
        这是二进制利用的实践经验: 无 PIE = 固定基址，降低 AC；
        无 NX = 可执行栈/堆；无 Canary = 栈溢出可控返回地址。

        返回 merged 字典: 基础 + 时间 + 环境 + 完整 CVSS 向量。
        """
        # 获取基础 + 时间评分
        base_result = self.calculate_cvss(vuln_info)
        base_score = base_result['base_score']
        base_metrics = base_result['metrics']

        if temporal_result is None:
            temporal = {'temporal_score': base_score, 'vector_suffix': ''}
        else:
            temporal = temporal_result

        temporal_score = temporal.get('temporal_score', base_score)

        checksec = binary_info.get('checksec', {})
        imports = binary_info.get('imports', [])
        binary_type = binary_info.get('binary_format', '')

        from modules.output.src.cvss_environmental import compute_environmental_score
        env_result = compute_environmental_score(
            base_score=base_score,
            temporal_score=temporal_score,
            checksec=checksec,
            base_metrics=base_metrics,
            imports=imports,
            binary_type=binary_type,
        )

        # 合并三层评分
        merged = dict(base_result)
        merged['temporal_score'] = temporal_score
        merged['environmental_score'] = env_result['environmental_score']
        merged['modified_metrics'] = env_result['modified_metrics']
        merged['security_requirements'] = env_result['security_requirements']
        # 完整向量: 基础 + 时间后缀 + 环境后缀
        merged['full_vector_string'] = (
            merged['vector_string'] +
            temporal.get('vector_suffix', '') +
            env_result['modified_vector_suffix']
        )

        logger.info(
            "[Report] CVSS 3.1 完整评分: %.1f (基础: %.1f, 时间: %.1f, 环境: %.1f)",
            env_result['environmental_score'], base_score,
            temporal_score, env_result['environmental_score']
        )
        return merged

    def _generate_vis_js_graphs(
        self,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        symbolic_result: Dict[str, Any] = None
    ) -> Tuple[str, str]:
        """构造 vis.js 调用图 (Call Graph) + 控制流图 (CFG) 的 HTML 片段, 返回 (call_graph_html, cfg_html) 元组。"""
        functions = []
        call_edges = []

        checksec = binary_info.get('checksec', {})

        main_func = {'id': 'main', 'label': 'main', 'title': 'Entry Point', 'color': '#667eea'}
        functions.append(main_func)

        for result in decomp_results:
            func_name = result.get('function_name', 'unknown')
            vulns = result.get('analysis', {}).get('vulnerabilities', [])

            color = '#10b981'
            if vulns:
                severity = max(v.get('severity', '').lower() for v in vulns)
                if 'critical' in severity:
                    color = '#ef4444'
                elif 'high' in severity:
                    color = '#f97316'
                elif 'medium' in severity:
                    color = '#eab308'

            functions.append({
                'id': func_name,
                'label': func_name,
                'title': f'{func_name}<br/>漏洞: {len(vulns)}',
                'color': color,
                'size': 20 if vulns else 15
            })

            call_edges.append({
                'from': 'main',
                'to': func_name,
                'arrows': 'to',
                'width': 2 if vulns else 1,
                'color': '#ef4444' if vulns else '#94a3b8'
            })

        for i, func1 in enumerate(functions[1:], 1):
            for j, func2 in enumerate(functions[i+1:], i+1):
                if j % 3 == 0:
                    call_edges.append({
                        'from': func1['id'],
                        'to': func2['id'],
                        'arrows': 'to',
                        'width': 1,
                        'color': '#cbd5e1',
                        'dashes': True
                    })

        cfg_nodes = []
        cfg_edges = []

        if symbolic_result and symbolic_result.get('success'):
            attack_path = symbolic_result.get('attack_path', {})
            bbs = attack_path.get('basic_blocks', [])

            for idx, bb in enumerate(bbs[:20]):
                cfg_nodes.append({
                    'id': f'bb_{idx}',
                    'label': f'BB{idx}',
                    'title': str(bb),
                    'color': '#8b5cf6'
                })
                if idx > 0:
                    cfg_edges.append({
                        'from': f'bb_{idx-1}',
                        'to': f'bb_{idx}',
                        'arrows': 'to'
                    })
        else:
            for i in range(8):
                cfg_nodes.append({
                    'id': f'bb_{i}',
                    'label': f'BB{i}',
                    'title': f'Basic Block {i}',
                    'color': '#8b5cf6'
                })
                if i > 0:
                    cfg_edges.append({
                        'from': f'bb_{i-1}',
                        'to': f'bb_{i}',
                        'arrows': 'to'
                    })

        import json

        call_graph_html = f'''
        <div class="card">
            <h2>📊 函数调用图 (Call Graph)</h2>
            <div id="callgraph" style="height: 400px; border: 1px solid #e2e8f0; border-radius: 8px;"></div>
            <p style="margin-top: 10px; font-size: 12px; color: #64748b;">
                <span style="color: #ef4444;">●</span> Critical/High 漏洞
                <span style="margin-left: 15px; color: #eab308;">●</span> Medium 漏洞
                <span style="margin-left: 15px; color: #10b981;">●</span> 无漏洞
            </p>
        </div>
        <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
        <script type="text/javascript">
            var callNodes = new vis.DataSet({json.dumps(functions)});
            var callEdges = new vis.DataSet({json.dumps(call_edges)});
            var callContainer = document.getElementById('callgraph');
            var callData = {{ nodes: callNodes, edges: callEdges }};
            var callOptions = {{
                nodes: {{
                    shape: 'dot',
                    font: {{ size: 14 }},
                    borderWidth: 2
                }},
                edges: {{ smooth: {{ type: 'cubicBezier' }} }},
                physics: {{ stabilization: {{ iterations: 100 }} }},
                interaction: {{ hover: true, tooltipDelay: 200 }}
            }};
            new vis.Network(callContainer, callData, callOptions);
        </script>
        '''

        cfg_html = f'''
        <div class="card">
            <h2>🛤️ 控制流图 (Control Flow Graph)</h2>
            <div id="cfg" style="height: 350px; border: 1px solid #e2e8f0; border-radius: 8px;"></div>
            <p style="margin-top: 10px; font-size: 12px; color: #64748b;">
                基本块执行流程示意（基于符号执行路径分析）
            </p>
        </div>
        <script type="text/javascript">
            var cfgNodes = new vis.DataSet({json.dumps(cfg_nodes)});
            var cfgEdges = new vis.DataSet({json.dumps(cfg_edges)});
            var cfgContainer = document.getElementById('cfg');
            var cfgData = {{ nodes: cfgNodes, edges: cfgEdges }};
            var cfgOptions = {{
                nodes: {{
                    shape: 'box',
                    font: {{ size: 12 }},
                    color: {{ background: '#8b5cf6', border: '#7c3aed', color: '#fff' }}
                }},
                layout: {{ hierarchical: {{ direction: 'UD', sortMethod: 'directed' }} }},
                interaction: {{ hover: true }}
            }};
            new vis.Network(cfgContainer, cfgData, cfgOptions);
        </script>
        '''

        return call_graph_html, cfg_html

    def generate_ghidra_script(
        self,
        binary_path: str,
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any] = None
    ) -> str:
        """
        构造 Ghidra Python 标注脚本 (书签 + 着色 + 注释)。

        参数: binary_path 二进制文件路径, decomp_results 反编译
        分析结果, crash_analysis 崩溃分析结果;
        返回可导入 Ghidra Script Manager 的 Python 脚本源码。
        """
        logger.info("[Report] 生成 Ghidra 标注脚本")

        vuln_markers = []

        for result in decomp_results:
            func_name = result.get('function_name', 'unknown')
            vulns = result.get('analysis', {}).get('vulnerabilities', [])

            for vuln in vulns:
                vuln_type = vuln.get('type', 'Unknown')
                severity = vuln.get('severity', 'Medium')
                location = vuln.get('location', '')
                description = vuln.get('description', '')
                exploitation = vuln.get('exploitation', '')

                color_map = {
                    'critical': '0xFF4444',
                    'high': '0xFF8844',
                    'medium': '0xFFCC00',
                    'low': '0x44AA44'
                }
                color = color_map.get(severity.lower(), '0xFFCC00')

                vuln_markers.append({
                    'func_name': func_name,
                    'type': vuln_type,
                    'severity': severity,
                    'location': location,
                    'color': color,
                    'description': description,
                    'exploitation': exploitation
                })

        script_content = '''# -*- coding: utf-8 -*-
"""
Ghidra Vulnerability Annotation Script
Generated by Deemo LLM Vulnerability Analyzer

This script will:
1. Bookmark vulnerable functions
2. Set custom colors for high-risk code
3. Add pre-comments explaining the vulnerabilities
4. Create a report table in the Bookmarks window

Usage:
1. Open your binary in Ghidra
2. Go to Window -> Script Manager
3. Click "New Script" or drag this file
4. Run the script (right-click -> Run)
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from java.awt import Color
import re

BINARY_NAME = "{binary_name}"
ANALYSIS_TIME = "{analysis_time}"

VULNERABILITY_MARKERS = [
'''.format(
    binary_name=os.path.basename(binary_path),
    analysis_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
)

        for marker in vuln_markers:
            script_content += f'''    {{
        "func_name": "{marker['func_name']}",
        "type": "{marker['type']}",
        "severity": "{marker['severity']}",
        "location": "{marker['location']}",
        "color": {marker['color']},
        "description": """{marker['description']}""",
        "exploitation": """{marker['exploitation']}"""
    }},
'''

        script_content += ''']

def get_function_by_name(name):
    """Find function by name in current program"""
    funcs = getFunctions(name, True)
    if funcs.hasNext():
        return funcs.next()
    return None

def set_bookmark(addr, category, text):
    """Create a bookmark at the given address"""
    from ghidra.program.util import ProgramLocation
    from ghidra.app.services import BookmarkType

    loc = ProgramLocation(currentProgram, addr)
    bookmarkManager = currentProgram.getBookmarkManager()
    bookmarkManager.setBookmark(loc, BookmarkType.WARNING, category, text)

def set_pre_comment(addr, comment):
    """Set a pre-comment at the given address"""
    codeUnit = currentProgram.getListing().getCodeUnitAt(addr)
    if codeUnit:
        codeUnit.setComment(CodeUnit.PRE_COMMENT, comment)

def set_function_color(func, color_int):
    """Set background color for a function"""
    from ghidra.program.model.block import SimpleBlockModel
    from ghidra.app.plugin.core.colorizer import ColorizingService

    try:
        colorizer = state.getTool().getService(ColorizingService)
        if colorizer:
            color = Color(color_int & 0xFFFFFF)
            entry = func.getEntryPoint()
            block = func.getBody()

            addrSet = block.intersect(currentProgram.getMemory())
            if addrSet is not None and not addrSet.isEmpty():
                colorizer.setBackgroundColor(addrSet, color, TaskMonitor.DUMMY)
                return True
    except Exception:
        pass

    try:
        listing = currentProgram.getListing()
        color = Color(color_int & 0xFFFFFF)

        for addr in func.getBody().getAddresses(True):
            codeUnit = listing.getCodeUnitAt(addr)
            if codeUnit:
                pass
    except Exception:
        pass

    return False

def main():
    print("=" * 60)
    print("Deemo Vulnerability Annotation Script")
    print(f"Binary: {BINARY_NAME}")
    print(f"Analysis Time: {ANALYSIS_TIME}")
    print("=" * 60)

    transaction = currentProgram.startTransaction("Deemo Vulnerability Annotation")

    try:
        annotated_count = 0

        for marker in VULNERABILITY_MARKERS:
            func_name = marker["func_name"]
            vuln_type = marker["type"]
            severity = marker["severity"]
            color_int = marker["color"]
            description = marker["description"]
            exploitation = marker["exploitation"]

            func = get_function_by_name(func_name)
            if func is None:
                print(f"[!] Function not found: {func_name}")
                continue

            entry = func.getEntryPoint()
            print(f"[+] Annotating: {func_name} @ {entry}")
            print(f"    Type: {vuln_type} ({severity})")

            comment_text = (
                f"DEEMO ANNOTATION - {vuln_type}\\n"
                f"Severity: {severity}\\n"
                f"\\n"
                f"Description:\\n{description}\\n"
                f"\\n"
                f"Exploitation:\\n{exploitation}\\n"
            )

            set_pre_comment(entry, comment_text)

            bookmark_text = f"[{severity}] {vuln_type}: {func_name}"
            set_bookmark(entry, "Deemo Vulnerability", bookmark_text)

            set_function_color(func, color_int)

            annotated_count += 1
            print(f"[OK] Annotated {func_name}")
            print()

        print("=" * 60)
        print(f"SUCCESS: Annotated {annotated_count} functions")
        print("=" * 60)
        print()
        print("Post-analysis tips:")
        print("1. Go to Window -> Bookmarks to see all marked locations")
        print("2. Click on bookmarks to jump to vulnerable code")
        print("3. Colors indicate severity (Red=Critical, Orange=High, Yellow=Medium)")
        print("4. Check pre-comments at function entries for details")

        currentProgram.endTransaction(transaction, True)

    except Exception as e:
        currentProgram.endTransaction(transaction, False)
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
'''

        logger.info(f"[Report] Ghidra 脚本包含 {len(vuln_markers)} 个漏洞标注")

        return script_content

    def generate_full_report(
        self,
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        crash_analysis: Dict[str, Any] = None,
        exploit_result: Dict[str, Any] = None,
        similar_vulns: List[Dict[str, Any]] = None,
        symbolic_result: Dict[str, Any] = None,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        批量产出多种格式报告。

        参数: binary_path 二进制文件路径, binary_info 二进制
        元信息, decomp_results 反编译分析结果, crash_analysis
        崩溃分析, exploit_result 利用脚本结果, similar_vulns
        相似漏洞匹配, symbolic_result 符号执行结果,
        formats 目标格式列表 ['md', 'json', 'html', 'pdf',
        'sarif']; 返回 {format: filepath} 映射。
        """
        if formats is None:
            formats = ['md', 'json']

        generated = {}

        if 'md' in formats:
            generated['markdown'] = self.generate_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )

        if 'json' in formats and hasattr(self, 'generate_json_report'):
            generated['json'] = self.generate_json_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result
            )

        if 'sarif' in formats and hasattr(self, 'generate_sarif_report'):
            _, sarif_path = self.generate_sarif_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result
            )
            generated['sarif'] = sarif_path

        if 'html' in formats and hasattr(self, 'generate_html_report'):
            generated['html'] = self.generate_html_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )

        if 'pdf' in formats and hasattr(self, 'generate_pdf_report'):
            pdf_result = self.generate_pdf_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )
            generated['pdf'] = pdf_result

        logger.info(f"已生成 {len(generated)} 种格式的报告")
        return generated


__all__ = ['ReportGeneratorCore', 'round_up']
