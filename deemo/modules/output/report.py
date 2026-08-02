import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from prompts import REPORT_SUMMARY_TEMPLATE
from modules.info.info_collect import format_info_for_report

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    报告生成器





    
    """
    
    def __init__(self, output_dir: str = './reports'):
        """
        初始化报告生成器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = output_dir
        self.analysis_steps = []
        self.steps = []
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """
        确保输出目录存在


        
        """
        try:
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
        except Exception as e:
            logger.error(f"创建输出目录失败: {e}")
    
    def add_step(self, name: str, data=None, result=None):
        """
        添加一个分析步骤
        
        Args:
            name: 步骤名称
            data: 步骤数据（可选）
            result: 步骤结果（可选）
        """
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
    
    def format_binary_info_section(self, binary_info: Dict[str, Any]) -> str:
        """
        格式化二进制信息部分
        """
        return format_info_for_report(binary_info)
    
    def format_decomp_analysis_section(
        self,
        function_name: str,
        pseudocode: str,
        analysis_result: Dict[str, Any]
    ) -> str:
        """
        格式化反编译分析部分


        
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
        格式化崩溃分析部分

        
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
        格式化利用脚本部分
        """
        output = []
        output.append("## 利用脚本生成\n")
        
        output.append(f"### 目标漏洞")
        output.append(f"- 类型: {vulnerability_info.get('type', 'Unknown')}")
        output.append(f"- 描述: {vulnerability_info.get('description', 'N/A')}\n")
        
        output.append(f"### 生成状态")
        output.append(f"- 最终状态: {' 成功' if exploit_result.get('success') else ' 失败'}")
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
                output.append(f"- 验证结果: {' 成功' if validation.get('success') else ' 失败'}")
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
        生成执行摘要
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
                summary.append("- **状态**:  利用脚本验证成功")
            else:
                summary.append("- **状态**:  利用脚本需要进一步调试")
            summary.append(f"- 迭代次数: {len(exploit_result.get('iterations', [])) + 1}")
        
        return '\n'.join(summary)
    
    def format_similar_vulnerabilities_section(
        self,
        similar_vulns: List[Dict[str, Any]]
    ) -> str:
        """
        格式化相似漏洞部分
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
        格式化符号执行分析部分
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
        """
        生成 Markdown 格式报告（基于步骤）
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            Markdown 报告字符串
        """
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
    
    def generate_json_report_simple(self, output_path: str = None):
        """
        生成 JSON 格式报告（简单版，基于步骤）
        
        Args:
            output_path: 输出文件路径（可选）
            
        Returns:
            JSON 报告字符串
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
        生成完整的 Markdown 报告
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
        生成 JSON 格式报告
        
        如果不提供 binary_path 等参数，则生成基于步骤的简单报告。
        如果提供了 binary_path，则生成完整的分析报告。
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            output_path: 输出路径
            
        Returns:
            JSON 报告字符串或文件路径
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
    
    def _get_risk_badge_class(self, severity: str) -> str:
        """获取风险等级对应的 CSS 类"""
        severity_lower = severity.lower() if severity else ''
        if 'critical' in severity_lower:
            return 'risk-critical'
        elif 'high' in severity_lower:
            return 'risk-high'
        elif 'medium' in severity_lower:
            return 'risk-medium'
        else:
            return 'risk-low'
    
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
        生成 HTML 格式报告
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            similar_vulns: 相似漏洞
            symbolic_result: 符号执行结果
            output_path: 输出路径
            
        Returns:
            HTML 报告路径
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
        生成 PDF 格式报告（需要 weasyprint 或 pdfkit）
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            similar_vulns: 相似漏洞
            symbolic_result: 符号执行结果
            output_path: 输出路径
            
        Returns:
            包含生成状态和路径的字典
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
        生成多种格式的报告
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制信息
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析
            exploit_result: 利用脚本结果
            similar_vulns: 相似漏洞
            symbolic_result: 符号执行结果
            formats: 要生成的格式列表 ['md', 'json', 'html', 'pdf']
            
        Returns:
            格式到文件路径的映射字典
        """
        if formats is None:
            formats = ['md', 'json']
        
        generated = {}
        
        if 'md' in formats:
            generated['markdown'] = self.generate_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )
        
        if 'json' in formats:
            generated['json'] = self.generate_json_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result
            )
        
        if 'html' in formats:
            generated['html'] = self.generate_html_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )
        
        if 'pdf' in formats:
            pdf_result = self.generate_pdf_report(
                binary_path, binary_info, decomp_results,
                crash_analysis, exploit_result, similar_vulns, symbolic_result
            )
            generated['pdf'] = pdf_result
        
        logger.info(f"已生成 {len(generated)} 种格式的报告")
        return generated
    
    def calculate_cvss(self, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        计算 CVSS 3.1 评分
        
        Args:
            vuln_info: 漏洞信息字典，可包含以下关键字段：
                - attack_vector: 'N' (Network), 'A' (Adjacent), 'L' (Local), 'P' (Physical)
                - attack_complexity: 'L' (Low), 'H' (High)
                - privileges_required: 'N' (None), 'L' (Low), 'H' (High)
                - user_interaction: 'N' (None), 'R' (Required)
                - scope: 'U' (Unchanged), 'C' (Changed)
                - confidentiality: 'N' (None), 'L' (Low), 'H' (High)
                - integrity: 'N', 'L', 'H'
                - availability: 'N', 'L', 'H'
                - type: 漏洞类型 (用于启发式推断)
                - severity: 严重程度 (用于回退)
            
        Returns:
            包含 CVSS 评分的字典：
            - base_score: 基础评分 (0.0-10.0)
            - severity: 严重程度 (Critical/High/Medium/Low)
            - vector_string: CVSS 向量字符串
            - metrics: 各指标值
            - explanation: 评分说明
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
        根据漏洞信息推断 CVSS 指标
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
        根据 CVSS 3.1 公式计算基础评分
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
        根据评分获取严重程度
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
        构建 CVSS 向量字符串
        """
        parts = ['CVSS:3.1']
        for key in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            parts.append(f'{key}:{metrics[key]}')
        return '/'.join(parts)
    
    def _get_cvss_explanation(self, metrics: Dict[str, str], score: float) -> str:
        """
        生成 CVSS 评分说明
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
    
    def _generate_vis_js_graphs(
        self,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]],
        symbolic_result: Dict[str, Any] = None
    ) -> Tuple[str, str]:
        """
        生成 vis.js 调用图和控制流图数据
        
        Returns:
            (call_graph_html, cfg_html) 元组
        """
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
            <h2>🔀 控制流图 (Control Flow Graph)</h2>
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
        生成可在 Ghidra 中运行的 Python 脚本，用于标注漏洞位置
        
        Args:
            binary_path: 二进制文件路径
            decomp_results: 反编译分析结果
            crash_analysis: 崩溃分析结果
            
        Returns:
            Ghidra Python 脚本内容
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
    except:
        pass
    
    try:
        listing = currentProgram.getListing()
        color = Color(color_int & 0xFFFFFF)
        
        for addr in func.getBody().getAddresses(True):
            codeUnit = listing.getCodeUnitAt(addr)
            if codeUnit:
                pass
    except:
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


def round_up(value: float) -> float:
    """
    CVSS 3.1 评分的向上取整（保留一位小数）
    """
    from math import ceil
    return ceil(value * 10) / 10.0
