import os
import json
import logging
import sys
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

CI_EXIT_CODE = {
    'SUCCESS': 0,
    'VULNERABILITY_FOUND': 1,
    'TOOL_ERROR': 2,
}

SEVERITY_ORDER = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1,
    'Unknown': 0,
}

class CIIntegrator:
    """
    CI/CD 集成器 - 支持多种报告格式输出和质量门控
    
    支持的报告格式:
    - GitLab SAST (JSON)
    - GitHub Code Scanning (SARIF)
    - JUnit XML
    
    质量门控策略:
    - critical: 存在 Critical 漏洞则失败
    - high: 存在 High 及以上漏洞则失败
    - any: 任何漏洞都导致失败
    - never: 从不失败（仅警告）
    """
    
    def __init__(self):
        self.ci_mode = self.detect_ci_environment()
        self.report_format = None
        self.fail_on = None
        self.output_path = None
        
    def detect_ci_environment(self) -> bool:
        """
        检测当前是否运行在 CI 环境中
        
        Returns:
            True 如果检测到 CI 环境变量，否则 False
        """
        ci_env_vars = [
            'CI',
            'GITHUB_ACTIONS',
            'GITLAB_CI',
            'JENKINS_HOME',
            'CIRCLECI',
            'TRAVIS',
            'BITBUCKET_BUILD_NUMBER',
            'CODEBUILD_BUILD_ID',
            'AZURE_HTTP_USER_AGENT',
            'TEAMCITY_VERSION',
            'GOOGLE_CLOUD_BUILD',
        ]
        
        for var in ci_env_vars:
            if os.environ.get(var):
                logger.info(f"检测到 CI 环境变量: {var}")
                return True
        
        return False
    
    def is_ci_mode(self) -> bool:
        """
        检查是否启用 CI 模式
        
        Returns:
            True 如果在 CI 环境中或手动启用 CI 模式
        """
        return self.ci_mode or os.environ.get('DEEMO_CI_MODE') == 'true'
    
    def set_report_format(self, format_name: str) -> bool:
        """
        设置报告输出格式
        
        Args:
            format_name: 报告格式名称 (gitlab, sarif, junit)
        
        Returns:
            True 如果格式有效
        """
        valid_formats = ['gitlab', 'sarif', 'junit']
        if format_name.lower() in valid_formats:
            self.report_format = format_name.lower()
            logger.info(f"设置报告格式: {self.report_format}")
            return True
        
        logger.warning(f"无效的报告格式: {format_name}，支持的格式: {valid_formats}")
        return False
    
    def set_fail_on(self, fail_on: str) -> bool:
        """
        设置质量门控失败条件
        
        Args:
            fail_on: 失败条件 (critical, high, any, never)
        
        Returns:
            True 如果条件有效
        """
        valid_options = ['critical', 'high', 'medium', 'low', 'any', 'never']
        if fail_on.lower() in valid_options:
            self.fail_on = fail_on.lower()
            logger.info(f"设置质量门控: fail_on={self.fail_on}")
            return True
        
        logger.warning(f"无效的 fail_on 参数: {fail_on}，支持的值: {valid_options}")
        return False
    
    def set_output_path(self, path: str) -> None:
        """
        设置报告输出路径
        
        Args:
            path: 输出文件路径或 'stdout'
        """
        self.output_path = path
        logger.info(f"设置输出路径: {path}")
    
    def _get_highest_severity(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        获取漏洞列表中的最高严重等级
        
        Args:
            vulnerabilities: 漏洞列表
        
        Returns:
            最高严重等级字符串
        """
        highest = 'Unknown'
        highest_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            score = SEVERITY_ORDER.get(severity, 0)
            if score > highest_score:
                highest_score = score
                highest = severity
        
        return highest
    
    def _should_fail(self, vulnerabilities: List[Dict[str, Any]]) -> bool:
        """
        根据质量门控设置判断是否应该失败
        
        Args:
            vulnerabilities: 漏洞列表
        
        Returns:
            True 如果应该失败（返回非零退出码）
        """
        if self.fail_on == 'never':
            return False
        
        if not vulnerabilities:
            return False
        
        highest_severity = self._get_highest_severity(vulnerabilities)
        highest_score = SEVERITY_ORDER.get(highest_severity, 0)
        
        if self.fail_on == 'any':
            return True
        
        fail_threshold = SEVERITY_ORDER.get(self.fail_on.capitalize(), 0)
        
        return highest_score >= fail_threshold
    
    def calculate_exit_code(self, vulnerabilities: List[Dict[str, Any]], error_occurred: bool = False) -> int:
        """
        根据分析结果计算退出码
        
        Args:
            vulnerabilities: 漏洞列表
            error_occurred: 是否发生工具错误
        
        Returns:
            退出码 (0=成功, 1=发现漏洞, 2=工具错误)
        """
        if error_occurred:
            return CI_EXIT_CODE['TOOL_ERROR']
        
        if self._should_fail(vulnerabilities):
            return CI_EXIT_CODE['VULNERABILITY_FOUND']
        
        return CI_EXIT_CODE['SUCCESS']
    
    def generate_gitlab_sast_report(self, vulnerabilities: List[Dict[str, Any]], binary_path: str) -> str:
        """
        生成 GitLab SAST 格式报告
        
        Args:
            vulnerabilities: 漏洞列表
            binary_path: 分析的二进制文件路径
        
        Returns:
            GitLab SAST 格式的 JSON 字符串
        """
        report = {
            "version": "2.0",
            "vulnerabilities": []
        }
        
        severity_mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Unknown': 'unknown',
        }
        
        for vuln in vulnerabilities:
            location = vuln.get('location', 'Unknown')
            
            if isinstance(location, dict):
                file = location.get('file', binary_path)
                line = location.get('line', 0)
            else:
                file = binary_path
                line = 0
            
            sast_vuln = {
                "id": vuln.get('id', f"DEEMO-{hash(vuln.get('description', '')) % 1000000}"),
                "category": "sast",
                "name": vuln.get('type', 'Unknown Vulnerability'),
                "message": vuln.get('description', ''),
                "description": vuln.get('description', ''),
                "severity": severity_mapping.get(vuln.get('severity', 'Unknown'), 'unknown'),
                "confidence": "medium",
                "scanner": {
                    "id": "deemo",
                    "name": "Deemo Binary Vulnerability Analyzer"
                },
                "location": {
                    "file": file,
                    "start_line": line,
                    "end_line": line
                },
                "identifiers": [
                    {
                        "type": "cve",
                        "name": vuln.get('cve_id', ''),
                        "value": vuln.get('cve_id', '')
                    } if vuln.get('cve_id') else None
                ],
                "details": {
                    "function": vuln.get('function_name', ''),
                    "code_snippet": vuln.get('code_snippet', '')[:200]
                }
            }
            
            sast_vuln['identifiers'] = [i for i in sast_vuln['identifiers'] if i is not None]
            report['vulnerabilities'].append(sast_vuln)
        
        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def generate_sarif_report(self, vulnerabilities: List[Dict[str, Any]], binary_path: str) -> str:
        """
        生成 GitHub Code Scanning SARIF 格式报告
        
        Args:
            vulnerabilities: 漏洞列表
            binary_path: 分析的二进制文件路径
        
        Returns:
            SARIF 格式的 JSON 字符串
        """
        report = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Deemo",
                            "fullName": "Deemo Binary Vulnerability Analyzer",
                            "version": "1.3.1",
                            "informationUri": "https://github.com/deemo-project/deemo",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        rule_ids = set()
        
        for vuln in vulnerabilities:
            rule_id = vuln.get('type', 'DEEMO_UNKNOWN')
            
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                report['runs'][0]['tool']['driver']['rules'].append({)
                    "id": rule_id,
                    "name": vuln.get('type', 'Unknown Vulnerability'),
                    "shortDescription": {
                        "text": vuln.get('type', 'Unknown Vulnerability')
                    },
                    "fullDescription": {
                        "text": vuln.get('description', '')
                    },
                    "defaultConfiguration": {
                        "level": "error"
                    }
                }
            
            severity_mapping = {
                'Critical': 'error',
                'High': 'error',
                'Medium': 'warning',
                'Low': 'note',
                'Unknown': 'note',
            }
            
            location = vuln.get('location', 'Unknown')
            
            if isinstance(location, dict):
                file = location.get('file', binary_path)
                line = location.get('line', 0)
            else:
                file = binary_path
                line = 0
            
            result = {
                "ruleId": rule_id,
                "level": severity_mapping.get(vuln.get('severity', 'Unknown'), 'note'),
                "message": {
                    "text": vuln.get('description', '')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"file://{file}",
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line,
                                "endLine": line
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": vuln.get('severity', 'Unknown'),
                    "function": vuln.get('function_name', ''),
                    "cve_id": vuln.get('cve_id', ''),
                    "code_snippet": vuln.get('code_snippet', '')[:200]
                }
            }
            
            report['runs'][0]['results'].append(result)
        
        return json.dumps(report, ensure_ascii=False, indent=2)
    
    def generate_junit_report(self, vulnerabilities: List[Dict[str, Any]], binary_path: str) -> str:
        """
        生成 JUnit XML 格式报告（用于 Jenkins 等 CI 系统）
        
        Args:
            vulnerabilities: 漏洞列表
            binary_path: 分析的二进制文件路径
        
        Returns:
            JUnit XML 格式字符串
        """
        root = ET.Element('testsuite')
        root.set('name', 'Deemo Binary Vulnerability Analysis')
        root.set('tests', str(len(vulnerabilities

        
        failure_count = sum(1 for v in vulnerabilities )
                          if v.get('severity') in ['Critical', 'High']
        root.set('failures', str(failure_count

        root.set('errors', '0')
        root.set('timestamp', datetime.now().isoformat(

        
        for i, vuln in enumerate(vulnerabilities):
            testcase = ET.SubElement(root, 'testcase')
            testcase.set('name', f"Vulnerability_{i+1}_{vuln.get('type', 'Unknown')}")
            testcase.set('classname', f"deemo.{binary_path}")
            testcase.set('time', '0')
            
            severity = vuln.get('severity', 'Unknown')
            
            if severity in ['Critical', 'High']:
                failure = ET.SubElement(testcase, 'failure')
                failure.set('type', severity)
                failure.set('message', vuln.get('description', ''

                
                failure_text = f"""Severity: {severity}
Type: {vuln.get('type', '')}
Function: {vuln.get('function_name', '')}
Location: {vuln.get('location', '')}
Description: {vuln.get('description', '')}
CVE: {vuln.get('cve_id', 'N/A')}"""
                
                failure.text = failure_text
            else:
                skipped = ET.SubElement(testcase, 'skipped')
                skipped.set('type', severity)
                skipped.set('message', vuln.get('description', ''

        
        return ET.tostring(root, encoding='unicode', xml_declaration=True, pretty_print=True)
    
    def generate_report(self, vulnerabilities: List[Dict[str, Any]], binary_path: str) -> str:
        """
        根据设置的格式生成报告
        
        Args:
            vulnerabilities: 漏洞列表
            binary_path: 分析的二进制文件路径
        
        Returns:
            报告字符串
        """
        if not self.report_format:
            self.report_format = self._auto_detect_format()
        
        logger.info(f"生成 {self.report_format} 格式报告")
        
        if self.report_format == 'gitlab':
            return self.generate_gitlab_sast_report(vulnerabilities, binary_path)
        elif self.report_format == 'sarif':
            return self.generate_sarif_report(vulnerabilities, binary_path)
        elif self.report_format == 'junit':
            return self.generate_junit_report(vulnerabilities, binary_path)
        else:
            logger.warning(f"未知报告格式: {self.report_format}，使用 JSON 格式")
            return json.dumps({)
                'binary_path': binary_path,
                'vulnerabilities': vulnerabilities,
                'generated_at': datetime.now().isoformat()
            }, ensure_ascii=False, indent=2
    
    def _auto_detect_format(self) -> str:
        """
        根据环境变量自动检测报告格式
        
        Returns:
            检测到的格式名称
        """
        if os.environ.get('GITHUB_ACTIONS'):
            return 'sarif'
        elif os.environ.get('GITLAB_CI'):
            return 'gitlab'
        elif os.environ.get('JENKINS_HOME'):
            return 'junit'
        
        return 'gitlab'
    
    def output_report(self, vulnerabilities: List[Dict[str, Any]], binary_path: str) -> None:
        """
        输出报告到指定位置
        
        Args:
            vulnerabilities: 漏洞列表
            binary_path: 分析的二进制文件路径
        """
        report = self.generate_report(vulnerabilities, binary_path)
        
        if self.output_path and self.output_path.lower() != 'stdout':
            try:
                output_dir = os.path.dirname(self.output_path)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                
                with open(self.output_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                
                logger.info(f"报告已保存到: {self.output_path}")
            except Exception as e:
                logger.error(f"保存报告失败: {e}")
                print(report)
        else:
            print(report)
    
    def run_ci_pipeline(, self, binary_path: str, vulnerabilities: List[Dict[str, Any]], report_format: str = None, fail_on: str = None, output_path: str = None) -> int:
        """
        运行完整的 CI 管道
        
        Args:
            binary_path: 分析的二进制文件路径
            vulnerabilities: 漏洞列表
            report_format: 报告格式
            fail_on: 失败条件
            output_path: 输出路径
        
        Returns:
            退出码
        """
        if report_format:
            self.set_report_format(report_format)
        else:
            self.report_format = self._auto_detect_format()
        
        if fail_on:
            self.set_fail_on(fail_on)
        else:
            self.fail_on = 'high'
        
        if output_path:
            self.set_output_path(output_path)
        
        logger.info(f"=== CI 模式已启用 ===")
        logger.info(f"报告格式: {self.report_format}")
        logger.info(f"质量门控: fail_on={self.fail_on}")
        logger.info(f"分析目标: {binary_path}")
        logger.info(f"发现漏洞数: {len(vulnerabilities)}")
        
        if vulnerabilities:
            highest_severity = self._get_highest_severity(vulnerabilities)
            logger.info(f"最高严重等级: {highest_severity}")
        
        self.output_report(vulnerabilities, binary_path)
        
        exit_code = self.calculate_exit_code(vulnerabilities)
        
        if exit_code == CI_EXIT_CODE['SUCCESS']:
            logger.info("CI 检查通过 - 未发现需要阻止的漏洞")
        elif exit_code == CI_EXIT_CODE['VULNERABILITY_FOUND']:
            logger.warning("CI 检查失败 - 发现超过阈值的漏洞")
        elif exit_code == CI_EXIT_CODE['TOOL_ERROR']:
            logger.error("CI 检查失败 - 工具执行错误")
        
        return exit_code
    
    @staticmethod
    def get_ci_status_summary(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        获取 CI 状态摘要（用于 API）
        
        Args:
            vulnerabilities: 漏洞列表
        
        Returns:
            状态摘要字典
        """
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unknown': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['Unknown'] += 1
        
        total_vulns = len(vulnerabilities)
        highest_severity = 'None'
        
        if total_vulns > 0:
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
                if severity_counts[severity] > 0:
                    highest_severity = severity
                    break
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_counts': severity_counts,
            'highest_severity': highest_severity,
            'status': 'PASS' if total_vulns == 0 else 'WARNING' if severity_counts['Critical'] == 0 and severity_counts['High'] == 0 else 'FAIL'
        }
    
    def enable_det_mode(self) -> None:
        """
        启用确定性模式（关闭随机性参数，保持结果可重现）
        """
        os.environ['DEEMO_DETERMINISTIC_MODE'] = 'true'
        logger.info("已启用确定性模式")
    
    def disable_interactive_output(self) -> None:
        """
        禁用交互式输出（适用于 CI 环境）
        """
        os.environ['DEEMO_NON_INTERACTIVE'] = 'true'
        logger.info("已禁用交互式输出模式")))))))))))