"""
SARIF v2.1.0 输出 — 静态分析结果交换格式。

依据:
  OASIS SARIF v2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/)
  GitHub Code Scanning 集成: SARIF 上传后自动生成 PR 告警
  Microsoft sarif-python-om (参考实现，本项目未直接依赖)

创新点:
  SARIF 标准未定义证据链/密码学完整性的标准字段。
  本项目利用 sarif.result.properties 扩展袋:
    - evidence_chain: 证据链的文本化表示
    - merkle_root: 证据链的 Merkle 根哈希 (SHA-256 hex)
    - cvss_base/temporal/environmental: 三层评分向量
  使每个 finding 在 SARIF 消费端 (GitHub/GitLab/Azure DevOps)
  不仅可查看，还可独立验证其分析过程未被篡改。

  SARIF 的 baselineState 可与 report_differ 联动:
    新增发现 → baselineState: "new"
    消失发现 → baselineState: "absent"

修改记录:
  2025-07-21 09:34 - 增加 codeFlows 构造，将证据链节点映射为 threadFlow 步骤
  2025-07-22 16:08 - tool.driver.rules 自动从 finding 的 CWE 字段生成
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from modules.output.src.sarif_codeflows import build_code_flows

_log = logging.getLogger(__name__)

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# 严重度 → SARIF level 映射
_SEVERITY_TO_LEVEL = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
    'info': 'note',
}

# CWE → SARIF rule 索引
_CWE_TAXONOMY = {
    'name': 'CWE',
    'version': '4.15',
    'organization': 'MITRE',
    'shortDescription': {'text': 'Common Weakness Enumeration'},
}


def _make_rule_id(cwe: str) -> str:
    """从 CWE 字符串提取标准 ruleId，如 'CWE-787'。非标准 CWE 回退为 'DEEMO-000'。"""
    cwe = (cwe or '').strip().upper()
    if cwe.startswith('CWE-'):
        return cwe
    if cwe.startswith('CWE') and len(cwe) > 3:
        return f"CWE-{cwe[3:]}"
    return 'DEEMO-000'


def _make_message(finding: Dict) -> Dict[str, str]:
    """构造 SARIF message: text + markdown 双格式。"""
    title = finding.get('title', finding.get('type', '未命名'))
    desc = finding.get('description', '')
    severity = finding.get('severity', 'INFO')
    cwe = finding.get('cwe', 'N/A')

    text = f"[{severity}] {title}"
    markdown = (
        f"**{title}**\n\n"
        f"| 属性 | 值 |\n|------|----|\n"
        f"| 严重度 | {severity} |\n"
        f"| CWE | {cwe} |\n"
    )
    if desc:
        markdown += f"\n{desc}"
    return {'text': text, 'markdown': markdown}


def _make_location(binary_path: str, function_name: str, vuln_location: str = '') -> Dict:
    """构造 SARIF physicalLocation。

    SARIF 中二进制分析没有源文件行号，使用 artifactLocation 指向二进制，
    在 properties 中附加函数名和偏移信息。
    """
    loc: Dict[str, Any] = {
        'physicalLocation': {
            'artifactLocation': {
                'uri': os.path.basename(binary_path),
                'uriBaseId': '%SRCROOT%',
            },
            'region': {
                'properties': {
                    'function': function_name,
                }
            }
        }
    }
    if vuln_location:
        loc['physicalLocation']['region']['properties']['location'] = vuln_location
    return loc


def generate_sarif(
    binary_path: str,
    binary_info: Dict[str, Any],
    decomp_results: List[Dict],
    crash_analysis: Optional[Dict] = None,
    exploit_result: Optional[Dict] = None,
    evidence_chains: Optional[Dict[str, Dict]] = None,
    merkle_roots: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    生成 SARIF v2.1.0 JSON 对象。

    evidence_chains: {finding_id: {nodes: [...], ...}}
    merkle_roots: {finding_id: hex_root_hash}

    返回完整的 SARIF log 字典，可直接 json.dump 写入文件。
    """
    driver_name = 'Deemo'
    driver_version = '1.0.0'
    driver_info_uri = 'https://github.com/hermit1016/deemo'

    # 收集所有 findings
    all_findings: List[Dict] = []
    for result in decomp_results:
        func_name = result.get('function_name', 'unknown')
        vulns = result.get('analysis', {}).get('vulnerabilities', [])
        for v in vulns:
            v = dict(v)
            v['_function_name'] = func_name
            all_findings.append(v)

    # 构建 ruleId → rule 索引 (去重)
    rules_by_id: Dict[str, Dict] = {}
    for f in all_findings:
        cwe = f.get('cwe', '')
        rule_id = _make_rule_id(cwe)
        if rule_id not in rules_by_id:
            desc_text = f.get('description', f.get('type', 'Unknown'))[:200]
            rules_by_id[rule_id] = {
                'id': rule_id,
                'shortDescription': {'text': f.get('type', 'Unknown')},
                'fullDescription': {'text': desc_text},
                'helpUri': f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html"
                if rule_id.startswith('CWE-') else driver_info_uri,
                'properties': {
                    'cwe': cwe,
                    'tags': [cwe] if cwe else [],
                }
            }

    # 构建 results
    results: List[Dict] = []
    for f in all_findings:
        rule_id = _make_rule_id(f.get('cwe', ''))
        finding_id = f.get('id', f.get('_function_name', ''))
        level = _SEVERITY_TO_LEVEL.get(f.get('severity', '').lower(), 'warning')

        result: Dict[str, Any] = {
            'ruleId': rule_id,
            'ruleIndex': list(rules_by_id.keys()).index(rule_id),
            'level': level,
            'message': _make_message(f),
            'locations': [_make_location(
                binary_path,
                f.get('_function_name', f.get('function_name', '')),
                f.get('location', '')
            )],
        }

        # 附加 SARIF properties 扩展
        props: Dict[str, Any] = {}
        if f.get('cvss'):
            cvss = f['cvss']
            props['cvss_base_score'] = cvss.get('base_score', 0)
            props['cvss_vector'] = cvss.get('full_vector_string', cvss.get('vector_string', ''))

        fid = f.get('id', '')
        if evidence_chains and fid in evidence_chains:
            ec = evidence_chains[fid]
            nodes = ec.get('nodes', ec if isinstance(ec, list) else [])
            if nodes:
                result['codeFlows'] = build_code_flows(nodes, fid)
                props['evidence_chain_nodes'] = len(nodes)

        if merkle_roots and fid in merkle_roots:
            props['merkle_root'] = merkle_roots[fid]

        if props:
            result['properties'] = props

        results.append(result)

    # 组装完整的 SARIF log
    sarif_log: Dict[str, Any] = {
        '$schema': SARIF_SCHEMA,
        'version': SARIF_VERSION,
        'runs': [{
            'tool': {
                'driver': {
                    'name': driver_name,
                    'version': driver_version,
                    'informationUri': driver_info_uri,
                    'rules': list(rules_by_id.values()),
                    'supportedTaxonomies': [_CWE_TAXONOMY],
                }
            },
            'invocations': [{
                'executionSuccessful': True,
                'startTimeUtc': datetime.utcnow().isoformat() + 'Z',
                'workingDirectory': {'uri': os.path.dirname(os.path.abspath(binary_path))},
                'properties': {
                    'binary_path': binary_path,
                    'arch': binary_info.get('arch', 'unknown'),
                    'bits': binary_info.get('bits', 0),
                    'format': binary_info.get('binary_format', 'unknown'),
                }
            }],
            'artifacts': [{
                'location': {
                    'uri': os.path.basename(binary_path),
                    'uriBaseId': '%SRCROOT%',
                },
                'properties': {
                    'sha256': binary_info.get('sha256', binary_info.get('binary_hash', '')),
                    'arch': binary_info.get('arch', ''),
                    'bits': binary_info.get('bits', 0),
                }
            }],
            'results': results,
            'properties': {
                'total_findings': len(results),
                'critical_count': sum(1 for r in results if r['level'] == 'error'),
                'analysis_timestamp': datetime.utcnow().isoformat() + 'Z',
            }
        }]
    }

    return sarif_log


def write_sarif_file(
    sarif_obj: Dict[str, Any],
    output_path: str
) -> str:
    """将 SARIF 对象写入文件，返回路径。"""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sarif_obj, f, indent=2, ensure_ascii=False, default=str)
    _log.info("SARIF 报告已生成: %s", output_path)
    return output_path
