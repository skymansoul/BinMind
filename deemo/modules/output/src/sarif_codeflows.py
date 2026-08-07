"""
SARIF codeFlows 证据映射 — 证据链节点 → SARIF threadFlow 步骤。

SARIF codeFlows 的 threadFlow 用于描述"分析结果是如何得出的"，
按因果/时序顺序展示发现路径。本项目将其重新用途化:
  每个 EvidenceNode → 一个 threadFlowLocation，
  source_module → importance，evidence_type → kind 标记，
  confidence → nestingLevel 的 proxy 权重。

SARIF 查看器 (如 VS Code SARIF Viewer、GitHub Code Scanning UI)
可按此结构展示漏洞发现的多层分析轨迹。

修改记录:
2025-07-22 16:08 - 独立维护 codeFlows 映射逻辑
"""

from typing import Any, Dict, List


def build_code_flows(evidence_nodes: List[Dict], finding_id: str) -> List[Dict]:
    """
    将证据链节点映射为 SARIF codeFlows/threadFlow 步骤。

    映射规则:
      step_index    ← 节点在证据链中的深度
      evidence_type ← 证据类型 (static/dynamic/llm/fuzz/symbex)
      confidence    ← 置信度，≥0.8 标记为 'essential'
      nestingLevel  ← min(depth, 3)，限制嵌套深度防止 SARIF 消费端溢出

    SARIF 标准中 threadFlowLocation 的 importance 字段取值:
      'essential' / 'important' / 'unimportant' — 此处仅在 ≥0.8 时用 essential。
    """
    if not evidence_nodes:
        return []

    steps = []
    for i, node in enumerate(evidence_nodes):
        conf = node.get('confidence', 0.0)
        step = {
            'location': {
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': f"evidence://{finding_id}/{node.get('source_module', 'unknown')}",
                        'uriBaseId': '%EVIDENCE%',
                    },
                    'region': {
                        'properties': {
                            'step_index': i,
                            'evidence_type': node.get('evidence_type', ''),
                            'confidence': conf,
                        }
                    }
                }
            },
            'importance': 'essential' if conf >= 0.8 else 'important',
            'nestingLevel': min(i, 3),
            'properties': {
                'source_module': node.get('source_module', ''),
                'finding_id': finding_id,
            }
        }
        steps.append(step)

    return [{
        'threadFlows': [{
            'id': finding_id,
            'locations': steps,
            'message': {
                'text': f'发现 {finding_id} 的证据链 ({len(steps)} 步)'
            }
        }]
    }]
