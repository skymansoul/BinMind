"""
数据来源链追踪 (Data Provenance Chain Tracker, DPCT)
------------------------------------------------------
记录分析数据的完整来源链: 原始二进制 → 中间产物 → 最终结果.

设计依据:
  安全审计要求可追溯性——某漏洞报告中的每个发现必须能回溯到
  原始二进制中的具体字节. 现有管线仅记录最终结果, 缺失中间步骤.
  DPCT 为每条数据建立 Merkle 风格的溯源链.
"""
import hashlib
import time
from typing import Any, Dict, List, Tuple


class ProvenanceChain:
    """数据来源链 — 单向追加的溯源记录.

    用法:
      chain = ProvenanceChain('binary_abc')
      chain.add_step('disasm', input_hash='abc', output_data=disasm_output)
      chain.add_step('decompile', input_hash=chain.tip_hash(), output_data=decomp_output)
      chain.verify()  # 验证整条链的完整性
    """

    def __init__(self, root_id: str, root_data: bytes = b''):
        self.root_id = root_id
        self._steps: List[Dict[str, Any]] = []
        self._root_hash = hashlib.sha256(root_data).hexdigest() if root_data else root_id

    def add_step(self, step_name: str, input_hash: str,
                 output_data: Any) -> str:
        """添加一个处理步骤, 返回本步骤的输出哈希."""
        output_bytes = self._serialize(output_data)
        output_hash = hashlib.sha256(output_bytes).hexdigest()
        self._steps.append({
            'name': step_name,
            'timestamp': time.time(),
            'input_hash': input_hash,
            'output_hash': output_hash,
            'output_size': len(output_bytes),
        })
        return output_hash

    def tip_hash(self) -> str:
        """当前链顶哈希 (最新步骤的输出)."""
        if not self._steps:
            return self._root_hash
        return self._steps[-1]['output_hash']

    def verify(self) -> Tuple[bool, List[str]]:
        """验证整条链的完整性."""
        errors = []
        prev_hash = self._root_hash
        for i, step in enumerate(self._steps):
            if step['input_hash'] != prev_hash:
                errors.append(
                    f'步骤 {i} ({step["name"]}): 输入哈希不匹配 '
                    f'(expected={prev_hash[:12]}, got={step["input_hash"][:12]})'
                )
            prev_hash = step['output_hash']
        return len(errors) == 0, errors

    def audit_trail(self) -> List[Dict[str, Any]]:
        """返回可审计的溯源追踪."""
        trail = [{
            'depth': 0, 'name': 'root',
            'hash': self._root_hash[:16],
        }]
        for i, step in enumerate(self._steps):
            trail.append({
                'depth': i + 1,
                'name': step['name'],
                'input': step['input_hash'][:16],
                'output': step['output_hash'][:16],
            })
        return trail

    @staticmethod
    def _serialize(data: Any) -> bytes:
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode()
        import json
        return json.dumps(data, sort_keys=True, default=str).encode()
