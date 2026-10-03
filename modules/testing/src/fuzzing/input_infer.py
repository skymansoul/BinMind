"""约束驱动的输入结构推断——符号约束 -> 字段推断 -> Kaitai Struct"""
import re
from typing import Dict, Any, List


class ConstraintBasedInputStructureInferer:
    """从符号执行约束集推断数据格式——输出 Kaitai Struct 定义"""

    def __init__(self):
        self.constraints: List[Dict[str, Any]] = []
        self.inferred_structure: Dict[str, Any] = {}
        self.kaitai_definition: str = ''

    def analyze_constraints(self, symbolic_constraints: List[str]) -> List[Dict[str, Any]]:
        """符号约束分类——魔数/长度/版本/字段范围"""
        analyzed = []

        for constraint in symbolic_constraints:
            if '==' in constraint and '0x' in constraint:
                match = re.search(r'input\[0\] == (0x[0-9a-fA-F]+)', constraint)
                if match:
                    analyzed.append({
                        'type': 'magic',
                        'offset': 0,
                        'value': match.group(1),
                        'description': '魔数校验'
                    })

            if 'len' in constraint or 'size' in constraint:
                match = re.search(r'len\(input\) >= (\d+)', constraint)
                if match:
                    analyzed.append({
                        'type': 'min_length',
                        'value': int(match.group(1)),
                        'description': '最小长度约束'
                    })

            if 'version' in constraint:
                analyzed.append({
                    'type': 'version',
                    'description': '版本字段校验'
                })

        self.constraints = analyzed
        return analyzed

    def analyze_constraints_with_offsets(
            self, symbolic_constraints: List[str]) -> List[Dict[str, Any]]:
        """扩展约束分析——提取 input[offset] 引用推断字段边界"""
        analyzed = self.analyze_constraints(symbolic_constraints)
        offset_pattern = re.compile(r'input\[(\d+)\]')
        for c in symbolic_constraints:
            offsets = [int(m) for m in offset_pattern.findall(c)]
            if offsets:
                min_off = min(offsets)
                max_off = max(offsets)
                if max_off > min_off:
                    analyzed.append({
                        'type': 'field_range',
                        'offset': min_off,
                        'end_offset': max_off,
                        'size': max_off - min_off + 1,
                        'description': f'字段跨字节 {min_off}-{max_off}',
                    })
        return analyzed

    def infer_structure(self) -> Dict[str, Any]:
        """从约束推断数据结构"""
        structure = {
            'fields': [],
            'magic': None,
            'min_size': 0
        }

        for constraint in self.constraints:
            if constraint['type'] == 'magic':
                structure['magic'] = {
                    'offset': constraint['offset'],
                    'value': constraint['value'],
                    'size': 4
                }
                structure['fields'].append({
                    'name': 'magic',
                    'type': 'bytes',
                    'size': 4,
                    'expected': constraint['value']
                })

            elif constraint['type'] == 'min_length':
                structure['min_size'] = constraint['value']

        self.inferred_structure = structure
        return structure

    def generate_kaitai_struct(self, format_name: str) -> str:
        """生成 Kaitai Struct YAML 定义"""
        structure = self.inferred_structure

        kaitai = f'''
meta:
  id: {format_name}
  file-extension: {format_name}

seq:
'''

        for i, field in enumerate(structure.get('fields', [])):
            kaitai += f'''
  - id: {field["name"]}
    type: {field["type"]}
    size: {field["size"]}
'''

        if structure.get('magic'):
            kaitai += f'''
instances:
  magic_check:
    value: magic == {structure["magic"]["value"]}
'''

        self.kaitai_definition = kaitai
        return kaitai

    def validate_structure(self, sample_data: bytes) -> bool:
        """用样本数据验证推断的结构——最小长度 + 魔数校验"""
        structure = self.inferred_structure

        if len(sample_data) < structure.get('min_size', 0):
            return False

        magic = structure.get('magic')
        if magic:
            expected = int(magic['value'], 16)
            actual = int.from_bytes(sample_data[magic['offset']:magic['offset'] + magic['size']], 'little')
            if actual != expected:
                return False

        return True
