import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PrimitiveType(Enum):
    ARBITRARY_WRITE = "arbitrary_write"
    ARBITRARY_READ = "arbitrary_read"
    CONTROLLED_WRITE = "controlled_write"
    CONTROLLED_READ = "controlled_read"
    CODE_EXECUTION = "code_execution"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"


@dataclass
class MemoryPrimitive:
    primitive_type: PrimitiveType
    address: int
    constraints: Dict[str, Any]
    payload_requirements: List[str]
    reliability: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'primitive_type': self.primitive_type.value,
            'address': hex(self.address),
            'constraints': self.constraints,
            'payload_requirements': self.payload_requirements,
            'reliability': self.reliability,
            'description': self.description
        }


@dataclass
class ExtractionResult:
    primitives: List[MemoryPrimitive]
    crash_address: int
    vulnerability_type: str
    exploitation_recipe: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'primitives': [p.to_dict() for p in self.primitives],
            'crash_address': hex(self.crash_address),
            'vulnerability_type': self.vulnerability_type,
            'exploitation_recipe': self.exploitation_recipe
        }


class MemoryPrimitiveExtractor:
    
    def __init__(self):
        self.primitive_patterns = {
            'arbitrary_write': [
                r'memcpy.*user.*controlled',
                r'write.*any.*address',
                r'overwrite.*pointer',
                r'heap.*overflow.*write',
                r'UAF.*write'
            ],
            'arbitrary_read': [
                r'memcpy.*read.*any',
                r'read.*arbitrary.*address',
                r'out.*of.*bounds.*read',
                r'UAF.*read'
            ],
            'code_execution': [
                r'jmp.*user.*controlled',
                r'call.*user.*controlled',
                r'ret.*overwrite',
                r'shellcode.*exec'
            ],
            'control_flow_hijack': [
                r'RIP.*control',
                r'PC.*control',
                r'stack.*smash',
                r'ROP.*chain'
            ]
        }
    
    def extract(self, crash_data: Dict[str, Any]) -> ExtractionResult:
        primitives = []
        crash_address = crash_data.get('crash_address', 0)
        vulnerability_type = crash_data.get('vulnerability_type', 'unknown')
        
        if self._has_arbitrary_write(crash_data):
            primitives.append(self._extract_arbitrary_write(crash_data

        
        if self._has_arbitrary_read(crash_data):
            primitives.append(self._extract_arbitrary_read(crash_data

        
        if self._has_code_execution(crash_data):
            primitives.append(self._extract_code_execution(crash_data

        
        if self._has_control_flow_hijack(crash_data):
            primitives.append(self._extract_control_flow_hijack(crash_data

        
        exploitation_recipe = self._generate_exploitation_recipe(primitives)
        
        return ExtractionResult(
            primitives=primitives,
            crash_address=crash_address,
            vulnerability_type=vulnerability_type,
            exploitation_recipe=exploitation_recipe)
        

    
    def _has_arbitrary_write(self, crash_data: Dict[str, Any]) -> bool:
        crash_info = str(crash_data.get('crash_info', '')).lower()
        return any(pattern in crash_info for pattern in self.primitive_patterns['arbitrary_write'])
    
    def _has_arbitrary_read(self, crash_data: Dict[str, Any]) -> bool:
        crash_info = str(crash_data.get('crash_info', '')).lower()
        return any(pattern in crash_info for pattern in self.primitive_patterns['arbitrary_read'])
    
    def _has_code_execution(self, crash_data: Dict[str, Any]) -> bool:
        crash_info = str(crash_data.get('crash_info', '')).lower()
        return any(pattern in crash_info for pattern in self.primitive_patterns['code_execution'])
    
    def _has_control_flow_hijack(self, crash_data: Dict[str, Any]) -> bool:
        crash_info = str(crash_data.get('crash_info', '')).lower()
        return any(pattern in crash_info for pattern in self.primitive_patterns['control_flow_hijack'])
    
    def _extract_arbitrary_write(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}
        
        if crash_data.get('crash_address'):
            constraints['target_address'] = hex(crash_data['crash_address'])
        
        if crash_data.get('registers'):
            constraints['controlled_register'] = crash_data['registers'].get('rdi', 'unknown')
        
        return MemoryPrimitive(
            primitive_type=PrimitiveType.ARBITRARY_WRITE,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                '可控的写入地址',
                '可控的写入数据',
                '足够的写入长度'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='可在任意地址写入任意数据')
        

    
    def _extract_arbitrary_read(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}
        
        if crash_data.get('registers'):
            constraints['output_register'] = crash_data['registers'].get('rax', 'unknown')
        
        return MemoryPrimitive(
            primitive_type=PrimitiveType.ARBITRARY_READ,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                '可控的读取地址',
                '读取结果可泄露'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='可从任意地址读取数据')
        

    
    def _extract_code_execution(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}
        
        if crash_data.get('registers'):
            constraints['instruction_pointer'] = crash_data['registers'].get('rip', 'unknown')
        
        return MemoryPrimitive(
            primitive_type=PrimitiveType.CODE_EXECUTION,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                '可执行内存区域',
                'Shellcode 或 ROP chain'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='可执行任意代码')
        

    
    def _extract_control_flow_hijack(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}
        
        if crash_data.get('registers'):
            constraints['stack_pointer'] = crash_data['registers'].get('rsp', 'unknown')
        
        return MemoryPrimitive(
            primitive_type=PrimitiveType.CONTROL_FLOW_HIJACK,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                'ROP gadgets',
                '栈溢出或返回地址控制'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='可劫持程序控制流')
        

    
    def _calculate_reliability(self, crash_data: Dict[str, Any]) -> float:
        reliability = 0.5
        
        if crash_data.get('registers'):
            reliability += 0.2
        
        if crash_data.get('stack_trace'):
            reliability += 0.2
        
        if crash_data.get('crash_info'):
            reliability += 0.1
        
        return min(1.0, reliability)
    
    def _generate_exploitation_recipe(self, primitives: List[MemoryPrimitive]) -> str:
        recipes = []
        
        write_primitives = [p for p in primitives if p.primitive_type == PrimitiveType.ARBITRARY_WRITE]
        read_primitives = [p for p in primitives if p.primitive_type == PrimitiveType.ARBITRARY_READ]
        exec_primitives = [p for p in primitives if p.primitive_type == PrimitiveType.CODE_EXECUTION]
        cfh_primitives = [p for p in primitives if p.primitive_type == PrimitiveType.CONTROL_FLOW_HIJACK]
        
        if read_primitives:
            recipes.append("1. 使用任意读原语泄露 libc 基地址")
        
        if write_primitives:
            recipes.append("2. 使用任意写原语修改关键数据结构")
        
        if cfh_primitives:
            recipes.append("3. 使用控制流劫持原语执行 ROP chain")
        
        if exec_primitives:
            recipes.append("4. 使用代码执行原语获取 shell")
        
        return '\n'.join(recipes)


def extract_memory_primitives(crash_data: Dict[str, Any]) -> ExtractionResult:
    extractor = MemoryPrimitiveExtractor()
    return extractor.extract))))))))