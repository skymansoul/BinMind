import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any

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
    constraints: Dict[str, Any] = field(default_factory=dict)
    payload_requirements: List[str] = field(default_factory=list)
    reliability: float = 0.5
    description: str = ""

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
    primitives: List[MemoryPrimitive] = field(default_factory=list)
    crash_address: int = 0
    vulnerability_type: str = ""
    exploitation_recipe: str = ""

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
            primitives.append(self._extract_arbitrary_write(crash_data))

        if self._has_arbitrary_read(crash_data):
            primitives.append(self._extract_arbitrary_read(crash_data))

        if self._has_code_execution(crash_data):
            primitives.append(self._extract_code_execution(crash_data))

        if self._has_control_flow_hijack(crash_data):
            primitives.append(self._extract_control_flow_hijack(crash_data))

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
                'Controlled write address',
                'Controlled write data',
                'Sufficient write length'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='Arbitrary-address arbitrary-data write primitive')

    def _extract_arbitrary_read(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}

        if crash_data.get('registers'):
            constraints['output_register'] = crash_data['registers'].get('rax', 'unknown')

        return MemoryPrimitive(
            primitive_type=PrimitiveType.ARBITRARY_READ,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                'Controlled read address',
                'Read result must be observable (leak primitive)'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='Arbitrary-address read primitive')

    def _extract_code_execution(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}

        if crash_data.get('registers'):
            constraints['instruction_pointer'] = crash_data['registers'].get('rip', 'unknown')

        return MemoryPrimitive(
            primitive_type=PrimitiveType.CODE_EXECUTION,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                'Executable memory region available',
                'Shellcode or ROP chain payload'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='Arbitrary code execution primitive')

    def _extract_control_flow_hijack(self, crash_data: Dict[str, Any]) -> MemoryPrimitive:
        constraints = {}

        if crash_data.get('registers'):
            constraints['stack_pointer'] = crash_data['registers'].get('rsp', 'unknown')

        return MemoryPrimitive(
            primitive_type=PrimitiveType.CONTROL_FLOW_HIJACK,
            address=crash_data.get('crash_address', 0),
            constraints=constraints,
            payload_requirements=[
                'ROP gadget chain available',
                'Stack overflow or return-address control'
            ],
            reliability=self._calculate_reliability(crash_data),
            description='Control-flow hijack primitive')

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
            recipes.append("1. Leak libc base via arbitrary-read primitive")

        if write_primitives:
            recipes.append("2. Overwrite critical data structures via arbitrary-write")

        if cfh_primitives:
            recipes.append("3. Execute ROP chain via control-flow hijack")

        if exec_primitives:
            recipes.append("4. Spawn shell via code-execution primitive")

        return '\n'.join(recipes)


def extract_memory_primitives(crash_data: Dict[str, Any]) -> ExtractionResult:
    extractor = MemoryPrimitiveExtractor()
    return extractor.extract(crash_data)
