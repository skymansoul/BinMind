import logging
from enum import Enum
from dataclasses import dataclass, field
import typing

__log = logging.getLogger(__name__)


class FrameType(str, Enum):
    NORMAL = "normal"
    INLINE = "inline"
    TRUNCATED = "truncated"
    SYMBOLIC = "symbolic"


@dataclass
class StackFrame:
    function_name: str
    address: int
    return_address: int
    frame_type: FrameType
    arguments: Dict[str, Any] = field(default_factory=dict)
    locals: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'address': hex(self.address),
            'return_address': hex(self.return_address),
            'frame_type': self.frame_type.value,
            'arguments': self.arguments,
            'locals': self.locals
        }


@dataclass
class CallStack:
    frames: List[StackFrame]
    crash_address: int
    signal: Optional[str] = None
    thread_id: Optional[str] = None
    reconstructed_frames: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'frames': [f.to_dict() for f in self.frames],
            'crash_address': hex(self.crash_address),
            'signal': self.signal,
            'thread_id': self.thread_id,
            'reconstructed_frames': self.reconstructed_frames
        }


class CallStackReconstructor:

    def __init__(self):
        self.register_offsets = {
            'x86_64': {
                'rbp': 0,
                'rsp': 8,
                'rdi': 32,
                'rsi': 40,
                'rdx': 48,
                'rcx': 56,
                'r8': 64,
                'r9': 72
            }
        }

    def reconstruct(self, crash_data: Dict[str, Any]) -> CallStack:
        frames = []
        crash_address = crash_data.get('crash_address', 0)
        signal = crash_data.get('signal')
        thread_id = crash_data.get('thread_id')

        if crash_data.get('stack_trace'):
            frames.extend(self._parse_stack_trace(crash_data['stack_trace']))

        if crash_data.get('registers'):
            frames.extend(self._reconstruct_from_registers(crash_data['registers']))

        frames = self._deduplicate_frames(frames)

        return CallStack(
            frames=frames,
            crash_address=crash_address,
            signal=signal,
            thread_id=thread_id,
            reconstructed_frames=len(frames))

    def _parse_stack_trace(self, stack_trace: str) -> List[StackFrame]:
        frames = []

        for line in stack_trace.split('\n'):
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            try:
                frame_num = int(parts[0].rstrip(':'))
            except ValueError:
                continue

            address_str = None
            func_name = 'unknown'

            for part in parts:
                if part.startswith('0x'):
                    address_str = part
                    break

            if address_str:
                try:
                    address = int(address_str, 16)

                    for part in parts:
                        if '+' in part and not part.startswith('0x'):
                            func_name = part.split('+')[0]
                            break

                    frames.append(StackFrame(
                        function_name=func_name,
                        address=address,
                        return_address=0,
                        frame_type=FrameType.NORMAL))

                except ValueError:
                    continue

        return frames

    def _reconstruct_from_registers(self, registers: Dict[str, Any]) -> List[StackFrame]:
        frames = []

        if 'rbp' in registers and 'rsp' in registers:
            try:
                rbp = int(registers['rbp'], 16)
                rsp = int(registers['rsp'], 16)

                frame = StackFrame(
                    function_name='unknown',
                    address=rbp,
                    return_address=self._get_return_address(rsp),
                    frame_type=FrameType.SYMBOLIC,
                    arguments=self._extract_arguments(registers))

                frames.append(frame)
            except ValueError:
                pass

        return frames

    def _get_return_address(self, rsp: int) -> int:
        return rsp

    def _extract_arguments(self, registers: Dict[str, Any]) -> Dict[str, Any]:
        args = {}

        if 'rdi' in registers:
            args['arg1'] = registers['rdi']
        if 'rsi' in registers:
            args['arg2'] = registers['rsi']
        if 'rdx' in registers:
            args['arg3'] = registers['rdx']
        if 'rcx' in registers:
            args['arg4'] = registers['rcx']
        if 'r8' in registers:
            args['arg5'] = registers['r8']
        if 'r9' in registers:
            args['arg6'] = registers['r9']

        return args

    def _deduplicate_frames(self, frames: List[StackFrame]) -> List[StackFrame]:
        seen = set()
        unique = []

        for frame in frames:
            key = (frame.function_name, frame.address)

            if key not in seen:
                seen.add(key)
                unique.append(frame)

        return unique


def reconstruct_call_stack(crash_data: Dict[str, Any]) -> CallStack:
    reconstructor = CallStackReconstructor()
    return reconstructor.reconstruct(crash_data)
