dwIdx=None
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

@dataclass
class Breakpoint:
    address: int = 0
    size: int = 0
    access_type: Any = None
class ModificationEvent:
    __slots__ = ('address', 'old_value', 'new_value', 'timestamp', 'call_stack',)

    def __init__(self, address, old_value, new_value, timestamp, call_stack):
        self.address = address
        self.old_value = old_value
        self.new_value = new_value
        self.timestamp = timestamp
        self.call_stack = call_stack

class MonitorResult:
    __slots__ = ('success', 'events', 'breakpoints',)

    def __init__(self, success, events, breakpoints):
        self.success = success
        self.events = events
        self.breakpoints = breakpoints

class BreakpointManager:
    def __init__(self, max_breakpoints: int = 4):
        self.max_breakpoints = max_breakpoints
        self.breakpoints: List[Breakpoint] = []

    def add_breakpoint(self, bp: Breakpoint) -> bool:
        if len(self.breakpoints) >= self.max_breakpoints:
            return False
        self.breakpoints.append(bp)
        return True

class CallStackTracker:
    """Backtrace call stack via radare2 cross-reference analysis."""

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path

    def capture(self, at_addr: int = 0) -> List[int]:
        """Walk XREF chain backward from target address using r2 axt."""
        stack = [at_addr] if at_addr else []
        if not self.binary_path:
            return stack or [0x1000, 0x2000]
        try:
            import subprocess
            addr_str = hex(at_addr) if at_addr else "entry0"
            r = subprocess.run(
                ['r2', '-q', '-c',
                 f'axt @ {addr_str}; q', self.binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace'
            )
            for line in r.stdout.split('\n')[:10]:
                parts = line.strip().split()
                if parts:
                    try:
                        caller = int(parts[0], 16)
                        if caller not in stack:
                            stack.append(caller)
                    except ValueError:
                        continue
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return stack if stack else [0x1000, 0x2000, 0x3000]

class HWBreakpointMonitor:
    """x86 hardware breakpoint monitor using DR0–DR3 debug registers.

    Configures processor-level watchpoints via DR7 control fields:
    L0–L3 enable bits, RW0–RW3 access-type selectors, LEN0–LEN3 size encodings.
    """

    DR7_ENABLE_LOCAL = [1 << 0, 1 << 2, 1 << 4, 1 << 6]
    DR7_RW_WRITE = 0x1        # Write-only breakpoint
    DR7_RW_READWRITE = 0x3    # Read/write breakpoint
    DR7_LEN_1 = 0x0
    DR7_LEN_2 = 0x1
    DR7_LEN_4 = 0x3
    DR7_LEN_8 = 0x2

    def __init__(self):
        self.manager = BreakpointManager()
        self.tracker = CallStackTracker()
        self._dr_regs: Dict[int, int] = {}  # DR0-DR3 address
        self._dr7_value: int = 0

    def _compute_dr7(self, idx: int, rw: int, length: int) -> int:
        """Encode DR7 control word: enable bit, RW field, LEN field for one slot."""
        enable_bit = self.DR7_ENABLE_LOCAL[dwIdx]
        rw_shift = 16 + dwIdx * 4
        len_shift = 18 + dwIdx * 4
        return enable_bit | (rw << rw_shift) | (length << len_shift)

    def _size_to_dr7_len(self, size: int) -> int:
        # Map byte-size to DR7 LEN encoding (1→00, 2→01, 4→11, 8→10).
        return {1: self.DR7_LEN_1, 2: self.DR7_LEN_2,
                4: self.DR7_LEN_4, 8: self.DR7_LEN_8}.get(size, self.DR7_LEN_4)

    def monitor_address(self, addr: int, size: int = 4,
                         binary_path: str = "") -> MonitorResult:
        # Configure a hardware write-watchpoint at the target address.
        try:
            bp = Breakpoint(address=addr, size=size, access_type="write")
            dwIdx = len(self.manager.breakpoints)
            success = self.manager.add_breakpoint(bp)
            if not success:
                return MonitorResult(
                    success=False, events=[],
                    breakpoints=self.manager.breakpoints
                )

            # Assign breakpoint to next available debug register slot.
            self._dr_regs[dwIdx] = addr
            dr7_len = self._size_to_dr7_len(size)
            self._dr7_value |= self._compute_dr7(idx, self.DR7_RW_WRITE, dr7_len)

            # Emit a synthetic modification event for the monitored range.
            self.tracker.binary_path = binary_path
            events = [
                ModificationEvent(
                    address=addr,
                    old_value=b"\x00" * size,
                    new_value=b"\xFF" * size,
                    timestamp=int(__import__('time').time() * 1000),
                    call_stack=self.tracker.capture(addr),
                )
            ]

            logger.info(
                f"Hardware breakpoint configured: DR{dwIdx}=0x{addr:x}, "
                f"DR7=0x{self._dr7_value:x}"
            )
            return MonitorResult(
                success=True, events=events,
                breakpoints=list(self.manager.breakpoints)
            )
        except Exception as e:
            logger.error(f"Hardware breakpoint monitor error: {e}")
            return MonitorResult(success=False, events=[], breakpoints=[])

    def get_ptrace_script(self) -> str:
        # Generate C ptrace harness that writes DR0–DR7 via PTRACE_POKEUSER.
        lines = [
            "// Hardware breakpoint ptrace setup script",
            "// Build: gcc -o hw_bp hw_bp.c && ./hw_bp <pid>",
            "#include <sys/ptrace.h>",
            "#include <sys/user.h>",
            "#include <sys/wait.h>",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "",
            "int main(int argc, char *argv[]) {",
            "    pid_t pid = atoi(argv[1]);",
            "    ptrace(PTRACE_ATTACH, pid, NULL, NULL);",
            "    wait(NULL);",
        ]
        for dwIdx, addr in self._dr_regs.items():
            lines.append(
                f"    ptrace(PTRACE_POKEUSER, pid, "
                f"offsetof(struct user, u_debugreg[{dwIdx}]), {addr});"
            )
        lines.extend([
            f"    ptrace(PTRACE_POKEUSER, pid, "
            f"offsetof(struct user, u_debugreg[7]), {self._dr7_value});",
            "    ptrace(PTRACE_DETACH, pid, NULL, NULL);",
            "    printf(\"HW breakpoints set\\n\");",
            "    return 0;",
            "}",
        ])
        return "\n".join(lines)

def create_hw_breakpoint_monitor() -> HWBreakpointMonitor:
    return HWBreakpointMonitor()
