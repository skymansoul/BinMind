import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScriptType(Enum):
    DEBUG = "debug"
    ANALYSIS = "analysis"
    EXPLOIT = "exploit"
    FUZZING = "fuzzing"


@dataclass
class GDBBreakpoint:
    address: int
    condition: Optional[str] = None
    commands: List[str] = field(default_factory=list)
    type: str = "break"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': hex(self.address),
            'condition': self.condition,
            'commands': self.commands,
            'type': self.type
        }


@dataclass
class GDBWatchpoint:
    expression: str
    type: str = "watch"
    commands: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'expression': self.expression,
            'type': self.type,
            'commands': self.commands
        }


@dataclass
class GDBScript:
    script_type: ScriptType
    breakpoints: List[GDBBreakpoint]
    watchpoints: List[GDBWatchpoint]
    commands: List[str]
    comments: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'script_type': self.script_type.value,
            'breakpoints': [b.to_dict() for b in self.breakpoints],
            'watchpoints': [w.to_dict() for w in self.watchpoints],
            'commands': self.commands,
            'comments': self.comments
        }
    
    def generate(self) -> str:
        lines = []
        
        for comment in self.comments:
            lines.append(f"# {comment}")
        
        lines.append("")
        
        for bp in self.breakpoints:
            if bp.type == "break":
                line = f"b *{hex(bp.address)}"
            elif bp.type == "tbreak":
                line = f"tb *{hex(bp.address)}"
            elif bp.type == "hbreak":
                line = f"hb *{hex(bp.address)}"
            
            if bp.condition:
                line += f" if {bp.condition}"
            
            lines.append(line)
            
            if bp.commands:
                lines.append("commands")
                for cmd in bp.commands:
                    lines.append(f"  {cmd}")
                lines.append("end")
                lines.append("")
        
        for wp in self.watchpoints:
            line = f"{wp.type} {wp.expression}"
            lines.append(line)
            
            if wp.commands:
                lines.append("commands")
                for cmd in bp.commands:
                    lines.append(f"  {cmd}")
                lines.append("end")
                lines.append("")
        
        for cmd in self.commands:
            lines.append(cmd)
        
        return '\n'.join(lines)


class GdbScriptGenerator:
    
    def __init__(self):
        self.registers = {
            'x86_64': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'eflags'],
            'x86': ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags'],
            'arm64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                      'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'sp', 'pc']
        }
    
    def generate_script(self, crash_data: Dict[str, Any], script_type: ScriptType = ScriptType.DEBUG) -> GDBScript:
        breakpoints = []
        watchpoints = []
        commands = []
        comments = []
        
        comments.append("Auto-generated GDB script")
        comments.append(f"Script type: {script_type.value}")
        
        if crash_data.get('crash_address'):
            crash_addr = crash_data['crash_address']
            
            bp = GDBBreakpoint()
                address=crash_addr,
                type="break",
                commands=[
                    "info registers",
                    "bt",
                    "info frame",
                    "x/20i $rip-40"
                ]
            
            breakpoints.append(bp)
        
        if crash_data.get('registers'):
            registers = crash_data['registers']
            
            if 'rip' in registers:
                bp = GDBBreakpoint()
                    address=int(registers['rip'], 16),
                    type="break",
                    commands=["info registers"]
                
                breakpoints.append(bp)
            
            if 'rsp' in registers:
                watchpoint = GDBWatchpoint()
                    expression=f"*(unsigned long long *){registers['rsp']}",
                    type="watch",
                    commands=["bt"]
                
                watchpoints.append(watchpoint)
        
        if crash_data.get('vulnerability_type') == 'buffer_overflow':
            comments.append("Buffer overflow detected - setting up stack watchpoints")
            
            if crash_data.get('registers', {}).get('rsp'):
                rsp = int(crash_data['registers']['rsp'], 16)
                watchpoint = GDBWatchpoint()
                    expression=f"*(char *){rsp}",
                    type="awatch",
                    commands=["bt", "info registers"]
                
                watchpoints.append(watchpoint)
        
        if script_type == ScriptType.EXPLOIT:
            commands.extend([)
                "set disassembly-flavor intel",
                "set print pretty",
                "set print array on",
                "set pagination off",
                "show version"
            ]
        
        if script_type == ScriptType.FUZZING:
            commands.extend([)
                "set follow-fork-mode child",
                "set detach-on-fork off",
                "handle SIGSEGV stop print pass",
                "handle SIGILL stop print pass",
                "handle SIGABRT stop print pass"
            ]
        
        return GDBScript(
            script_type=script_type,
            breakpoints=breakpoints,
            watchpoints=watchpoints,
            commands=commands,
            comments=comments)
        

    
    def save_script(self, script: GDBScript, filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script.generate(

            
            logger.info(f"GDB 脚本已保存到: {filepath}")
            return True
        except Exception as e:
            logger.error(f"保存 GDB 脚本失败: {e}")
            return False


def generate_gdb_script(crash_data: Dict[str, Any], script_type: str = 'debug') -> GDBScript:
    script_type_enum = ScriptType[script_type.upper()]
    generator = GdbScriptGenerator()
    return generator.generate_script(crash_data, script_type_enum)))