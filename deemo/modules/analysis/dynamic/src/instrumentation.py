# 2026-08-01
"""
插桩 facade — Frida-based 钩子 script generation, 检查点
management for 快照 持久化, auto-recovery strategies for
插桩 failures

Wraps engine/插桩.py engine/breakpoint_recovery.py

// Using registry pattern instead inheritance — less type-safe but
// avoids deep class hierarchies hurt readability
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# Frida插桩 — 钩子 script generation

class HookCategory(str, Enum):
    ANTI_DEBUG = "anti_debug"
    RETURN_MODIFY = "return_modify"
    SYSCALL_MONITOR = "syscall_monitor"
    API_TRACE = "api_trace"
    MEMORY_MONITOR = "memory_monitor"
    GENERIC_HOOK = "generic_hook"


@dataclass
class HookSpec:
    name: str
    target: str  # function name or address
    category: HookCategory
    on_enter: Optional[str] = None  # JavaScript code for onEnter
    on_leave: Optional[str] = None  # JavaScript code for onLeave
    arguments: Dict[str, Any] = field(default_factory=dict)


class FridaInstrumentation:
    """Frida-based 钩子 script template generator
    
    构造 JavaScript 钩子 scripts for Frida's interceptor API
    支持 common patterns: 反调试 bypass, 返回 value modification
    系统调用 monitoring, API 追踪, memory access monitoring
    
    Usage::
    
    frida = Frida插桩()
    script = frida.generate_钩子_script([
    frida.anti_debug_钩子("IsDebuggerPresent")
    frida.return_value_钩子("CheckRemoteDebuggerPresent", 0)
    ], output_format="javascript")
    """

    def __init__(self, device: str = "local") -> None:
        self._device = device
        self._hooks: List[HookSpec] = []

# 钩子 工厂 methods

    def anti_debug_hook(self, function_name: str) -> HookSpec:
        """创建 a 钩子 spec bypass 反调试 检查"""
        return HookSpec(
            name=f"bypass_{function_name}",
            target=function_name,
            category=HookCategory.ANTI_DEBUG,
            on_enter=f"""
    // Bypass anti-debug
    console.log("[+] {function_name} called — bypassing");
""",
            on_leave="""
    // Force return 0 (not being debugged)
    this.retval.replace(ptr(0));
""",
        )

    def return_value_hook(
        self, function_name: str, forced_value: Any
    ) -> HookSpec:
        """创建 a 钩子 spec modify a function's 返回 value"""
        return HookSpec(
            name=f"modify_ret_{function_name}",
            target=function_name,
            category=HookCategory.RETURN_MODIFY,
            on_leave=f"""
    // Force return value
    this.retval.replace(ptr({forced_value}));
    console.log("[+] {function_name} retval -> {forced_value}");
""",
        )

    def syscall_monitor_hook(
        self, syscall_number: int, log_args: bool = True
    ) -> HookSpec:
        """创建 a 钩子 spec for 系统调用 monitoring"""
        return HookSpec(
            name=f"syscall_{syscall_number}",
            target=f"syscall_{syscall_number}",
            category=HookCategory.SYSCALL_MONITOR,
            on_enter=f"""
    console.log("[*] Syscall #{syscall_number} invoked");
    if ({str(log_args).lower()}) {{
        console.log("    args: " + JSON.stringify(this.args));
    }}
""",
        )

    def api_trace_hook(self, function_name: str) -> HookSpec:
        """创建 a 钩子 spec for API调用 追踪"""
        return HookSpec(
            name=f"trace_{function_name}",
            target=function_name,
            category=HookCategory.API_TRACE,
            on_enter=f"""
    console.log("[trace] {function_name}(" + JSON.stringify(Array.prototype.slice.call(arguments)) + ")");
    this.startTime = Date.now();
""",
            on_leave="""
    var elapsed = Date.now() - this.startTime;
    console.log("[trace] returned " + this.retval + " in " + elapsed + "ms");
""",
        )

    def memory_monitor_hook(
        self, address_range: Tuple[int, int], access_type: str = "rw"
    ) -> HookSpec:
        """创建 a memory access monitoring 钩子 spec"""
        start, end = address_range
        return HookSpec(
            name=f"mem_monitor_{start:#x}_{end:#x}",
            target=f"Memory.protect(ptr({start}), {end - start}, '{access_type}')",
            category=HookCategory.MEMORY_MONITOR,
            arguments={"start": start, "end": end, "access": access_type},
        )

# Script generation

    def generate_hook_script(
        self,
        hooks: Optional[List[HookSpec]] = None,
        output_format: str = "javascript",
    ) -> str:
        """构造 a complete Frida 钩子 script a list 钩子Specs
        
        Args:
        钩子s: List 钩子 specifications. None, 使用 accumulated 钩子s
        output_format: "javascript" (Frida script) or "python" (frida-python)
        
        返回:
        A string containing complete Frida 钩子 script
        """
        if hooks is None:
            hooks = self._hooks

        if not hooks:
            return "console.log('[!] No hooks defined');"

        if output_format == "javascript":
            return self._generate_js_script(hooks)
        else:
            return self._generate_python_script(hooks)

    def _generate_js_script(self, hooks: List[HookSpec]) -> str:
        """构造 a JavaScript Frida script 钩子s"""
        lines: List[str] = [
            "// Auto-generated Frida hook script",
            f"// Generated at {time.ctime()}",
            f"// Target device: {self._device}",
            f"// {len(hooks)} hook(s) defined",
            "",
            "var moduleBase = Module.findBaseAddress(Process.enumerateModules()[0].name);",
            "console.log('[+] Module base: ' + moduleBase);",
            "",
        ]

        for hook in hooks:
            lines.append(f"// ---- {hook.name} ({hook.category.value}) ----")
            lines.append(f"Interceptor.attach(")
            lines.append(f"    Module.findExportByName(null, '{hook.target}'),")
            lines.append(f"    {{")
            if hook.on_enter:
                lines.append(f"        onEnter: function(args) {{{hook.on_enter.rstrip()}    }},")
            if hook.on_leave:
                lines.append(f"        onLeave: function(retval) {{{hook.on_leave.rstrip()}    }}")
            lines.append(f"    }}")
            lines.append(f");")
            lines.append("")

        lines.append("console.log('[+] All hooks installed');")
        return "\n".join(lines)

    def _generate_python_script(self, hooks: List[HookSpec]) -> str:
        """构造 a Python frida-python script"""
        lines: List[str] = [
            "#!/usr/bin/env python3",
            "# Auto-generated Frida instrumentation script",
            "import frida",
            "import sys",
            "",
            f"# {len(hooks)} hook(s) defined",
            "",
            "def on_message(message, data):",
            "    print(f'[*] {{message}}')",
            "",
            "js_code = '''",
        ]
        lines.append(self._generate_js_script(hooks))
        lines.extend([
            "'''",
            "",
            "def main():",
            "    if len(sys.argv) < 2:",
            "        print('Usage: {} <process name or PID>'.format(sys.argv[0]))",
            "        sys.exit(1)",
            "    target = sys.argv[1]",
            "    try:",
            "        pid = int(target)",
            "        session = frida.attach(pid)",
            "    except ValueError:",
            "        session = frida.attach(target)",
            "    script = session.create_script(js_code)",
            "    script.on('message', on_message)",
            "    script.load()",
            "    print('[+] Script loaded. Press Ctrl+C to stop.')",
            "    sys.stdin.read()",
            "    session.detach()",
            "",
            "if __name__ == '__main__':",
            "    main()",
        ])
        return "\n".join(lines)

# 钩子 management

    def add_hook(self, hook: HookSpec) -> None:
        """Add a 钩子 specification"""
        self._hooks.append(hook)

    def clear_hooks(self) -> None:
        """Remove 钩子 specifications"""
        self._hooks.clear()

    def list_hooks(self) -> List[HookSpec]:
        """List 寄存器ed 钩子s"""
        return list(self._hooks)


# 检查点Manager — 快照 持久化

class CheckpointState(str, Enum):
    INITIAL = "initial"
    RUNNING = "running"
    SAVED = "saved"
    RESTORED = "restored"
    CORRUPT = "corrupt"


@dataclass
class Checkpoint:
    checkpoint_id: str
    state: CheckpointState
    timestamp: float
    snapshot_path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None


class CheckpointManager:
    """快照 持久化 for 动态分析 state
    
    支持 保存/恢复 execution state, memory 快照s
    寄存器 files. 使用 JSON manifests 追踪 检查点 lineage
    支持 incremental diffs 检查点s
    
    Usage::
    
    cm = 检查点Manager("快照s/")
    cm.保存("after_init", {"寄存器s": {"eax": 0, "ebx": 1}})
    state = cm.恢复("after_init")
    """

    def __init__(self, snapshot_dir: str) -> None:
        self._snapshot_dir = snapshot_dir
        self._checkpoints: Dict[str, Checkpoint] = {}
        self._current: Optional[str] = None
        os.makedirs(snapshot_dir, exist_ok=True)

    def save(
        self,
        name: str,
        state_data: Dict[str, Any],
        parent: Optional[str] = None,
    ) -> Checkpoint:
        """保存 a 检查点"""
        checkpoint_id = f"{name}_{int(time.time())}"
        snapshot_path = os.path.join(self._snapshot_dir, f"{checkpoint_id}.json")
        snapshot_data = {
            "checkpoint_id": checkpoint_id,
            "name": name,
            "timestamp": time.time(),
            "state_data": state_data,
            "parent_id": parent,
        }
        try:
            with open(snapshot_path, "w") as f:
                json.dump(snapshot_data, f, indent=2)
        except OSError as e:
            log.error("Failed to save checkpoint: %s", e)
            raise

        cp = Checkpoint(
            checkpoint_id=checkpoint_id,
            state=CheckpointState.SAVED,
            timestamp=time.time(),
            snapshot_path=snapshot_path,
            metadata=state_data,
            parent_id=parent,
        )
        self._checkpoints[checkpoint_id] = cp
        self._current = checkpoint_id
        log.info("Checkpoint saved: %s -> %s", name, snapshot_path)
        return cp

    def restore(self, checkpoint_id: str) -> Dict[str, Any]:
        """恢复 a 检查点"""
        if checkpoint_id not in self._checkpoints:
            raise KeyError(f"Checkpoint not found: {checkpoint_id}")

        cp = self._checkpoints[checkpoint_id]
        try:
            with open(cp.snapshot_path, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("Failed to restore checkpoint: %s", e)
            raise

        self._current = checkpoint_id
        log.info("Checkpoint restored: %s", checkpoint_id)
        return data.get("state_data", {})

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """List saved 检查点s"""
        return [
            {
                "id": cp.checkpoint_id,
                "timestamp": cp.timestamp,
                "state": cp.state.value,
                "parent": cp.parent_id,
            }
            for cp in self._checkpoints.values()
        ]

    def delete_checkpoint(self, checkpoint_id: str) -> None:
        """删除 a 检查点 快照 file"""
        if checkpoint_id not in self._checkpoints:
            return
        cp = self._checkpoints[checkpoint_id]
        try:
            if os.path.isfile(cp.snapshot_path):
                os.remove(cp.snapshot_path)
        except OSError as e:
            log.warning("Failed to delete snapshot file: %s", e)
        del self._checkpoints[checkpoint_id]
        if self._current == checkpoint_id:
            self._current = None


# RecoveryStrategy — auto-重试, skip, rollback

class RecoveryAction(str, Enum):
    RETRY = "retry"
    SKIP = "skip"
    ROLLBACK = "rollback"
    ABORT = "abort"


@dataclass
class RecoveryDecision:
    action: RecoveryAction
    reason: str
    checkpoint_id: Optional[str] = None
    retry_after_seconds: float = 1.0
    max_retries: int = 3


class RecoveryStrategy:
    """Auto-recovery strategy for 插桩 failures
    
    插桩 fails (e.g., process crash, 钩子 conflict
    沙箱 detection), class decides whether 重试, skip
    current step, rollback a previous 检查点, or abort entirely
    
    Usage::
    
    rs = RecoveryStrategy(max_retries=3)
    for attempt range(rs.max_retries):
    try:
    run_插桩()
    break
    except 插桩Error e:
    decision = rs.on_error(e, attempt)
    decision.action == RecoveryAction.ABORT:
    raise
    """

    def __init__(self, max_retries: int = 3, checkpoint_manager: Optional[CheckpointManager] = None) -> None:
        self.max_retries = max_retries
        self._cm = checkpoint_manager
        self._error_history: List[Tuple[Exception, float]] = []

    def on_error(self, error: Exception, attempt: int) -> RecoveryDecision:
        """Decide recovery action 基于 error type attempt count"""
        self._error_history.append((error, time.time()))

        # Clean old history
        cutoff = time.time() - 300  # 5 minutes
        self._error_history = [
            (e, t) for e, t in self._error_history if t > cutoff
        ]

        # Too attempts -> skip
        if attempt >= self.max_retries:
            return RecoveryDecision(
                action=RecoveryAction.SKIP,
                reason=f"Exceeded max retries ({self.max_retries})",
            )

        # Process crash -> rollback 检查点 available, else 重试
        if "crash" in str(error).lower() or "segfault" in str(error).lower():
            if self._cm and self._cm._current:
                return RecoveryDecision(
                    action=RecoveryAction.ROLLBACK,
                    reason="Process crash detected, rolling back",
                    checkpoint_id=self._cm._current,
                )
            return RecoveryDecision(
                action=RecoveryAction.RETRY,
                reason="Process crash, retrying with backoff",
                retry_after_seconds=2.0 ** attempt,
                max_retries=self.max_retries,
            )

        # 钩子 conflict -> skip 钩子
        if "hook" in str(error).lower():
            return RecoveryDecision(
                action=RecoveryAction.SKIP,
                reason="Hook conflict detected, skipping",
            )

        # Default: 重试 exponential backoff
        return RecoveryDecision(
            action=RecoveryAction.RETRY,
            reason=str(error)[:100],
            retry_after_seconds=min(2.0 ** attempt, 60.0),
            max_retries=self.max_retries,
        )

    def should_abort(self) -> bool:
        """检查 error rate too high — abort analysis"""
        if len(self._error_history) >= 10:
            return True
        recent = [t for _, t in self._error_history if t > time.time() - 60]
        return len(recent) >= 5

    def reset(self) -> None:
        """清除 error history"""
        self._error_history.clear()
