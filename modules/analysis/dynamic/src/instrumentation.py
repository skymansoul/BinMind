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


# Frida插桩 — 钩子脚本生成

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
    on_enter: Optional[str] = None  # onEnter 回调的 JavaScript 代码
    on_leave: Optional[str] = None  # onLeave 回调的 JavaScript 代码
    arguments: Dict[str, Any] = field(default_factory=dict)


class FridaInstrumentation:

    def __init__(self, device: str = "local") -> None:
        self._device = device
        self._hooks: List[HookSpec] = []

# 钩子工厂方法

    def anti_debug_hook(self, function_name: str) -> HookSpec:
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
        start, end = address_range
        return HookSpec(
            name=f"mem_monitor_{start:#x}_{end:#x}",
            target=f"Memory.protect(ptr({start}), {end - start}, '{access_type}')",
            category=HookCategory.MEMORY_MONITOR,
            arguments={"start": start, "end": end, "access": access_type},
        )

# 脚本生成

    def generate_hook_script(
        self,
        hooks: Optional[List[HookSpec]] = None,
        output_format: str = "javascript",
    ) -> str:
        if hooks is None:
            hooks = self._hooks

        if not hooks:
            return "console.log('[!] No hooks defined');"

        if output_format == "javascript":
            return self._generate_js_script(hooks)
        else:
            return self._generate_python_script(hooks)

    def _generate_js_script(self, hooks: List[HookSpec]) -> str:
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

# 钩子管理

    def add_hook(self, hook: HookSpec) -> None:
        self._hooks.append(hook)

    def clear_hooks(self) -> None:
        self._hooks.clear()

    def list_hooks(self) -> List[HookSpec]:
        return list(self._hooks)


# 检查点管理器 — 快照持久化

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


# 恢复策略 — 自动重试、跳过、回滚

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

    def __init__(self, max_retries: int = 3, checkpoint_manager: Optional[CheckpointManager] = None) -> None:
        self.max_retries = max_retries
        self._cm = checkpoint_manager
        self._error_history: List[Tuple[Exception, float]] = []

    def on_error(self, error: Exception, attempt: int) -> RecoveryDecision:
        self._error_history.append((error, time.time()))

        # 清理过期错误历史
        cutoff = time.time() - 300  # 5 minutes
        self._error_history = [
            (e, t) for e, t in self._error_history if t > cutoff
        ]

        # 超过最大重试次数则跳过
        if attempt >= self.max_retries:
            return RecoveryDecision(
                action=RecoveryAction.SKIP,
                reason=f"Exceeded max retries ({self.max_retries})",
            )

        # 进程崩溃：有可用检查点则回滚，否则重试
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

        # 钩子冲突：跳过当前钩子
        if "hook" in str(error).lower():
            return RecoveryDecision(
                action=RecoveryAction.SKIP,
                reason="Hook conflict detected, skipping",
            )

        # 默认：指数退避重试
        return RecoveryDecision(
            action=RecoveryAction.RETRY,
            reason=str(error)[:100],
            retry_after_seconds=min(2.0 ** attempt, 60.0),
            max_retries=self.max_retries,
        )

    def should_abort(self) -> bool:
        if len(self._error_history) >= 10:
            return True
        recent = [t for _, t in self._error_history if t > time.time() - 60]
        return len(recent) >= 5

    def reset(self) -> None:
        self._error_history.clear()
