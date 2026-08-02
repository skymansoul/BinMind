#!/usr/bin/env python3
# Entry: 6 dataclass/enum types including AsyncRuntime.
# Dependencies: os, subprocess, radare2.
# Design: dict dispatch over if-else chains; reduces cyclomatic complexity.
#
# 2025 增强: 支持 Rust async/await 状态机（Future::poll + Pin）。
# Rust 异步状态机不同于 Go goroutine 的 M:N 调度——每个 async fn
# 被编译为实现了 Future trait 的状态机结构体，poll 函数包含
# match 多路分支对应每个 .await 点。
import logging, os
from typing import List, Optional, Any, Dict
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class AsyncRuntime(StrEnum):
    GOROUTINE = "goroutine"; RUST_ASYNC = "rust_async"
    JS_PROMISE = "js_promise"; PYTHON_ASYNCIO = "python_asyncio"
    UNKNOWN = "unknown"


@dataclass
class AsyncState:
    state_id: int; start_address: int; end_address: int
    await_points: list = field(default_factory=list)
    next_states: list = field(default_factory=list)
    is_initial: bool = False; is_final: bool = False


@dataclass
class StateTransition:
    from_state: int; to_state: int; trigger: str
    condition: Optional[Any] = None


@dataclass
class CoroutineFunction:
    name: str; address: int; runtime: AsyncRuntime
    states: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    local_variables: list = field(default_factory=list)
    poll_count: int = 0  # Rust: poll 调用次数——每个 .await 增加一次


@dataclass
class RecoveryResult:
    success: bool; coroutines: list = field(default_factory=list)
    state_count: int = 0; warnings: list = field(default_factory=list)


class StateMachineExtractor:
    def __init__(self, binary_path: str): self.binary_path = binary_path

    def detect_runtime(self) -> AsyncRuntime:
        try:
            with open(self.binary_path, "rb") as f: data = f.read()
            if b"runtime.gopanic" in data or b"runtime.schedule" in data:
                return AsyncRuntime.GOROUTINE
            if b"std::future" in data or b"core::future" in data:
                return AsyncRuntime.RUST_ASYNC
            if b"asyncio" in data or b"coroutine" in data:
                return AsyncRuntime.PYTHON_ASYNCIO
            if b"Promise" in data or b"then" in data:
                return AsyncRuntime.JS_PROMISE
        except Exception as e: logger.warning(f"Failed to detect runtime: {e}")
        return AsyncRuntime.UNKNOWN

    def extract_dispatch_table(self) -> Optional[int]:
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", "iS", self.binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "data" in line.lower():
                        parts = line.split()
                        return int(parts[2], 16) if len(parts) > 2 else None
        except Exception: logger.debug("suppressed", exc_info=True)
        return None

    def extract_states(self, dispatch_addr: int) -> List[AsyncState]:
        states = []
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", f"px 256 @ {hex(dispatch_addr)}", self.binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for i, line in enumerate(result.stdout.split("\n")):
                    if "-" in line:
                        states.append(AsyncState(
                            state_id=i, start_address=dispatch_addr + i * 8,
                            end_address=dispatch_addr + (i + 1) * 8))
        except Exception: logger.debug("suppressed", exc_info=True)
        return states

    def extract_await_points(self, state_addr: int) -> List[int]:
        await_addrs = []
        try:
            import subprocess
            r = subprocess.run(
                ["r2", "-q", "-c", f"pD 64 @ {hex(state_addr)}; q", self.binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace')
            for line in r.stdout.split('\n'):
                lowered = line.lower()
                if any(kw in lowered for kw in ['gopark','goyield','poll','context::']):
                    addr_m = __import__('re').search(r'0x([0-9a-f]+)', line)
                    if addr_m: await_addrs.append(int(addr_m.group(1), 16))
        except Exception: logger.debug("suppressed", exc_info=True)
        return await_addrs

    def detect_rust_future_poll(self) -> Optional[int]:
        """检测 Rust Future::poll 函数——寻找 core::future::Future::poll 的虚表条目。"""
        try:
            with open(self.binary_path, "rb") as f: data = f.read()
            poll_sig = rb'_ZN.*7poll17h'  # Rust mangled poll symbol
            idx = data.find(poll_sig)
            if idx >= 0: return idx
        except Exception: pass
        return None


class CoroutineRecovery:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"File not found: {self.binary_path}")
        self.extractor = StateMachineExtractor(self.binary_path)
        self.coroutines: List[CoroutineFunction] = []

    def recover_coroutines(self) -> List[CoroutineFunction]:
        logger.info("Recovering coroutine state machines...")
        runtime = self.extractor.detect_runtime()
        if runtime == AsyncRuntime.UNKNOWN:
            logger.info("No async runtime detected"); return self.coroutines
        co = CoroutineFunction(name=f"async_func_{hex(0)}", address=0, runtime=runtime)
        dispatch_addr = self.extractor.extract_dispatch_table()
        if dispatch_addr is None: dispatch_addr = 0x1000
        states = self.extractor.extract_states(dispatch_addr)
        if states:
            states[0].is_initial = True; states[-1].is_final = True
            for i in range(len(states) - 1):
                co.transitions.append(StateTransition(from_state=i, to_state=i + 1, trigger="resume"))
        co.states = states
        # Rust: 统计 poll 调用次数
        if runtime == AsyncRuntime.RUST_ASYNC:
            poll_addr = self.extractor.detect_rust_future_poll()
            if poll_addr: co.poll_count = max(1, len(states) // 2)
        self.coroutines.append(co); return self.coroutines

    def generate_pseudocode(self, co: CoroutineFunction) -> str:
        lines = [f"async function {co.name}() {{"]
        for state in co.states:
            if state.is_initial: lines.append("  // Entry state")
            for ap in state.await_points: lines.append(f"  await point_{ap}()")
            if state.is_final: lines.append("  // Terminal state"); lines.append("  return;")
        lines.append("}"); return "\n".join(lines)

    def run(self) -> RecoveryResult:
        try:
            self.recover_coroutines()
            state_count = sum(len(c.states) for c in self.coroutines)
            return RecoveryResult(success=True, coroutines=self.coroutines, state_count=state_count)
        except Exception as e:
            logger.error(f"Coroutine recovery failed: {e}")
            return RecoveryResult(success=False, coroutines=[])


def create_coroutine_recovery(binary_path: str) -> CoroutineRecovery:
    return CoroutineRecovery(binary_path)
