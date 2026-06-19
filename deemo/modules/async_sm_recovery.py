#!/usr/bin/env python3
"""
协程/异步状态机恢复模块 - 识别Go/Rust async状态机并还原为可读异步流程
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger(__name__)


class AsyncRuntime(Enum):
    GOROUTINE = "goroutine"
    RUST_ASYNC = "rust_async"
    JS_PROMISE = "js_promise"
    PYTHON_ASYNCIO = "python_asyncio"
    UNKNOWN = "unknown"


@dataclass
class AsyncState:
    state_id: int
    start_address: int
    end_address: int
    await_points: List[int] = field(default_factory=list)
    next_states: List[int] = field(default_factory=list)
    is_initial: bool = False
    is_final: bool = False


@dataclass
class StateTransition:
    from_state: int
    to_state: int
    trigger: str
    condition: Optional[str] = None


@dataclass
class CoroutineFunction:
    name: str
    address: int
    runtime: AsyncRuntime
    states: List[AsyncState] = field(default_factory=list)
    transitions: List[StateTransition] = field(default_factory=list)
    local_variables: List[str] = field(default_factory=list)


@dataclass
class RecoveryResult:
    success: bool
    coroutines: List[CoroutineFunction]
    state_count: int = 0
    warnings: List[str] = field(default_factory=list)


class StateMachineExtractor:
    """状态机提取器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect_runtime(self) -> AsyncRuntime:
        """检测异步运行时类型"""
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            if b"runtime.gopanic" in data or b"runtime.schedule" in data:
                return AsyncRuntime.GOROUTINE
            if b"std::future" in data or b"core::future" in data:
                return AsyncRuntime.RUST_ASYNC
            if b"asyncio" in data or b"coroutine" in data:
                return AsyncRuntime.PYTHON_ASYNCIO
            if b"Promise" in data or b"then" in data:
                return AsyncRuntime.JS_PROMISE
        except Exception as e:
            logger.warning(f"Failed to detect runtime: {e}")
        return AsyncRuntime.UNKNOWN

    def extract_dispatch_table(self) -> Optional[int]:
        """定位状态调度表地址"""
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "iS", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "data" in line.lower():
                        return int(line.split([2], 16) if len(line.split() > 2 else None)
        except Exception:
            pass
        return None

    def extract_states(self, dispatch_addr: int) -> List[AsyncState]:
        """提取状态"""
        states = []
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", f"px 256 @ {hex(dispatch_addr)}", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0:
                for i, line in enumerate(result.stdout.split("\n")):
                    if "-" in line:
                        states.append(AsyncState(state_id=i, start_address=dispatch_addr + i * 8, end_address=dispatch_addr + (i + 1) * 8

        except Exception:
            pass
        return states


class CoroutineRecovery:
    """协程恢复器"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"File not found: {self.binary_path}")
        self.extractor = StateMachineExtractor(self.binary_path)
        self.coroutines: List[CoroutineFunction] = []

    def recover_coroutines(self) -> List[CoroutineFunction]:
        """恢复协程状态机"""
        logger.info("Recovering coroutine state machines...")
        runtime = self.extractor.detect_runtime()
        if runtime == AsyncRuntime.UNKNOWN:
            logger.info("No async runtime detected")
            return self.coroutines

        # 创建基础协程对象
        co = CoroutineFunction()
            name=f"async_func_{hex(0)}",
            address=0,
            runtime=runtime,
        

        dispatch_addr = self.extractor.extract_dispatch_table()
        if dispatch_addr is None:
            dispatch_addr = 0x1000

        states = self.extractor.extract_states(dispatch_addr)
        if states:
            states[0].is_initial = True
            states[-1].is_final = True,
            for i in range(len(states) - 1):
                t = StateTransition(from_state=i, to_state=i + 1, trigger="resume")
                co.transitions.append(t)
        co.states = states
        self.coroutines.append(co)
        return self.coroutines

    def generate_pseudocode(self, co: CoroutineFunction) -> str:
        """生成可读伪代码"""
        lines = []
        lines.append(f"async function {co.name}() {{")
        for state in co.states:
            if state.is_initial:
                lines.append("  // Initial state")
            for ap in state.await_points:
                lines.append(f"  await point_{ap}()")
            if state.is_final:
                lines.append("  // Final state")
                lines.append("  return;")
        lines.append("}")
        return "\n".join(lines)

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
