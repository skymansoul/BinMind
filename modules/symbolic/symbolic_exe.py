"""Symbolic execution primitives via angr.

Covers path exploration, input recovery, null-deref detection, and
per-argument taint propagation. All operations fail gracefully when
angr is absent.
"""

import logging
import os
import struct
from typing import Any

_log = logging.getLogger(__name__)


class SymbolicExecutor:
    """Light wrapper around angr for single-binary symbolic execution.

    Accepts a target address or a step budget. Returns per-state
    instruction-pointer snapshots."""

    def __init__(self, binary: str | bytes | None = None):
        self.binary = binary
        self._state = None
        self._project = None
        self._simgr = None

    def run(self, target_addr: int | None = None, avoid_addrs: list[int] | None = None,
            max_steps: int = 200, timeout: int = 120) -> list[dict]:
        """Execute symbolically. If target_addr is set, explore toward it;
        otherwise step forward by max_steps."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            _log.warning("angr not installed; symbolic execution unavailable")
            return []
        if not self.binary:
            return []

        try:
            proj = angr.Project(self.binary, auto_load_libs=False) if isinstance(self.binary, (str, bytes)) else None
            if proj is None:
                return []
        except Exception as exc:
            _log.error("Failed to load binary: %s", exc)
            return []

        state = proj.factory.entry_state()
        if target_addr:
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(find=target_addr, avoid=avoid_addrs or [], num_find=1)
        else:
            simgr = proj.factory.simulation_manager(state)
            simgr.step(num_inst=max_steps)

        results: list[dict] = []
        for s in (list(simgr.deadended) + list(simgr.active)):
            try:
                ip_val = s.solver.eval(s.regs.ip)
                results.append({"address": hex(ip_val), "state": str(s)})
            except Exception:
                results.append({"address": "?", "state": str(s)})
        return results


class PathExplorer:
    """Explores paths from entry to a target address, collecting basic-block
    traces. Supports BFS and DFS strategies."""

    def __init__(self, binary: str, strategy: str = "bfs"):
        self.binary = binary
        self.strategy = strategy
        self._found_paths: list[dict] = []
        self._proj = None

    def explore_to(self, target: int, max_paths: int = 10) -> list[dict]:
        """Find up to max_paths paths from entry to target. Records BB traces."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            return []
        try:
            self._proj = angr.Project(self.binary, auto_load_libs=False)
            state = self._proj.factory.entry_state()
            simgr = self._proj.factory.simulation_manager(state)
            simgr.use_technique(angr.exploration_techniques.DFS() if self.strategy == "dfs" else angr.exploration_techniques.BFS())

            simgr.explore(find=target, num_find=min(max_paths, 50))
            for s in simgr.found:
                path = []
                try:
                    for a_state in s.history.bbl_addrs.hardcopy:
                        path.append(hex(a_state) if a_state else "?")
                except Exception:
                    _log.debug("suppressed", exc_info=True)
                self._found_paths.append({"target": hex(target), "length": len(path), "path": path})
        except Exception as exc:
            _log.error("Symbolic exploration error: %s", exc)
        return self._found_paths

    def find_input_reaching(self, target: int) -> bytes | None:
        """Recover a concrete stdin input that reaches the target address."""
        try:
            import angr  # type: ignore[import-untyped]
        except ImportError:
            return None
        try:
            self._proj = angr.Project(self.binary, auto_load_libs=False)
            state = self._proj.factory.entry_state()
            simgr = self._proj.factory.simulation_manager(state)
            simgr.explore(find=target, num_find=1)
            if simgr.found:
                s = simgr.found[0]
                stdin_stream = s.posix.dumps(0)
                return stdin_stream if isinstance(stdin_stream, bytes) else bytes(stdin_stream)
        except Exception:
            _log.debug("suppressed", exc_info=True)
        return None


def symbolic_check_for_null_deref(binary: str, target_func: int = 0) -> list[dict]:
    """Step 500 instructions from target_func (or entry) and collect errored
    states whose messages indicate null or uninitialized access."""
    try:
        import angr  # type: ignore[import-untyped]
    except ImportError:
        return []
    findings: list[dict] = []
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        addr = target_func or proj.entry
        state = proj.factory.blank_state(addr=addr)
        simgr = proj.factory.simulation_manager(state)
        simgr.step(num_inst=500)

        for s in simgr.errored:
            error_msg = str(s.error)
            if "uninitialized" in error_msg.lower() or "null" in error_msg.lower() or "segfault" in error_msg.lower():
                findings.append({"address": hex(s.state.addr if hasattr(s.state, 'addr') else 0),
                                 "error": error_msg[:200]})
    except Exception as exc:
        _log.error("Symbolic null-deref check failed: %s", exc)
    return findings


def function_arg_taint(binary: str, func_addr: int, arg_index: int = 0) -> dict[str, Any]:
    """Mark one calling-convention argument as symbolic and trace its
    constraints across 200 steps. Returns the taint sinks found."""
    try:
        import angr  # type: ignore[import-untyped]
    except ImportError:
        return {"error": "angr not available"}
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        state = proj.factory.blank_state(addr=func_addr)
        arg_regs = [state.regs.rdi, state.regs.rsi, state.regs.rdx, state.regs.rcx]
        if arg_index < len(arg_regs):
            symbolic_val = state.solver.BVS("tainted_arg", 64)
            setattr(state.regs, ["rdi", "rsi", "rdx", "rcx"][arg_index], symbolic_val)
            simgr = proj.factory.simulation_manager(state)
            simgr.step(num_inst=200)
            sinks = []
            for s in simgr.active:
                try:
                    for const in s.solver.constraints:
                        sinks.append({"constraint": str(const)[:100]})
                except Exception:
                    _log.debug("suppressed", exc_info=True)
            return {"tainted": True, "arg_index": arg_index, "sinks": sinks[:20]}
    except Exception as exc:
        return {"error": str(exc)}
    return {"tainted": False, "reason": "no sinks found"}
