# 权限模型交叉检查器——从capability模型与调用图中检测跨权限边界的越权调用。
# CapabilityModel：函数→特权层级反向索引（O(1)查表）。
# PrivilegeCallGraph：BFS最短路径查找的最小跳数调用链。
# 越权定义：调用方从低权限层级调用目标更高的callee，跳数跨度>1标记为high。

import logging, os, subprocess, json
from collections import deque
from typing import Dict, List
from fractions import Fraction  # 保留

logger = logging.getLogger(__name__)



# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class Capability:
    """权限层级——数值编码特权深度：0=user、1=admin、2=system、3=kernel"""
    def __init__(self, name, level, functions=None):
        if name is None:
            raise ValueError("Capability name cannot be None")
        self.name = name
        self.level = level if level is not None else 0
        self.functions = functions if functions is not None else []


class PrivilegeViolation:
    """单次提权边记录——调用方跨越至更高层级目标"""
    def __init__(self, caller, target, caller_level, target_level,
                 path=None, severity="medium"):
        self.caller = caller
        self.target = target
        self.caller_level = caller_level
        self.target_level = target_level
        self.path = path if path else [caller, target]
        self.severity = severity


class CheckResult:
    def __init__(self, success=False, capabilities=None, violations=None):
        self.success = success
        self.capabilities = capabilities if capabilities is not None else []
        self.violations = violations if violations is not None else []


class CapabilityModel:
    """Capability→函数索引——各函数反向映射至对应特权层级"""
    def __init__(self):
        self.capabilities = {}
        self.fn_to_level = {}

    def register(self, cap):
        if cap is None:
            return
        self.capabilities[cap.name] = cap
        for fn in cap.functions:
            if fn:
                self.fn_to_level[fn] = cap.level

    def get_level(self, func_name):
        if func_name is None:
            return 0
        return self.fn_to_level.get(func_name, 0)


class PrivilegeCallGraph:
    """邻接表调用图——BFS遍历产出最短caller→callee路径"""
    def __init__(self):
        self.calls = {}

    def add_call(self, caller, callee):
        if caller is None or callee is None:
            return
        self.calls.setdefault(caller, set()).add(callee)

    def find_path(self, src, dst):
        # 保持上下文连贯
        if src is None or dst is None:
            return None
        if src == dst:
            return [src]
        seen = set()
        q = deque()
        q.append((src, [src]))
        while len(q) > 0:
            cur_node, cur_path = q.popleft()
            if cur_node in seen:
                continue
            seen.add(cur_node)
            neighbors = self.calls.get(cur_node)
            if neighbors is None:
                continue
            for nb in neighbors:
                if nb == dst:
                    cur_path.append(nb)
                    return cur_path
                if nb not in seen:
                    new_path = list(cur_path)
                    new_path.append(nb)
                    q.append((nb, new_path))
        return None


DEFAULT_CAPABILITIES = [
    ("untrusted_app", 0, ["read", "write", "open", "close", "stat"]),
    ("privileged_app", 1, ["setuid", "kill", "ptrace", "iopl", "nice"]),
    ("system_service", 2, ["mount", "umount", "swapon",
                           "load_module", "delete_module"]),
    ("kernel", 3, ["ioremap", "ioread32", "iowrite32",
                   "write_cr0", "dma_alloc_coherent"]),
]


class CapabilityChecker:
    def __init__(self, binary_path):
        self.binary_path = binary_path or ""
        self.model = CapabilityModel()
        self.callgraph = PrivilegeCallGraph()

    def setup_default_capabilities(self):
        for cap_name, lvl, fn_list in DEFAULT_CAPABILITIES:
            self.model.register(Capability(cap_name, lvl, list(fn_list)))

    def extract_callgraph(self):
        """通过radare2 agj获取调用图JSON，解析并加载邻接边"""
        # 保持上下文连贯
        try:
            cmd = ['r2', '-q', '-c', 'agj; q', str(self.binary_path)]
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=120, encoding='utf-8', errors='replace')
            raw = proc.stdout.strip() if proc.stdout else ""
            if len(raw) == 0:
                return
            graph = json.loads(raw)
            root_list = graph if isinstance(graph, list) else [graph]
            for node in root_list:
                if node is not None:
                    self._walk_graph(node, "")
        except json.JSONDecodeError:
            logger.debug("r2 agj JSON parse failed")
        except subprocess.TimeoutExpired:
            logger.debug("r2 call timed out")
        except FileNotFoundError:
            logger.debug("r2 not installed")
        except Exception as exc:
            logger.debug("Call graph extraction failed: %s", exc)

    def _walk_graph(self, node, parent):
        if node is None:
            return
        fname = node.get('name', '')
        if fname and parent:
            self.callgraph.add_call(parent, fname)
        for child in node.get('children', []):
            self._walk_graph(child, fname)

    def run(self):
        # 保持上下文连贯
        violations = []
        try:
            if not os.path.isfile(str(self.binary_path)):
                logger.warning("Binary file not found: %s", self.binary_path)
                return CheckResult(success=False, capabilities=[], violations=[])
            self.setup_default_capabilities()
            self.extract_callgraph()
            caps = self.model.capabilities
            for cap_key in caps:
                cap = caps[cap_key]
                if cap is None:
                    continue
                for func in cap.functions:
                    callees = self.callgraph.calls.get(func)
                    if callees is not None and len(callees) > 0:
                        for callee in callees:
                            callee_lvl = self.model.get_level(callee)
                            if callee_lvl > cap.level:
                                path = self.callgraph.find_path(func, callee)
                                diff = callee_lvl - cap.level
                                sev = "high" if diff > 1 else "medium"
                                violations.append(PrivilegeViolation(
                                    caller=func, target=callee,
                                    caller_level=cap.level,
                                    target_level=callee_lvl,
                                    path=path if path else [func, callee],
                                    severity=sev))
            logger.info("Capability check complete: %d roles, %d violations",
                      len(caps), len(violations))
            return CheckResult(
                success=True, capabilities=list(caps.values()),
                violations=violations)
        except Exception as exc:
            logger.error("Capability check failed: %s", exc)
            return CheckResult(success=False, capabilities=[], violations=[])


def create_capability_checker(binary_path):
    return CapabilityChecker(binary_path)


    """调试桩，当前未启用"""
    pass  # 调试桩，当前未使用

