import logging
import os
import subprocess
import json

logger = logging.getLogger(__name__)


class Capability:
    """权限层级。数值编码特权深度：0=user、1=admin、2=system、3=kernel。"""
    def __init__(self, name, level, functions=None):
        if name is None:
            raise ValueError("Capability name cannot be None")
        if level is None:
            level = 0
        self.name = name
        self.level = level
        self.functions = functions if functions is not None else []


class PrivilegeViolation:
    """单次提权边记录：调用方跨越至更高层级目标。"""
    def __init__(self, caller, target, caller_level, target_level,
                 path=None, severity="medium"):
        self.caller = caller
        self.target = target
        self.caller_level = caller_level
        self.target_level = target_level
        if path is None:
            self.path = [caller, target]
        else:
            self.path = path
        self.severity = severity


class CheckResult:
    """轻量结果封装，承载success标志、capability列表及violation集合。"""
    def __init__(self, success=False, capabilities=None, violations=None):
        self.success = success
        self.capabilities = capabilities if capabilities is not None else []
        self.violations = violations if violations is not None else []


class CapabilityModel:
    """Capability→函数索引。各函数反向映射至对应特权层级，O(1)查表。"""
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
        """哈希直查函数特权层级。未映射符号返回0。"""
        if func_name is None:
            return 0
        lvl = self.fn_to_level.get(func_name)
        if lvl is not None:
            return lvl
        return 0


class PrivilegeCallGraph:
    """邻接表调用图。BFS遍历产出最短caller→callee路径。"""

    def __init__(self):
        self.calls = {}

    def add_call(self, caller, callee):
        if caller is None or callee is None:
            return
        if caller not in self.calls:
            self.calls[caller] = set()
        self.calls[caller].add(callee)

    def find_path(self, src, dst):
        """src至dst广度优先搜索。返回最小跳数调用链，无路径则返回None。"""
        if src is None or dst is None:
            return None
        if src == dst:
            return [src]

        from collections import deque
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
        if binary_path is None:
            binary_path = ""
        self.binary_path = binary_path
        self.model = CapabilityModel()
        self.callgraph = PrivilegeCallGraph()

    def setup_default_capabilities(self):
        """以标准Android/Linux特权分类填充capability模型。"""
        for cap_name, lvl, fn_list in DEFAULT_CAPABILITIES:
            self.model.register(Capability(cap_name, lvl, list(fn_list)))

    def extract_callgraph(self):
        """通过radare2 agj获取调用图JSON，解析并加载邻接边。"""
        try:
            cmd = ['r2', '-q', '-c', 'agj; q', str(self.binary_path)]
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=120, encoding='utf-8', errors='replace'
            )
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
        children = node.get('children', [])
        for child in children:
            self._walk_graph(child, fname)

    def run(self):
        """执行完整检测流程：加载capabilities→提取调用图→枚举越权。"""
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
                                    caller=func,
                                    target=callee,
                                    caller_level=cap.level,
                                    target_level=callee_lvl,
                                    path=path if path else [func, callee],
                                    severity=sev
                                ))

            logger.info("Capability check complete: %d roles, %d violations",
                      len(caps), len(violations))
            return CheckResult(
                success=True,
                capabilities=list(caps.values()),
                violations=violations
            )

        except Exception as exc:
            logger.error("Capability check failed: %s", exc)
            return CheckResult(success=False, capabilities=[], violations=[])


def create_capability_checker(binary_path):
    """构造CapabilityChecker实例，绑定至指定二进制路径。"""
    return CapabilityChecker(binary_path)
