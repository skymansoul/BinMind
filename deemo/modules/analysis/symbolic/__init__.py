# symbolic - symbolic & concolic execution engine

__version__ = "0.11.0"

import json
import os
import time
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

_submodules = {
    "concolic_execution": ".concolic_execution",
    "constraint_cache_persistence": ".constraint_cache_persistence",
    "constraint_solver_manager": ".constraint_solver_manager",
    "coverage_guided_symbex": ".coverage_guided_symbex",
    "distributed_symbex": ".distributed_symbex",
    "distributed_symbolic_executor": ".distributed_symbolic_executor",
    "incremental_symbex": ".incremental_symbex",
    "on_demand_symbolic": ".on_demand_symbolic",
    "path_diversity": ".path_diversity",
    "solver_pool": ".solver_pool",
    "symbex_fuzz_coop": ".symbex_fuzz_coop",
    "symbex_mapreduce": ".symbex_mapreduce",
    "symbolic_analysis": ".symbolic_analysis",
    "symbolic_exe": ".symbolic_exe",
    "symbolic_path_merge": ".symbolic_path_merge",
    "symbolic_scheduler": ".symbolic_scheduler",
    "symexec_optimizer": ".symexec_optimizer",
}

# 四轮增强 - LazyImportProfiler：惰性导入计时器
#
# 包装 __getattr__，在首次访问每个子模块时记录 import 耗时至毫秒级
# 累计所有子模块后，__import_profile_report() 按耗时降序输出报告
# 帮助定位减慢包初始化速度的模块
#
# 设计决策 - 使用模块级别的 _import_times 字典替代 class-level 属性
# 避免在 __getattr__ 中引入额外对象分配

_import_times: dict = {}
_import_lock = None  # 延迟初始化，避免循环导入


def _get_import_lock():
    """Lazy-init threading lock for import 性能分析"""
    global _import_lock
    if _import_lock is None:
        import threading
        _import_lock = threading.Lock()
    return _import_lock


def __getattr__(name):
    if name in _submodules:
        import importlib

        # 四轮增强 - 惰性导入计时
        t0 = time.perf_counter()
        try:
            mod = importlib.import_module(_submodules[name], package=__package__)
        finally:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            with _get_import_lock():
                if name not in _import_times:
                    _import_times[name] = elapsed_ms

        return mod

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def import_profile_report() -> str:
    """Emit a formatted 报告 import times per submodule

    在首次访问所有子模块后调用（或按需调用），按耗时降序排列
    标识拖慢包初始化速度的瓶颈模块

    返回:
    Multiline string sorted import timing 报告
    """
    if not _import_times:
        return "[LazyImportProfiler] No modules imported yet."

    with _get_import_lock():
        entries = sorted(_import_times.items(), key=lambda x: x[1], reverse=True)

    total_ms = sum(v for _, v in entries)
    lines = []
    lines.append("=" * 70)
    lines.append(f"  LazyImportProfiler - {len(entries)} modules, "
                 f"{total_ms:.1f}ms total import time")
    lines.append("=" * 70)
    lines.append(f"  {'Module':<38} {'Time (ms)':>10} {'%':>8}")
    lines.append("-" * 70)
    for mod_name, elapsed_ms in entries:
        pct = (elapsed_ms / max(0.001, total_ms)) * 100
        lines.append(f"  {mod_name:<38} {elapsed_ms:>10.2f} {pct:>7.1f}%")
    lines.append("=" * 70)

    report = "\n".join(lines)
    return report


# 模块注册表：自动扫描各子模块的 __doc__ 和健康检查函数，构建
# mod_registry 字典（mod_name → {version, description, has_health_check}）
#
# 意图 - 无需手动维护模块元数据；每个子模块的文档字符串和函数签名
# 即为权威注册信息源

_mod_registry = None  # 延迟初始化，避免循环导入


def _build_mod_registry() -> dict:
    """Scan submodule once, extracting docstring summary health
    function presence. Result is缓存d ``_mod_registry``"""
    registry = {}
    for mod_name, mod_path in _submodules.items():
        try:
            import importlib
            mod = importlib.import_module(mod_path, package=__package__)
        except Exception:
            # 模块不可用 -- 仍然登记，标记为不可用
            registry[mod_name] = {
                "version": "unknown",
                "description": "(import failed)",
                "has_health_check": False,
            }
            continue

        # 提取 __doc__ 首行作为描述
        doc = getattr(mod, "__doc__", None)
        if doc and isinstance(doc, str):
            desc = doc.strip().split("\n")[0].strip()
        else:
            desc = "(no docstring)"

        # 检测是否存在健康检查相关函数
        has_hc = False
        for attr in ("health_check", "check", "validate", "status", "ping"):
            candidate = getattr(mod, attr, None)
            if callable(candidate):
                has_hc = True
                break

        # 版本号优先取模块的 __version__，否则用包的版本
        version = getattr(mod, "__version__", __version__)

        registry[mod_name] = {
            "version": version,
            "description": desc,
            "has_health_check": has_hc,
        }

    return registry


def get_mod_registry() -> dict:
    """返回 auto-populated module registry

    Lazily built first call;缓存d thereafter

    返回:
    ``mod_registry`` dict keyed module name, value containing
    ``version``, ``description``, ``has_health_check``
    """
    global _mod_registry
    if _mod_registry is None:
        _mod_registry = _build_mod_registry()
    return _mod_registry


# 插件加载器：通过 importlib.metadata.entry_points 发现 入口 组
# 'symbolic_plugins' 中注册的第三方插件，并在首次访问时自动加载
#
# plugin_eps 为原始 EntryPoint 列表；已加载的插件对象缓存在 _loaded_plugins 中
# 设计意图 - 与 pip 生态无缝集成，第三方包在 setup.cfg / pyproject.toml 中
# 声明 [project.entry-points."symbolic_plugins"] 即可被自动发现和注册

_plugin_eps = None
_loaded_plugins: list = []


class PluginLoader:
    """Discovers 寄存器s plugins via ``symbolic_plugins`` 入口 group

    Usage::

    加载器 = Plugin加载器()
    加载器.discover()
    for name, plugin 加载器.plugins.items():
    print(f"Loaded: {name}")
    """

    def __init__(self):
        self.plugins: Dict[str, Any] = {}

    def discover(self) -> Dict[str, Any]:
        """Scan ``importlib.metadata.entry_points`` for group
        ``symbolic_plugins``, 加载 入口, 寄存器

        返回:
        Dict plugin name → loaded plugin object
        """
        global _plugin_eps
        try:
            from importlib.metadata import entry_points
        except ImportError:
            # Python < 3.10 回退
            try:
                from importlib_metadata import entry_points
            except ImportError:
                return {}

        eps = entry_points()
        # entry_points() 返回值因 Python 版本而异：3.12+ 返回
        # EntryPoints 集合；3.10-3.11 返回 dict；均支持 group 过滤
        try:
            _plugin_eps = eps.select(group="symbolic_plugins")
        except AttributeError:
            # 兼容旧式 dict 接口
            _plugin_eps = eps.get("symbolic_plugins", [])

        for ep in _plugin_eps:
            try:
                plugin_obj = ep.load()
                self.plugins[ep.name] = plugin_obj
                _loaded_plugins.append(plugin_obj)
            except Exception as e:
                import logging
                _log = logging.getLogger(__name__)
                _log.warning(
                    f"Failed to load symbolic_plugins entry point {ep.name}: {e}"
                )

        return self.plugins


# 包导入时自动发现插件
_auto_loader = PluginLoader()
_auto_loader.discover()


# 四轮增强 - QuickBench：微基准测试套件
#
# 由环境变量 SYMBEX_RUN_BENCH=1 控制，在包导入时运行一组轻量级测试：
#   1. Z3 求解器基准：100 个平凡约束的平均求解时间
#   2. r2 启动时间：调用 subprocess 测量启动延迟
#   3. 子模块导入延迟：按 LazyImportProfiler 统计
#
# 结果缓存至 JSON 文件（默认 ~/.symbex_bench_cache.json），后续导入
# 直接读取缓存而不重新执行基准
#
# 设计意图 - 部署前自检：比较当前环境与基准环境的求解器/工具性能；
# 帮助诊断 CI worker 性能退化

_QUICKBENCH_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".symbex_bench_cache.json"
)
_QUICKBENCH_CACHE_TTL = 86400  # 24 小时


def _run_quickbench() -> dict:
    """执行 micro基准测试 suite

    仅在 SYMBEX_RUN_BENCH=1 且缓存过期或不存在时执行
    返回包含各项基准结果的字典
    """
    # 检查缓存
    if os.path.exists(_QUICKBENCH_CACHE_PATH):
        try:
            with open(_QUICKBENCH_CACHE_PATH, 'r', encoding='utf-8') as f:
                cached = json.load(f)
            cache_age = time.time() - cached.get('timestamp', 0)
            if cache_age < _QUICKBENCH_CACHE_TTL:
                return cached
        except (json.JSONDecodeError, KeyError):
            pass  # 缓存损坏，重新执行

    bench_result: Dict[str, Any] = {
        'version': __version__,
        'timestamp': time.time(),
        'z3_solve_time_ms': None,
        'z3_solve_count': 100,
        'r2_startup_ms': None,
        'submodule_import_times': {},
    }

# Z3 平凡约束基准
    try:
        import z3
        z3_times = []
        x = z3.Int('x')
        for i in range(100):
            solver = z3.Solver()
            solver.add(x > 0)
            solver.add(x < i + 2)
            t0 = time.perf_counter()
            solver.check()
            elapsed_ms = (time.perf_counter() - t0) * 1000
            z3_times.append(elapsed_ms)
        bench_result['z3_solve_time_ms'] = round(sum(z3_times) / len(z3_times), 3)
        bench_result['z3_solve_min_ms'] = round(min(z3_times), 3)
        bench_result['z3_solve_max_ms'] = round(max(z3_times), 3)
    except ImportError:
        bench_result['z3_solve_time_ms'] = None
    except Exception as e:
        bench_result['z3_error'] = str(e)

# r2 启动时间
    try:
        import subprocess
        r2_times = []
        for _ in range(5):
            t0 = time.perf_counter()
            subprocess.run(
                ['r2', '-q', '-c', '?e hello', '-'],
                capture_output=True, timeout=5,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            r2_times.append(elapsed_ms)
        bench_result['r2_startup_ms'] = round(sum(r2_times) / len(r2_times), 3)
    except FileNotFoundError:
        bench_result['r2_startup_ms'] = None
    except Exception as e:
        bench_result['r2_error'] = str(e)

# 子模块导入延迟（已在 __getattr__ 中自动记录）
    for mod_name in _submodules:
        t0 = time.perf_counter()
        try:
            __getattr__(mod_name)
        except Exception:
            pass
        elapsed_ms = (time.perf_counter() - t0) * 1000
        bench_result['submodule_import_times'][mod_name] = round(elapsed_ms, 3)

    # 写入缓存
    try:
        os.makedirs(os.path.dirname(_QUICKBENCH_CACHE_PATH) or '.', exist_ok=True)
        with open(_QUICKBENCH_CACHE_PATH, 'w', encoding='utf-8') as f:
            json.dump(bench_result, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return bench_result


def quickbench_report() -> str:
    """格式化 QuickBench results a human-readable string

    返回:
    Multiline string suitable for 日志 or console 输出
    """
    result = _run_quickbench()

    lines = []
    lines.append("=" * 70)
    lines.append("  QuickBench Report")
    lines.append(f"  Version: {result.get('version', '?')}")
    lines.append("=" * 70)

    z3_ms = result.get('z3_solve_time_ms')
    if z3_ms is not None:
        lines.append(f"  Z3 solve avg: {z3_ms:.3f}ms "
                     f"(min={result.get('z3_solve_min_ms', '?')}ms, "
                     f"max={result.get('z3_solve_max_ms', '?')}ms, "
                     f"n={result.get('z3_solve_count', '?')})")
    else:
        lines.append(f"  Z3: unavailable ({result.get('z3_error', 'not installed')})")

    r2_ms = result.get('r2_startup_ms')
    if r2_ms is not None:
        lines.append(f"  r2 startup:  {r2_ms:.3f}ms")
    else:
        lines.append(f"  r2: unavailable ({result.get('r2_error', 'not found on PATH')})")

    lines.append("-" * 70)
    lines.append("  Submodule import latency:")

    import_times = result.get('submodule_import_times', {})
    if import_times:
        sorted_imports = sorted(import_times.items(), key=lambda x: x[1], reverse=True)
        for mod_name, elapsed_ms in sorted_imports:
            lines.append(f"    {mod_name:<36} {elapsed_ms:>10.2f}ms")
    else:
        lines.append("    (no submodule import times recorded)")

    total_import = sum(import_times.values()) if import_times else 0
    lines.append(f"  Total submodule import: {total_import:.1f}ms")
    lines.append("=" * 70)

    return "\n".join(lines)


# 环境变量门控：SYMBEX_RUN_BENCH=1 时在导入时运行基准
if os.environ.get('SYMBEX_RUN_BENCH') == '1':
    _bench_result = _run_quickbench()
    print(quickbench_report())


# 四轮增强 - CrossModuleValidator：跨模块兼容性验证
#
# 验证所有存在相互依赖的子模块之间：
#   1. 版本兼容性（无 breaking change 级别的版本不一致）
# 2. 循环依赖检测：constraint_cache_持久化 的 缓存是否被
#      symexec_optimizer 正确引用（检查 import 图的依赖方向）
#   3. 关键接口一致性：确保被依赖模块暴露了依赖方所需的函数/类
#
# 设计意图 - 20+ 子模块的松散耦合在持续迭代中容易产生隐式依赖断裂
# CrossModuleValidator 在包导入时运行轻量级检查，尽早发现集成问题

# 已知的跨模块依赖关系（手动维护，作为验证基准）
# 格式: {消费者_module: {depended_module: [expected_attribute,.]}}
_CROSS_DEPS: Dict[str, Dict[str, List[str]]] = {
    "symexec_optimizer": {
        "constraint_cache_persistence": ["ConstraintSolverCache"],
    },
    "symbolic_scheduler": {
        "symbolic_path_merge": ["PathMerger", "SymbolicState"],
    },
    "distributed_symbex": {
        "symbolic_scheduler": ["PriorityScheduler"],
    },
    "incremental_symbex": {
        "symexec_optimizer": ["IncrementalSolverCache"],
    },
}


class CrossModuleValidator:
    """Verify interdependent submodules compatible interfaces

    四轮增强 - 两个检查维度：
    1. 依赖方是否能正常 import 被依赖方的模块及其声明属性
    2. 循环依赖检测：A imports B 且 B imports A 会阻止包初始化

    Usage::

    validator = CrossModuleValidator()
    报告 = validator.校验()
    for issue 报告['issues']:
    print(f"WARNING: {issue}")
    """

    def __init__(self):
        self._issues: List[str] = []
        self._import_graph: Dict[str, Set[str]] = defaultdict(set)

    def validate(self) -> Dict[str, Any]:
        """运行 cross-module 兼容性 检查

        返回:
        Dict keys:
        'valid': bool, True issues found
        'issues': List[str], human-readable issue descriptions
        'circular_deps': List[Tuple[str, str]], detected cycles
        'missing_attrs': List[Dict], missing expected attributes
        """
        self._issues = []
        missing_attrs: List[Dict] = []

        for consumer, dep_map in _CROSS_DEPS.items():
            for depended, expected_attrs in dep_map.items():
                # 检查消费者能否导入被依赖者
                try:
                    import importlib
                    dep_mod = importlib.import_module(
                        _submodules[depended], package=__package__
                    )
                except ImportError as e:
                    self._issues.append(
                        f"Cross-module: {consumer} cannot import {depended}: {e}"
                    )
                    continue
                except Exception as e:
                    self._issues.append(
                        f"Cross-module: {consumer} import {depended} failed: {e}"
                    )
                    continue

                # 检查消费者模块本身是否可导入
                try:
                    consumer_mod = importlib.import_module(
                        _submodules[consumer], package=__package__
                    )
                except Exception:
                    continue  # 消费者不可用，不检查属性

                # 检查被依赖者是否暴露了预期的属性
                for attr in expected_attrs:
                    if not hasattr(dep_mod, attr) and not hasattr(consumer_mod, attr):
                        missing_attrs.append({
                            'consumer': consumer,
                            'depended': depended,
                            'missing_attr': attr,
                        })
                        self._issues.append(
                            f"Cross-module: {consumer} expects {attr} from "
                            f"{depended}, but attribute not found in either module"
                        )

        # 循环依赖检测
        circular_deps = self._detect_circular_deps()

        return {
            'valid': len(self._issues) == 0,
            'issues': self._issues,
            'circular_deps': circular_deps,
            'missing_attrs': missing_attrs,
        }

    def _detect_circular_deps(self) -> List[Tuple[str, str]]:
        """检测 circular import dependencies submodules

        构建有向图，用 DFS 检测后向边（back edges）

        返回:
        List (module_a, module_b) pairs involved cycles
        """
        # 构建导入图
        graph: Dict[str, Set[str]] = defaultdict(set)
        for mod_name, mod_path in _submodules.items():
            try:
                import importlib
                mod = importlib.import_module(mod_path, package=__package__)
            except Exception:
                continue

            # 检查模块的全局命名空间中对其他子模块的引用
            for other_name, other_path in _submodules.items():
                if other_name == mod_name:
                    continue
                # 检查模块的 __all__ 或 dir 中对 模块的引用
                mod_all = set(getattr(mod, '__all__', []))
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name, None)
                    if obj is None:
                        continue
                    obj_module = getattr(obj, '__module__', '')
                    # 检查对象是否来自 子模块
                    if other_path.lstrip('.') == obj_module or \
                       obj_module == __name__ + other_path:
                        graph[mod_name].add(other_name)
                        break

        # DFS 检测环
        WHITE, GRAY, BLACK = 0, 1, 2
        color: Dict[str, int] = {name: WHITE for name in _submodules}
        circular_pairs: List[Tuple[str, str]] = []

        def dfs(node: str, path: List[str]) -> None:
            color[node] = GRAY
            path.append(node)
            for neighbor in graph.get(node, set()):
                if color.get(neighbor) == GRAY:
                    # 发现后向边
                    cycle_start = path.index(neighbor)
                    cycle_nodes = path[cycle_start:]
                    for i in range(len(cycle_nodes)):
                        circular_pairs.append(
                            (cycle_nodes[i], cycle_nodes[(i + 1) % len(cycle_nodes)])
                        )
                elif color.get(neighbor) == WHITE:
                    dfs(neighbor, path)
            path.pop()
            color[node] = BLACK

        for node in _submodules:
            if color.get(node) == WHITE:
                dfs(node, [])

        return circular_pairs


# 包导入时运行跨模块验证（结果仅缓存，按需查询）
_cross_validator = CrossModuleValidator()
_cross_validation_report = _cross_validator.validate()


def cross_validation_report() -> Dict[str, Any]:
    """返回 the缓存d cross-module 兼容性 校验 报告

    返回:
    Dict keys: valid, issues, circular_deps, missing_attrs
    """
    return _cross_validation_report


# 诊断函数：全系统检查，输出结构化 diag_report
#
# 检查项目：
#   1. 所有子模块的可导入性
#   2. Z3 solver 可用性（如果可用则跑一个简单断言）
#   3. r2 命令行工具是否在 PATH 中
#   4. 综合健康评分（0-100）
#   5. 四轮增强 - CrossModuleValidator 的验证结果
#
# diag_report 用于 CI/部署前自检或运行时问题定位


def diagnose() -> dict:
    """运行 a full system diagnostic 返回 a structured 报告

    检查:
    * submodule imported
    * Z3 约束求解器 usable (运行 a trivial constraint)
    * radare2 (r2) available PATH
    * Cross-module dependencies valid (CrossModuleValidator)
    * 计算 an overall ``health_score`` (0-100)

    返回:
    ``diag_report`` dict keys:
    ``version``, ``modules``, ``dependencies``, ``cross_module``
    ``health_score``, ``issues``, ``timestamp``
    """
    import time as _time
    import shutil

    diag_report: Dict[str, Any] = {
        "version": __version__,
        "timestamp": _time.time(),
        "modules": {},
        "dependencies": {},
        "cross_module": {},
        "issues": [],
        "health_score": 0,
    }

# 1. 子模块可导入性
    passed_mods = 0
    total_mods = len(_submodules)
    for mod_name, mod_path in _submodules.items():
        try:
            import importlib
            mod = importlib.import_module(mod_path, package=__package__)
            diag_report["modules"][mod_name] = {
                "status": "ok",
                "version": getattr(mod, "__version__", "unknown"),
                "has_doc": bool(getattr(mod, "__doc__", None)),
            }
            passed_mods += 1
        except ImportError as e:
            diag_report["modules"][mod_name] = {"status": "import_error", "error": str(e)}
            diag_report["issues"].append(f"module {mod_name}: import error - {e}")
        except Exception as e:
            diag_report["modules"][mod_name] = {"status": "error", "error": str(e)}
            diag_report["issues"].append(f"module {mod_name}: unexpected error - {e}")

# 2. Z3 可用性
    z3_status = {"status": "unavailable", "trivial_test": False}
    try:
        import z3
        # 跑一个简单约束验证 Z3 是否真正可用
        x = z3.Int("x")
        s = z3.Solver()
        s.add(x > 0)
        s.add(x < 5)
        result = s.check()
        z3_status["status"] = "ok"
        z3_status["trivial_test"] = str(result) == "sat"
        if not z3_status["trivial_test"]:
            diag_report["issues"].append("z3: trivial constraint returned unexpected result")
    except ImportError:
        diag_report["issues"].append("z3: not installed - constraint solving unavailable")
    except Exception as e:
        z3_status["status"] = f"error: {e}"
        diag_report["issues"].append(f"z3: runtime error - {e}")
    diag_report["dependencies"]["z3"] = z3_status

# 3. r2 PATH 检查
    r2_found = shutil.which("r2") is not None
    diag_report["dependencies"]["r2"] = {
        "status": "ok" if r2_found else "missing",
        "path": shutil.which("r2") if r2_found else None,
    }
    if not r2_found:
        diag_report["issues"].append("r2: not found on PATH - binary analysis fallback disabled")

# 4. 四轮增强 - 跨模块验证
    cross_report = cross_validation_report()
    diag_report["cross_module"] = {
        "valid": cross_report["valid"],
        "circular_deps_count": len(cross_report["circular_deps"]),
        "missing_attrs_count": len(cross_report["missing_attrs"]),
    }
    if not cross_report["valid"]:
        for issue in cross_report["issues"]:
            diag_report["issues"].append(f"cross-module: {issue}")

# 5. 健康评分
    # 评分逻辑：模块可导入率占 60%，依赖可用性占 30%，跨模块验证占 10%
    mod_score = (passed_mods / max(1, total_mods)) * 60.0
    dep_score = 0.0
    dep_count = 0
    for dep_name, dep_info in diag_report["dependencies"].items():
        dep_count += 1
        if dep_info.get("status") == "ok":
            dep_score += 1.0
    dep_score = (dep_score / max(1, dep_count)) * 20.0 if dep_count else 15.0

    cross_score = 10.0 if cross_report["valid"] else (5.0 if not cross_report["missing_attrs"] else 0.0)

    health_score = round(mod_score + dep_score + cross_score)
    diag_report["health_score"] = max(0, min(100, health_score))

    if diag_report["issues"]:
        diag_report["issues"].append(
            f"total {len(diag_report['issues'])} issue(s) detected; "
            f"health_score={health_score}/100"
        )

    return diag_report


# 向后兼容的公开接口


def health_check() -> dict:
    """返回所有子模块的可用性及版本信息

    每个模块尝试导入，捕获 ImportError 并标记为 unavailable
    用于 CI/部署时的快速自检 -- 不依赖外部工具即可验证安装完整性"""
    status = {"version": __version__, "modules": {}}
    for mod_name in _submodules:
        try:
            import importlib
            importlib.import_module(_submodules[mod_name], package=__package__)
            status["modules"][mod_name] = "available"
        except ImportError as e:
            status["modules"][mod_name] = f"unavailable: {e}"
        except Exception as e:
            status["modules"][mod_name] = f"error: {e}"
    available = sum(1 for v in status["modules"].values() if v == "available")
    status["summary"] = f"{available}/{len(_submodules)} modules available"
    return status


def list_dependencies() -> dict:
    """检查外部依赖（angr, z3, unicorn, r2）的安装状态

    angr 和 z3 是核心依赖；unicorn 用于混合执行；r2 用于二进制分析回退"""
    deps = {}
    for pkg in ("angr", "z3", "unicorn", "claripy"):
        try:
            __import__(pkg)
            deps[pkg] = "installed"
        except ImportError:
            deps[pkg] = "missing"
    # r2 是命令行工具，检查 PATH
    import shutil
    deps["r2"] = "found" if shutil.which("r2") else "missing"
    return deps


__all__ = list(_submodules.keys()) + [
    "__version__",
    "health_check",
    "list_dependencies",
    "diagnose",
    "get_mod_registry",
    "PluginLoader",
    # 四轮增强 - 公开接口
    "import_profile_report",
    "quickbench_report",
    "cross_validation_report",
    "CrossModuleValidator",
]
