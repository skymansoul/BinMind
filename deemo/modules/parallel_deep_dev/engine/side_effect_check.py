"""
创建: 2026-06-13
跨模块全局副作用碰撞检测 — 检测并行生成的模块是否修改了相同的全局资源。

问题：Worker A 的模块注册了 `signal.signal(signal.SIGTERM, handler_a)`，
Worker B 的模块注册了 `signal.signal(signal.SIGTERM, handler_b)`。
两个 worker 独立生成时各自正确，合并后后注册的 handler 静默覆盖前者。
类似问题：多个模块写入同一环境变量、修改同一全局变量、注册同一 atexit 回调。

现有工具（pylint/pyflakes）检测单文件内的全局变量使用，不检查跨模块碰撞。
线程安全分析器（ThreadSanitizer）关注并发访问而非分布式生成的资源争用。

方案：静态扫描 + 资源指纹匹配。
  1. 扫描所有生成文件，提取"副作用点"：
     - 环境变量写入: os.environ["KEY"] = ...
     - 信号注册: signal.signal(SIG, handler)
     - atexit 注册: atexit.register(func)
     - 全局变量赋值: module_level_assignment
     - 文件系统写入: open(path, "w")
     - 日志配置: logging.basicConfig(...)
  2. 对同类副作用抽取"资源指纹"（如环境变量的 KEY、信号的 SIG 值）
  3. 指纹相同的多个副作用点 → 碰撞告警
  4. 分类为 CRITICAL（确定性覆盖）或 WARNING（潜在冲突）

区别于线程安全分析器和 pylint——本模块聚焦并行代码生成场景的
跨模块资源争用，是分布式生成特有的问题类别。
"""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class SideEffect:
    """单个副作用点。"""
    filepath: str
    lineno: int
    category: str        # environ | signal | atexit | global_var | file_write | logging
    resource_key: str    # 用于碰撞检测的资源标识
    description: str


@dataclass
class Collision:
    """两个或多个副作用点之间的碰撞。"""
    resource_key: str
    category: str
    severity: str        # CRITICAL | WARNING
    effects: list[SideEffect]
    description: str


class SideEffectChecker:
    """跨模块全局副作用碰撞检测器。"""

    # 已知会修改全局状态的目标
    _ENVIRON_TARGETS = {"os.environ", "environ"}
    _SIGNAL_TARGETS = {"signal.signal", "signal.siginterrupt"}
    _ATEXIT_TARGETS = {"atexit.register"}
    _LOGGING_TARGETS = {"logging.basicConfig", "logging.getLogger",
                         "logging.setLoggerClass"}

    def scan(self, filepaths: list[str]) -> list[Collision]:
        """扫描文件列表，检测副作用碰撞。"""
        effects: list[SideEffect] = []
        for fpath in filepaths:
            if not fpath.endswith(".py") or not os.path.isfile(fpath):
                continue
            source = self._read(fpath)
            if source is None:
                continue
            tree = self._parse(source)
            if tree is None:
                continue
            effects.extend(self._extract_effects(fpath, source, tree))

        return self._detect_collisions(effects)

    def _extract_effects(
        self, fpath: str, source: str, tree: ast.Module,
    ) -> list[SideEffect]:
        effects: list[SideEffect] = []
        lines = source.split("\n")

        for node in ast.walk(tree):
            # 环境变量写入: os.environ["KEY"] = val
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        key = self._extract_environ_key(target)
                        if key:
                            effects.append(SideEffect(
                                filepath=fpath, lineno=node.lineno,
                                category="environ", resource_key=key,
                                description=f"环境变量写入: {key}",
                            ))

            # 信号注册: signal.signal(SIG, handler)
            if isinstance(node, ast.Call):
                call_name = self._resolve_call_name(node.func)
                if call_name in self._SIGNAL_TARGETS and len(node.args) >= 1:
                    sig_val = self._extract_constant(node.args[0])
                    effects.append(SideEffect(
                        filepath=fpath, lineno=node.lineno,
                        category="signal", resource_key=str(sig_val),
                        description=f"信号注册: {call_name}({sig_val})",
                    ))

                # atexit 注册
                if call_name in self._ATEXIT_TARGETS and node.args:
                    handler = self._resolve_call_name(node.args[0]) if isinstance(node.args[0], ast.Name) else "?"
                    effects.append(SideEffect(
                        filepath=fpath, lineno=node.lineno,
                        category="atexit", resource_key="atexit",
                        description=f"atexit注册: {handler}",
                    ))

                # 日志配置（全局单例）
                if call_name in self._LOGGING_TARGETS:
                    effects.append(SideEffect(
                        filepath=fpath, lineno=node.lineno,
                        category="logging", resource_key=call_name,
                        description=f"全局日志配置: {call_name}",
                    ))

            # 文件写入: open(path, "w")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    if len(node.args) >= 2:
                        mode = self._extract_constant(node.args[1])
                        if mode and "w" in str(mode):
                            path_val = self._extract_constant(node.args[0])
                            effects.append(SideEffect(
                                filepath=fpath, lineno=node.lineno,
                                category="file_write",
                                resource_key=str(path_val),
                                description=f"文件写入: {path_val}",
                            ))

        # 模块级全局变量赋值
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        effects.append(SideEffect(
                            filepath=fpath, lineno=node.lineno,
                            category="global_var", resource_key=target.id,
                            description=f"全局常量赋值: {target.id}",
                        ))

        return effects

    def scan_with_order(self, filepaths: list[str]) -> list[Collision]:
        """扫描文件列表并分析导入时序——后导入的模块覆盖先导入的副作用。

        当两个模块注册同一信号或写入同一环境变量时，
        import 顺序决定最终生效的是哪个。此方法沿文件列表顺序
        （即 Python 的 import 顺序）检测覆盖关系。"""
        collisions = self.scan(filepaths)
        if not collisions:
            return collisions

        # 为每个碰撞标注时序信息
        for c in collisions:
            if c.severity != "CRITICAL":
                continue
            # 按文件在 filepaths 中的顺序排列 effects
            ordered = sorted(
                c.effects,
                key=lambda e: filepaths.index(e.filepath) if e.filepath in filepaths else 999,
            )
            if len(ordered) >= 2:
                winner = ordered[-1]  # 后导入者覆盖先导入者
                losers = ordered[:-1]
                c.description = (
                    f"{len(c.effects)} 个模块修改了 '{c.resource_key}': "
                    f"{os.path.basename(winner.filepath)} (最后导入) 将覆盖 "
                    f"{', '.join(os.path.basename(l.filepath) for l in losers)}——"
                    f"若预期行为依赖于先导入模块的注册，这会导致静默失效"
                )
        return collisions

    def _detect_collisions(self, effects: list[SideEffect]) -> list[Collision]:
        """检测副作用碰撞——同一 category 内 resource_key 相同的多个副作用。"""
        grouped: dict[str, list[SideEffect]] = defaultdict(list)
        for e in effects:
            key = f"{e.category}:{e.resource_key}"
            grouped[key].append(e)

        collisions: list[Collision] = []
        for key, group in grouped.items():
            if len(group) < 2:
                continue
            # 去重：同一文件内的重复不计为碰撞
            files = {e.filepath for e in group}
            if len(files) < 2:
                continue

            cat = group[0].category
            sev = "CRITICAL" if cat in ("signal", "environ", "logging") else "WARNING"

            collisions.append(Collision(
                resource_key=group[0].resource_key,
                category=cat,
                severity=sev,
                effects=group,
                description=(
                    f"{len(group)} 个模块修改了同一资源 "
                    f"'{group[0].resource_key}' ({cat})——"
                    f"可能导致静默覆盖或未定义行为"
                ),
            ))

        collisions.sort(key=lambda c: (0 if c.severity == "CRITICAL" else 1, c.resource_key))
        return collisions

    # 辅助

    @staticmethod
    def _read(filepath: str) -> str | None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    @staticmethod
    def _parse(source: str) -> ast.Module | None:
        try:
            return ast.parse(source)
        except SyntaxError:
            return None

    @staticmethod
    def _resolve_call_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = SideEffectChecker._resolve_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    @staticmethod
    def _extract_constant(node: ast.expr) -> str:
        if isinstance(node, ast.Constant):
            return str(node.value)
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{SideEffectChecker._resolve_call_name(node.value)}.{node.attr}"
        return "?"

    @staticmethod
    def _extract_environ_key(target: ast.Subscript) -> str | None:
        """检查是否为 os.environ['KEY'] 形式的赋值目标。"""
        if not isinstance(target.value, ast.Attribute):
            return None
        attr = target.value
        base = SideEffectChecker._resolve_call_name(attr.value)
        if base is None:
            return None
        # 匹配 os.environ 或 environ
        if base in ("os", "") and attr.attr == "environ":
            pass
        elif base == "os.environ":
            pass
        else:
            return None
        if isinstance(target.slice, ast.Constant):
            return str(target.slice.value)
        return "?"


# 便捷集成入口

def check_side_effects(
    filepaths: list[str],
    blackboard=None,
) -> list[Collision]:
    """扫描文件列表检测副作用碰撞，可选写入黑板。"""
    checker = SideEffectChecker()
    collisions = checker.scan(filepaths)

    if blackboard is not None:
        for c in collisions[:5]:
            blackboard.deposit(
                "error" if c.severity == "CRITICAL" else "warning",
                f"[副作用碰撞] {c.description}",
                source_module="side_effect_check",
                tags=["side_effect", c.category, c.severity.lower()],
            )

    return collisions
