"""
创建: 2024-08-14
修改:
  2025-08-03 - 持久化路径统一到 _data_dir()
跨会话代码稳定性演化追踪 — 函数级 AST 指纹跨会话演化链。

区别于 git blame（追踪人类提交者）和 provenance（单会话 worker 追踪），
本模块追踪生成代码的跨会话稳定性，将时间维度引入代码质量评估。
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field


from ..config import _data_dir
_FINGERPRINTS_PATH = os.path.join(_data_dir(), "evo_fingerprints.json")


@dataclass
class FuncFingerprint:
    """单个函数在单次会话中的演化指纹。"""
    func_name: str
    filepath: str
    session_id: str
    timestamp: float
    ast_hash: str           # 归一化 AST 的 SHA-256 前16字符
    body_hash: str           # 函数体的结构哈希
    line_count: int
    arg_count: int


@dataclass
class StabilityReport:
    """单个函数的稳定性报告。"""
    func_name: str
    filepath: str
    total_sessions: int        # 该函数被追踪的会话总数
    stable_sessions: int       # 连续未变的会话数（从最近往前数）
    stability_score: float     # stable_sessions / max_stable_sessions_possible
    is_converged: bool         # stability_score >= 0.8 且 stable_sessions >= 3
    last_changed_session: str  # 最后一次变更所在的会话
    volatility: str            # 'stable' | 'converging' | 'volatile' | 'new'


class EvoTracker:
    """跨会话代码稳定性演化追踪器。

    持久化到 .evo_fingerprints.json。
    每个函数维护其跨会话的指纹链，用于计算稳定性分数。"""

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or f"session_{int(time.time())}"
        # filepath:func_name → [FuncFingerprint, ...] (按时间排序)
        self._history: dict[str, list[FuncFingerprint]] = defaultdict(list)
        self._load()

    # 指纹记录

    def fingerprint_file(self, filepath: str) -> list[FuncFingerprint]:
        """为文件中所有顶层函数计算演化指纹。返回指纹列表。"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError:
            return []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        fps: list[FuncFingerprint] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fp = self._fingerprint_func(node, filepath, source)
                if fp:
                    fps.append(fp)
                    key = f"{filepath}:{fp.func_name}"
                    self._history[key].append(fp)
        return fps

    def fingerprint_batch(self, filepaths: list[str]) -> int:
        """批量为文件列表计算指纹。返回处理的函数数。"""
        count = 0
        for fpath in filepaths:
            if fpath.endswith(".py") and os.path.isfile(fpath):
                fps = self.fingerprint_file(fpath)
                count += len(fps)
        self._save()
        return count

    # 稳定性查询

    def stability_report(self, filepath: str, func_name: str) -> StabilityReport | None:
        """查询单个函数的稳定性报告。"""
        key = f"{filepath}:{func_name}"
        chain = self._history.get(key, [])
        if not chain:
            return None

        total = len(chain)
        # 计算连续未变的会话数（从最近往前）
        stable = 1
        for i in range(len(chain) - 1, 0, -1):
            if chain[i].ast_hash == chain[i - 1].ast_hash:
                stable += 1
            else:
                break

        max_possible = min(total, 5)
        score = stable / max_possible if max_possible > 0 else 0.0

        # 确定易变性分类
        if stable >= 3 and score >= 0.8:
            vol = "stable"
        elif stable >= 2:
            vol = "converging"
        elif total >= 3:
            vol = "volatile"
        else:
            vol = "new"

        last_change = chain[-1].session_id
        for i in range(len(chain) - 1, 0, -1):
            if chain[i].ast_hash != chain[i - 1].ast_hash:
                last_change = chain[i].session_id
                break

        return StabilityReport(
            func_name=func_name, filepath=filepath,
            total_sessions=total, stable_sessions=stable,
            stability_score=round(score, 3),
            is_converged=(stable >= 3 and score >= 0.8),
            last_changed_session=last_change,
            volatility=vol,
        )

    def stable_functions(self) -> list[StabilityReport]:
        """返回所有已收敛的函数。"""
        reports: list[StabilityReport] = []
        seen: set[str] = set()
        for key in self._history:
            parts = key.split(":", 1)
            if len(parts) != 2:
                continue
            fpath, fname = parts
            report = self.stability_report(fpath, fname)
            if report and report.is_converged:
                uid = f"{fpath}:{fname}"
                if uid not in seen:
                    reports.append(report)
                    seen.add(uid)
        reports.sort(key=lambda r: r.stability_score, reverse=True)
        return reports

    def volatile_functions(self) -> list[StabilityReport]:
        """返回所有易变（不稳定）的函数。"""
        reports: list[StabilityReport] = []
        seen: set[str] = set()
        for key in self._history:
            parts = key.split(":", 1)
            if len(parts) != 2:
                continue
            fpath, fname = parts
            report = self.stability_report(fpath, fname)
            if report and report.volatility == "volatile":
                uid = f"{fpath}:{fname}"
                if uid not in seen:
                    reports.append(report)
                    seen.add(uid)
        return reports

    # 持久化

    def _save(self) -> None:
        payload: dict = {}
        for key, chain in self._history.items():
            payload[key] = [
                {
                    "func_name": fp.func_name, "filepath": fp.filepath,
                    "session_id": fp.session_id, "timestamp": fp.timestamp,
                    "ast_hash": fp.ast_hash, "body_hash": fp.body_hash,
                    "line_count": fp.line_count, "arg_count": fp.arg_count,
                }
                for fp in chain
            ]
        try:
            with open(_FINGERPRINTS_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _load(self) -> None:
        if not os.path.isfile(_FINGERPRINTS_PATH):
            return
        try:
            with open(_FINGERPRINTS_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        for key, chain in payload.items():
            for d in chain:
                self._history[key].append(FuncFingerprint(
                    func_name=d["func_name"], filepath=d["filepath"],
                    session_id=d.get("session_id", ""),
                    timestamp=d.get("timestamp", 0.0),
                    ast_hash=d["ast_hash"], body_hash=d.get("body_hash", ""),
                    line_count=d.get("line_count", 0),
                    arg_count=d.get("arg_count", 0),
                ))

    # 内部

    def _fingerprint_func(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
        filepath: str, source: str,
    ) -> FuncFingerprint | None:
        """计算单个函数的演化指纹。"""
        try:
            body_str = ast.unparse(node.body) if node.body else ""
            normalized = self._normalize_func_body(node)
            ast_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
            body_hash = hashlib.sha256(body_str.encode()).hexdigest()[:12]
        except Exception:
            return None

        return FuncFingerprint(
            func_name=node.name, filepath=filepath,
            session_id=self.session_id, timestamp=time.time(),
            ast_hash=ast_hash, body_hash=body_hash,
            line_count=node.end_lineno - node.lineno if node.end_lineno else 0,
            arg_count=len(node.args.args),
        )

    @staticmethod
    def _normalize_func_body(node: ast.FunctionDef) -> str:
        """归一化函数体——与 semantic_dedup 共享逻辑。

        替换标识符为占位符，规范化字面量，使结构等价但命名不同的
        函数产生相同的归一化 AST。"""
        name_map: dict[str, str] = {}
        counter = [0]

        class Normalizer(ast.NodeTransformer):
            def visit_Name(self, n: ast.Name) -> ast.Name:
                if n.id not in name_map:
                    name_map[n.id] = f"_v{counter[0]}"
                    counter[0] += 1
                return ast.Name(id=name_map[n.id], ctx=n.ctx)
            def visit_Constant(self, n: ast.Constant) -> ast.Constant:
                if isinstance(n.value, str):
                    return ast.Constant(value="")
                if isinstance(n.value, (int, float)):
                    return ast.Constant(value=0)
                return n
            def visit_arg(self, n: ast.arg) -> ast.arg:
                if n.arg not in name_map:
                    name_map[n.arg] = f"_v{counter[0]}"
                    counter[0] += 1
                n.arg = name_map[n.arg]
                return n

        norm = Normalizer()
        normalized = norm.visit(node)
        ast.fix_missing_locations(normalized)
        return ast.dump(normalized, annotate_fields=False)

    def stats(self) -> dict:
        stable = len(self.stable_functions())
        volatile = len(self.volatile_functions())
        return {
            "tracked_functions": len(self._history),
            "stable": stable,
            "volatile": volatile,
            "stable_ratio": round(stable / max(len(self._history), 1), 3),
        }
