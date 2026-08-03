"""LLM 路径排名器 — ReCopilot/FoC 启发的语义路径兴趣评分"""
import os, hashlib, json, re, logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


@dataclass
class PathState:
    """符号执行路径状态 — 封装 angr 状态的元数据"""
    state_id: str
    address: int
    depth: int
    constraints_count: int
    func_name: str = ""
    pseudocode_snippet: str = ""
    llm_interest_score: float = 0.0
    raw_state: Any = None


class LLMPathRanker:
    """LLM 语义路径排名器 — 评估每条路径包含漏洞模式的可能性
    排名维度: 1.危险函数接近度 2.用户可控输入 3.已知漏洞模式 4.路径约束复杂性"""
    _DANGER_PATTERNS = [
        "system", "execve", "execvp", "popen",
        "memcpy", "strcpy", "sprintf", "gets", "scanf",
        "malloc", "free", "mmap",
        "copy_from_user", "copy_to_user",
    ]

    def __init__(self, api_key: str = "", model: str = "claude-sonnet-5-20251001"):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model
        self._cache: Dict[str, float] = {}

    def rank_paths(self, paths: List[PathState], top_k: int = 10) -> List[PathState]:
        """对路径进行语义排名, 返回 top-K — LLM 优先, 不可用时启发式降级"""
        if not paths:
            return []
        if self._api_key:
            return self._llm_rank(paths, top_k)
        return self._heuristic_rank(paths, top_k)

    def _heuristic_rank(self, paths: List[PathState], top_k: int) -> List[PathState]:
        """启发式排名 — LLM 不可用时的降级: 危险关键词密度 + 深度 + 约束 + 新颖性"""
        for path in paths:
            if not path.pseudocode_snippet:
                path.llm_interest_score = 0.3
                continue
            cl = path.pseudocode_snippet.lower()
            danger_score = min(1.0, sum(1 for kw in self._DANGER_PATTERNS if kw in cl) / 5.0) * 0.5
            depth_score = min(1.0, path.depth / 50.0) * 0.2
            constraint_penalty = max(0.0, (10 - path.constraints_count) / 10.0) * 0.2
            novelty = 0.1 if path.func_name not in self._cache else 0.0
            path.llm_interest_score = danger_score + depth_score + constraint_penalty + novelty
            self._cache[hashlib.md5(path.pseudocode_snippet.encode()).hexdigest()] = path.llm_interest_score
        paths.sort(key=lambda p: p.llm_interest_score, reverse=True)
        return paths[:top_k]

    def _llm_rank(self, paths: List[PathState], top_k: int) -> List[PathState]:
        """LLM 语义排名 — 批量评估 (每批最多 20 条)"""
        try:
            import anthropic
            snippets = []
            for i, path in enumerate(paths[:20]):
                snippets.append(f"[{i}] @{path.address:#x} depth={path.depth}:\n{path.pseudocode_snippet[:500]}")
            prompt = (
                "你是二进制漏洞分析专家。对以下符号执行路径评估漏洞可能性(0-100):\n\n"
                + "\n\n".join(snippets)
                + "\n\n返回 JSON: [{\"id\": int, \"score\": int}, ...]"
            )
            client = anthropic.Anthropic(api_key=self._api_key)
            resp = client.messages.create(
                model=self._model, max_tokens=500, temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )
            try:
                scores = json.loads(resp.content[0].text)
            except json.JSONDecodeError:
                scores = [{"id": int(m.group(1)), "score": int(m.group(2))}
                         for m in re.finditer(r'"id":\s*(\d+).*?"score":\s*(\d+)', resp.content[0].text)]
            for item in scores:
                idx = item.get("id", -1)
                if 0 <= idx < len(paths):
                    paths[idx].llm_interest_score = item.get("score", 50) / 100.0
        except Exception as e:
            _log.debug("LLM 排名失败: %s — 回退启发式", e)
            return self._heuristic_rank(paths, top_k)
        paths.sort(key=lambda p: p.llm_interest_score, reverse=True)
        return paths[:top_k]


__all__ = ["PathState", "LLMPathRanker"]

def _debug_print(*args, **kwargs):  # 调试残余——未删除
    """Print debug info env var set. currently"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
