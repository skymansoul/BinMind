"""
创建: 2026-06-24
修改:
  2025-08-01 - 精简 docstring，移除装饰性 Optional/field 导入
收敛感知对抗性自审查 — 二次 LLM 审查，利用语义收敛信号引导审查方向。

三阶段管线：
  1. 收敛感知聚焦：将语义等价的文件对送入同一 prompt，审查者评估差异充分性
  2. 因果影响排序：对发现的问题按因果图影响分数降序排列
  3. 伪阴性风险评估：审查者需说明"若未发现此问题会导致什么具体故障"

与 CTRL (RL-trained critic) 和 RevAgent (多 agent 分类) 的差异：
  收敛感知维度在文献中未见——将去重结果反馈给审查者以调整焦点。
  伪阴性风险使审查者做反事实推理，增加结果可信度。

默认仅在检测到语义收敛时触发，避免无谓 API 开销。
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from parallel_deep_dev.config import CONFIG


@dataclass
class ReviewFinding:
    """单条审查发现。"""
    file: str
    line: int
    severity: str           # critical | high | medium | low
    category: str           # logic_error | convergence | security | perf | style
    description: str
    suggestion: str
    false_negative_risk: str  # 若未发现的后果（阶段 3 输出）
    impact_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "file": self.file, "line": self.line,
            "severity": self.severity, "category": self.category,
            "description": self.description, "suggestion": self.suggestion,
            "false_negative_risk": self.false_negative_risk,
            "impact_score": self.impact_score,
        }


@dataclass
class ReviewConfig:
    """审查配置——可通过修改此数据类调整审查行为。"""
    max_findings: int = 15          # 单次审查最多返回的发现数
    min_severity: str = "low"       # 最低保留严重级别
    model: str = ""                 # 审查用模型，空串表示使用主配置
    include_convergence_context: bool = True

    def __post_init__(self):
        if not self.model:
            self.model = CONFIG.API_MODEL


SEVERITY_ORDER: dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1,
}


def build_review_prompt(
    module_files: list[str],
    convergence_context: list[dict] | None = None,
    causal_context: list[dict] | None = None,
) -> tuple[str, str]:
    """构建对抗性审查 prompt。
    收敛上下文：标注语义等价文件对，引导差异化评估。
    因果上下文：标注高影响文件，引导优先审查。"""

    convergence_section = ""
    if convergence_context and len(convergence_context) > 0:
        pairs = "\n".join(
            f"  - {c.get('file_a','?')} ≈ {c.get('file_b','?')} "
            f"(操作相似度: {c.get('op_similarity', 0):.3f})"
            for c in convergence_context[:5]
        )
        convergence_section = f"""
# 语义收敛检测结果（需特别审查）
以下文件对被检测为功能高度相似但实现不同。审查时需回答：
1. 两个实现中哪一个更优？为什么？
2. 是否存在因过早收敛而遗漏的差异化优化机会？
3. 即便实现不同，是否存在共享的缺陷模式（如相同的错误处理缺陷）？

{pairs}
"""

    causal_section = ""
    if causal_context and len(causal_context) > 0:
        impacts = "\n".join(
            f"  - {c.get('file','?')}: 影响分数={c.get('impact_score',0):.3f}, "
            f"距离={c.get('distance','?')}跳"
            for c in causal_context[:8]
        )
        causal_section = f"""
# 因果影响传播（优先审查高影响文件）
{impacts}
"""

    system_msg = (
        "你是一位资深软件安全审计专家，专门从事对抗性代码审查。"
        "你的任务不是确认代码是否'看起来正确'，而是找出其中实际存在的缺陷、"
        "安全隐患、逻辑错误和性能问题。审查原则：\n"
        "1. 假定代码有缺陷，你的任务是证明这一点\n"
        "2. 不接受'看起来没问题'的结论，始终追问边界条件\n"
        "3. 每个发现必须附带'伪阴性风险'——如果这个问题未被发现，会导致什么具体后果\n"
        "4. 不受代码作者的设计决策影响，从外部视角评估\n"
        "5. 输出严格 JSON 格式，不包含任何解释性文字\n"
    )

    files_list = "\n".join(f"  - {f}" for f in module_files[:15])
    user_msg = f"""审查以下模块的代码文件：

{files_list}

{convergence_section}
{causal_section}

请找出其中的缺陷、安全隐患、逻辑错误和性能问题。每个发现必须包含：
- file: 文件路径
- line: 行号（整数，无法确定时填 0）
- severity: critical | high | medium | low
- category: logic_error | convergence | security | perf | style
- description: 问题描述（中文，一针见血）
- suggestion: 修复建议（中文，具体可操作）
- false_negative_risk: 若忽略此问题的后果（中文）

仅输出 JSON 数组，格式：
[{{"file":"...","line":0,"severity":"...","category":"...","description":"...","suggestion":"...","false_negative_risk":"..."}}]
"""
    return system_msg, user_msg


def parse_review_response(api_response: str) -> list[ReviewFinding]:
    """解析 LLM 返回的 JSON 审查结果。容错处理格式偏差。"""
    findings: list[ReviewFinding] = []
    if not api_response:
        return findings

    # 尝试提取首个 JSON 数组
    text = api_response.strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1:
        return findings

    try:
        raw_list = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return findings

    if not isinstance(raw_list, list):
        return findings

    for item in raw_list:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "low")).lower()
        if severity not in SEVERITY_ORDER:
            severity = "low"

        findings.append(ReviewFinding(
            file=str(item.get("file", "")),
            line=int(item.get("line", 0)),
            severity=severity,
            category=str(item.get("category", "logic_error")),
            description=str(item.get("description", "")),
            suggestion=str(item.get("suggestion", "")),
            false_negative_risk=str(item.get("false_negative_risk", "")),
        ))

    return findings


def rank_by_impact(
    findings: list[ReviewFinding],
    causal_graph=None,
) -> list[ReviewFinding]:
    """因果影响加权排序。高影响文件的发现自动提级。"""
    if causal_graph is None:
        return sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True,
        )

    changed_files = list({f.file for f in findings})
    impact = causal_graph.impact_query(changed_files) if changed_files else []
    impact_map: dict[str, float] = {r.file: r.impact_score for r in impact}

    for f in findings:
        f.impact_score = impact_map.get(f.file, 0.0)
        # 高影响文件提升严重级别
        if f.impact_score >= 0.5 and f.severity == "medium":
            f.severity = "high"
        elif f.impact_score >= 0.3 and f.severity == "low":
            f.severity = "medium"

    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 0),
            f.impact_score,
        ), reverse=True,
    )


def run_adversarial_review(
    module_files: list[str],
    convergence_reports: list | None = None,
    causal_graph=None,
    config: ReviewConfig | None = None,
    api_key: str | None = None,
) -> list[ReviewFinding]:
    """执行完整审查管线。收敛检测结果引导 prompt 聚焦；因果图用于排序。
    API 失败返回空列表。"""
    if config is None:
        config = ReviewConfig()

    if api_key is None:
        api_key = CONFIG.API_KEY
    if not api_key:
        return []

    conv_ctx: list[dict] | None = None
    if config.include_convergence_context and convergence_reports:
        conv = [r for r in convergence_reports if getattr(r, 'is_converged', False)]
        if conv:
            conv_ctx = [
                {"file_a": r.file_a, "file_b": r.file_b,
                 "op_similarity": r.op_similarity}
                for r in conv[:5]
            ]

    causal_ctx: list[dict] | None = None
    if causal_graph is not None and module_files:
        try:
            impact = causal_graph.impact_query(module_files)
            if impact:
                causal_ctx = [
                    {"file": r.file, "impact_score": r.impact_score,
                     "distance": r.distance}
                    for r in impact[:8]
                ]
        except Exception:
            pass

    system_msg, user_msg = build_review_prompt(
        module_files, conv_ctx, causal_ctx,
    )

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=config.model,
            max_tokens=4096,
            temperature=0.2,
            system=system_msg,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = response.content[0].text
    except Exception:
        return []

    findings = parse_review_response(raw)
    findings = findings[:config.max_findings]

    # 过滤低严重级别
    min_lvl = SEVERITY_ORDER.get(config.min_severity, 1)
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_lvl]

    # 因果影响排序
    findings = rank_by_impact(findings, causal_graph)

    return findings


def review_to_blackboard(
    blackboard,
    findings: list[ReviewFinding],
) -> int:
    """将 critical/high 发现写入黑板。返回写入条目数。"""
    count = 0
    for f in findings:
        if f.severity in ("critical", "high"):
            blackboard.deposit(
                "error",
                f"[{f.severity}] {f.file}:{f.line} — {f.description}",
                source_module="adversarial_review",
                tags=["review", f.severity, f.category],
                meta=f.to_dict(),
            )
            count += 1
    return count
