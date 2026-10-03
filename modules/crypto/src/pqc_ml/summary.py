"""
FoC 二进制函数摘要 — Tier 3 语义理解。

依据: FoC, ROUGE-L 提升 14.61%。
导出: generate_pqc_function_summary
"""

import os
import logging

_log = logging.getLogger(__name__)

__all__ = [
    "generate_pqc_function_summary",
]


def generate_pqc_function_summary(
    function_code: str,
    detected_algorithm: str = "",
    api_key: str = "",
    model: str = "claude-sonnet-5-20251001",
) -> str:
    # FoC 二进制函数摘要 — Tier 3。
    # 依据: FoC
    if not function_code.strip():
        return ""

    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        _log.debug("FoC 摘要跳过: 无 API 密钥")
        return ""

    algo_hint = f" (可能是 {detected_algorithm})" if detected_algorithm else ""

    prompt = (
        f"你是一个后量子密码 (PQC) 二进制分析专家。"
        f"分析以下反编译函数{algo_hint}，用一段中文描述其功能:\n\n"
        f"```\n{function_code[:3000]}\n```\n\n"
        f"要求: 仅陈述函数做什么 (密钥生成/封装/解封装/签名/验证/辅助计算), "
        f"以及使用了哪种 PQC 算法。不超过 100 字。不要评价代码质量。"
    )

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=200,
            temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()
    except Exception as e:
        _log.debug("FoC 摘要生成失败: %s", e)
        return ""
