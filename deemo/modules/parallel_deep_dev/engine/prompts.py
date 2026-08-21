"""Prompt 生成 — 为每个子模块构建完整的开发 prompt。"""
import os
from ..config import CONFIG


def generate_sub_prompt(module_key: str, module_def: dict) -> str:
    """为指定子模块生成完整的开发 prompt。"""
    innovation = module_def["innovation"]

    papers_text = ""
    for i, paper in enumerate(innovation["papers"], 1):
        papers_text += (
            f"  {i}. {paper['title']}\n"
            f"     发表: {paper['venue']}\n"
            f"     核心贡献: {paper['key_idea']}\n"
        )
    if not innovation["papers"]:
        papers_text = "  (此创新点基于内部架构分析与工程最佳实践，无需外部论文支撑)\n"

    return f"""
# 子模块: {module_key} — {module_def['name']}

# 当前功能描述
{module_def['description']}

# 深度创新点: {innovation['title']}

**动机与理论依据:**
{innovation['rationale']}

**支撑论文:**
{papers_text}

# 开发要求 (必须严格遵守)

1. **保留所有原有功能**: 不得删除、精简或修改任何现有的功能、接口和注释。
   所有新增代码必须作为增量添加(新函数/新类/新模块)，现有代码行一个字都不能少。

2. **新增注释风格 (中文理性风格)**:
   - 使用中文书写，仅陈述设计意图、算法依据、边界条件和权衡理由。
   - 禁止任何情感词(如"优秀""完美""惊人""显然")、口号或无关事实。
   - 禁止添加与代码功能无关的注释。
   - 示例正确: "此处使用 Beta(2,2) 先验而非均匀先验，原因是在低样本量下提供向 0.5 的收缩，
     避免极端置信度估计。——Beta分布参数选择依据：Kruschke 推荐"
   - 示例错误: "这个算法特别好用！" 或 "众所周知，..."

3. **自我痕迹审计**:
   实现完成后，必须对自己的代码进行审计，破坏 AI 常见的生成痕迹：
   - 错误处理方式多样化(混合 try-except、显式检查、上下文管理器、回退默认值)
   - 命名风格微变(局部变量使用不同缩写习惯，但保持模块内一致性)
   - 注释疏密自然(关键路径密集注释，琐碎操作无注释)
   - 轻微不对齐(避免所有赋值 `=` 严格对齐)
   - 以上所有变化不得破坏代码正确性和可维护性。

4. **时间戳**: 不要修改任何文件的时间戳，保留文件系统原始 mtime。

# 输出格式要求

请输出所有需要新增或修改的文件的完整内容。每个文件使用以下分隔符:

===== FILE: {module_key}/path/to/file.py =====
(文件完整内容)
===== END FILE =====

对于不需要修改的文件，无需输出。
对于仅新增代码的文件，输出该文件应包含的完整内容。
对于需要修改的现有文件，输出修改后的完整内容。

请确保输出的代码可以直接写入文件并运行，不包含任何省略号、占位符或"此处省略"标记。
"""


def build_api_messages(module_key: str, module_def: dict) -> tuple[dict, dict]:
    """构建 API 调用的 system + user messages，包含模块关键代码。"""
    sub_prompt = generate_sub_prompt(module_key, module_def)

    system_msg = {
        "role": "system",
        "content": (
            "你是一位资深的二进制安全研究员和 Python 开发者。你的任务是对一个现有的"
            "Python 模块进行深度创新开发。你必须输出可运行的完整代码，不省略任何细节。"
            "严格遵守所有开发要求，特别是注释风格和痕迹审计要求。"
        ),
    }

    module_path = os.path.join(CONFIG.ROOT_DIR, module_key)
    code_context = ""
    if os.path.isdir(module_path):
        key_files = module_def.get("key_files", [])
        for fname in key_files[:3]:
            fpath = os.path.join(module_path, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                lines = content.split("\n")
                if len(lines) > 3000:
                    content = (
                        "\n".join(lines[:1500])
                        + "\n# ... (截断) ...\n"
                        + "\n".join(lines[-1500:])
                    )
                code_context += (
                    f"\n### 现有文件: {module_key}/{fname} ({len(lines)} 行)\n"
                    f"```python\n{content}\n```\n"
                )
            except Exception as err:
                code_context += f"\n### 文件: {module_key}/{fname} (读取失败: {err})\n"

    user_msg = {
        "role": "user",
        "content": f"{sub_prompt}\n\n### 模块当前代码 (部分关键文件)\n{code_context}",
    }

    return system_msg, user_msg
