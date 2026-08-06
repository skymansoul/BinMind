"""响应解析与文件写入 — 解析 AI 返回的文件内容并安全写入磁盘。"""
import os
import re
from parallel_deep_dev.config import CONFIG


def parse_and_write_files(module_key: str, response_text: str) -> list[str]:
    """解析 AI 响应中的文件内容并写入磁盘。返回已写入的文件路径列表。"""
    modified_files: list[str] = []

    file_pattern = re.compile(
        r'=====\s*FILE:\s*(.+?)\s*=====\s*\n(.*?)\n=====\s*END\s*FILE\s*=====',
        re.DOTALL,
    )
    matches = file_pattern.findall(response_text)

    if not matches:
        alt_pattern = re.compile(
            r'```(?:python|py)?\s*\n?#+\s*(?:文件|FILE|File):\s*(.+?)\n(.*?)```',
            re.DOTALL,
        )
        matches = alt_pattern.findall(response_text)

    for file_path, file_content in matches:
        file_path = file_path.strip()
        full_path = os.path.join(CONFIG.ROOT_DIR, file_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        if not os.path.abspath(full_path).startswith(os.path.abspath(CONFIG.ROOT_DIR)):
            print(f"[安全] {module_key}: 拒绝写出模块目录之外: {file_path}")
            continue

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(file_content.strip() + "\n")
        modified_files.append(full_path)
        print(f"[写入] {file_path}")

    if not modified_files:
        patch_path = os.path.join(
            CONFIG.ROOT_DIR, module_key, f"_ai_innovation_patch_{module_key}.py"
        )
        os.makedirs(os.path.dirname(patch_path), exist_ok=True)
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(
                f"# AI 生成的创新代码 — 需人工审查后整合\n"
                f"# 模块: {module_key}\n\n{response_text}\n"
            )
        print(
            f"[注意] {module_key}: 未找到标准文件分隔符，"
            f"完整响应已写入 {patch_path}"
        )

    return modified_files
