"""
样本管理器 - 目录结构初始化。

提供样本库子目录创建与 README 自动生成，独立于 SampleManager 类。
"""


import os
from typing import Dict

from .sample_manager_types import SAMPLE_DIRS


def init_sample_directories(base_dir: str) -> Dict[str, str]:
    """初始化样本库目录结构。"""
    created = {}
    for dirname, description in SAMPLE_DIRS.items():
        dirpath = os.path.join(base_dir, dirname)
        os.makedirs(dirpath, exist_ok=True)
        readme_path = os.path.join(dirpath, 'README.md')
        if not os.path.exists(readme_path):
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(f'# {description}\n\n放置 {description} 的二进制文件。\n')
        created[dirname] = dirpath
    return created
