"""共享文件读取辅助 — 读取失败统一返回 None。

多个扫描器对项目文件做容错读取, 分散的 try/except 会各自
处理 OSError。收拢为一个入口, 调用方只需判空。
"""


from typing import Optional


def safe_read(path: str) -> Optional[str]:
    """按 UTF-8 容错读取文本文件。失败返回 None, 成功返回内容。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None
