"""时间戳锻造 — 接口预留。

run.py 通过 engine 包引用 forge_timestamps; 实现尚未落地。
此处显式抛出, 避免静默空操作掩盖功能缺失。
"""


from typing import Any, Iterable


def forge_timestamps(changed_files: Iterable[str], **kwargs: Any) -> None:
    """锻造文件时间戳, 分散到合理窗口。实现待补。"""
    raise NotImplementedError("forge_timestamps 尚未实现")
