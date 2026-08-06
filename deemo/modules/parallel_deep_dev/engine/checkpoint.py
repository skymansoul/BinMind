"""断点续传 — 保存/恢复执行进度，支持中断后继续。"""
import os
import json
from datetime import datetime
from parallel_deep_dev.config import CONFIG

CHECKPOINT_FILE = os.path.join(CONFIG.ROOT_DIR, ".parallel_deep_checkpoint.json")


def save_checkpoint(completed: set[str], failed: set[str], pending: set[str]) -> None:
    """将当前进度写入断点文件。"""
    payload = {
        "timestamp": datetime.now().isoformat(),
        "completed": sorted(completed),
        "failed": sorted(failed),
        "pending": sorted(pending),
    }
    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"[断点] 已保存: {len(completed)} 完成 / {len(failed)} 失败 / {len(pending)} 待处理")
    except OSError as e:
        print(f"[断点] 保存失败: {e}")


def load_checkpoint() -> dict | None:
    """从断点文件恢复上次进度。若无断点返回 None。"""
    if not os.path.isfile(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["completed"] = set(data.get("completed", []))
        data["failed"] = set(data.get("failed", []))
        data["pending"] = set(data.get("pending", []))
        print(
            f"[断点] 恢复: {len(data['completed'])} 完成 / "
            f"{len(data['failed'])} 失败 / {len(data['pending'])} 待处理"
        )
        return data
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"[断点] 读取失败: {e}，将从头开始")
        return None


def clear_checkpoint() -> None:
    """清除断点文件。"""
    try:
        if os.path.isfile(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)
    except OSError:
        pass
