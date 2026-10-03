"""引擎差分测试结果归一化 — 名称、集合、相似度归一化。"""
import re
import json


class ResultNormalizer:

    @staticmethod
    def normalize_function_name(name: str) -> str:
        if not name:
            return ""
        name = name.strip()
        name = re.sub(r"^_+", "", name)
        name = re.sub(r"@\d+$", "", name)
        return name.lower()

    @staticmethod
    def normalize_set(items: list) -> set:
        result: set = set()
        for item in items:
            if isinstance(item, dict):
                key = item.get("name") or item.get("addr") or json.dumps(
                    item, sort_keys=True)
                result.add(str(key))
            else:
                result.add(str(item))
        return result

    @staticmethod
    def jaccard_similarity(a: set, b: set) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        inter = len(a & b)
        union = len(a | b)
        return inter / union if union else 0.0
