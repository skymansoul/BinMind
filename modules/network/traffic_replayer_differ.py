# 响应差分比较器——对原始与重放响应的结构差异进行量化分析
import math
from .traffic_replayer_types import logger


class ResponseDiffer:
    """当同一输入在原始捕获与重放目标上产生不同响应时，差异揭示：
    版本变更、补丁回退、或中间件注入。通过字节直方图余弦相似度和长度比双指标量化。
    """

    @staticmethod
    def compare(original_resp: bytes, replayed_resp: bytes) -> dict:
        if original_resp == replayed_resp:
            return {
                "match": True,
                "classification": "identical",
                "diff_level": "identical",
                "len_delta": 0,
                "length_ratio": 1.0,
                "cosine_similarity": 1.0,
            }

        len_delta = abs(len(original_resp) - len(replayed_resp))
        len_ratio = max(len(original_resp), len(replayed_resp), 1)

        # 字节直方图余弦相似度——快速近似结构差异
        if original_resp and replayed_resp:
            orig_hist = [original_resp.count(i) for i in range(256)]
            repl_hist = [replayed_resp.count(i) for i in range(256)]
            dot = sum(orig_hist[i] * repl_hist[i] for i in range(256))
            norm_a = math.sqrt(sum(h ** 2 for h in orig_hist))
            norm_b = math.sqrt(sum(h ** 2 for h in repl_hist))
            cos_sim = dot / max(norm_a * norm_b, 0.001)
        else:
            cos_sim = 0.0

        if cos_sim > 0.95 and len_delta / len_ratio < 0.05:
            level = "minor"
        elif cos_sim > 0.7:
            level = "moderate"
        else:
            level = "significant"

        return {
            "match": False,
            "classification": level,
            "diff_level": level,
            "len_delta": len_delta,
            "length_ratio": round(len_delta / len_ratio, 4),
            "cosine_similarity": round(cos_sim, 4),
        }
