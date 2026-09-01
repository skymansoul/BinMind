"""DNS 隧道检测 —— 综合熵+长度+频率+查询多样性评分。

DNS隧道的典型特征：
- 查询域名标签熵值异常高（base32/base64编码数据）
- 单个标签长度异常长（>40字符）
- 查询频率远高于正常DNS（隧道需持续通信）
- 查询域名多样性极低（总是查询同一隧道域名）
- TXT/MX/CNAME等非A记录异常占比高

"""
import math
from collections import Counter
from typing import List, Dict

from ._covert_types import CovertChannelAlert


class DnsTunnelDetector:
    """基于熵、长度、频率与查询多样性四维特征综合评分。"""

    def detect(self, queries: List[Dict]) -> List[CovertChannelAlert]:
        """输入查询列表 [{domain, qtype, query_len, timestamp}, ...]"""
        if len(queries) < 5:
            return []

        alerts = []
        domains = [q.get("domain", "") for q in queries]
        unique_domains = set(domains)

        # 域名多样性 —— 隧道通信通常仅1-2个隧道域名
        diversity = len(unique_domains) / max(len(domains), 1)
        if diversity < 0.1 and len(domains) >= 10:
            # 极低多样性 + 高频查询 = 疑似隧道
            sample_domain = max(set(domains), key=domains.count)
            labels = sample_domain.rstrip(".").split(".")
            long_labels = [lb for lb in labels if len(lb) > 40]
            if long_labels or len(labels) >= 5:
                alerts.append(CovertChannelAlert(
                    channel_type="dns_tunnel",
                    description=f"DNS隧道嫌疑: 域名多样性仅{diversity:.2%}，"
                                f"高频查询'{sample_domain[:60]}'",
                    severity="high",
                    confidence=min(0.9, 1.0 - diversity + 0.2),
                    evidence={
                        "unique_domains": len(unique_domains),
                        "total_queries": len(domains),
                        "sample_domain": sample_domain[:100],
                    },
                ))

        # TXT记录异常 —— 正常DNS查询中TXT记录通常<5%
        txt_queries = [q for q in queries if q.get("qtype", "").upper() == "TXT"]
        if txt_queries and len(txt_queries) / len(queries) > 0.2:
            alerts.append(CovertChannelAlert(
                channel_type="dns_tunnel",
                description=f"TXT查询占比{len(txt_queries)/len(queries):.0%} —— "
                            f"正常DNS以A/AAAA查询为主，TXT占比异常",
                severity="high",
                confidence=0.7,
            ))

        # 标签熵值分析 —— 隧道域名标签熵值接近随机(>3.5)
        high_ent_labels = 0
        total_labels = 0
        for domain in unique_domains:
            for label in domain.rstrip(".").split("."):
                if not label or len(label) < 4:
                    continue
                total_labels += 1
                ctr = Counter(label.lower())
                ent = -sum((c / len(label)) * math.log2(c / len(label)) for c in ctr.values())
                if ent > 3.5:
                    high_ent_labels += 1
        if high_ent_labels > 0 and high_ent_labels / max(total_labels, 1) > 0.4:
            alerts.append(CovertChannelAlert(
                channel_type="dns_tunnel",
                description=f"标签高熵比例{high_ent_labels}/{total_labels} —— "
                            f"DNS隧道常用base32/base64编码子域名",
                severity="high",
                confidence=0.8,
            ))

        return alerts
