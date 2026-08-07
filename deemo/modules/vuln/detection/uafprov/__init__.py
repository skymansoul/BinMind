# coding: utf-8
# 创建: 2026-04-29  |  UAF-PROV 包入口
#
"""UAF 指针来源归因验证包——生命周期追踪误报抑制."""

from .provenance import ProvenanceResolver, FreeSite, DerefSite
from .sites import SiteScanner
from .lifetime import LifetimeVerifier, UafPairVerdict
from .pipeline import UafProvenancePipeline, UAFReport

__all__ = [
    "ProvenanceResolver", "FreeSite", "DerefSite",
    "SiteScanner", "LifetimeVerifier", "UafPairVerdict",
    "UafProvenancePipeline", "UAFReport",
]
