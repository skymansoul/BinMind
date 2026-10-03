# 兼容入口：实现迁移至 hardware/timing_side_channel，此处聚合重导出。
from modules.hardware.timing_side_channel import (
    TimingIssueSeverity,
    TimingIssueType,
    TimingAnalysisResult,
    TimingSideChannelDetector,
)

__all__ = [
    'TimingIssueSeverity',
    'TimingIssueType',
    'TimingAnalysisResult',
    'TimingSideChannelDetector',
]
