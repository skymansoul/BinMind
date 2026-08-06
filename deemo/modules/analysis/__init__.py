# analysis/ — 分析引擎层
# 静态分析 → 动态分析 → 符号执行 → 反编译 → 去混淆

# 跨分析融合 / 冗余检测 / 调度优化 (2026 Q3 专利补齐)
def get_cross_analysis_fusion():
    from modules.analysis.cross_analysis_fusion import CrossAnalysisFusion, AnalysisItem, FusedFinding
    return CrossAnalysisFusion, AnalysisItem, FusedFinding

def get_analysis_redundancy_detector():
    from modules.analysis.analysis_redundancy import AnalysisRedundancyDetector
    return AnalysisRedundancyDetector

def get_analysis_schedule_optimizer():
    from modules.analysis.analysis_schedule_opt import AnalysisScheduleOptimizer, StageProfile
    return AnalysisScheduleOptimizer, StageProfile
