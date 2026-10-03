# 兼容入口：实现迁移至 core/compat/attack_surface，此处聚合重导出。
from modules.core.compat.attack_surface import (
    AttackSurfaceType,
    RiskLevel,
    AttackSurfacePoint,
    AttackSurfaceFinding,
    AttackSurfaceResult,
    AttackSurfaceReport,
    AttackSurfaceMapper,
    AttackSurfaceMapperAlias,
    calculate_surface_metric,
)

__all__ = [
    'AttackSurfaceType',
    'RiskLevel',
    'AttackSurfacePoint',
    'AttackSurfaceFinding',
    'AttackSurfaceResult',
    'AttackSurfaceReport',
    'AttackSurfaceMapper',
    'AttackSurfaceMapperAlias',
    'calculate_surface_metric',
]
