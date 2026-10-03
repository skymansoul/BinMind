"""stubs 模块定义 — 向后兼容代理层。"""
STUBS = {
    "name": "向后兼容代理层",
    "description": (
        "53 个薄代理文件，将旧版导入路径(from modules.xxx import Y)转发到"
        "modules.core.compat.xxx 的实际实现。含 StubRegistry(桩注册表)、"
        "lazy_loader(冷却重试)、stub_validator(完整性验证)。"
    ),
    "key_files": ["stub_registry.py", "lazy_loader.py", "stub_validator.py"],
    "core_keywords": ["backward compatibility", "proxy", "stub", "adapter"],
    "innovation": {
        "title": "自动桩健康监控与渐进式废弃 (Automated Stub Health Monitor)",
        "rationale": (
            "当前 stubs 是静态代理，StubValidator 仅检查加载完整性。"
            "创新点：(1) 运行时调用追踪：在代理层透明记录每个桩的调用频率和调用者，"
            "识别仍在使用旧路径的外部代码；"
            "(2) 渐进式废弃调度：当桩的调用频率降至阈值以下时，自动生成废弃警告日志；"
            "(3) 桩-to-新API 映射文档自动生成：从桩→compat→实际模块的转发链中"
            "提取新的导入路径，生成迁移指南。"
            "差异点：当前桩层没有使用统计，无法判断哪些桩可以安全删除。"
        ),
        "papers": [
            {"id": "API-Evolution", "title": "Automated API Migration and Compatibility Testing in Evolving Software Systems",
             "venue": "软件工程最佳实践 2024-2026", "key_idea": "API生命周期管理 + 渐进式废弃策略 + 自动迁移路径生成"},
            {"id": "Compat-Test", "title": "Compatibility Layer Testing: Methods and Automated Regression Detection",
             "venue": "软件测试最佳实践 2025", "key_idea": "兼容层回归检测 + 桩调用频率追踪 + 自动废弃决策"},
        ],
    },
}
