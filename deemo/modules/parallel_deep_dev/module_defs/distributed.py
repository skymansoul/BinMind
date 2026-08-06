"""distributed 模块定义 — 分布式任务调度。"""
DISTRIBUTED = {
    "name": "分布式任务调度",
    "description": (
        "基于 Celery + Redis 的分布式作业执行框架：三优先级队列、Redis 心跳+psutil 负载监控、"
        "结果缓存(TTL)、Cron 调度器(五字段cron解析)、令牌桶/分布式令牌桶限流、"
        "自适应熔断器、一致性哈希负载均衡、弹性伸缩(阈值+预测策略)、"
        "反压控制、优雅关闭(多阶段排空)、Prometheus 兼容指标(无 prometheus_client 依赖)。"
    ),
    "key_files": [
        "worker.py", "src/scheduler.py", "src/rate_limiter.py",
        "src/adaptive_breaker.py", "src/load_balancer.py",
        "src/elastic_pool.py", "src/backpressure.py",
    ],
    "core_keywords": ["distributed scheduling", "rate limiting", "circuit breaker", "auto-scaling", "load balancing"],
    "innovation": {
        "title": "基于汤普森采样的预测性弹性伸缩 + 自适应熔断 + 反压控制",
        "rationale": (
            "当前 elastic_pool.py 使用 ThresholdScalePolicy 和 PredictiveScalePolicy，"
            "但预测策略未利用多臂老虎机进行最优配置选择。借鉴 BandFuzz 的 ML 驱动资源分配："
            "(1) 汤普森采样自动扩缩器：维护每个扩缩动作(扩容/缩容/维持)的 Beta 分布，"
            "根据实际任务完成时间和资源利用率更新后验，实现遗憾最小化；"
            "(2) 自适应熔断器增强：FractionalCircuitBreaker 集成 EMA 趋势检测，"
            "在故障率上升趋势(而非仅超过阈值)时提前触发半开状态。"
            "差异点：现有阈值策略是被动的，汤普森采样可实现前瞻性资源预分配。"
        ),
        "papers": [
            {"id": "arXiv:2507.10845", "title": "BandFuzz: An ML-powered Collaborative Fuzzing Framework",
             "venue": "arXiv 2025", "key_idea": "ML驱动协同模糊测试资源分配"},
            {"id": "Cupid", "title": "Cupid: Automatic Fuzzer Selection for Collaborative Fuzzing",
             "venue": "arXiv 2025", "key_idea": "数据驱动互补模糊器组合 → 显著降低CPU小时"},
            {"id": "Slyp", "title": "Slyp: Agentic Vulnerability Reasoning on COTS Binaries",
             "venue": "arXiv 2026", "key_idea": "MCP工具服务器+ReAct管道 → 分布式任务调度参考架构"},
        ],
    },
}
