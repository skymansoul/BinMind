# distributed 测试套件
# pytest 自动发现 test_*.py，保持 __init__.py 最小化
# 按组件组织：
#   test_core.py            — Task/Node 数据模型、工具函数、序列化
#   test_circuit_breaker.py — Nygard 三态断路器 CLOSED/OPEN/HALF_OPEN
#   test_rate_limiter.py    — TokenBucket、ConcurrencyLimiter、限流装饰器
#   test_load_balancer.py   — 六种策略 + 一致性哈希环
#   test_elastic_pool.py    — 阈值/预测扩缩策略 + 冷却保护
#   test_thompson_autoscaler.py — Beta 后验更新、汤普森采样
#   test_backpressure.py    — 五种背压策略 + 综合压力指数
#   test_state_machine.py   — 转移表、守卫、动作
#   test_partition.py       — 哈希/范围/轮询分区器、节点注册
#   test_idempotency.py     — 幂等守卫、优先级队列、死信队列
#   test_cli.py             — argparse 分发、子命令路由
#   test_config.py          — YAML 加载、环境变量覆盖、默认值回退
#   test_utils.py           — 序列化、memoize、WorkerConfig
#   test_integration.py     — 跨组件集成流程
#
# 执行: pytest tests/ -v
# 跳过 Redis 依赖: pytest tests/ -v -k "not redis"
