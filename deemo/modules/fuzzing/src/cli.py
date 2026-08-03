#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# — hermit1016: 深重重写，接入全部子模块

"""fuzzing — 命令行入口

统一CLI入口,支持 fault-inject / cluster / coverage / dictionary / harness / evolve
六个子命令。YAML 配置文件通过 --config 指定或自动探测 config/default.yaml。

用法:
    python -m fuzzing.src.cli --config config/default.yaml fault-inject --binary /tmp/test.bin
    python -m fuzzing.src.cli --config config/default.yaml evolve --seed-dir /tmp/seeds

子命令分发策略 (2026-08-02):
    - fault-inject: 调用 FaultInjectionFuzzer.run()
    - cluster:     实例化 FuzzClusterAutoscaler.tick()
    - coverage:    FuzzCoverageVisualizer 解析 JSON 并生成 heatmap
    - dictionary:  DictionaryGenerator 生成 AFL/LibFuzzer 字典
    - harness:     FuzzHarnessOptimizer 生成 C++ harness 骨架
    - evolve:      SeedPopulation.evolve() 遗传算法优化种子
"""

import argparse
import logging
import os
import sys
import time
import json

# 尝试自动发现 config 目录 (相对路径)
def _find_default_config() -> str | None:
    """从当前文件向上查找 config/default.yaml.

    fuzzing/src/cli.py → fuzzing/config/default.yaml 的距离是 ../config/default.yaml
    """
    candidate = os.path.join(os.path.dirname(__file__), '..', 'config', 'default.yaml')
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)
    return None


def _setup_logging(verbose: bool, debug: bool, log_file: str | None = None):
    """统一日志配置 — 控制台 + 可选文件输出.

    格式: [2026-08-02 14:30:00] [fault_injection] INFO: message
    """
    handlers: list[logging.Handler] = [
        logging.StreamHandler(sys.stderr)
    ]
    if log_file:
        os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))

    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def _load_config(config_path: str | None) -> dict:
    """加载 YAML/JSON 配置文件, 失败则返回空字典。

    加载顺序:
    1. 显式 --config 路径
    2. 自动探测 config/default.yaml
    3. 使用硬编码默认值 (见 LOG.md 1680-1683)
    """
    if config_path and os.path.isfile(config_path):
        pass
    elif config_path is None:
        config_path = _find_default_config()
    else:
        print(f"[WARN] 配置文件不存在: {config_path}, 使用默认值", file=sys.stderr)
        config_path = None

    if config_path is None:
        return {}

    try:
        # 检测文件类型 — YAML vs JSON
        if config_path.endswith(('.yaml', '.yml')):
            try:
                import yaml
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            except ImportError:
                # 无 PyYAML 时回退 JSON 解析 (YAML 是 JSON 的超集, 但这里做不了)
                logging.getLogger(__name__).warning(
                    "PyYAML 未安装 — 尝试 JSON 解析 %s", config_path
                )
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        elif config_path.endswith('.json'):
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # 未知扩展名 — 尝试 YAML
            try:
                import yaml
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            except ImportError:
                pass
    except Exception as e:
        print(f"[WARN] 配置加载失败: {e}", file=sys.stderr)
    return {}


def _cmd_fault_inject(args: argparse.Namespace, config: dict) -> int:
    """故障注入 — 比特翻转 / 指令跳过 / NOP-sled / 寄存器翻转.

    默认从 CLI 参数取值, 未指定则从 YAML config 中 fallback。
    """
    from fuzzing.fault_injection_fuzzer import FaultInjectionFuzzer
    log = logging.getLogger("fault_inject")

    binary = args.binary or config.get('fault_injection', {}).get('binary_path', '')
    if not binary or not os.path.isfile(binary):
        log.error("二进制文件不存在: %s", binary)
        return 1

    max_inj = args.max_injections or config.get('fault_injection', {}).get('max_injections', 300)
    fuzzer = FaultInjectionFuzzer(binary)

    if args.quick:
        result = fuzzer.run_quick_skip()
    else:
        result = fuzzer.run(max_injections=int(max_inj))

    log.info("完成: %d 注入点, %d 潜在漏洞, %.2fs",
             result.total_injections, result.vulnerabilities_found, result.elapsed)

    if args.output:
        _dump_result(result, args.output)

    return 0


def _cmd_cluster(args: argparse.Namespace, config: dict) -> int:
    """集群自动伸缩 — 单次 tick 或持续循环."""
    from fuzzing.fuzz_cluster_autoscaler import (
        FuzzClusterAutoscaler, TaskQueue, NodeRegistry
    )
    log = logging.getLogger("cluster")

    queue = TaskQueue()
    registry = NodeRegistry()
    autoscaler = FuzzClusterAutoscaler(registry=registry, queue=queue)

    if args.daemon:
        interval = args.interval or config.get('cluster', {}).get('tick_interval', 5.0)
        log.info("以守护模式启动, tick间隔 %.1fs", interval)
        autoscaler.start(interval=float(interval))
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("收到中断信号, 正在停止...")
        finally:
            autoscaler.stop()
    else:
        result = autoscaler.tick()
        log.info("tick 结果: %s", json.dumps(result, ensure_ascii=False, default=str))

    return 0


def _cmd_coverage(args: argparse.Namespace, config: dict) -> int:
    """覆盖率可视化 — 解析 JSON 并生成 heatmap / HTML 报告."""
    from fuzzing.fuzz_coverage_visualizer import FuzzCoverageVisualizer
    log = logging.getLogger("coverage")

    coverage_file = args.coverage_file or config.get('coverage', {}).get('input_file', '')
    if not coverage_file or not os.path.isfile(coverage_file):
        log.error("覆盖率 JSON 文件不存在: %s", coverage_file)
        return 1

    out_dir = args.output_dir or config.get('coverage', {}).get('output_dir', './coverage_output')
    viz = FuzzCoverageVisualizer(output_dir=out_dir)
    data = viz.parse_coverage_data(coverage_file)
    data.binary_path = args.binary or config.get('coverage', {}).get('binary_path', 'unknown')

    if args.html:
        html_path = viz.export_html_report(data)
        log.info("HTML 报告已生成: %s", html_path)
    else:
        vis = viz.generate_heatmap(data)
        log.info("覆盖率: %.2f%%, 函数: %d/%d",
                 data.coverage_rate * 100,
                 vis.summary.get('covered_functions', 0),
                 vis.summary.get('total_functions', 0))

    return 0


def _cmd_dictionary(args: argparse.Namespace, config: dict) -> int:
    """字典生成 — 二进制分析 + LLM 增强字典输出."""
    from fuzzing.fuzz_dictionary_generator import generate_fuzz_dictionary
    log = logging.getLogger("dictionary")

    binary = args.binary or config.get('dictionary', {}).get('binary_path', '')
    if not binary or not os.path.isfile(binary):
        log.error("二进制文件不存在: %s", binary)
        return 1

    fmt = args.format or config.get('dictionary', {}).get('format', 'json')
    use_llm = not args.no_llm
    out_path = args.output or config.get('dictionary', {}).get('output_path')

    result = generate_fuzz_dictionary(
        binary, output_path=out_path, format_type=fmt, use_llm=use_llm
    )

    if result.get('success'):
        log.info("生成 %d 个字典条目, 格式: %s", result.get('entries_count', 0), fmt)
    else:
        log.error("字典生成失败: %s", result.get('error', 'unknown'))
        return 1

    return 0


def _cmd_harness(args: argparse.Namespace, config: dict) -> int:
    """Harness 优化 — 从二进制生成 C++ fuzz harness."""
    from fuzzing.fuzz_harness_optimizer import FuzzHarnessOptimizer
    log = logging.getLogger("harness")

    binary = args.binary or config.get('harness', {}).get('binary_path', '')
    func = args.func or config.get('harness', {}).get('func_name', '')
    if not binary or not func:
        log.error("需指定 --binary 和 --func")
        return 1

    out = args.output or config.get('harness', {}).get('output_path')
    corpus = args.corpus_dir or config.get('harness', {}).get('corpus_dir')

    opt = FuzzHarnessOptimizer()
    spec = opt.optimize(binary, func, output_path=out, corpus_dir=corpus)

    log.info("Harness 生成: %s, %d 参数, %d 种子",
             spec.func_name, len(spec.params), len(spec.initial_corpus))

    return 0


def _cmd_evolve(args: argparse.Namespace, config: dict) -> int:
    """种子进化 — 遗传算法 (tournament/roulette/elitism).

    从 seed-dir 加载初始种子, 运行 N 代进化, 输出蒸馏后的最佳种子。
    """
    from fuzzing.fuzz_seed_evolution import evolve_seeds
    log = logging.getLogger("evolve")

    seed_dir = args.seed_dir or config.get('seed_evolution', {}).get('seed_dir', '')
    generations = args.generations or config.get('seed_evolution', {}).get('generations', 10)

    seeds: list[bytes] = []
    if seed_dir and os.path.isdir(seed_dir):
        for fn in sorted(os.listdir(seed_dir))[:50]:
            fpath = os.path.join(seed_dir, fn)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, 'rb') as f:
                        seeds.append(f.read()[:1024])
                except OSError:
                    pass

    if not seeds:
        # 无种子目录时生成随机种子作为起点
        log.warning("未提供种子目录, 使用随机种子")
        import random as _r
        seeds = [bytes([_r.randint(0, 255) for _ in range(64)]) for _ in range(10)]

    result = evolve_seeds(seeds, generations=int(generations), use_annealing=not args.no_annealing)
    log.info("进化完成: %d 代, 输出 %d 个最佳种子", generations, len(result))

    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'wb') as f:
            for i, s in enumerate(result):
                f.write(f"# seed_{i:03d}\n".encode())
                f.write(s)
                f.write(b"\n")

    return 0


def _dump_result(result: object, path: str):
    """将 FaultResult 序列化为 JSON 输出."""
    import json as _json
    from dataclasses import asdict
    try:
        d = asdict(result)
    except TypeError:
        d = {
            'success': getattr(result, 'success', True),
            'injection_points': len(getattr(result, 'injection_points', [])),
            'vulnerabilities_found': getattr(result, 'vulnerabilities_found', 0),
            'elapsed': getattr(result, 'elapsed', 0.0),
        }
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        _json.dump(d, f, ensure_ascii=False, indent=2, default=str)


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口 — 解析参数并分发到各子命令处理函数."""

    # ── 全局参数 ──────────────────────────────────────────
    p = argparse.ArgumentParser(
        prog="binmind-fuzzing",
        description="BinMind Fuzzing CLI — 故障注入 / 集群调度 / 覆盖率 / 字典 / Harness / 种子进化",
    )
    p.add_argument("--config", "-c", default=None, help="YAML 配置文件路径")
    p.add_argument("--verbose", "-v", action="store_true", help="INFO 级别日志")
    p.add_argument("--debug", action="store_true", help="DEBUG 级别日志")
    p.add_argument("--log-file", default=None, help="日志文件路径")

    sp = p.add_subparsers(dest="command", help="可用子命令")

    # ── fault-inject ──────────────────────────────────────
    p_fi = sp.add_parser("fault-inject", help="故障注入分析 (比特翻转/指令跳过)")
    p_fi.add_argument("--binary", "-b", required=True, help="目标二进制路径")
    p_fi.add_argument("--max-injections", type=int, default=300, help="最大注入点数 (默认300)")
    p_fi.add_argument("--quick", action="store_true", help="快速模式 (仅指令跳过 + NOP sled)")
    p_fi.add_argument("--output", "-o", default=None, help="结果 JSON 输出路径")

    # ── cluster ───────────────────────────────────────────
    p_cl = sp.add_parser("cluster", help="集群自动伸缩控制")
    p_cl.add_argument("--daemon", action="store_true", help="以守护模式持续运行")
    p_cl.add_argument("--interval", type=float, default=5.0, help="tick 间隔(秒)")

    # ── coverage ──────────────────────────────────────────
    p_cv = sp.add_parser("coverage", help="覆盖率可视化")
    p_cv.add_argument("--coverage-file", "-f", required=True, help="覆盖率 JSON 文件")
    p_cv.add_argument("--binary", "-b", default=None, help="关联的二进制路径")
    p_cv.add_argument("--html", action="store_true", help="输出 HTML 报告")
    p_cv.add_argument("--output-dir", "-o", default=None, help="输出目录")

    # ── dictionary ────────────────────────────────────────
    p_dc = sp.add_parser("dictionary", help="AFL/LibFuzzer 字典生成")
    p_dc.add_argument("--binary", "-b", required=True, help="目标二进制路径")
    p_dc.add_argument("--format", "-f", default="json",
                      choices=["afl", "libfuzzer", "honggfuzz", "json", "raw"])
    p_dc.add_argument("--no-llm", action="store_true", help="禁用 LLM 增强")
    p_dc.add_argument("--output", "-o", default=None, help="输出文件路径")

    # ── harness ───────────────────────────────────────────
    p_hr = sp.add_parser("harness", help="C++ Fuzz Harness 生成")
    p_hr.add_argument("--binary", "-b", required=True, help="目标二进制路径")
    p_hr.add_argument("--func", "-f", required=True, help="目标函数名")
    p_hr.add_argument("--output", "-o", default=None, help="Harness 输出路径")
    p_hr.add_argument("--corpus-dir", default=None, help="语料种子输出目录")

    # ── evolve ────────────────────────────────────────────
    p_ev = sp.add_parser("evolve", help="遗传算法种子进化")
    p_ev.add_argument("--seed-dir", "-s", default=None, help="初始种子目录")
    p_ev.add_argument("--generations", "-g", type=int, default=10, help="进化代数")
    p_ev.add_argument("--no-annealing", action="store_true", help="禁用模拟退火")
    p_ev.add_argument("--output", "-o", default=None, help="最佳种子输出路径")

    args = p.parse_args(argv)

    # ── 日志初始化 ────────────────────────────────────────
    _setup_logging(args.verbose, args.debug, args.log_file)
    log = logging.getLogger("cli")

    # ── 配置加载 ──────────────────────────────────────────
    config = _load_config(args.config)
    if config:
        log.info("已加载配置: %s", args.config or _find_default_config())

    if not args.command:
        p.print_help()
        return 1

    # ── 子命令分发 ────────────────────────────────────────
    log.info("执行子命令: %s", args.command)
    _commands = {
        "fault-inject": _cmd_fault_inject,
        "cluster": _cmd_cluster,
        "coverage": _cmd_coverage,
        "dictionary": _cmd_dictionary,
        "harness": _cmd_harness,
        "evolve": _cmd_evolve,
    }
    handler = _commands.get(args.command)
    if handler is None:
        log.error("未知子命令: %s", args.command)
        return 1

    try:
        return handler(args, config)
    except Exception as e:
        log.exception("子命令 %s 执行失败", args.command)
        return 1


if __name__ == "__main__":
    sys.exit(main())
