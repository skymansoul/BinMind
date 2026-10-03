#!/usr/bin/env python3
# ai_ml模块CLI入口
# argparse调度: mutation/search/vuln预测/config show

import argparse as _argparse
import sys as _sys
import os as _os
import logging as _logging

# 确保ai_ml根目录在路径中以便直接导入
_ROOT = _os.path.dirname(_os.path.abspath(__file__))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


def _setup(args):
    """从配置或CLI参数设置日志。"""
    try:
        from src.utils.logging_setup import setup_logging
        from src.config import load_config
        cfg = load_config()
        log_cfg = cfg.get('logging', {})
        setup_logging(
            level='DEBUG' if args.debug else log_cfg.get('level', 'INFO'),
            log_file=log_cfg.get('file', 'logs/ai_ml.log'),
            debug=args.debug
        )
    except ImportError as e:
        _logging.basicConfig(level=_logging.DEBUG if args.debug else _logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        _logging.getLogger(__name__).warning(f"config/logging import failed: {e}")


# mutation子命令
def _cmd_mutate(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.mutate")
    _log.info("mutation模式——从stdin或文件加载语料")
    try:
        from ai_mutator import AIMutator
        mut = AIMutator()
        # 加载语料库
        corpus = []
        if args.corpus_file:
            with open(args.corpus_file, 'rb') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        corpus.append(line)
        else:
            # 从stdin读取——每行一个seed(二进制安全)
            import sys
            data = sys.stdin.buffer.read()
            if data:
                corpus = [data]
        if corpus:
            mut.learn_mt(corpus)
        # 执行变异
        if args.seed:
            seed_data = args.seed.encode('utf-8') if isinstance(args.seed, str) else args.seed
        elif corpus:
            seed_data = corpus[0]
        else:
            seed_data = b"\x00" * 64
        result = mut.run_mt(seed_data, count=args.count)
        _log.info(f"变异结果: ok={result.m_ok}, total={result.m_total}, seed={result.m_seed}")
        for mi in result.m_muts:
            _log.info(f"  [{mi.m_type}] conf={mi.m_conf:.2f} len={len(mi.m_mut)}")
        # 输出JSON供下游消费
        import json
        out = {"ok": result.m_ok, "seed": result.m_seed, "total": result.m_total,
               "mutations": [{"type": m.m_type, "conf": m.m_conf, "len": len(m.m_mut)}
                              for m in result.m_muts]}
        print(json.dumps(out, indent=2))
    except Exception as e:
        _log.error(f"变异失败: {e}")
        _sys.exit(1)


# search子命令
def _cmd_search(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.search")
    _log.info("search模式")
    try:
        from deep_search import EmbeddingStore
        store = EmbeddingStore()
        if args.benchmark:
            # 快速基准测试: 插入100随机向量并搜索
            import random, time
            n_insert = 100
            dim = 128
            t0 = time.perf_counter()
            bi = 0
            while bi < n_insert:
                vec = [random.random() for _ in range(dim)]
                store.add_es(f"func_{bi}", vec)
                bi += 1
            t_insert = time.perf_counter() - t0
            query = [random.random() for _ in range(dim)]
            t0 = time.perf_counter()
            results = store.search_es(query, top_k=10)
            t_search = time.perf_counter() - t0
            print(f"基准测试: {n_insert}次插入 @ {t_insert:.3f}s, "
                  f"搜索 @ {t_search:.4f}s, {len(results)}条结果")
        else:
            print("search模式——用--benchmark快速测试或通过API连接")
    except Exception as e:
        _log.error(f"搜索失败: {e}")
        _sys.exit(1)


# vuln子命令
def _cmd_vuln(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.vuln")
    _log.info("vuln预测模式")
    try:
        from vuln_ml import VulnSeverityPredictor
        import json
        predictor = VulnSeverityPredictor(use_rules=True)
        # argparse存储的list是字符串，需安全反序列化
        # 接受JSON dict作为漏洞特征输入
        if args.vuln_data:
            features = json.loads(args.vuln_data)
        else:
            # 默认: 模拟缓冲区溢出
            features = {
                "vuln_type": "buffer_overflow",
                "severity": "HIGH",
                "function_name": "test_func",
                "reachable_from_input": True,
                "is_exported": False,
                "is_hot_path": True,
                "has_attacker_controlled_input": True,
                "no_stack_canary": True,
                "no_nx": False,
                "no_pie": True,
                "no_full_relro": False,
                "no_safe_seh": True,
                "no_cfi": True,
                "no_asan": True,
                "has_exploit": False,
                "dangerous_api_ratio": 0.8,
                "cvss_score": 8.5,
                "exploit_available": False,
                "is_apt_relevant": False,
                "cve_age_days": 30,
            }
        result = predictor.predict(features)
        print(json.dumps(result, indent=2, default=str))
        _log.info(f"预测: {result.get('severity')} (置信度: {result.get('confidence', 0):.2f})")
    except Exception as e:
        _log.error(f"vuln预测失败: {e}")
        _sys.exit(1)


# config子命令
def _cmd_config(args):
    try:
        from src.config import load_config, get
        import json
        if args.show:
            cfg = load_config()
            print(json.dumps(cfg, indent=2, default=str))
        elif args.key:
            val = get(args.key)
            print(f"{args.key} = {val}")
    except ImportError as e:
        print(f"配置不可用: {e}")
        _sys.exit(1)


# CLI构建器
def build_parser():
    parser = _argparse.ArgumentParser(
        prog='ai_ml',
        description='BinMind AI/ML模块——变异/搜索/漏洞预测',
    )
    parser.add_argument('--debug', action='store_true', default=False,
                       help='启用调试日志')
    sub = parser.add_subparsers(dest='command', help='子命令')

    # mutation
    p_mut = sub.add_parser('mutate', help='语料感知变异引擎')
    p_mut.add_argument('--corpus-file', type=str, default=None,
                      help='每行一个seed的语料文件路径')
    p_mut.add_argument('--seed', type=str, default=None,
                      help='待变异的seed输入')
    p_mut.add_argument('--count', type=int, default=5,
                      help='生成变异数量(默认5)')

    # search
    p_src = sub.add_parser('search', help='二进制函数相似性搜索')
    p_src.add_argument('--benchmark', action='store_true', default=False,
                      help='运行搜索引擎快速基准测试')

    # vuln
    p_vul = sub.add_parser('vuln', help='漏洞严重性预测')
    p_vul.add_argument('--vuln-data', type=str, default=None,
                       help='漏洞特征JSON dict')

    # config
    p_cfg = sub.add_parser('config', help='查看配置')
    p_cfg.add_argument('--show', action='store_true', default=False,
                       help='打印完整配置')
    p_cfg.add_argument('--key', type=str, default=None,
                       help='获取指定配置键(点分路径)')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        _sys.exit(0)
    dispatch = {
        'mutate': _cmd_mutate,
        'search': _cmd_search,
        'vuln':   _cmd_vuln,
        'config': _cmd_config,
    }
    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        print(f"未知命令: {args.command}", file=_sys.stderr)
        _sys.exit(1)


if __name__ == '__main__':
    main()
