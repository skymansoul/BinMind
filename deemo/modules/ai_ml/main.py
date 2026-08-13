#!/usr/bin/env python3
# main.py — ai_ml CLI entry point
# argparse-based dispatch: mutation, search, vuln 预测, config show
# 不拆 — CLI dispatch is a single coherent argparse 树

import argparse as _argparse
import sys as _sys
import os as _os
import logging as _logging

# Ensure ai_ml root is on path for direct imports
_ROOT = _os.path.dirname(_os.path.abspath(__file__))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


def _setup(args):
    """Apply logging setup from config or CLI flags."""
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


# mutation subcommand
def _cmd_mutate(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.mutate")
    _log.info("mutation mode — corpus from stdin or file")
    try:
        from ai_mutator import AIMutator
        mut = AIMutator()
        # Load 语料库
        corpus = []
        if args.corpus_file:
            with open(args.corpus_file, 'rb') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        corpus.append(line)
        else:
            # Read from stdin — one seed per line (binary-safe)
            import sys
            data = sys.stdin.buffer.read()
            if data:
                corpus = [data]
        if corpus:
            mut.learn_mt(corpus)
        # Run mutation
        if args.seed:
            seed_data = args.seed.encode('utf-8') if isinstance(args.seed, str) else args.seed
        elif corpus:
            seed_data = corpus[0]
        else:
            seed_data = b"\x00" * 64
        result = mut.run_mt(seed_data, count=args.count)
        _log.info(f"mutation result: ok={result.m_ok}, total={result.m_total}, seed={result.m_seed}")
        for mi in result.m_muts:
            _log.info(f"  [{mi.m_type}] conf={mi.m_conf:.2f} len={len(mi.m_mut)}")
        # Output as JSON for downstream consumption
        import json
        out = {"ok": result.m_ok, "seed": result.m_seed, "total": result.m_total,
               "mutations": [{"type": m.m_type, "conf": m.m_conf, "len": len(m.m_mut)}
                             for m in result.m_muts]}
        print(json.dumps(out, indent=2))
    except Exception as e:
        _log.error(f"mutation failed: {e}")
        _sys.exit(1)


# search subcommand
_CMD_SEARCH = None
def _cmd_search(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.search")
    _log.info("search mode")
    try:
        from deep_search import EmbeddingStore
        store = EmbeddingStore()
        if args.benchmark:
            # Run a quick benchmark: insert 100 random vectors, search
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
            print(f"benchmark: {n_insert} inserts @ {t_insert:.3f}s, "
                  f"search @ {t_search:.4f}s, {len(results)} results")
        else:
            print("search mode — use --benchmark for quick test or connect via API")
    except Exception as e:
        _log.error(f"search failed: {e}")
        _sys.exit(1)


# vuln subcommand
_CMD_VULN = None
def _cmd_vuln(args):
    _setup(args)
    _log = _logging.getLogger("ai_ml.cli.vuln")
    _log.info("vuln prediction mode")
    try:
        from vuln_ml import VulnSeverityPredictor
        import json
        predictor = VulnSeverityPredictor(use_rules=True)
        # 修复: argparse-stored list is string, needs safer deserialize pattern
        # Accept input as JSON dict with vuln features
        if args.vuln_data:
            features = json.loads(args.vuln_data)
        else:
            # Default: simulate a 缓冲区 overflow
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
        _log.info(f"prediction: {result.get('severity')} (confidence: {result.get('confidence', 0):.2f})")
    except Exception as e:
        _log.error(f"vuln prediction failed: {e}")
        _sys.exit(1)


# config subcommand
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
        print(f"config not available: {e}")
        _sys.exit(1)


# main CLI builder
def build_parser():
    parser = _argparse.ArgumentParser(
        prog='ai_ml',
        description='BinMind AI/ML module - mutation, search, vulnerability prediction',
    )
    parser.add_argument('--debug', action='store_true', default=False,
                       help='enable debug logging')
    sub = parser.add_subparsers(dest='command', help='sub-command')

    # mutation
    p_mut = sub.add_parser('mutate', help='corpus-aware mutation engine')
    p_mut.add_argument('--corpus-file', type=str, default=None,
                      help='path to file with one seed per line')
    p_mut.add_argument('--seed', type=str, default=None,
                      help='seed input to mutate')
    p_mut.add_argument('--count', type=int, default=5,
                      help='number of mutations to generate (default: 5)')

    # search
    p_src = sub.add_parser('search', help='binary function similarity search')
    p_src.add_argument('--benchmark', action='store_true', default=False,
                      help='run a quick benchmark of the search engine')

    # vuln
    p_vul = sub.add_parser('vuln', help='vulnerability severity prediction')
    p_vul.add_argument('--vuln-data', type=str, default=None,
                       help='JSON dict of vulnerability features')

    # config
    p_cfg = sub.add_parser('config', help='view configuration')
    p_cfg.add_argument('--show', action='store_true', default=False,
                       help='print full configuration')
    p_cfg.add_argument('--key', type=str, default=None,
                       help='get a specific config key (dotted path)')

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
        print(f"unknown command: {args.command}", file=_sys.stderr)
        _sys.exit(1)


if __name__ == '__main__':
    main()
