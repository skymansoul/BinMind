# DepLLM-Crypto 依赖引导误用检测测试集
# 逐层单元测试（图/上下文/启发式/缓存/符号表）后全流水线覆盖。
# LLM路径可选；无API配置时走启发式降级，另含单mock-server LLM测试。
import sys
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.depllm.dependency_graph import (
    DependencyGraph, GraphNode, NodeType, build_dependency_graph,
    trace_dependency_paths, summarize_call_chain, classify_api,
)
from src.depllm.heuristic import score_hit, adjust_with_llm
from src.depllm.llm_validator import LLMValidator
from src.depllm.verdict_cache import VerdictCache, Verdict
from src.depllm.symbol_table import ModuleSymbolTable
from src.depllm.pipeline import (
    DepLLMCryptoAnalyzer, DepFinding, build_dependency_context, filter_findings,
)
from src.crypto_misuse import Misuse

Z = bytes(1)
PAD = bytes([0xAA]) * 32


class TestDependencyGraph:
    def test_node_and_edge(self):
        g = DependencyGraph()
        a = g.new_node(0x10, NodeType.SOURCE, 'rand')
        b = g.new_node(0x40, NodeType.CONSTANT, 'iv')
        c = g.new_node(0x80, NodeType.SINK, 'enc')
        g.add_edge(a, b)
        g.add_edge(b, c)
        assert g.shortest_path([a], [c]) == [a, b, c]

    def test_build_graph_from_misuses(self):
        data = b'RAND_bytes' + PAD + b'\x00' * 16 + PAD + b'Cipher.getInstance'
        # 锚点(IV)位于 RAND_bytes(上游) 与 Cipher.getInstance(下游) 之间
        strings = [(0, 'RAND_bytes'), (41, 'Cipher.getInstance')]
        mus = [Misuse('STATIC_IV', 'N/A', hex(10), 'static iv', 'HIGH')]
        g, anchors = build_dependency_graph(data, strings, mus)
        assert len(anchors) == 1
        assert g.nodes[anchors[0]].offset == 10  # 锚点偏移 = 解析地址
        assert g.nodes_by_type(NodeType.SOURCE)
        assert g.nodes_by_type(NodeType.SINK)

    def test_trace_path_and_summary(self):
        data = b'RAND_bytes' + PAD + b'\x00' * 16 + PAD + b'Cipher.getInstance'
        strings = [(0, 'RAND_bytes'), (41, 'Cipher.getInstance')]
        mus = [Misuse('STATIC_IV', 'N/A', hex(10), 'static iv', 'HIGH')]
        g, anchors = build_dependency_graph(data, strings, mus)
        path = trace_dependency_paths(g, anchors[0])
        summary = summarize_call_chain(path)
        assert 'RAND_bytes' in summary
        assert 'STATIC_IV' in summary
        assert 'Cipher.getInstance' in summary

    def test_classify_api(self):
        assert classify_api('RAND_bytes') == NodeType.SOURCE
        assert classify_api('EVP_EncryptInit') == NodeType.SINK
        assert classify_api('memcpy') == NodeType.TRANSFORM
        assert classify_api('random_text') is None


class TestHeuristic:
    def test_severity_base_ordering(self):
        high = score_hit(Misuse('STATIC_IV', 'N/A', '0x0', 'iv', 'HIGH'),
                         api_proximity=0.0, region_entropy=0.5)
        crit = score_hit(Misuse('WEAK_KEY', 'DES', '0x0', 'key', 'CRITICAL'),
                         api_proximity=0.0, region_entropy=0.5)
        assert crit['confidence'] > high['confidence']

    def test_api_context_raises_confidence(self):
        isolated = score_hit(Misuse('STATIC_IV', 'N/A', '0x0', 'iv', 'HIGH'),
                             api_proximity=0.0, region_entropy=0.5)
        anchored = score_hit(Misuse('STATIC_IV', 'N/A', '0x0', 'iv', 'HIGH'),
                             api_proximity=1.0, region_entropy=0.5)
        assert anchored['confidence'] > isolated['confidence']

    def test_high_entropy_penalty(self):
        random_hit = score_hit(Misuse('STATIC_IV', 'N/A', '0x0', 'iv', 'HIGH'),
                               api_proximity=0.5, region_entropy=0.98)
        structured = score_hit(Misuse('STATIC_IV', 'N/A', '0x0', 'iv', 'HIGH'),
                               api_proximity=0.5, region_entropy=0.40)
        assert structured['confidence'] > random_hit['confidence']

    def test_llm_adjust(self):
        assert adjust_with_llm(0.5, 'confirmed') > 0.5
        assert adjust_with_llm(0.5, 'rejected') < 0.5
        assert adjust_with_llm(0.5, 'uncertain') == 0.5
        assert adjust_with_llm(0.5, 'heuristic_only') == 0.5


class TestVerdictCache:
    def test_hit_and_miss(self):
        vc = VerdictCache(maxsize=4)
        ctx = {'misuse_type': 'STATIC_IV', 'api': 'N/A', 'severity': 'HIGH',
               'upstream_apis': ['rand'], 'downstream_apis': ['enc'],
               'call_chain': 'a', 'region_entropy': 0.5}
        assert vc.get(ctx) is None
        vc.put(ctx, Verdict('confirmed', 'ok'))
        got = vc.get(ctx)
        assert got.verdict == 'confirmed' and got.from_cache
        s = vc.stats()
        assert s['hits'] == 1 and s['misses'] == 1

    def test_key_order_independent(self):
        vc = VerdictCache()
        c1 = {'misuse_type': 'X', 'api': 'A', 'severity': 'HIGH',
              'upstream_apis': ['b', 'a'], 'downstream_apis': ['d'],
              'call_chain': 'c', 'region_entropy': 0.3}
        c2 = {'misuse_type': 'X', 'api': 'A', 'severity': 'HIGH',
              'upstream_apis': ['a', 'b'], 'downstream_apis': ['d'],
              'call_chain': 'c', 'region_entropy': 0.3}
        vc.put(c1, Verdict('rejected', 'x'))
        assert vc.get(c2).verdict == 'rejected'


class TestModuleSymbolTable:
    def test_record_and_cross_unit(self):
        t = ModuleSymbolTable()
        t.record(b'\x01' * 8, 'key', 'a.bin', 0x100)
        lst = t.lookup(b'\x01' * 8)
        assert len(lst) == 1 and lst[0].origin_source == 'a.bin'
        cu, others = t.cross_unit(b'\x01' * 8, 'b.bin')
        assert cu and len(others) == 1 and others[0].origin_source == 'a.bin'
        cu2, _ = t.cross_unit(b'\x01' * 8, 'a.bin')  # 同源不计入
        assert not cu2

    def test_merge_same_source_close_offset(self):
        t = ModuleSymbolTable()
        t.record(b'\x02' * 8, 'key', 'a.bin', 0x100)
        t.record(b'\x02' * 8, 'key', 'a.bin', 0x110)  # 偏移带内 → 合并
        assert len(t.lookup(b'\x02' * 8)) == 1


class TestLLMValidatorDegrade:
    def test_unconfigured(self):
        v = LLMValidator()
        assert not v.is_configured()
        res = v.validate({'misuse_type': 'X'})
        assert res.verdict == 'uncertain' and res.source == 'heuristic'


class TestPipeline:
    def _sample_data(self):
        return (b'RAND_bytes' + PAD + b'EVP_EncryptInit' + PAD +
                b'\x00' * 16 + PAD + bytes.fromhex('0101010101010101') + PAD +
                b'deadbeef' + PAD + b'Cipher.getInstance' + PAD)

    def test_end_to_end_heuristic(self):
        ana = DepLLMCryptoAnalyzer()
        findings = ana.analyze(self._sample_data())
        types = {f.misuse_type for f in findings}
        assert 'STATIC_IV' in types
        assert all(f.llm_verdict == 'heuristic_only' for f in findings)
        static = [f for f in findings if f.misuse_type == 'STATIC_IV'][0]
        assert static.upstream_apis or static.downstream_apis

    def test_filter_findings(self):
        f1 = DepFinding('A', '', '0x0', '', 'HIGH', 0.8, 'heuristic_only', '', False,
                        False, heuristic_conf=0.8)
        f2 = DepFinding('B', '', '0x0', '', 'LOW', 0.2, 'heuristic_only', '', False,
                        False, heuristic_conf=0.2)
        kept = filter_findings([f1, f2], min_conf=0.5)
        assert [f.misuse_type for f in kept] == ['A']

    def test_cross_unit_propagation(self):
        table = ModuleSymbolTable()  # 独立表实例确保确定性
        ana1 = DepLLMCryptoAnalyzer(symbol_table=table)
        ana1.analyze(self._sample_data(), source='unitA.bin')
        ana2 = DepLLMCryptoAnalyzer(symbol_table=table)
        f2 = ana2.analyze(self._sample_data(), source='unitB.bin')
        cross = [f for f in f2 if f.cross_unit]
        assert cross
        assert any('unitA.bin' in o for o in cross[0].cross_unit_origins)

    def test_analyze_file_nonexistent(self):
        ana = DepLLMCryptoAnalyzer()
        assert ana.analyze('/nonexistent/file.bin') == []


class TestPipelineWithMockLLM:
    """Mock OpenAI兼容服务端驱动真实urllib客户端 + 缓存路径。"""
    @staticmethod
    def _serve():
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(n) or b'{}')
                content = '{"verdict": "confirmed", "reason": "real misuse"}'
                resp = json.dumps({'choices': [{'message': {'content': content}}]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_llm_confirms_and_caches(self):
        srv = self._serve()
        try:
            port = srv.server_address[1]
            ana = DepLLMCryptoAnalyzer(base_url='http://127.0.0.1:{}'.format(port),
                                       model='mock', timeout=10)
            data = (b'RAND_bytes' + PAD + b'EVP_EncryptInit' + PAD + b'\x00' * 16 + PAD)
            f1 = ana.analyze(data)
            ana.analyze(data)  # 二遍走缓存命中
            assert any(f.llm_verdict == 'confirmed' for f in f1)
            assert ana.cache_stats()['hits'] >= 1
        finally:
            srv.shutdown()
