# 修改记录:
# 2025-08-03 14:42 - 增加 taint 子命令，桥接 MMIO→内核→侧信道污点追踪

"""
platform/ 统一命令行入口。

子命令:
  analyze   — 跨平台层分析 (firmware + kernel + hardware + mobile + malware + sc)
  correlate — 对已有分析结果做跨层关联
  provenance — 二进制来源追踪与版本格查询
  diff      — OTA 差分安全分类与漏洞引入定位
  taint     — MMIO→内核→侧信道跨层污点传播追踪

用法:
  python -m platform.main analyze --firmware fw.bin --kernel vmlinux
  python -m platform.main correlate --findings results.json
  python -m platform.main provenance --sbom sbom.json --hash abc123
  python -m platform.main diff --old v1.bin --new v2.bin
  python -m platform.main taint --mmio 0xfed00000 --ebpf sys_read
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )


def cmd_analyze(args) -> int:
    """跨平台层统一分析。"""
    from platform.platform_orchestrator import PlatformOrchestrator, PlatformLayer

    orch = PlatformOrchestrator(target_id=args.target or f"cli_{int(time.time())}")

    layer_map = {
        'firmware': (PlatformLayer.FIRMWARE, args.firmware),
        'kernel': (PlatformLayer.KERNEL, args.kernel),
        'hardware': (PlatformLayer.HARDWARE, args.hardware),
        'mobile': (PlatformLayer.MOBILE, args.mobile),
        'malware': (PlatformLayer.MALWARE, args.malware),
        'smart_contract': (PlatformLayer.SMART_CONTRACT, args.smart_contract),
    }
    registered = 0
    for name, (layer, path) in layer_map.items():
        if path and os.path.exists(path):
            orch.register_target(layer, path)
            registered += 1

    if registered == 0:
        print("error: at least one target path is required")
        print("usage: analyze --firmware fw.bin --kernel vmlinux ...")
        return 1

    if args.dry_run:
        results = orch.dry_run()
        print(json.dumps(results, indent=2))
        return 0

    def _progress(stage: str, pct: float) -> None:
        print(f"  [{pct * 100:3.0f}%] {stage}")

    orch.on_progress(_progress)
    report = orch.run()

    # 输出
    output = {
        'target_id': report.target_id,
        'elapsed_sec': round(report.total_elapsed_sec, 3),
        'layers': {
            layer.name: {
                'status': result.status.value,
                'findings_count': len(result.findings),
                'vuln_nodes': len(result.vuln_nodes),
                'elapsed_sec': round(result.elapsed_sec, 3),
                'error': result.error,
            }
            for layer, result in report.layers.items()
        },
        'layer_risks': {k.name: round(v, 4) for k, v in report.layer_risks.items()},
        'graph_summary': report.summary.get('graph_summary', {}),
        'cross_layer_edges': report.summary.get('cross_layer_edges', 0),
        'top_risk_paths': [
            {'path': path, 'risk': round(risk, 4)}
            for path, risk in report.top_risk_paths
        ],
    }

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"report written to {args.output}")
    else:
        print(json.dumps(output, indent=2, ensure_ascii=False))

    return 0


def cmd_correlate(args) -> int:
    """跨层关联——将已有分析结果加载到传播图并运行规则引擎。"""
    from platform.propagation_graph import PropagationGraph, PlatformLayer, VulnNode
    from platform.cross_platform_correlator import CrossPlatformCorrelator

    graph = PropagationGraph()
    correlator = CrossPlatformCorrelator()

    if args.findings:
        with open(args.findings, 'r') as f:
            data = json.load(f)
        # 期望格式: {"layer": "firmware", "findings": [...]}
        ctx = CrossPlatformCorrelator.build_context_from_analysis(
            firmware_findings=data.get('firmware'),
            kernel_findings=data.get('kernel'),
            hardware_findings=data.get('hardware'),
            malware_findings=data.get('malware'),
        )
        new_edges = correlator.correlate(graph, ctx)
        print(f"cross-layer edges discovered: {new_edges}")
        print(json.dumps(graph.summary(), indent=2))
    else:
        print("error: --findings is required for correlate")
        return 1

    return 0


def cmd_provenance(args) -> int:
    """二进制来源追踪——构建 SBOM 依赖图并与版本格关联。"""
    from platform.binary_provenance import (
        ProvenanceGraph, ProvenanceNode, DependencyEdge, ProvenanceLatticeIntegrator,
    )
    from platform.version_lattice import VersionLattice

    pg = ProvenanceGraph()
    lattice = VersionLattice()

    if args.sbom:
        with open(args.sbom, 'r') as f:
            sbom = json.load(f)
        for comp in sbom.get('components', []):
            node = ProvenanceNode(
                purl=comp.get('purl', f"pkg:generic/{comp.get('name', 'unknown')}@{comp.get('version', '0')}"),
                name=comp.get('name', 'unknown'),
                version=comp.get('version', '0'),
                supplier=comp.get('supplier', ''),
                binary_hash=comp.get('hash', ''),
                vuln_ids=set(comp.get('vulns', [])),
            )
            pg.add_component(node)
        for dep in sbom.get('dependencies', []):
            pg.add_dependency(DependencyEdge(
                source_purl=dep['source'], target_purl=dep['target'],
                dependency_type=dep.get('type', 'runtime'),
            ))

    if args.hash:
        integrator = ProvenanceLatticeIntegrator(pg, lattice)
        vulns = pg.transitive_vulnerabilities(args.hash)
        print(f"transitive vulnerabilities: {sorted(vulns)}")
        paths = integrator.find_vulnerable_dependency_paths(
            args.hash, next(iter(vulns)) if vulns else '', max_depth=5,
        )
        for p in paths:
            print(f"  path: {' → '.join(p)}")

    print(json.dumps(pg.summary(), indent=2))
    return 0


def cmd_diff(args) -> int:
    """OTA 差分安全分类——桥接 ota_diff_analyzer 与 VersionLattice。"""
    from platform.diff_lattice_bridge import DiffLatticeBridge
    from platform.version_lattice import VersionLattice
    from platform.firmware.ota_diff_analyzer import OTADiffResult

    if not args.old or not args.new:
        print("error: --old and --new are required for diff")
        return 1

    lattice = VersionLattice()
    bridge = DiffLatticeBridge(lattice)

    # 若 old/new 是可解析的 diff JSON，直接加载；否则运行 ota_diff_analyzer
    if args.diff_json:
        with open(args.diff_json, 'r') as f:
            diff_data = json.load(f)
        # 简易构造 OTADiffResult——实际使用时建议直接调 ota_diff_analyzer
        print("diff classification requires ota_diff_analyzer output")
        print(f"bridge ready: {lattice.summary()}")
    else:
        old_node, new_node = bridge.ingest_diff(
            args.old, args.new,
            OTADiffResult(old_file=args.old, new_file=args.new, diffs=[]),
            old_version_tag=args.old_tag or '',
            new_version_tag=args.new_tag or '',
        )
        print(f"old: {old_node.node_id}")
        print(f"new: {new_node.node_id}")
        print(f"classifications: {bridge.classification_summary}")

    return 0


def cmd_taint(args) -> int:
    """跨层污点传播追踪。"""
    from platform.taint_bridge import TaintBridge

    bridge = TaintBridge()

    if args.mmio:
        for spec in args.mmio:
            bridge.register_mmio_source(spec, byte_count=args.mmio_bytes or 8)

    if args.ebpf:
        for hook in args.ebpf:
            bridge.register_kernel_hook(
                hook, intercepts=args.intercept_regs or ['RAX'],
            )

    if args.sidechannel:
        for channel in args.sidechannel:
            bridge.register_sidechannel_leak(
                channel, leaks=args.leak_slots or ['RAX[0]'],
            )

    if args.sink:
        bridge.register_userspace_sink(args.sink, source_hops=args.sink_sources or [])

    # 追踪路径
    source = args.source or (args.mmio[0] if args.mmio else '')
    if source:
        paths = bridge.trace_paths(source=source)
        print(f"taint paths from {source}: {len(paths)} found")
        for i, path in enumerate(paths[:10]):
            hop_desc = ' → '.join(
                f"[{h.direction.value}]" for h in path.hops
            )
            print(f"  path {i}: {hop_desc}")
            print(f"    confidence: {path.joint_confidence:.4f}")
    else:
        print(f"registered hops: {bridge.hop_count_by_direction()}")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='platform',
        description='BinMind cross-platform security analysis CLI',
    )
    parser.add_argument('-v', '--verbose', action='store_true')

    sub = parser.add_subparsers(dest='command', title='commands')

    # --- analyze ---
    p_analyze = sub.add_parser('analyze', help='cross-platform analysis')
    p_analyze.add_argument('--target', help='target system identifier')
    p_analyze.add_argument('--firmware', help='firmware image path')
    p_analyze.add_argument('--kernel', help='kernel image / vmlinux path')
    p_analyze.add_argument('--hardware', help='hardware description or trace file')
    p_analyze.add_argument('--mobile', help='mobile APK/IPA path')
    p_analyze.add_argument('--malware', help='malware sample path')
    p_analyze.add_argument('--smart-contract', help='smart contract bytecode path')
    p_analyze.add_argument('--dry-run', action='store_true', help='check toolchain only')
    p_analyze.add_argument('-o', '--output', help='output JSON path')

    # --- correlate ---
    p_corr = sub.add_parser('correlate', help='cross-layer correlation')
    p_corr.add_argument('--findings', required=True, help='findings JSON path')

    # --- provenance ---
    p_prov = sub.add_parser('provenance', help='binary provenance tracking')
    p_prov.add_argument('--sbom', help='SBOM JSON path')
    p_prov.add_argument('--hash', help='binary hash to query')

    # --- diff ---
    p_diff = sub.add_parser('diff', help='OTA diff security classification')
    p_diff.add_argument('--old', required=True, help='old firmware path')
    p_diff.add_argument('--new', required=True, help='new firmware path')
    p_diff.add_argument('--old-tag', help='old version tag')
    p_diff.add_argument('--new-tag', help='new version tag')
    p_diff.add_argument('--diff-json', help='pre-computed diff JSON')

    # --- taint ---
    p_taint = sub.add_parser('taint', help='cross-layer taint tracking')
    p_taint.add_argument('--mmio', nargs='+', help='MMIO source specs')
    p_taint.add_argument('--mmio-bytes', type=int, default=8)
    p_taint.add_argument('--ebpf', nargs='+', help='eBPF hook specs')
    p_taint.add_argument('--intercept-regs', nargs='+', help='registers intercepted')
    p_taint.add_argument('--sidechannel', nargs='+', help='side-channel leak specs')
    p_taint.add_argument('--leak-slots', nargs='+', help='leaked register slots')
    p_taint.add_argument('--sink', help='userspace sink spec')
    p_taint.add_argument('--sink-sources', nargs='+', help='sink source specs')
    p_taint.add_argument('--source', help='taint source spec for path tracing')

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        'analyze': cmd_analyze,
        'correlate': cmd_correlate,
        'provenance': cmd_provenance,
        'diff': cmd_diff,
        'taint': cmd_taint,
    }
    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    return 1


if __name__ == '__main__':
    sys.exit(main())
