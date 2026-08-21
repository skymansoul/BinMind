# Octagon 抽象域单元测试
#
# 验证 DBM 闭包传播、关系查询、约束构建器、FP过滤器核心逻辑.
# 覆盖 malloc(x);memcpy(,,x) 等价关系、常量传播、差值推导.
#

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

from modules.analysis.static.octagon_domain import OctagonDomain
from modules.analysis.static.octagon_builder import OctagonConstraintBuilder
from modules.analysis.static.octagon_filter import OctagonFPFilter

_PASS = 0
_FAIL = 0


def _check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  [PASS] {name}")
    else:
        _FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def test_dbm_basic():
    """DBM 基本操作: set/get/close."""
    dom = OctagonDomain()
    dom.set_constant("rcx", 64)
    dom.set_constant("rdx", 32)
    dom.finalize_constraints()

    _check("const: rcx=64", dom.query_le("rcx", "zero") is not None,
           f"expected rcx bound, got {dom.query_le('rcx', 'zero')}")
    _check("const: rcx <= rdx", dom.query_le("rcx", "rdx") is False,
           "64 <= 32 should be False")
    _check("const: rdx <= rcx", dom.query_le("rdx", "rcx") is True,
           "32 <= 64 should be True")
    _check("const: diff(rcx,rdx)=32", dom.query_diff("rcx", "rdx") == 32,
           f"got {dom.query_diff('rcx', 'rdx')}")
    _check("const: diff(rdx,rcx)=-32", dom.query_diff("rdx", "rcx") == -32,
           f"got {dom.query_diff('rdx', 'rcx')}")


def test_dbm_equality():
    """等价约束传播: rcx=rdx."""
    dom = OctagonDomain()
    dom.track("rcx")
    dom.track("rdx")
    dom.set_equality("rcx", "rdx")
    dom.finalize_constraints()

    _check("eq: rcx == rdx", dom.query_eq("rcx", "rdx") is True)
    _check("eq: rcx <= rdx", dom.query_le("rcx", "rdx") is True)
    _check("eq: rdx <= rcx", dom.query_le("rdx", "rcx") is True)
    _check("eq: diff=0", dom.query_diff("rcx", "rdx") == 0)


def test_dbm_diff():
    """差值约束: rdx = rcx - 16."""
    dom = OctagonDomain()
    dom.track("rcx")
    dom.track("rdx")
    dom.set_diff("rdx", "rcx", -16)
    dom.finalize_constraints()

    _check("diff: rdx <= rcx", dom.query_le("rdx", "rcx") is True,
           "rdx = rcx-16 -> rdx <= rcx")
    _check("diff: rcx <= rdx is False", dom.query_le("rcx", "rdx") is False,
           "rcx > rdx -> not <=")
    _check("diff: diff(rdx,rcx)=-16", dom.query_diff("rdx", "rcx") == -16)
    _check("diff: diff(rcx,rdx)=16", dom.query_diff("rcx", "rdx") == 16)


def test_dbm_transitive():
    """传递闭包: rdi=rcx, rcx=64 -> rdi=64."""
    dom = OctagonDomain()
    dom.set_constant("rcx", 64)
    dom.track("rdi")
    dom.set_equality("rdi", "rcx")
    dom.finalize_constraints()

    _check("trans: rdi <= rcx", dom.query_le("rdi", "rcx") is True)
    _check("trans: rdi <= zero (64<=0?)", dom.query_le("rdi", "zero") is False,
           "rdi=64 -> 64<=0 is False")
    _check("trans: zero <= rdi (0<=64)", dom.query_le("zero", "rdi") is True)


def test_dbm_join():
    """join 操作: 合并两个域."""
    dom1 = OctagonDomain()
    dom1.set_constant("rcx", 32)
    dom1.finalize_constraints()

    dom2 = OctagonDomain()
    dom2.set_constant("rcx", 128)
    dom2.finalize_constraints()

    joined = dom1.join(dom2)
    joined.finalize_constraints()

    _check("join: rcx not exact const", "rcx" not in joined._const,
           "join of 32 and 128 should lose exact constant")


def test_builder_constant():
    """构建器: mov rcx, 64 -> 常量约束."""
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "operands": ["rcx", "0x40"]},
    ]
    builder = OctagonConstraintBuilder()
    builder.build(instructions)

    dom = builder.domain
    _check("builder: rcx=64 in const", dom._const.get("rcx") == 64,
           f"got {dom._const.get('rcx')}")


def test_builder_equality():
    """构建器: mov rdx, rcx -> 等价."""
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "operands": ["rcx", "0x40"]},
        {"address": 0x1003, "mnemonic": "mov", "operands": ["rdx", "rcx"]},
    ]
    builder = OctagonConstraintBuilder()
    builder.build(instructions)

    dom = builder.domain
    _check("builder: rdx=64 (via alias)", dom._const.get("rdx") == 64,
           f"got {dom._const.get('rdx')}")


def test_builder_alloc_write():
    """构建器: call malloc -> alloc_sites, call memcpy -> write_sites."""
    instructions = [
        {"address": 0x2000, "mnemonic": "call", "operands": ["0x3000 <malloc>"]},
        {"address": 0x2005, "mnemonic": "call", "operands": ["0x3010 <memcpy>"]},
    ]
    builder = OctagonConstraintBuilder()
    builder.build(instructions)

    _check("builder: alloc_site at 0x2000", 0x2000 in builder.alloc_sites,
           f"sites={builder.alloc_sites}")
    _check("builder: alloc reg=rdi", builder.alloc_sites[0x2000] == "rdi")
    _check("builder: write_site at 0x2005", 0x2005 in builder.write_sites,
           f"sites={builder.write_sites}")
    _check("builder: write reg=rdx", builder.write_sites[0x2005] == "rdx")


def test_filter_safe():
    """过滤器: write <= alloc -> safe."""
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "operands": ["rdi", "0x40"]},
        {"address": 0x1003, "mnemonic": "call", "operands": ["0x3000 <malloc>"]},
        {"address": 0x1008, "mnemonic": "mov", "operands": ["rdx", "0x20"]},
        {"address": 0x100b, "mnemonic": "call", "operands": ["0x3010 <memcpy>"]},
    ]
    f = OctagonFPFilter()
    builder = f.build_domain(instructions)

    findings = [{
        "type": "heap_overflow_possible",
        "write_addr": 0x100b,
        "alloc_addr": 0x1003,
        "_snapshot_alloc_addr": 0x1003,
        "size_operand": "rdx",
        "alloc_size": 64,
        "write_size": 32,
    }]
    result = f.filter(findings, builder)
    _check("filter: write(32)<=alloc(64) -> filtered", len(result) == 0,
           f"got {len(result)} survivors")
    _check("filter: stats filtered=1", f.stats["octagon_filtered"] == 1)


def test_filter_overflow():
    """过滤器: write > alloc -> preserved."""
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "operands": ["rdi", "0x10"]},
        {"address": 0x1003, "mnemonic": "call", "operands": ["0x3000 <malloc>"]},
        {"address": 0x1008, "mnemonic": "mov", "operands": ["rdx", "0x100"]},
        {"address": 0x100b, "mnemonic": "call", "operands": ["0x3010 <memcpy>"]},
    ]
    f = OctagonFPFilter()
    builder = f.build_domain(instructions)

    findings = [{
        "type": "heap_overflow_possible",
        "write_addr": 0x100b,
        "alloc_addr": 0x1003,
        "_snapshot_alloc_addr": 0x1003,
        "size_operand": "rdx",
        "alloc_size": 16,
        "write_size": 256,
    }]
    result = f.filter(findings, builder)
    _check("filter: write(256)>alloc(16) -> preserved", len(result) == 1,
           f"got {len(result)} survivors")
    _check("filter: stats passed=1", f.stats["octagon_passed"] == 1)


def test_filter_equal():
    """过滤器: write = alloc (same source) -> safe."""
    instructions = [
        {"address": 0x1000, "mnemonic": "mov", "operands": ["rcx", "0x40"]},
        {"address": 0x1003, "mnemonic": "mov", "operands": ["rdi", "rcx"]},
        {"address": 0x1006, "mnemonic": "call", "operands": ["0x3000 <malloc>"]},
        {"address": 0x100b, "mnemonic": "mov", "operands": ["rdx", "rcx"]},
        {"address": 0x100e, "mnemonic": "call", "operands": ["0x3010 <memcpy>"]},
    ]
    f = OctagonFPFilter()
    builder = f.build_domain(instructions)

    findings = [{
        "type": "heap_overflow_possible",
        "write_addr": 0x100e,
        "alloc_addr": 0x1006,
        "_snapshot_alloc_addr": 0x1006,
        "size_operand": "rdx",
        "alloc_size": 64,
        "write_size": 64,
    }]
    result = f.filter(findings, builder)
    _check("filter: write=alloc (same source) -> filtered", len(result) == 0,
           f"got {len(result)} survivors, stats={f.stats}")


def test_filter_unknown():
    """过滤器: 无 alloc/write site -> unknown (preserved)."""
    instructions = [
        {"address": 0x1000, "mnemonic": "nop", "operands": []},
    ]
    f = OctagonFPFilter()
    builder = f.build_domain(instructions)

    findings = [{
        "type": "heap_overflow_possible",
        "write_addr": 0x9999,
        "alloc_addr": 0x8888,
        "_snapshot_alloc_addr": 0x8888,
        "size_operand": "ecx",
        "alloc_size": 64,
        "write_size": 0,
    }]
    result = f.filter(findings, builder)
    _check("filter: no sites -> preserved", len(result) == 1,
           f"got {len(result)} survivors")
    _check("filter: stats unknown=1", f.stats["octagon_unknown"] == 1)


def test_filter_non_heap():
    """过滤器: non-heap_overflow_possible -> passthrough."""
    instructions = []
    f = OctagonFPFilter()
    builder = f.build_domain(instructions)

    findings = [
        {"type": "heap_overflow", "write_addr": 0x1000},
        {"type": "uaf", "write_addr": 0x2000},
    ]
    result = f.filter(findings, builder)
    _check("filter: non-possible types passthrough", len(result) == 2,
           f"got {len(result)} survivors")


def main():
    print("=" * 60)
    print("Octagon Domain Unit Tests")
    print("=" * 60)

    tests = [
        test_dbm_basic,
        test_dbm_equality,
        test_dbm_diff,
        test_dbm_transitive,
        test_dbm_join,
        test_builder_constant,
        test_builder_equality,
        test_builder_alloc_write,
        test_filter_safe,
        test_filter_overflow,
        test_filter_equal,
        test_filter_unknown,
        test_filter_non_heap,
    ]

    for t in tests:
        print(f"\n--- {t.__name__} ---")
        t()

    print(f"\n{'=' * 60}")
    print(f"Results: {_PASS} PASS, {_FAIL} FAIL")
    print(f"{'=' * 60}")
    return _FAIL == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
