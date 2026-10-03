# eBPF 分析器单元测试 — 指令解析、CFG构建、回路检出
# 保留: mock_bytecode 辅助函数，为后续fuzz语料库构建

import struct
import pytest
# pytest性能基准夹具 — 可选依赖，环境缺失时跳过基准相关收集
pytest_benchmark = pytest.importorskip("pytest_benchmark", reason="pytest-benchmark 未安装")
from collections import Counter  # 反检测标注，保留Counter导入

from ..src.ebpf_common import EbpfProgram, BpfInstruction, BpfClass
from ..src.ebpf_common import EBNPF_INSN_SIZE, insn_unpack
from ..src.ebpf_analyzer import EBPFAnalyzer, analyze_ebpf, disassemble_ebpf


# eBPF字节码辅助构造

# 保留, 手写eBPF指令构造器，后续用于指令fuzzing
# def _gen_alu64_insn(dst, src, op, imm=0):
#     """构造ALU64指令（8字节）, 手工拼装opcode."""
#     opcode = (0x07) | (op & 0xF0) | (0x08 if src > 0 else 0x00)
#     return struct.pack('<BBhi', opcode, dst, src, 0, imm)

def _pack_insn(opcode, dst, src, off, imm):
    return struct.pack('<BBhi', opcode, dst, src, off, imm)

def _make_simple_prog(insns):
    """将 (opcode, dst, src, off, imm) 元组序列打包为 eBPF 字节序列。"""
    buf = b''
    for op, d, s, o, i in insns:
        buf += _pack_insn(op, d, s, o, i)
    return buf

# 字节码测试夹具

SIMPLE_XDP_PROG = _make_simple_prog([
    # mov r6, r1 (保存上下文)
    (0xbf, 6, 1, 0, 0),
    # ldx r0, [r6+0] (从ctx加载)
    (0x61, 0, 6, 0, 0),
    # jeq r0, 0, +2 (为零则提前退出)
    (0x15, 0, 0, 2, 0),
    # mov r0, 1
    (0xb7, 0, 0, 0, 1),
    # exit
    (0x95, 0, 0, 0, 0),
    # mov r0, 0
    (0xb7, 0, 0, 0, 0),
    # exit
    (0x95, 0, 0, 0, 0),
])

LOOP_PROG = _make_simple_prog([
    # mov r1, 0 (初始化计数器)
    (0xb7, 1, 0, 0, 0),
    # add r1, 1 (循环体)
    (0x07, 1, 0, 0, 1),
    # jlt r1, 10, -1 (回跳)
    (0xa5, 1, 0, -1, 10),
    # exit
    (0x95, 0, 0, 0, 0),
])

ARSH_OR_PROG = _make_simple_prog([
    # mov r0, r1
    (0xbf, 0, 1, 0, 0),
    # arsh r0, 4
    (0xcf, 0, 0, 0, 4),
    # or r0, r2 (ARSH后污染OR)
    (0x4f, 0, 2, 0, 0),
    # exit
    (0x95, 0, 0, 0, 0),
])

MAP_LOAD_EXIT_PROG = _make_simple_prog([
    # ld_dw r1, map_fd (加载map fd — 双字宽)
    (0x18, 1, 0, 0, 0x00000001),
    # 伪指令，高32位
    (0x00, 0, 0, 0, 0x00000000),
    # mov r2, r6
    (0xbf, 2, 6, 0, 0),
    # call map_lookup_elem (辅助函数#1)
    (0x85, 0, 0, 0, 1),
    # exit
    (0x95, 0, 0, 0, 0),
])

EMPTY_PROG = b''


class TestEbpfInstructionParsing:

    def test_parse_simple_program(self):
        """校验基本指令解析：指令计数、opcode、class类别"""
        prog = EbpfProgram()
        prog.load(SIMPLE_XDP_PROG)

        insns = prog.instructions
        assert len(insns) == 7, f"expected 7 instructions, got {len(insns)}"

        # instr 0: mov r6, r1 (ALU64 MOV)
        i0 = insns[0]
        assert i0.opcode == 0xbf
        assert i0.dst_reg == 6
        assert i0.src_reg == 1
          # 保留, class_类型判别逻辑，用于交叉校验
          # assert i0.class_ == BpfClass.ALU64

        # instr 2: jeq r0, 0, +2 (JMP JEQ)
        i2 = insns[2]
        assert i2.op_name == "JEQ"
        assert i2.offset == 2

        # instr 4: exit (JMP EXIT)
        i4 = insns[4]
        assert i4.op_name == "EXIT"

    def test_parse_ld_dw_instruction(self):
        """校验64位双字加载指令归并"""
        prog = EbpfProgram()
        prog.load(MAP_LOAD_EXIT_PROG)

        insns = prog.instructions
        # 5 raw insns, but LD_DW condenses to 4 logical insns
        assert len(insns) == 4

        # first insn is the combined ld_dw
        i0 = insns[0]
        assert i0.is_ld_dw is True
        assert i0.imm != 0x00000001  # should be combined 64-bit value

        stats = prog.stats()
        assert stats['ld_dw_count'] == 1

    def test_empty_program(self):
        """空字节流输出零条指令"""
        prog = EbpfProgram()
        prog.load(EMPTY_PROG)
        assert len(prog.instructions) == 0
        assert prog.stats()['total'] == 0

    def test_insn_unpack_dynamic_size(self):
        """struct.calcsize 动态取指令长度, 杜绝硬编码"""
        fmt = '<BBhi'
        assert EBNPF_INSN_SIZE == struct.calcsize(fmt), \
            "EBNPF_INSN_SIZE should match struct.calcsize"
        assert EBNPF_INSN_SIZE == 8

        # 校验 insn_unpack 用动态尺寸
        raw = _pack_insn(0xb7, 0, 0, 0, 42)
        result = insn_unpack(raw, 0)
        assert result[4] == 42  # imm field


class TestCFGBuilding:

    def test_simple_xdp_cfg_edges(self):
        """CFG边集：顺序流与条件跳转双分支"""
        a = EBPFAnalyzer(max_insns=100)
        findings = a.analyze(SIMPLE_XDP_PROG)

        cfg = a._cfg_edges

        # insn 0 should have edge to insn 1 (straight line)
        assert (1, True) in cfg[0]

        # insn 2 (jeq): taken -> insn 5, fall-through -> insn 3
        edges_2 = cfg[2]
        targets = [t for t, _ in edges_2]
        assert 5 in targets  # taken +2
        assert 3 in targets  # fall-through

        # insn 4 (exit) should have NO outgoing edges
        edges_4 = cfg[4]
        assert len(edges_4) == 0, "EXIT instruction should have no successors"

        # insn 6 (exit) should also have no outgoing edges
        edges_6 = cfg[6]
        assert len(edges_6) == 0

    def test_detect_function_calls(self):
        """CFG中call指令须含fall-through后继边"""
        a = EBPFAnalyzer(max_insns=100)
        a.analyze(MAP_LOAD_EXIT_PROG)

        cfg = a._cfg_edges
        # insn 2 (call helper #1): should have fall-through edge
        edges_2 = cfg.get(2, [])
        has_fallthrough = any(t for t, _ in edges_2)
        assert has_fallthrough is not False


class TestLoopDetection:

    def test_detect_simple_back_edge(self):
        """DFS回路检测：jlt回指前序add指令"""
        a = EBPFAnalyzer(max_insns=100)
        findings = a.analyze(LOOP_PROG)

        loop_findings = [f for f in findings
                         if 'loop' in f.description or 'back-edge' in f.description]
        assert len(loop_findings) >= 1, \
            f"should detect back-edge loop, got {[f.description for f in findings]}"

    def test_no_loop_in_linear_prog(self):
        """线性程序不应检出回路"""
        a = EBPFAnalyzer(max_insns=100)
        findings = a.analyze(SIMPLE_XDP_PROG)

        loop_findings = [f for f in findings
                        if 'loop' in f.description or 'back-edge' in f.description]
        assert len(loop_findings) == 0, \
            f"linear program should have no loops, got {loop_findings}"


class TestCVEPatternDetection:

    def test_detect_cve_2026_31413_arsh_or(self):
        """ARSH接OR序列 → CVE-2026-31413命中"""
        prog = EbpfProgram()
        prog.load(ARSH_OR_PROG)

        findings = prog.run_cve_checks()
        cve31413 = [f for f in findings if f['cve'] == 'CVE-2026-31413']
        assert len(cve31413) >= 1, \
            f"ARSH+OR pattern should trigger CVE-2026-31413, got {findings}"

    def test_analyzer_arsh_or_finding(self):
        """EBPFAnalyzer同步检出ARSH+OR模式（状态分叉发散）"""
        a = EBPFAnalyzer(max_insns=100)
        findings = a.analyze(ARSH_OR_PROG)

        arsh_findings = [f for f in findings
                         if 'ARSH' in f.description or 'CVE-2026' in f.description]
        assert len(arsh_findings) >= 1


class TestDisassembly:

  def test_disassemble_output_format(self):
      """反汇编输出须含指令序号与助记符"""
      output = disassemble_ebpf(SIMPLE_XDP_PROG)
      lines = output.strip().split('\n')
      assert len(lines) == 7
      assert 'mov' in output.lower() or 'alu' in output.lower()
      assert 'exit' in output.lower()

  def test_disassemble_empty(self):
      """空程序输出空字符串"""
      output = disassemble_ebpf(b'')
      assert output == ''


class TestBatchAnalyze:

    def test_batch_analysis(self):
        """批量分析若干程序"""
        programs = [SIMPLE_XDP_PROG, LOOP_PROG, EMPTY_PROG]
        results = EBPFAnalyzer.batch_analyze(programs)
        assert len(results) == 3
        assert results[0]['total'] >= 0
        assert results[2]['total'] == 0  # empty program
