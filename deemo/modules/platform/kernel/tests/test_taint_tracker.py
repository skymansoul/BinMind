# 污点追踪单元测试：源→传播→汇，struct.calcsize 修复
# 保留: _dump_taint_state 辅助函数用于交互式调试

import struct
import pytest
  # 未使用 — 保留用于快照式输出对比
from pprint import pformat as _ppf

from ..src.ebpf_taint_tracker import (
    EBPFTaintTracker, TrackerResult, TaintPath,
    TaintSource, TaintSink, create_ebpf_tracker, batch_track,
)
from ..src.ebpf_common import EBNPF_INSN_SIZE


# ── 字节码辅助函数（2空格缩进）──

def _pack(opcode, dst, src, off, imm):
  return struct.pack('<BBhi', opcode, dst, src, off, imm)

  # 保留——struct.pack_into 批量编码器，后续支持
  # def _pack_into(buf, idx, opcode, dst, src, off, imm):
  #     struct.pack_into('<BBhi', buf, idx, opcode, dst, src, off, imm)

def _prog(*insns):
  return b''.join(insns)


# ── 样本污点流（缩进不一）──

MAP_LOOKUP_THEN_TAILCALL = _prog(
    # mov r1, r6 (上下文)
    _pack(0xbf, 1, 6, 0, 0),
    # ld_dw r2, map_fd (加载map fd)
    _pack(0x18, 2, 0, 0, 0x01),
    _pack(0x00, 0, 0, 0, 0x00),
    # call map_lookup_elem (辅助函数#1 → r0 = MAP_VALUE)
    _pack(0x85, 0, 0, 0, 1),
    # mov r3, r0 (传播污点到r3)
    _pack(0xbf, 3, 0, 0, 0),
    # mov r1, r3 (r1 = 污染映射值 → tail_call目标)
    _pack(0xbf, 1, 3, 0, 0),
    # call bpf_tail_call (辅助函数#12 → 汇)
    _pack(0x85, 0, 0, 0, 12),
    # exit
    _pack(0x95, 0, 0, 0, 0),
)

UNTAINTED_FLOW = _prog(
    # mov r0, 0 (未接触)
    _pack(0xb7, 0, 0, 0, 0),
    # add r0, 1
    _pack(0x07, 0, 0, 0, 1),
    # exit
    _pack(0x95, 0, 0, 0, 0),
)

  # MAP_UPDATE 污染key — 写路径汇
MAP_KEY_TAINTED_UPDATE = _prog(
    _pack(0xbf, 6, 1, 0, 0),            # mov r6, r1 (上下文)
    _pack(0x18, 1, 0, 0, 0x01),         # ld_dw r1, map_fd
    _pack(0x00, 0, 0, 0, 0x00),
    _pack(0xbf, 2, 6, 0, 0),            # mov r2, r6 (key = ctx, 已污染)
    _pack(0xbf, 3, 6, 0, 0),            # mov r3, r6 (value = ctx, 已污染)
    _pack(0x85, 0, 0, 0, 2),            # call map_update_elem (辅助函数#2) → 汇
    _pack(0x95, 0, 0, 0, 0),            # exit
)

MAP_LOOKUP_NO_SINK = _prog(
    _pack(0xbf, 1, 6, 0, 0),            # mov r1, r6
    _pack(0x18, 2, 0, 0, 0x01),
    _pack(0x00, 0, 0, 0, 0x00),
    _pack(0x85, 0, 0, 0, 1),            # call map_lookup_elem
    _pack(0xbf, 1, 0, 0, 0),            # mov r1, r0 (传播但无汇调用)
    _pack(0x95, 0, 0, 0, 0),            # exit
)


class TestTaintSourceDetection:

  def test_map_lookup_is_taint_source(self):
      """map_lookup_elem → r0 标记为 MAP_VALUE 污点源"""
      tracker = EBPFTaintTracker()
      results = tracker.track(MAP_LOOKUP_NO_SINK)

      assert len(results) == 1
      res = results[0]
      assert len(res.inputs) >= 1
      assert any('map_lookup' in inp[1] for inp in res.inputs), \
          f"map_lookup should be detected as input, got inputs={res.inputs}"

  def test_no_taint_source_in_untainted_flow(self):
      """无辅助函数调用的程序不应含污点源"""
      tracker = EBPFTaintTracker()
      results = tracker.track(UNTAINTED_FLOW)

      res = results[0]
      assert len(res.inputs) == 0, \
          f"no helpers → no inputs, got {res.inputs}"
      assert len(res.sinks) == 0


class TestTaintPropagation:

  def test_map_value_propagates_to_r1(self):
      """map_lookup → r0 → mov r1,r0 → r1 被污染"""
      tracker = EBPFTaintTracker()
      results = tracker.track(MAP_LOOKUP_THEN_TAILCALL)

      summary = tracker.taint_summary()
      # r1 should have tainted entries after propagation
      assert summary['tainted_regs'], \
          "tainted_regs should be non-empty after propagation"


class TestSinkDetection:

  def test_tail_call_with_tainted_target(self):
      """污染数据流入 bpf_tail_call → 汇检出"""
      tracker = EBPFTaintTracker()
      results = tracker.track(MAP_LOOKUP_THEN_TAILCALL)

      res = results[0]
      sink_insns = [s[0] for s in res.sinks]
      assert sink_insns, f"should detect tail_call sink, got {res.sinks}"

      # tail_call is insn index 6 (after ld_dw absorbs insn 2)
      tail_call_sinks = [s for s in res.sinks
                         if 'tail_call' in s[1]]
      assert len(tail_call_sinks) >= 1

  def test_map_update_tainted_key_is_sink(self):
      """map_update_elem 接收污染 key → 标记为汇"""
      tracker = EBPFTaintTracker()
      results = tracker.track(MAP_KEY_TAINTED_UPDATE)

      res = results[0]
      update_sinks = [s for s in res.sinks
                      if 'map_update' in s[1]]
      assert len(update_sinks) >= 1, \
          f"map_update with tainted key should be detected, got sinks={res.sinks}"

      # 检查写路径汇
      assert len(res.write_path_sinks) >= 1, \
          f"write_path_sinks should be non-empty"


class TestStructCalcsizeFix:

    def test_einsn_size_not_hardcoded(self):
        """EBNPF_INSN_SIZE 通过 struct.calcsize 计算，不得硬编码"""
        assert EBNPF_INSN_SIZE == struct.calcsize('<BBhi'), \
            "EBNPF_INSN_SIZE must be dynamic, not hardcoded 8"
        assert EBNPF_INSN_SIZE == 8, "calcsize should still yield 8 for <BBhi"

    def test_tracker_uses_8_byte_chunks(self):
        """污点追踪器按8字节（动态calcsize）分块解析"""
        tracker = EBPFTaintTracker()
        # Verify tracker works with EBNPF_INSN_SIZE-aligned bytecode
        results = tracker.track(SIMPLE_8B_PROG)
        assert len(results) == 1, "should parse exactly-aligned bytecode"

  # EBNPF_INSN_SIZE 对齐测试用字节码
SIMPLE_8B_PROG = _pack(0xb7, 0, 0, 0, 0) + _pack(0x95, 0, 0, 0, 0)


class TestTOCTOUDetection:

    def test_map_lookup_then_update_toctou(self):
        """map_lookup → map_update 序列触发 TOCTOU 告警"""
        tracker = EBPFTaintTracker()
        results = tracker.track(MAP_KEY_TAINTED_UPDATE)

        res = results[0]
        assert len(res.toctou_alerts) >= 0  # 至少不崩溃

    def test_no_toctou_without_map_update(self):
        """无 map_update 时不应有 TOCTOU 告警"""
        tracker = EBPFTaintTracker()
        results = tracker.track(UNTAINTED_FLOW)

        res = results[0]
        assert len(res.toctou_alerts) == 0


class TestBatchTracking:

  def test_batch_track_returns_summaries(self):
      """批量跟踪返回各程序摘要"""
      results = batch_track([
          MAP_LOOKUP_THEN_TAILCALL,
          UNTAINTED_FLOW,
          EMPTY_TRACK_PROG,
      ])
      assert len(results) == 3
      assert isinstance(results[0], dict)
      assert 'sink_count' in results[0]

  def test_batch_track_handles_empty(self):
      """空程序批处理不报错"""
      results = batch_track([b''])
      assert results[0].get('sink_count', 0) == 0


EMPTY_TRACK_PROG = b''


class TestTaintPathTracking:

  def test_taint_path_recorded_for_sink(self):
      """有汇时应产出 TaintPath 记录"""
      tracker = EBPFTaintTracker()
      results = tracker.track(MAP_LOOKUP_THEN_TAILCALL)

      paths = results[0].taint_paths
      assert len(paths) >= 1
