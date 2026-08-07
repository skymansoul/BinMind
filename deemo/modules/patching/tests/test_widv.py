# 核心创新模块单元测试 — WIDV 写侧区间与双向交汇
"""覆盖:
  - 汇编规范化(MinGW格式/ABI)
  - 写侧区间追踪(strcpy无界/常量/taint)
  - 双向交汇(必定溢出/必定安全/重叠)
  - 循环写检测(守卫安全/无守卫溢出)
用法: python -m pytest tests/test_widv.py -v  (或直接python运行)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..'))

from src.asm_normalize import normalize_asm_lines, normalize_call
from src.write_interval_tracker import WriteIntervalTracker, WriteInterval
from src.bidirectional_interval import BidirectionalIntervalVerifier
from src.loop_write_detector import LoopWriteDetector


class TestAsmNormalize(unittest.TestCase):
    def test_call_minGW_format(self):
        line = '   140001511:\te8 a2 81 00 00 \tcall   1400096b8 <malloc>'
        self.assertEqual(normalize_call(line), 'call malloc')

    def test_call_sysv_format(self):
        line = '   call   malloc@plt'
        self.assertEqual(normalize_call(line), 'call malloc')

    def test_normalize_list(self):
        lines = [
            '   140001511:\te8 a2 81 00 00 \tcall   1400096b8 <malloc>',
            '   140001516:\t48 89 45 f0 \tmov    QWORD PTR [rbp-0x10],rax',
        ]
        out = normalize_asm_lines(lines)
        self.assertTrue(any('call malloc' in l for l in out))
        # QWORD PTR → QWORD ptr (ptr统一小写, 供下游lower后匹配)
        self.assertTrue(any('QWORD ptr' in l for l in out))
        self.assertTrue(any('qword ptr' in l.lower() for l in out))


class TestWriteInterval(unittest.TestCase):
    def setUp(self):
        self.tracker = WriteIntervalTracker()

    def test_constant_write(self):
        asm = ['140001000: b9 08 00 00 00 mov ecx,0x8',
               '140001005: 49 89 c8 mov r8,rcx',
               '140001008: 48 89 c1 mov rcx,rax',
               'call memcpy']
        w = self.tracker.trace(asm, 3, 'memcpy')
        self.assertTrue(w.is_known)
        self.assertEqual(w.high, 8)

    def test_unbounded_strcpy(self):
        asm = ['call strcpy']
        w = self.tracker.trace(asm, 0, 'strcpy')
        self.assertFalse(w.is_known)
        self.assertTrue(w.is_tainted)

    def test_unknown_write(self):
        asm = ['mov r8,QWORD ptr [rbp-0x20]', 'mov rcx,rax', 'call memcpy']
        w = self.tracker.trace(asm, 2, 'memcpy')
        # 无法回溯为常量 → 不判known(避免cannot_overflow误判)
        self.assertFalse(w.is_known)


class TestBidirectionalVerifier(unittest.TestCase):
    def setUp(self):
        self.v = BidirectionalIntervalVerifier()

    def test_safe_alloc_constant(self):
        # alloc=256 → usable≈272, write=200 → 安全
        r = self.v.verify(256, 256, 200, 200, True, False,
                          False, False, True)
        self.assertTrue(r.cannot_overflow)

    def test_definite_overflow(self):
        # alloc=8 → usable≤24, write=512 → 必定溢出
        r = self.v.verify(8, 8, 512, 512, True, True,
                          False, False, True)
        self.assertTrue(r.will_overflow)

    def test_unknown_write_no_cannot(self):
        # write上界不可知 → 不得判cannot_overflow
        r = self.v.verify(0, 2**31 - 1, 0, 0x7FFFFFFF, False, True,
                          True, False, False)
        self.assertFalse(r.cannot_overflow)
        self.assertTrue(r.may_overflow)

    def test_overlap_tainted_unbounded(self):
        r = self.v.verify(0, 2**31 - 1, 100, 200, True, True,
                          True, False, False)
        self.assertTrue(r.may_overflow)


class TestLoopWriteDetector(unittest.TestCase):
    def setUp(self):
        self.d = LoopWriteDetector()

    def _make_loop(self, with_guard=False):
        lines = [
            '140001000: mov rcx,0x10',
            'call malloc',
            '140001010: mov DWORD ptr [rbp-0x4],0x0',
            '140001014: mov eax,DWORD ptr [rbp-0x4]',
            '140001018: movsxd rcx,eax',
            '14000101c: mov rax,QWORD ptr [rbp-0x18]',
            '140001020: add rax,rcx',
            '140001024: mov BYTE ptr [rax],dl',
            '140001028: add DWORD ptr [rbp-0x4],0x1',
            '14000102c: mov eax,DWORD ptr [rbp-0x4]',
            '140001030: cmp eax,DWORD ptr [rbp-0xc]',
            '140001034: jl 140001014',
        ]
        if with_guard:
            # 插入守卫: cmp [rbp-0xc], [rbp-0x4] (loop<=alloc) 在alloc前
            lines = [
                '1400010f0: cmp eax,DWORD ptr [rbp-0x4]',
                '1400010f4: jle 140001000',
            ] + lines
        return lines

    def test_loop_without_guard_overflows(self):
        lines = self._make_loop(with_guard=False)
        res = self.d.detect(lines, 1, 0, 2**31 - 1, True)
        self.assertTrue(any(r.may_overflow for r in res))

    def test_loop_with_guard_safe(self):
        # FP005模式: alloc size来自[rbp-0x4], 守卫 cmp loop_m,[rbp-0x4]; jle 进
        lines = [
            # 守卫: loop_m <= alloc_size 才进入
            '1400010e0: mov eax,DWORD ptr [rbp-0xc]',
            '1400010e4: cmp eax,DWORD ptr [rbp-0x4]',
            '1400010e8: jle 140001000',
            '1400010ec: jmp 140001200',
            # alloc: size = [rbp-0x4]
            '140001000: mov eax,DWORD ptr [rbp-0x4]',
            '140001004: cdqe',
            '140001006: mov rcx,rax',
            'call malloc',
            '140001010: mov DWORD ptr [rbp-0x8],0x0',
            '140001014: mov eax,DWORD ptr [rbp-0x8]',
            '140001018: movsxd rcx,eax',
            '14000101c: mov rax,QWORD ptr [rbp-0x18]',
            '140001020: add rax,rcx',
            '140001024: mov BYTE ptr [rax],dl',
            '140001028: add DWORD ptr [rbp-0x8],0x1',
            '14000102c: mov eax,DWORD ptr [rbp-0x8]',
            '140001030: cmp eax,DWORD ptr [rbp-0xc]',
            '140001034: jl 140001014',
        ]
        res = self.d.detect(lines, 7, 0, 2**31 - 1, True)
        # 守卫使循环受alloc约束 → 不告警
        self.assertTrue(all(not r.may_overflow for r in res))

    def test_constant_alloc_skipped(self):
        lines = self._make_loop(with_guard=False)
        res = self.d.detect(lines, 1, 0, 2**31 - 1, False)
        self.assertEqual(len(res), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
