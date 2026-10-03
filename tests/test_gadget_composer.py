# ROP/JOP/COP/SROP gadget -- 真实 API 断言驱动测试
import unittest

from modules.gadget_composer import (
    ComposeResult,
    GadgetChain,
    GadgetComposer,
    GadgetDatabase,
    GadgetTemplate,
    GadgetType,
    TemplateEngine,
    create_gadget_composer,
)


class TestGadgetType(unittest.TestCase):
    """GadgetType enum: ROP / JOP / COP / SROP"""

    def test_gadget_type_values(self):
        self.assertEqual(GadgetType.ROP.value, "rop")
        self.assertEqual(GadgetType.JOP.value, "jop")
        self.assertEqual(GadgetType.COP.value, "cop")
        self.assertEqual(GadgetType.SROP.value, "srop")


class TestGadgetTemplate(unittest.TestCase):
    """Template 对象 -- preconditions + effect + constraints"""

    def test_template_creation(self):
        template = GadgetTemplate(
            gadget_type=GadgetType.ROP,
            preconditions=["pop rdi", "ret"],
            effect="set rdi to controlled value",
        )
        self.assertIsNotNone(template)
        self.assertEqual(template.gadget_type, GadgetType.ROP)
        self.assertEqual(len(template.preconditions), 2)
        self.assertEqual(template.effect, "set rdi to controlled value")

    def test_template_defaults(self):
        template = GadgetTemplate(GadgetType.JOP)
        self.assertEqual(template.preconditions, [])
        self.assertEqual(template.effect, "")
        self.assertEqual(template.constraints, {})


class TestGadgetChain(unittest.TestCase):
    def test_chain_creation(self):
        chain = GadgetChain(
            gadgets=[0x1000, 0x1002],
            gadget_type=GadgetType.ROP,
            effects=["set rdi"],
            success_probability=0.85,
        )
        self.assertEqual(len(chain.gadgets), 2)
        self.assertEqual(chain.gadget_type, GadgetType.ROP)
        self.assertEqual(chain.success_probability, 0.85)


class TestComposeResult(unittest.TestCase):
    def test_success_result(self):
        chain = GadgetChain(
            gadgets=[0x1000], gadget_type=GadgetType.ROP,
            effects=["test"], success_probability=0.5,
        )
        result = ComposeResult(success=True, chain=chain)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.chain)

    def test_failure_result(self):
        result = ComposeResult(success=False, chain=None)
        self.assertFalse(result.success)
        self.assertIsNone(result.chain)


class TestGadgetDatabase(unittest.TestCase):
    """GadgetDatabase.scan：r2 缺失/二进制缺失时返回空列表，不抛异常"""

    def test_scan_missing_binary_returns_empty(self):
        db = GadgetDatabase("/nonexistent/gadget.bin")
        self.assertEqual(db.scan(), [])


class TestTemplateEngine(unittest.TestCase):
    """match_gadgets：gadget_type 过滤 + precondition 子串匹配"""

    def test_match_by_type_and_precondition(self):
        gadgets = [
            (0x1000, "pop rdi; ret", GadgetType.ROP),
            (0x2000, "pop rdi; jmp rax", GadgetType.JOP),
            (0x3000, "mov rax, rdi; ret", GadgetType.ROP),
        ]
        template = GadgetTemplate(GadgetType.ROP, preconditions=["pop rdi"])
        matched = TemplateEngine.match_gadgets(gadgets, template)
        self.assertEqual(matched, [(0x1000, "pop rdi; ret")])

    def test_match_ignores_other_type(self):
        # 同地址同指令，JOP 模板只匹配 JOP 条目
        gadgets = [
            (0x1000, "xchg rax, rsp; ret", GadgetType.ROP),
            (0x1000, "xchg rax, rsp; ret", GadgetType.JOP),
        ]
        template = GadgetTemplate(GadgetType.JOP, preconditions=["xchg"])
        matched = TemplateEngine.match_gadgets(gadgets, template)
        self.assertEqual(matched, [(0x1000, "xchg rax, rsp; ret")])

    def test_match_precondition_substring(self):
        # precondition 为子串：code 同时包含全部前置条件才命中
        gadgets = [
            (0x5000, "pop rdi; ret", GadgetType.ROP),
            (0x5001, "pop rax; ret", GadgetType.ROP),
        ]
        template = GadgetTemplate(GadgetType.ROP, preconditions=["rdi", "ret"])
        matched = TemplateEngine.match_gadgets(gadgets, template)
        self.assertEqual(matched, [(0x5000, "pop rdi; ret")])

    def test_match_srop_template(self):
        template = GadgetTemplate(GadgetType.SROP, preconditions=["syscall"])
        gadgets = [
            (0x6000, "syscall; ret", GadgetType.SROP),
            (0x6001, "syscall; ret", GadgetType.ROP),
        ]
        matched = TemplateEngine.match_gadgets(gadgets, template)
        self.assertEqual(matched, [(0x6000, "syscall; ret")])


class TestGadgetComposer(unittest.TestCase):
    """GadgetComposer：真实行为断言，无需真实二进制"""

    def test_composer_init(self):
        composer = GadgetComposer("/nonexistent/binary")
        self.assertIsNotNone(composer.db)
        self.assertIsNotNone(composer.engine)
        self.assertEqual(composer.bad_bytes, set())

    def test_create_gadget_composer(self):
        composer = create_gadget_composer("/nonexistent/binary")
        self.assertIsInstance(composer, GadgetComposer)

    def test_run_missing_binary_does_not_raise(self):
        # scan 无结果时 success=False，chain 为空链（真实实现不返回 None）
        composer = GadgetComposer("/nonexistent/binary")
        template = GadgetTemplate(GadgetType.ROP, preconditions=["pop rdi"])
        result = composer.run(template)
        self.assertIsInstance(result, ComposeResult)
        self.assertFalse(result.success)
        self.assertEqual(result.chain.gadgets, [])

    def test_score_gadget_leave_penalty(self):
        composer = GadgetComposer("/nonexistent/binary")
        base = composer._score_gadget(0x1000, "pop rax; ret")
        leave = composer._score_gadget(0x1000, "leave; ret")
        self.assertLess(leave, base)

    def test_score_gadget_xchg_bonus(self):
        composer = GadgetComposer("/nonexistent/binary")
        base = composer._score_gadget(0x1000, "pop rax; ret")
        xchg = composer._score_gadget(0x1000, "xchg rax, rsp; ret")
        self.assertGreater(xchg, base)

    def test_bad_bytes_penalty(self):
        composer = GadgetComposer("/nonexistent/binary")
        composer.bad_bytes = {0x0a}
        plain = composer._score_gadget(0x1000, "pop rax; ret")
        poisoned = composer._score_gadget(0x100a, "pop rax; ret")
        self.assertLess(poisoned, plain)

    def test_chain_syscall_gadgets(self):
        composer = GadgetComposer("/nonexistent/binary")
        gadgets = [
            (0x1000, "pop rdi; ret"),
            (0x1001, "pop rsi; ret"),
            (0x1002, "pop rdx; ret"),
            (0x1003, "syscall; ret"),
        ]
        chain = composer._chain_syscall_gadgets(gadgets)
        self.assertEqual(chain, [0x1000, 0x1001, 0x1002, 0x1003])

    def test_find_stack_pivot_missing_binary_empty(self):
        composer = GadgetComposer("/nonexistent/binary")
        self.assertEqual(composer._find_stack_pivot(), [])


if __name__ == "__main__":
    unittest.main()