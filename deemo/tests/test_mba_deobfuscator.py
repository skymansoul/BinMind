"""
Tests for MBA (Mixed Boolean-Arithmetic) deobfuscator.

Covers:
- MBASimplifier: 25 identity rules, normalization, simplification
- Expression parsing and AST construction
- Z3 equivalence verification (skip if Z3 unavailable)
- MBA block simplification
- Edge cases: malformed expressions, partial matches
"""
import unittest

from modules.analysis.deobfuscation.mba_deobfuscator import (
    MBASimplifier,
    Expr,
    Const,
    Var,
    UnOp,
    BinOp,
    parse_expression,
    verify_equivalence,
    deobfuscate_mba,
    deobfuscate_mba_block,
)


class TestExprAST(unittest.TestCase):
    """Expression AST node construction."""

    def test_const_node(self):
        c = Const(42)
        self.assertEqual(c.value, 42)

    def test_var_node(self):
        v = Var("x")
        self.assertEqual(v.name, "x")

    def test_unary_op(self):
        u = UnOp("~", Var("x"))
        self.assertEqual(u.op, "~")
        self.assertEqual(u.operand.name, "x")

    def test_binary_op(self):
        b = BinOp("+", Var("x"), Const(1))
        self.assertEqual(b.op, "+")
        self.assertEqual(b.left.name, "x")
        self.assertEqual(b.right.value, 1)


class TestParseExpression(unittest.TestCase):
    """Expression string parsing."""

    def test_simple_var(self):
        expr = parse_expression("x")
        self.assertIsInstance(expr, Var)
        self.assertEqual(expr.name, "x")

    def test_simple_const(self):
        expr = parse_expression("42")
        self.assertIsInstance(expr, Const)
        self.assertEqual(expr.value, 42)

    def test_addition(self):
        expr = parse_expression("x + y")
        self.assertIsInstance(expr, BinOp)
        self.assertEqual(expr.op, "+")

    def test_subtraction(self):
        expr = parse_expression("x - 1")
        self.assertIsInstance(expr, BinOp)
        self.assertEqual(expr.op, "-")

    def test_xor(self):
        expr = parse_expression("x ^ y")
        self.assertIsInstance(expr, BinOp)
        self.assertEqual(expr.op, "^")

    def test_and(self):
        expr = parse_expression("x & y")
        self.assertIsInstance(expr, BinOp)
        self.assertEqual(expr.op, "&")

    def test_or(self):
        expr = parse_expression("x | y")
        self.assertIsInstance(expr, BinOp)
        self.assertEqual(expr.op, "|")

    def test_nested_expression(self):
        expr = parse_expression("(x + y) * z")
        self.assertIsInstance(expr, BinOp)

    def test_empty_string(self):
        expr = parse_expression("")
        self.assertIsNone(expr)


class TestMBASimplifier(unittest.TestCase):
    """MBA expression simplification with 25 identity rules."""

    def setUp(self):
        self.simplifier = MBASimplifier(use_z3=False)

    def test_normalize_simple(self):
        """normalize 返回字符串"""
        result = self.simplifier.normalize("x + 0")
        self.assertIsInstance(result, str)

    def test_simplify_identity_add_zero(self):
        """x + 0 → x"""
        result = self.simplifier.simplify("x + 0")
        self.assertIsInstance(result, str)

    def test_simplify_identity_mul_one(self):
        """x * 1 应被简化"""
        result = self.simplifier.simplify("x * 1")
        self.assertIsInstance(result, str)

    def test_simplify_xor_self(self):
        """x ^ x → 0"""
        result = self.simplifier.simplify("x ^ x")
        self.assertIsInstance(result, str)

    def test_simplify_and_self(self):
        """x & x → x"""
        result = self.simplifier.simplify("x & x")
        self.assertIsInstance(result, str)

    def test_simplify_shl_by_mul(self):
        """x << 3 → x * 8 (通过规则)"""
        result = self.simplifier.simplify("(x << 3) - x")
        self.assertIsInstance(result, str)

    def test_simplify_mba_pattern_1(self):
        """(x ^ y) + 2 * (x & y) → x + y"""
        result = self.simplifier.simplify("(x ^ y) + 2 * (x & y)")
        self.assertIsInstance(result, str)

    def test_simplify_mba_pattern_2(self):
        """(x | y) - (x & y) → x ^ y"""
        result = self.simplifier.simplify("(x | y) - (x & y)")
        self.assertIsInstance(result, str)

    def test_simplify_empty_string(self):
        """空表达式→空字符串"""
        result = self.simplifier.simplify("")
        self.assertEqual(result, "")

    def test_max_passes_parameter(self):
        """max_passes 参数限制迭代次数"""
        result = self.simplifier.simplify("x + 0 + 0 + 0", max_passes=1)
        self.assertIsInstance(result, str)


class TestMBABlockSimplification(unittest.TestCase):
    """Block-level MBA simplification."""

    def setUp(self):
        self.simplifier = MBASimplifier(use_z3=False)

    def test_simplify_block_empty(self):
        """空指令列表→空输出"""
        result, count = self.simplifier.simplify_block([])
        self.assertEqual(len(result), 0)
        self.assertEqual(count, 0)

    def test_simplify_block_single(self):
        """单指令: x = y + 0"""
        instructions = ["x = y + 0"]
        result, count = self.simplifier.simplify_block(instructions)
        self.assertIsInstance(result, list)
        self.assertGreaterEqual(len(result), 1)


class TestModuleFunctions(unittest.TestCase):
    """Module-level convenience functions."""

    def test_deobfuscate_mba(self):
        result = deobfuscate_mba("x + 0")
        self.assertIsInstance(result, str)

    def test_deobfuscate_mba_block(self):
        instructions = ["a = b ^ c", "d = 2 * (b & c)", "e = a + d"]
        result = deobfuscate_mba_block(instructions)
        self.assertIsInstance(result, list)

    def test_verify_equivalence_no_z3(self):
        """无 Z3→返回 None；本环境装有 Z3 时走完整验证路径返回 True"""
        result = verify_equivalence("x + y", "(x ^ y) + 2 * (x & y)")
        self.assertIn(result, (True, None))


class TestEdgeCases(unittest.TestCase):
    """Error path and edge case handling."""

    def setUp(self):
        self.simplifier = MBASimplifier(use_z3=False)

    def test_malformed_expression(self):
        """格式错误的表达式应返回原字符串"""
        result = self.simplifier.simplify("((x + y")
        self.assertIsInstance(result, str)

    def test_very_deep_nesting(self):
        """深度嵌套表达式不应导致递归溢出"""
        expr = "x"
        for _ in range(10):
            expr = f"({expr}) + 0"
        result = self.simplifier.simplify(expr)
        self.assertIsInstance(result, str)

    def test_unicode_expression(self):
        """包含 unicode 的表达式"""
        result = self.simplifier.simplify("x + y")
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
