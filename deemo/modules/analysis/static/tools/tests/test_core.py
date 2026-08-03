"""Tests for core 静态分析 algorithms"""

import pytest


# =============================================================================
# SemanticRoleLabeler Tests
# =============================================================================

class TestSemanticRoleLabeler:
    """Tests for SemanticRoleLabeler"""

    @pytest.fixture
    def labeler(self):
        from src.core import SemanticRoleLabeler
        return SemanticRoleLabeler()

    def test_label_counter_var(self, labeler):
        """Loop counter variables like, j, k labeled LOOP_COUNTER"""
        assert labeler.label_variable("i") == "LOOP_COUNTER"
        assert labeler.label_variable("j") == "LOOP_COUNTER"
        assert labeler.label_variable("k") == "LOOP_COUNTER"
        assert labeler.label_variable("counter") == "LOOP_COUNTER"
        assert labeler.label_variable("cnt") == "LOOP_COUNTER"

    def test_label_buffer_ptr(self, labeler):
        """缓冲区 指针 variables labeled 缓冲区_指针"""
        assert labeler.label_variable("ptr") == "BUFFER_POINTER"
        assert labeler.label_variable("buf") == "BUFFER_POINTER"
        assert labeler.label_variable("buffer") == "BUFFER_POINTER"
        assert labeler.label_variable("data") == "BUFFER_POINTER"
        assert labeler.label_variable("p_buf") == "BUFFER_POINTER"

    def test_label_unknown(self, labeler):
        """Arbitrary names labeled UNKNOWN"""
        assert labeler.label_variable("xyz_foo_bar") == "UNKNOWN"


# =============================================================================
# SemanticDiffAnalyzer Tests
# =============================================================================

class TestSemanticDiffAnalyzer:
    """Tests for SemanticDiffAnalyzer"""

    @pytest.fixture
    def diff_analyzer(self):
        from src.core import SemanticDiffAnalyzer
        return SemanticDiffAnalyzer()

    def test_extract_hashes(self, diff_analyzer):
        """extract_hashes 返回 a list SHA256 hex strings"""
        insns = ["mov eax, 1", "add eax, ebx"]
        hashes = diff_analyzer.extract_hashes(insns)
        assert len(hashes) == 2
        assert all(isinstance(h, str) for h in hashes)
        assert all(len(h) == 64 for h in hashes)

    def test_jaccard_similarity_identical(self, diff_analyzer):
        """Identical hash sets similarity 1.0"""
        h = diff_analyzer.extract_hashes(["nop"])
        assert diff_analyzer.compute_similarity(h, h) == 1.0

    def test_jaccard_similarity_different(self, diff_analyzer):
        """Completely different hash sets similarity 0.0"""
        h1 = diff_analyzer.extract_hashes(["nop"])
        h2 = diff_analyzer.extract_hashes(["ret"])
        assert diff_analyzer.compute_similarity(h1, h2) == 0.0

    def test_diff_detects_added(self, diff_analyzer):
        """diff 检测 functions present binary B"""
        binary_a = {"functions": {"func1": ["nop", "ret"]}}
        binary_b = {"functions": {"func1": ["nop", "ret"], "func2": ["push rbp"]}}
        result = diff_analyzer.diff(binary_a, binary_b)
        assert "func2" in result["added"]
        assert len(result["removed"]) == 0


# =============================================================================
# LLVMIRAnalyzer Tests
# =============================================================================

class TestLLVMIRAnalyzer:
    """Tests for LLVMIRAnalyzer"""

    @pytest.fixture
    def ir_analyzer(self):
        from src.core import LLVMIRAnalyzer
        return LLVMIRAnalyzer()

    def test_detect_bitcast(self, ir_analyzer):
        """检测 bitcast i8* a larger type"""
        ir_text = (
            "define void @test(i8* %ptr) {\n"
            "  %1 = bitcast i8* %ptr to i32*\n"
            "  ret void\n"
            "}"
        )
        findings = ir_analyzer.scan_unsafe_casts(ir_text)
        assert len(findings) == 1
        assert findings[0]["type"] == "unsafe_cast"

    def test_detect_missing_bounds(self, ir_analyzer):
        """检测 getelementptr subsequent bounds 检查"""
        ir_text = (
            "define void @test(i32* %arr, i32 %idx) {\n"
            "  %ptr = getelementptr i32, i32* %arr, i32 %idx\n"
            "  store i32 42, i32* %ptr\n"
            "  ret void\n"
            "}"
        )
        findings = ir_analyzer.scan_missing_bounds_checks(ir_text)
        assert len(findings) >= 1
        assert findings[0]["type"] == "missing_bounds_check"

    def test_no_false_positive(self, ir_analyzer):
        """Safe code produce findings"""
        ir_text = (
            "define i32 @safe(i32* %arr, i32 %n) {\n"
            "  %result = alloca i32\n"
            "  store i32 0, i32* %result\n"
            "  %val = load i32, i32* %result\n"
            "  ret i32 %val\n"
            "}"
        )
        findings = ir_analyzer.analyze(ir_text)
        assert findings["total_findings"] == 0


# =============================================================================
# AbstractInterpreter Tests
# =============================================================================

class TestAbstractInterpreter:
    """Tests for AbstractInterpreter"""

    @pytest.fixture
    def interpreter(self):
        from src.core import AbstractInterpreter
        return AbstractInterpreter()

    def test_basic_interval(self, interpreter):
        """Basic assignment 创建 a precise interval"""
        insns = [{"op": "assign", "dest": "x", "value": 5}]
        state = interpreter.interpret(insns)
        assert state["x"] == (5.0, 5.0)

    def test_widening(self, interpreter):
        """Widening extrapolate infinity"""
        old = (0.0, 10.0)
        new = (0.0, 20.0)
        widened = interpreter._widen(old, new)
        assert widened == (0.0, float("inf"))

    def test_narrowing(self, interpreter):
        """Narrowing tighten infinity actual bounds"""
        old = (0.0, float("inf"))
        new = (0.0, 50.0)
        narrowed = interpreter._narrow(old, new)
        assert narrowed == (0.0, 50.0)


# =============================================================================
# 系统调用分类器 Tests
# =============================================================================

class TestSyscallClassifier:
    """Tests for 系统调用分类器"""

    @pytest.fixture
    def classifier(self):
        from src.core import SyscallClassifier
        return SyscallClassifier(n=3)

    def test_extract_trigrams(self, classifier):
        """提取 3-grams a sequence"""
        seq = ["open", "read", "write", "close"]
        ngrams = classifier.extract_ngrams(seq)
        assert len(ngrams) == 2
        assert ngrams[0] == ("open", "read", "write")
        assert ngrams[1] == ("read", "write", "close")

    def test_cosine_similarity_identical(self, classifier):
        """Identical vectors similarity 1.0"""
        vec = {("a", "b", "c"): 0.5, ("b", "c", "d"): 0.5}
        score = classifier.cosine_similarity(vec, vec)
        assert abs(score - 1.0) < 1e-6

    def test_cosine_different(self, classifier):
        """Orthogonal vectors similarity 0.0"""
        v1 = {("a", "b", "c"): 1.0}
        v2 = {("x", "y", "z"): 1.0}
        score = classifier.cosine_similarity(v1, v2)
        assert abs(score - 0.0) < 1e-6


# =============================================================================
# Branch漏洞利用ability Tests
# =============================================================================

class TestBranchExploitability:
    """Tests for Branch漏洞利用ability"""

    @pytest.fixture
    def exploiter(self):
        from src.core import BranchExploitability
        return BranchExploitability()

    def test_extract_cfg(self, exploiter):
        """提取 a valid CFG instruction list"""
        insns = [
            {"addr": 0x1000, "op": "push", "fallthrough": 0x1001},
            {"addr": 0x1001, "op": "mov", "fallthrough": 0x1002},
            {"addr": 0x1002, "op": "jmp", "target": 0x2000},
            {"addr": 0x2000, "op": "ret"},
        ]
        cfg = exploiter.extract_cfg(insns)
        assert cfg["entry"] == 0x1000
        assert len(cfg["nodes"]) == 4
        assert len(cfg["edges"]) >= 3

    def test_find_simple_path(self, exploiter):
        """查找 a path a simple CFG"""
        insns = [
            {"addr": 0x1000, "op": "push", "fallthrough": 0x1001},
            {"addr": 0x1001, "op": "mov", "fallthrough": 0x1002},
            {"addr": 0x1002, "op": "cmp", "fallthrough": 0x1003, "target": 0x2000},
            {"addr": 0x1003, "op": "ret"},
        ]
        cfg = exploiter.extract_cfg(insns)
        path = exploiter.find_exploit_path(cfg, 0x1000, 0x1003)
        assert len(path) >= 2
        assert path[0] == 0x1000
        assert path[-1] == 0x1003
