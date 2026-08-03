"""
Tests for code anonymizer modules -- both main anonymizer and info_collection src variant.
"""
import pytest
from modules.anonymizer import (
_MOD_DEBUG = False
    CodeAnonymizer,
    AnonymizationLevel,
    anonymize_code,
    is_sensitive_content,
    AnonymizationContextManager
)

# Also test the info_collection/src variant
from modules.info.info_collection.src.anonymizer import (
    Anonymizer,
    _C_KEYWORDS,
    _PYTHON_KEYWORDS,
    _SECRET_PATTERNS,
)


class TestAnonymizer:
    """测试代码匿名化器 (main module)"""

    @pytest.fixture
    def anonymizer(self):
        return CodeAnonymizer()

    def test_api_key_redaction(self, anonymizer):
        code = """
        // API密钥配置
        const char* api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'sk-REDACTED_API_KEY' in result.anonymized
        assert 'sk-proj-' not in result.anonymized
        assert len(result.replacements) >= 1

    def test_ip_address_redaction(self, anonymizer):
        code = """
        char* server = "192.168.1.100";
        char* gateway = "10.0.0.1";
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'X.X.X.X' in result.anonymized
        assert '192.168.1.100' not in result.anonymized

    def test_email_redaction(self, anonymizer):
        code = 'send_email("admin@company.com", message);'
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'REDACTED@example.com' in result.anonymized

    def test_url_redaction(self, anonymizer):
        code = 'curl("https://api.secret-service.com/v1/data");'
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'https://REDACTED_URL' in result.anonymized

    def test_password_literal_redaction(self, anonymizer):
        code = 'char* db_password = "SuperSecret123!"; password = "admin123";'
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'password="REDACTED"' in result.anonymized
        assert 'SuperSecret123!' not in result.anonymized

    def test_private_key_redaction(self, anonymizer):
        code = """
        const char* private_key = "-----BEGIN RSA PRIVATE KEY-----\\n"
                                  "MIIEpAIBAAKCAQEAz...\\n"
                                  "-----END RSA PRIVATE KEY-----";
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert '-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----' in result.anonymized
        assert len(result.warnings) == 1

    def test_identifier_obfuscation(self, anonymizer):
        code = """
        void process_user_data(UserData* user_info) {
            int result = validate_input(user_info->username);
            if (result == 0) {
                save_to_database(user_info);
            }
        }
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.MEDIUM)
        assert 'var_' in result.anonymized
        assert 'process_user_data' not in result.anonymized
        assert 'void' in result.anonymized
        assert 'int' in result.anonymized
        assert 'if' in result.anonymized

    def test_string_obfuscation(self, anonymizer):
        code = """
        char* message = "Welcome to Secret System v2.0";
        char* secret = "ThisIsASecretPassword";
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.HIGH)
        assert '*' in result.anonymized

    def test_comment_removal(self, anonymizer):
        code = """
        // 这是一个敏感的注释，包含密码: admin123
        /* 多行注释 包含敏感信息 */
        int x = 1; // 单行注释
        """
        result = anonymizer.anonymize(code, AnonymizationLevel.EXTREME)
        assert '// REDACTED' in result.anonymized
        assert '/* REDACTED */' in result.anonymized

    def test_is_sensitive_content(self):
        assert is_sensitive_content('sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP') is True
        assert is_sensitive_content('AKIAIOSFODNN7EXAMPLE') is True
        assert is_sensitive_content('-----BEGIN RSA PRIVATE KEY-----') is True
        assert is_sensitive_content('password="secret123"') is True
        assert is_sensitive_content('int x = 1;') is False
        assert is_sensitive_content('printf("hello world");') is False

    def test_different_levels(self, anonymizer):
        code = """
        char* key = "sk-abcdefgh12345678";
        char* name = "my_secret_function";
        char* str = "sensitive data";
        // comment with secret
        """
        result_low = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'sk-REDACTED_API_KEY' in result_low.anonymized
        assert 'my_secret_function' in result_low.anonymized

        result_medium = anonymizer.anonymize(code, AnonymizationLevel.MEDIUM)
        assert 'my_secret_function' not in result_medium.anonymized

        result_extreme = anonymizer.anonymize(code, AnonymizationLevel.EXTREME)
        assert '// REDACTED' in result_extreme.anonymized

    def test_anonymize_code_convenience(self):
        code = 'const char* api = "sk-abcdef12345";'
        result = anonymize_code(code, AnonymizationLevel.LOW)
        assert result is not None
        assert 'sk-REDACTED_API_KEY' in result.anonymized

    def test_context_manager(self):
        with AnonymizationContextManager(level=AnonymizationLevel.LOW) as ctx:
            code = 'char* key = "sk-abcdefgh12345678";'
            anonymized = ctx.process(code)
            assert 'sk-REDACTED_API_KEY' in anonymized
            result = ctx.get_last_result()
            assert result is not None
            assert len(result.replacements) >= 1

    def test_no_sensitive_content(self, anonymizer):
        code = "int add(int a, int b) { return a + b; }"
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert result.anonymized == code
        assert len(result.replacements) == 0

    def test_aws_key_redaction(self, anonymizer):
        code = 'char* access_key = "AKIAIOSFODNN7EXAMPLE";'
        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'AKIA_REDACTED_KEY' in result.anonymized


# ---------------------------------------------------------------------------
# Tests for info_collection/src/anonymizer variant
# ---------------------------------------------------------------------------

class TestSrcAnonymizer:
    """Tests for info_collection/src/anonymizer.py Anonymizer class."""

    def test_creation(self):
        a = Anonymizer(threshold=0.5)
        assert a.threshold == 0.5

    def test_c_keywords_loaded(self):
        assert len(_C_KEYWORDS) > 0
        assert "if" in _C_KEYWORDS
        assert "return" in _C_KEYWORDS

    def test_python_keywords_loaded(self):
        assert len(_PYTHON_KEYWORDS) > 0
        assert "def" in _PYTHON_KEYWORDS
        assert "class" in _PYTHON_KEYWORDS

    def test_anonymize_identifiers_python(self):
        a = Anonymizer()
        code = "def calculate(items):\n    return sum(items)"
        result = a.anonymize_identifiers(code, language="python")
        assert "def" in result
        assert "return" in result
        assert "calculate" not in result

    def test_anonymize_strings(self):
        a = Anonymizer()
        code = 'x = "hello"; y = "hello";'
        result = a.anonymize_strings(code)
        assert '"hello"' not in result
        # Same string → same alias
        assert result.count('"str_1"') == 2

    def test_anonymize_numbers(self):
        a = Anonymizer()
        code = "x = 12345; y = 0xABCD;"
        result = a.anonymize_numbers(code)
        assert "12345" not in result
        assert "ABCD" not in result

    def test_full_anonymize(self):
        a = Anonymizer()
        code = 'name = "alice"; age = 25;'
        anon, replace_map = a.full_anonymize(code, language="python")
        assert isinstance(anon, str)
        assert isinstance(replace_map, dict)
        assert len(replace_map) > 0

    def test_deterministic_output(self):
        a1 = Anonymizer()
        a2 = Anonymizer()
        code = 'x = "secret"; y = 42;'
        r1, _ = a1.full_anonymize(code, language="python")
        r2, _ = a2.full_anonymize(code, language="python")
        assert r1 == r2

    def test_python_detected(self):
        lang = Anonymizer._auto_detect_language("def foo():\n    return 1")
        assert lang == "python"

    def test_c_detected(self):
        lang = Anonymizer._auto_detect_language("#include <stdio.h>\nint main(){}")
        assert lang == "c"
