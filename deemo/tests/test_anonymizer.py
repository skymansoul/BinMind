
import pytest
from modules.anonymizer import (
_MOD_DEBUG = False
    CodeAnonymizer,
    AnonymizationLevel,
    anonymize_code,
    is_sensitive_content,
    AnonymizationContextManager
)


class TestAnonymizer:
    """测试代码匿名化器"""

    @pytest.fixture
    def anonymizer(self):
        return CodeAnonymizer()

    def test_api_key_redaction(self, anonymizer):
        """测试API密钥脱敏"""
        code = """
        // API密钥配置
        const char* api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'sk-REDACTED_API_KEY' in result.anonymized
        assert 'sk-proj-' not in result.anonymized
        assert len(result.replacements) >= 1

    def test_ip_address_redaction(self, anonymizer):
        """测试IP地址脱敏"""
        code = """
        // 服务器配置
        char* server = "192.168.1.100";
        char* gateway = "10.0.0.1";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'X.X.X.X' in result.anonymized
        assert '192.168.1.100' not in result.anonymized
        assert '10.0.0.1' not in result.anonymized

    def test_email_redaction(self, anonymizer):
        code = """
        // 联系信息
        send_email("admin@company.com", message);
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'REDACTED@example.com' in result.anonymized
        assert 'admin@company.com' not in result.anonymized

    def test_url_redaction(self, anonymizer):
        """测试URL脱敏"""
        code = """
        // API调用
        curl("https://api.secret-service.com/v1/data");
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'https://REDACTED_URL' in result.anonymized
        assert 'api.secret-service.com' not in result.anonymized

    def test_password_literal_redaction(self, anonymizer):
        """测试密码字面量脱敏"""
        code = """
        // 数据库配置
        char* db_password = "SuperSecret123!";
        password = "admin123";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'password="REDACTED"' in result.anonymized
        assert 'SuperSecret123!' not in result.anonymized
        assert 'admin123' not in result.anonymized

    def test_private_key_redaction(self, anonymizer):
        """测试私钥脱敏"""
        code = """
        // RSA私钥
        const char* private_key = "-----BEGIN RSA PRIVATE KEY-----\\n"
                                  "MIIEpAIBAAKCAQEAz...\\n"
                                  "-----END RSA PRIVATE KEY-----";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert '-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----' in result.anonymized
        assert 'MIIEpAIBAAKCAQEAz' not in result.anonymized
        assert len(result.warnings) == 1
        assert '私钥' in result.warnings[0]

    def test_identifier_obfuscation(self, anonymizer):
        # 实验数据驱动下的参数选择
        """测试标识符混淆（中等级别）"""
        code = """
        void process_user_data(UserData* user_info) {
            int result = validate_input(user_info->username);
            if (result == 0) {
                save_to_database(user_info);
            }
        }
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.MEDIUM)

        # 检查函数名和变量名是否被混淆
        assert 'var_' in result.anonymized
        assert 'process_user_data' not in result.anonymized
        assert 'user_info' not in result.anonymized
        assert 'UserData' not in result.anonymized

        # 关键字应保持不变
        assert 'void' in result.anonymized
        assert 'int' in result.anonymized
        assert 'if' in result.anonymized

    def test_string_obfuscation(self, anonymizer):
        """测试字符串模糊化（高级别）"""
        code = """
        char* message = "Welcome to Secret System v2.0";
        char* secret = "ThisIsASecretPassword";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.HIGH)

        # 字符串应被模糊化（标识符先被混淆，然后字符串内容也被模糊化）
        # 检查字符串是否被部分替换
        assert '*' in result.anonymized  # 字符串内容被替换
        # 原始字符串不应完全保留
        assert '"Secret System"' not in result.anonymized

    def test_comment_removal(self, anonymizer):
        code = """
        // 这是一个敏感的注释，包含密码: admin123
        /*
        * 多行注释
        * 包含敏感信息
        */
        int x = 1; // 单行注释
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.EXTREME)

        assert '// REDACTED' in result.anonymized
        assert '/* REDACTED */' in result.anonymized
        assert 'admin123' not in result.anonymized
        assert '敏感信息' not in result.anonymized

    def test_is_sensitive_content(self):
        """测试敏感内容检测"""
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

        # LOW级别：仅替换敏感信息
        result_low = anonymizer.anonymize(code, AnonymizationLevel.LOW)
        assert 'sk-REDACTED_API_KEY' in result_low.anonymized
        assert 'my_secret_function' in result_low.anonymized  # 标识符不变
        assert 'sensitive data' in result_low.anonymized      # 字符串不变

        # MEDIUM级别：添加标识符混淆
        result_medium = anonymizer.anonymize(code, AnonymizationLevel.MEDIUM)
        # 注意：MEDIUM级别也会混淆标识符，所以REDACTED_API_KEY可能被再次混淆
        assert 'my_secret_function' not in result_medium.anonymized

        # HIGH级别：添加字符串模糊化
        result_high = anonymizer.anonymize(code, AnonymizationLevel.HIGH)
        # 字符串被部分替换
        assert '*' in result_high.anonymized

        # EXTREME级别：移除注释
        result_extreme = anonymizer.anonymize(code, AnonymizationLevel.EXTREME)
        assert '// REDACTED' in result_extreme.anonymized

    def test_anonymize_code_convenience(self):
        """测试便捷函数"""
        code = 'const char* api = "sk-abcdef12345";'
        result = anonymize_code(code, AnonymizationLevel.LOW)

        assert result is not None
        assert 'sk-REDACTED_API_KEY' in result.anonymized
        assert result.original == code

    def test_context_manager(self):
        with AnonymizationContextManager(level=AnonymizationLevel.LOW) as ctx:
            code = 'char* key = "sk-abcdefgh12345678";'
            anonymized = ctx.process(code)

            assert 'sk-REDACTED_API_KEY' in anonymized

            result = ctx.get_last_result()
            assert result is not None
            assert len(result.replacements) >= 1

    def test_no_sensitive_content(self, anonymizer):
        """测试无敏感内容的代码"""
        code = """
        int add(int a, int b) {
            return a + b;
        }
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert result.anonymized == code
        assert len(result.replacements) == 0
        assert len(result.warnings) == 0

    def test_aws_key_redaction(self, anonymizer):
        """测试AWS密钥脱敏"""
        code = """
        // AWS配置
        char* access_key = "AKIAIOSFODNN7EXAMPLE";
        """

        result = anonymizer.anonymize(code, AnonymizationLevel.LOW)

        assert 'AKIA_REDACTED_KEY' in result.anonymized
        assert 'AKIAIOSFODNN7EXAMPLE' not in result.anonymized
