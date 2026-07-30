<<<<<<< HEAD
import os
import logging
import re
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

AI_PROVIDER_OPENAI = 'openai'
AI_PROVIDER_AZURE = 'azure'
AI_PROVIDER_OLLAMA = 'ollama'
AI_PROVIDER_LLAMACPP = 'llamacpp'
AI_PROVIDER_CUSTOM = 'custom'


def mask_api_key(api_key: str, show_first: int = 4, show_last: int = 4) -> str:
    """
    脱敏 API Key，显示前 N 位和后 N 位，中间用 * 代替
    
    Args:
        api_key: 原始 API Key
        show_first: 显示前几位
        show_last: 显示后几位
        
    Returns:
        脱敏后的 API Key
    """
    if not api_key or not isinstance(api_key, str):
        return api_key
    
    key_length = len(api_key)
    
    if key_length <= show_first + show_last:
        return '*' * key_length
    
    prefix = api_key[:show_first]
    suffix = api_key[-show_last:]
    middle = '*' * (key_length - show_first - show_last)
    
    return f"{prefix}{middle}{suffix}"


def mask_sensitive_data(text: str) -> str:
    """
    脱敏处理敏感信息，适用于日志输出
    显示前 4 位和后 4 位，中间用 * 代替
    
    Args:
        text: 原始文本
        
    Returns:
        脱敏后的文本
    """
    if not text or not isinstance(text, str):
        return text
    
    def replace_partial(match):
        prefix = match.group(1) if len(match.groups()) >= 2 else ''
        key = match.group(2) if len(match.groups()) >= 2 else match.group(1)
        
        if key:
            masked_key = mask_api_key(key)
            return prefix + masked_key
        
        return match.group(0)
    
    def replace_full(match):
        prefix = match.group(1) if len(match.groups()) >= 2 else ''
        env_name = match.group(2) if len(match.groups()) >= 2 else ''
        key = match.group(3) if len(match.groups()) >= 3 else match.group(1)
        
        if key and env_name and 'key' in env_name.lower():
            masked_key = mask_api_key(key)
            return prefix + masked_key
        elif key:
            masked_key = mask_api_key(key)
            return prefix + masked_key
        
        return match.group(0)
    
    api_key_patterns = [
        r'(api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
        r'(key\s*[=:]\s*["\']?)(sk-[a-zA-Z0-9_\-]{32,})',
        r'()(sk-[a-zA-Z0-9_\-]{32,})',
        r'(authorization\s*[=:]\s*["\']?Bearer\s+)([a-zA-Z0-9\-_.]+)',
        r'(AZURE_OPENAI_API_KEY\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
        r'(CUSTOM_API_KEY\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
    ]
    
    masked = text
    for pattern in api_key_patterns:
        masked = re.sub(pattern, replace_partial, masked, flags=re.IGNORECASE)
    
    token_patterns = [
        r'(token\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(access[_-]?token\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(secret\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(password\s*[=:]\s*["\']?)([^"\'\s]{4,})',
    ]
    
    for pattern in token_patterns:
        masked = re.sub(pattern, replace_partial, masked, flags=re.IGNORECASE)
    
    env_patterns = [
        r'([A-Z0-9_]+_API_KEY)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
        r'([A-Z0-9_]+_SECRET)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
        r'([A-Z0-9_]+_TOKEN)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
    ]
    
    for pattern in env_patterns:
        masked = re.sub(pattern, r'\1=***MASKED***', masked, flags=re.IGNORECASE)
    
    return masked


class SensitiveFilter(logging.Filter):
    """
    日志过滤器，自动脱敏敏感信息
    """
    
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_data(record.msg)
        
        if record.args:
            args_list = list(record.args)
            for i, arg in enumerate(args_list):
                if isinstance(arg, str):
                    args_list[i] = mask_sensitive_data(arg)
            record.args = tuple(args_list)
        
        return True


class Config:
    """
    项目配置管理类
    """
    
    # AI 服务配置请直接在这里填写，不再通过环境变量读取。
    # 可选值: openai / azure / ollama / llamacpp / custom
    AI_PROVIDER = AI_PROVIDER_OPENAI
    
    # OpenAI 或 OpenAI 兼容服务
    OPENAI_API_KEY = ''
    OPENAI_MODEL = 'gpt-4'
    OPENAI_BASE_URL = None
    OPENAI_ORGANIZATION = None
    
    # Azure OpenAI
    AZURE_API_KEY = ''
    AZURE_ENDPOINT = ''
    AZURE_API_VERSION = '2024-02-15-preview'
    AZURE_DEPLOYMENT = ''
    
    # Ollama
    OLLAMA_HOST = 'http://localhost:11434'
    OLLAMA_MODEL = 'llama2'
    
    # llama.cpp
    LLAMACPP_HOST = 'http://localhost:8080'
    
    # 自定义 OpenAI 兼容 API
    CUSTOM_API_KEY = ''
    CUSTOM_BASE_URL = ''
    CUSTOM_MODEL = ''
    
    LOGS_DIR = './logs'
    REPORTS_DIR = './reports'
    EXPLOITS_DIR = './exploits'
    DB_DIR = './data'
    DATA_DIR = './data'
    CACHE_DIR = './data/cache'
    CORPUS_DIR = './data/corpus'
    
    MAX_ITERATIONS = 5
    SUBPROCESS_TIMEOUT = 30
    RADARE2_TIMEOUT = 120
    GHIDRA_TIMEOUT = 300
    IDA_TIMEOUT = 300
    ANGR_TIMEOUT = 300
    
    REQUIRED_FIELDS_CRASH_DATA = ['registers']
    OPTIONAL_FIELDS_CRASH_DATA = ['stack_trace', 'fault_instruction', 'output', 'stdout', 'stderr']
    
    DEFAULT_DECOMPILER = os.environ.get('DEFAULT_DECOMPILER', 'auto')
    ENABLE_SYMBOLIC_EXECUTION = os.environ.get('ENABLE_SYMBOLIC_EXECUTION', 'false').lower() == 'true'
    
    DB_PATH = os.path.join(DB_DIR, 'vulnerabilities.db')
    
    SANDBOX_MODE = os.environ.get('SANDBOX_MODE', 'none').lower()
    SANDBOX_IMAGE = os.environ.get('SANDBOX_IMAGE', 'deemo-analyzer:latest')
    SANDBOX_TIMEOUT = int(os.environ.get('SANDBOX_TIMEOUT', '60'))
    SANDBOX_MEMORY_LIMIT = os.environ.get('SANDBOX_MEMORY_LIMIT', '512m')
    SANDBOX_CPU_LIMIT = float(os.environ.get('SANDBOX_CPU_LIMIT', '1.0'))
    SANDBOX_NETWORK_ENABLED = os.environ.get('SANDBOX_NETWORK_ENABLED', 'false').lower() == 'true'
    
    DB_TYPE = os.environ.get('DB_TYPE', 'sqlite').lower()
    POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
    POSTGRES_PORT = int(os.environ.get('POSTGRES_PORT', '5432'))
    POSTGRES_USER = os.environ.get('POSTGRES_USER', 'deemo')
    POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')
    POSTGRES_DB = os.environ.get('POSTGRES_DB', 'deemo_vuln_db')
    
    API_HOST = os.environ.get('API_HOST', '0.0.0.0')
    API_PORT = int(os.environ.get('API_PORT', '8000'))
    API_RELOAD = os.environ.get('API_RELOAD', 'false').lower() == 'true'
    
    CACHE_TTL = int(os.environ.get('CACHE_TTL', '3600'))
    EXTERNAL_API_RATE_LIMIT = int(os.environ.get('EXTERNAL_API_RATE_LIMIT', '10'))
    EXTERNAL_API_RATE_PERIOD = int(os.environ.get('EXTERNAL_API_RATE_PERIOD', '60'))
    
    FUZZER_MAX_RUNTIME = int(os.environ.get('FUZZER_MAX_RUNTIME', '3600'))
    FUZZER_MAX_CPU = int(os.environ.get('FUZZER_MAX_CPU', '1'))
    FUZZER_MEMORY_LIMIT = int(os.environ.get('FUZZER_MEMORY_LIMIT', '2048'))


def check_openai_api_key() -> bool:
    """
    检查 OpenAI API Key 是否配置
    
        True 如果配置了 API Key，否则 False
    """
    api_key = Config.OPENAI_API_KEY
    if not api_key or api_key.strip() == '':
        return False
    return True


def get_openai_client():
    """
    获取 AI 客户端实例，支持多种 AI 提供商
    
        OpenAI 兼容的客户端实例，如果未配置则返回 None
    """
    provider = Config.AI_PROVIDER
    logger.info(f"正在初始化 AI 客户端，提供商: {provider}")
    
    try:
        from openai import OpenAI, AzureOpenAI
    except ImportError:
        logger.error("openai 库未安装，请运行: pip install openai")
        return None
    
    try:
        if provider == AI_PROVIDER_OPENAI:
            return _create_openai_client()
        elif provider == AI_PROVIDER_AZURE:
            return _create_azure_client()
        elif provider == AI_PROVIDER_OLLAMA:
            return _create_ollama_client()
        elif provider == AI_PROVIDER_LLAMACPP:
            return _create_llamacpp_client()
        elif provider == AI_PROVIDER_CUSTOM:
            return _create_custom_client()
        else:
            logger.warning(f"未知的 AI 提供商: {provider}，使用 OpenAI 作为默认")
            return _create_openai_client()
    except Exception as e:
        logger.error(f"初始化 AI 客户端失败: {e}")
        return None


def _create_openai_client():
    """
    创建标准 OpenAI 客户端
    """
    if not check_openai_api_key():
        logger.warning("Config.OPENAI_API_KEY 未配置，将使用启发式分析模式")
        return None
    
    from openai import OpenAI
    
    client_kwargs = {'api_key': Config.OPENAI_API_KEY}
    if Config.OPENAI_BASE_URL:
        client_kwargs['base_url'] = Config.OPENAI_BASE_URL
        logger.info(f"使用自定义 OpenAI Base URL: {Config.OPENAI_BASE_URL}")
    
    if Config.OPENAI_ORGANIZATION:
        client_kwargs['organization'] = Config.OPENAI_ORGANIZATION
    
    client = OpenAI(**client_kwargs)
    
    masked_key = mask_api_key(Config.OPENAI_API_KEY)
    logger.info(f"OpenAI 客户端初始化成功，API Key: {masked_key}, 模型: {Config.OPENAI_MODEL}")
    return client


def _create_azure_client():
    """
    创建 Azure OpenAI 客户端
    """
    if not Config.AZURE_API_KEY:
        logger.warning("Config.AZURE_API_KEY 未配置")
        return None
    
    if not Config.AZURE_ENDPOINT:
        logger.warning("Config.AZURE_ENDPOINT 未配置")
        return None
    
    from openai import AzureOpenAI
    
    client = AzureOpenAI(
        api_key=Config.AZURE_API_KEY,
        azure_endpoint=Config.AZURE_ENDPOINT,
        api_version=Config.AZURE_API_VERSION,
        azure_deployment=Config.AZURE_DEPLOYMENT if Config.AZURE_DEPLOYMENT else None
    )
    
    masked_key = mask_api_key(Config.AZURE_API_KEY)
    logger.info(f"Azure OpenAI 客户端初始化成功，API Key: {masked_key}")
    return client


def _create_ollama_client():
    """
    创建 Ollama 本地模型客户端
    """
    from openai import OpenAI
    
    ollama_base = f"{Config.OLLAMA_HOST}/v1"
    
    client = OpenAI(
        api_key="ollama",
        base_url=ollama_base
    )
    
    logger.info(f"Ollama 客户端初始化成功，Host: {Config.OLLAMA_HOST}, Model: {Config.OLLAMA_MODEL}")
    return client


def _create_llamacpp_client():
    """
    创建 llama.cpp 本地模型客户端
    """
    from openai import OpenAI
    
    llamacpp_base = f"{Config.LLAMACPP_HOST}/v1"
    
    client = OpenAI(
        api_key="llama-cpp",
        base_url=llamacpp_base
    )
    
    logger.info(f"llama.cpp 客户端初始化成功，Host: {Config.LLAMACPP_HOST}")
    return client


def _create_custom_client():
    """
    创建自定义 API 客户端
    """
    if not Config.CUSTOM_BASE_URL:
        logger.warning("CUSTOM_BASE_URL 未配置")
        return None
    
    from openai import OpenAI
    
    api_key = Config.CUSTOM_API_KEY or "custom"
    client_kwargs = {
        'api_key': api_key,
        'base_url': Config.CUSTOM_BASE_URL
    }
    
    client = OpenAI(**client_kwargs)
    
    if Config.CUSTOM_API_KEY:
        masked_key = mask_api_key(Config.CUSTOM_API_KEY)
        logger.info(f"自定义 API 客户端初始化成功，API Key: {masked_key}, Base URL: {Config.CUSTOM_BASE_URL}")
    else:
        logger.info(f"自定义 API 客户端初始化成功（无 API Key），Base URL: {Config.CUSTOM_BASE_URL}")
    
    return client


def get_current_ai_model() -> str:
    """
    获取当前配置的 AI 模型名称
    
    Returns:
        当前模型名称
    """
    provider = Config.AI_PROVIDER
    
    if provider == AI_PROVIDER_OLLAMA:
        return Config.OLLAMA_MODEL
    elif provider == AI_PROVIDER_CUSTOM:
        if Config.CUSTOM_MODEL:
            return Config.CUSTOM_MODEL
    elif provider == AI_PROVIDER_AZURE:
        if Config.AZURE_DEPLOYMENT:
            return Config.AZURE_DEPLOYMENT
    
    return Config.OPENAI_MODEL


def ensure_directories():
    """
    确保所需目录存在
    """
    dirs_to_create = {
        Config.LOGS_DIR,
        Config.REPORTS_DIR,
        Config.EXPLOITS_DIR,
        Config.DB_DIR,
        Config.CACHE_DIR,
        Config.CORPUS_DIR
    }
    
    for dir_path in dirs_to_create:
        try:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                logger.info(f"创建目录: {dir_path}")
        except Exception as e:
            logger.error(f"创建目录失败 {dir_path}: {e}")


def validate_sandbox_config() -> Dict[str, Any]:
    """
    验证沙箱配置
    
    Returns:
        包含验证结果的字典
    """
    sandbox_mode = Config.SANDBOX_MODE
    valid_modes = ['none', 'docker', 'podman']
    
    result = {
        'valid': sandbox_mode in valid_modes,
        'mode': sandbox_mode,
        'issues': []
    }
    
    if sandbox_mode not in valid_modes:
        result['issues'].append(
            f"无效的 SANDBOX_MODE: {sandbox_mode}。有效值: {valid_modes}"
        )
    
    if sandbox_mode == 'docker':
        try:
            import docker
            client = docker.from_env()
            client.ping()
            result['docker_available'] = True
        except ImportError:
            result['issues'].append("Docker SDK 未安装，请运行: pip install docker")
        except Exception as e:
            result['issues'].append(f"Docker 不可用: {e}")
    
    if sandbox_mode == 'podman':
        try:
            import subprocess
            subprocess.run(['podman', '--version'], capture_output=True, check=True)
            result['podman_available'] = True
        except (FileNotFoundError, subprocess.CalledProcessError):
            result['issues'].append("Podman 未安装或不在 PATH 中")
    
    return result


def get_postgres_connection_string() -> Optional[str]:
    """
    获取 PostgreSQL 连接字符串
    
    Returns:
        PostgreSQL 连接字符串，如果配置不完整则返回 None
    """
    if Config.DB_TYPE != 'postgres':
        return None
    
    if not Config.POSTGRES_PASSWORD:
        logger.warning("POSTGRES_PASSWORD 未设置")
        return None
    
    return (
        f"postgresql://{Config.POSTGRES_USER}:{Config.POSTGRES_PASSWORD}"
        f"@{Config.POSTGRES_HOST}:{Config.POSTGRES_PORT}/{Config.POSTGRES_DB}"
    )


def validate_crash_data(crash_data: dict) -> tuple:
    """
    验证崩溃数据格式
    
    """
    if not isinstance(crash_data, dict):
        return False, "崩溃数据必须是字典格式"
    
    has_required = any(field in crash_data for field in Config.REQUIRED_FIELDS_CRASH_DATA)
    has_optional = any(field in crash_data for field in Config.OPTIONAL_FIELDS_CRASH_DATA)
    
    if not has_required and not has_optional:
        return False, f"崩溃数据缺少必要字段，至少需要包含: {Config.REQUIRED_FIELDS_CRASH_DATA}"
    
    return True, None


def get_crash_data_example() -> dict:
    """
    获取崩溃数据示例格式
    
    Returns:
        示例崩溃数据字典
    """
    return {
        "registers": {
            "rax": "0x0000000000000000",
            "rbx": "0x0000000000000000",
            "rcx": "0x0000000000000000",
            "rdx": "0x0000000000000000",
            "rsi": "0x0000000000000000",
            "rdi": "0x0000000000000000",
            "rbp": "0x00007fffffffdc00",
            "rsp": "0x00007fffffffdbe8",
            "r8": "0x0000000000000000",
            "r9": "0x0000000000000000",
            "r10": "0x0000000000000000",
            "r11": "0x0000000000000000",
            "r12": "0x0000000000000000",
            "r13": "0x0000000000000000",
            "r14": "0x0000000000000000",
            "r15": "0x0000000000000000",
            "rip": "0x000055555555514a",
            "eflags": "0x0000000000010202",
            "cs": "0x0000000000000033",
            "ss": "0x000000000000002b"
        },
        "stack_trace": [
            "#0  0x000055555555514a in main ()",
            "#1  0x00007ffff7c29d90 in __libc_start_call_main ()",
            "#2  0x00007ffff7c29e40 in __libc_start_main_impl ()"
        ],
        "fault_instruction": "0x55555555514a <main+31>:    ret",
        "output": "Segmentation fault (core dumped)",
        "signal": "SIGSEGV"
    }


def call_ai_with_retry(client, **kwargs) -> Optional[str]:
    """
    统一的 AI API 调用函数，包含指数退避重试和降级支持
    
    Args:
        client: OpenAI 兼容的客户端
        **kwargs: 传递给 chat.completions.create 的参数
        
    Returns:
        AI 响应文本，失败返回 None
    """
    import time
    
    max_retries = 3
    base_delay = 1
    
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            logger.info(f"[AI] 调用 API (尝试 {attempt + 1}/{max_retries})")
            
            response = client.chat.completions.create(**kwargs)
            result_text = response.choices[0].message.content
            logger.info("[AI] API 调用成功")
            return result_text
            
        except Exception as e:
            last_exception = e
            logger.warning(f"[AI] API 调用失败 (尝试 {attempt + 1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                logger.info(f"[AI] 等待 {delay} 秒后重试...")
                time.sleep(delay)
    
    logger.error(f"[AI] 所有重试均失败: {last_exception}")
    logger.warning("[AI] 切换到启发式分析模式")
    
    return None


def test_api_connection(client) -> bool:
    """
    测试 AI API 连接是否正常
    
    Args:
        client: OpenAI 兼容的客户端
        
    Returns:
        True 如果连接正常，否则 False
    """
    try:
        model = get_current_ai_model()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": "Hello"}
            ],
            max_tokens=5
        )
        return True
    except Exception as e:
        logger.error(f"AI API 连接测试失败: {e}")
        return False
=======
#!/usr/bin/env python3
"""
Static configuration for the binary analysis pipeline.
All values can be overridden via environment variables.
No external config file dependency — keeps Docker deploys simple.
"""

import os as _os

_BASE = _os.path.dirname(_os.path.abspath(__file__))


# -- paths -----------------------------------------------------------
DATA_DIR     = _os.path.join(_BASE, 'data')
RESULTS_DIR  = _os.path.join(_BASE, 'results')
LOGS_DIR     = _os.path.join(_BASE, 'logs')
CACHE_DIR    = _os.path.join(_BASE, 'cache')
CORPUS_DIR   = _os.path.join(_BASE, 'corpus')
DB_PATH      = _os.path.join(DATA_DIR, 'vulnerabilities.db')

# -- API keys (env-only, never hardcoded) ----------------------------
OPENAI_API_KEY      = _os.environ.get('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY   = _os.environ.get('ANTHROPIC_API_KEY', '')
GITHUB_TOKEN        = _os.environ.get('GITHUB_TOKEN', '')

# -- AI provider ----------------------------------------------------
AI_PROVIDER  = _os.environ.get('AI_PROVIDER', 'openai')
AI_MODEL     = _os.environ.get('AI_MODEL', 'gpt-4o')

# -- timeouts (seconds) ----------------------------------------------
SUBPROCESS_TIMEOUT = int(_os.environ.get('TIMEOUT', '300'))
R2_TIMEOUT         = 60
ANGR_TIMEOUT       = 300
GHIDRA_TIMEOUT     = 1800

# -- decompiler ------------------------------------------------------
DEFAULT_DECOMPILER = _os.environ.get('DECOMPILER', 'auto')   # auto | r2 | ghidra | ida

# -- analysis limits ------------------------------------------------
MAX_FUNCTIONS       = int(_os.environ.get('MAX_FUNCTIONS', '20'))
MAX_PARALLEL        = int(_os.environ.get('MAX_PARALLEL', '4'))
MAX_STRING_LENGTH   = int(_os.environ.get('MAX_STRING_LENGTH', '1024'))

# -- feature flags --------------------------------------------------
ENABLE_SYMBOLIC     = _os.environ.get('ENABLE_SYMBOLIC', 'true').lower() == 'true'
ENABLE_CRYPTO_SCAN  = _os.environ.get('ENABLE_CRYPTO_SCAN', 'true').lower() == 'true'
ENABLE_TAINTRACK    = _os.environ.get('ENABLE_TAINTRACK', 'false').lower() == 'true'
ENABLE_FUZZING      = _os.environ.get('ENABLE_FUZZING', 'false').lower() == 'true'
ENABLE_UNPACK       = _os.environ.get('ENABLE_UNPACK', 'true').lower() == 'true'

# -- module-specific configs (kept as dicts for JSON compat) --------
CRYPTO_SCAN = {
    'check_weak_random': True,
    'check_hardcoded_iv': True,
    'check_weak_hash': True,
    'check_weak_cipher': True,
    'check_hardcoded_secrets': True,
}

HEAP_ANALYSIS = {
    'default_allocator': 'ptmalloc',
    'tcache_count': 7,
    'enable_fastbin': True,
}

EXPLOIT_GEN = {
    'validate_exploit': False,
    'no_rop': False,
    'output_dir': _os.path.join(RESULTS_DIR, 'exploits'),
}

# -- external tool paths --------------------------------------------
R2_PATH      = _os.environ.get('R2_PATH', 'r2')
QEMU_PATH    = _os.environ.get('QEMU_PATH', 'qemu-system-x86_64')
GCC_PATH     = _os.environ.get('GCC_PATH', 'gcc')

# -- LLM backend endpoints ------------------------------------------
LLM_ENDPOINTS = {
    'openai':    'https://api.openai.com/v1',
    'anthropic': 'https://api.anthropic.com/v1',
    'ollama':    _os.environ.get('OLLAMA_HOST', 'http://localhost:11434'),
    'llamacpp':  _os.environ.get('LLAMACPP_HOST', 'http://localhost:8080'),
    'custom':    _os.environ.get('CUSTOM_LLM_URL', ''),
}


def ensure_dirs():
    """Create data/log/results/cache dirs if missing."""
    for p in [DATA_DIR, RESULTS_DIR, LOGS_DIR, CACHE_DIR, CORPUS_DIR]:
        _os.makedirs(p, exist_ok=True)


def check_openai_api_key() -> bool:
    return bool(OPENAI_API_KEY)


def get_current_ai_model() -> str:
    return AI_MODEL
>>>>>>> d81973a (精简冗余模块)
