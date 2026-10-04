# Config 配置类与提供商常量
import os
from typing import Dict, Any

from _config_sensitive import (
    AI_PROVIDER_OPENAI,
    AI_PROVIDER_AZURE,
    AI_PROVIDER_OLLAMA,
    AI_PROVIDER_LLAMACPP,
    AI_PROVIDER_CUSTOM,
)

logger = __import__('logging').getLogger('config')


class Config:
    """项目配置管理类"""

    # AI 服务配置-可选值: openai / azure / ollama / llamacpp / custom / deepseek
    AI_PROVIDER = os.environ.get('AI_PROVIDER', AI_PROVIDER_OPENAI)

    # OpenAI 或 OpenAI 兼容服务
    OPENAI_API_KEY = os.environ.get('API_KEY') or os.environ.get('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.environ.get('AI_MODEL', 'gpt-4')
    OPENAI_BASE_URL = os.environ.get('BASE_URL') or os.environ.get('OPENAI_BASE_URL') or None
    # 本地 DeepSeek 代理端口，Cloudflare Tunnel 转发的目标
    # OPENAI_BASE_URL = 'http://localhost:8800/v1'
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
    CUSTOM_API_KEY = os.environ.get('API_KEY') or os.environ.get('CUSTOM_API_KEY', '')
    CUSTOM_BASE_URL = os.environ.get('BASE_URL') or os.environ.get('CUSTOM_BASE_URL', '')
    CUSTOM_MODEL = os.environ.get('AI_MODEL', '')

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
