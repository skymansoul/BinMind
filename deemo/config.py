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
    """脱敏 API Key — 保留首尾各 N 位，中间替换为 *"""
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
    """检查 OpenAI API Key 是否已配置"""
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
    """返回当前 provider 对应的模型名称；未显式配置则回退到 OPENAI_MODEL"""
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
    """验证崩溃数据格式 — 返回 (is_valid, error_message)"""
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


# =============================================================================
# 模块级导出常量 — from config import X 需要模块级名称。
# Config 类属性通过 os.environ.get 动态读取，以下为其模块级别名，
# 供 core/pipeline.py、core/decompiler.py 等直接导入。
# 注：这些不是独立的配置项，仅桥接 Config 类属性到模块命名空间。
# =============================================================================

# 反编译器与工具路径 — 默认值仅作为回退，生产环境通过环境变量注入
R2_PATH = os.environ.get('R2_PATH', 'radare2')

# LLM 端点映射 — JSON 格式, 支持 ollama/llamacpp/custom 三种后端
# 默认值指向本地默认端口, 部署时通过 LLM_ENDPOINTS 环境变量覆盖
import json as _json
_default_llm_endpoints = _json.dumps({
    'ollama': 'http://localhost:11434',
    'llamacpp': 'http://localhost:8080',
    'custom': '',
})
LLM_ENDPOINTS = _json.loads(os.environ.get('LLM_ENDPOINTS', _default_llm_endpoints))

# API 密钥 — 敏感信息，仅允许通过环境变量注入
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

# 功能开关 — 环境变量控制，默认关闭重型分析
ENABLE_SYMBOLIC = os.environ.get('ENABLE_SYMBOLIC', 'false').lower() == 'true'
ENABLE_CRYPTO_SCAN = os.environ.get('ENABLE_CRYPTO_SCAN', 'false').lower() == 'true'
ENABLE_TAINTRACK = os.environ.get('ENABLE_TAINTRACK', 'false').lower() == 'true'
ENABLE_UNPACK = os.environ.get('ENABLE_UNPACK', 'false').lower() == 'true'

# 并行与规模限制
MAX_FUNCTIONS = int(os.environ.get('MAX_FUNCTIONS', '500'))
MAX_PARALLEL = int(os.environ.get('MAX_PARALLEL', '4'))
EXPLOIT_GEN = os.environ.get('EXPLOIT_GEN', 'false').lower() == 'true'

# 报告输出目录
RESULTS_DIR = os.environ.get('RESULTS_DIR', './reports')

# 兼容性别名 — ensure_dirs 是代码中广泛使用的名称，ensure_directories 是 config.py 内定义的函数
ensure_dirs = ensure_directories

# AI 提供商常量 — 模块级别名
AI_PROVIDER = os.environ.get('AI_PROVIDER', AI_PROVIDER_OPENAI)

# Config 类属性的模块级别名 — core/decompiler.py, core/pipeline.py 等直接导入
# 注：Config 类的同名属性可在运行时通过 os.environ 动态覆盖，此处为模块级默认值
SUBPROCESS_TIMEOUT = Config.SUBPROCESS_TIMEOUT
DEFAULT_DECOMPILER = Config.DEFAULT_DECOMPILER
GHIDRA_TIMEOUT = Config.GHIDRA_TIMEOUT
ANGR_TIMEOUT = Config.ANGR_TIMEOUT
DB_PATH = Config.DB_PATH
CORPUS_DIR = Config.CORPUS_DIR


# =============================================================================
# 以下配置项对应各模块的可调参数。
# 集中定义而非在各模块内硬编码——便于跨模块调参和基准测试。
# 默认值基于开发环境的初步调试，生产部署前需在各目标 workload 上校准。
# =============================================================================

# --- 路径多样性管理 (PathDiversityTracker) ---
# SimHash 排斥阈值——汉明距离超过此值的路径对直接判定为不相似
SIMHASH_REJECTION_THRESHOLD = 3  # [1, 5]，越低越保守（更少排斥，更多精确计算）
# 自适应阈值的速度窗口和步长
DIVERSITY_VELOCITY_WINDOW_SEC = 10.0
DIVERSITY_THRESHOLD_STEP = 0.02
DIVERSITY_THRESHOLD_MIN = 0.50
DIVERSITY_THRESHOLD_MAX = 0.95
DIVERSITY_VELOCITY_LOW = 0.5   # 低于此值→降低阈值（促进分裂）
DIVERSITY_VELOCITY_HIGH = 5.0  # 高于此值→提高阈值（减少冗余）
# DiversityBudget 配额
DIVERSITY_MAX_PATHS = 1000
DIVERSITY_BUDGET_REFRESH_INTERVAL = 60  # 配额重算间隔（秒）

# --- 求解器资源自适应管理 ---
# ConstraintComplexityEstimator
COMPLEXITY_ESTIMATOR_LEARNING_RATE = 0.01
COMPLEXITY_ESTIMATOR_HISTORY_SIZE = 500
# IncrementalSolverCache 定期重建
INCREMENTAL_SOLVER_REBUILD_CONSTRAINT_LIMIT = 500
INCREMENTAL_SOLVER_REBUILD_SOLVE_COUNT = 200
# SolverBudgetManager
SOLVER_BUDGET_PER_INTERVAL = 60.0   # 每周期预算（秒）
SOLVER_BUDGET_INTERVAL = 60.0       # 刷新周期（秒）
# 熵引导预算分配
ENTROPY_BUDGET_MAX_RATIO = 3.0      # 高熵路径可获得的最大预算倍率
ENTROPY_BUDGET_MIN_RATIO = 0.3      # 低熵路径可被削减的最小预算倍率

# --- 时态路径缓存 (TemporalPathCache) ---
# SimHash 分桶 + 指数时间衰减 + 自适应半衰期
# 探索速度骤降时临时缩短半衰期以加速遗忘旧路径
TEMPORAL_CACHE_HALFLIFE_SEC = 120.0      # 权重衰减半衰期（基准值）
TEMPORAL_CACHE_MAX_PER_BUCKET = 50       # 触发子桶分裂的阈值
TEMPORAL_CACHE_EVICT_MAX_AGE = 600.0     # 批量逐出阈值（秒）
TEMPORAL_CACHE_MIN_RETENTION_SEC = 5.0   # 最小保留时间——防刚添加的路径被逐出
TEMPORAL_CACHE_ADAPTIVE_HALFLIFE = True  # 自适应半衰期开关

# --- GNN 图增强与粗化 ---
# 度感知边丢弃
GRAVITY_DROPOUT_RATE = 0.15
# CFG 粗化
CFG_COARSENING_MAX_CHAIN_LENGTH = 4  # 收缩链长度上限——防止 O0 代码过度合并

# --- 跨架构归一化 ---
CROSS_ARCH_NORMALIZE_ARM_COND = True  # ARM 条件执行后缀归一化开关

# --- 模糊测试 ---
# 覆盖密度感知变异
COVERAGE_DENSITY_BUCKET_SHIFT = 6    # 64 条边/bucket
COVERAGE_DENSITY_HALFLIFE_EXECS = 500
# 稀有度加权调度
RARITY_SCHEDULER_RECALC_INTERVAL = 1000

# --- 反编译器集成 ---
DECOMPILER_ENSEMBLE_TEMPERATURE = 0.5
DECOMPILER_ENSEMBLE_EMA_ALPHA = 0.1

# --- 状态备忘录 (StateMemento) ---
# ref: KLEE 2024 ICSE Workshop "State Merging with Quantifiers"
# 本模块采用 Memento 模式而非状态合并，保留路径特异性的同时压缩存储
STATE_MEMENTO_MEMORY_BUDGET_MB = 256.0   # 全局内存预算（MB）
STATE_MEMENTO_MAX_PER_PATH = 10          # 单路径最大快照数
STATE_MEMENTO_BUDGET_EVICT_TARGET = 0.8  # 逐出目标（预算的 80%）

# --- 冷点引导探索器 (ColdSpotGuidedExplorer) ---
# ref: Sun et al. ICSE 2024 — 基于约束编辑距离的冷点引导符号执行
# 在符号执行框架内计算约束编辑距离——不依赖 LLM
COLDSPOT_MAX_EDIT_DISTANCE = 15.0        # 超过此编辑距离的方案丢弃
COLDSPOT_MIN_REACHABILITY = 0.1          # 最低可达性估计阈值
COLDSPOT_TOP_K_NEAREST = 3               # 每个冷点的最近邻路径数

# --- 度保持边丢弃 (DegreePreservingDropout) ---
# ref: DropEdge (Rong et al., ICLR 2020); BEGA gravity model
# 在 DropEdge 的 O(|V|) 复杂度上加入度数感知保护
DEGREE_DROPOUT_GLOBAL_PROB = 0.15        # 全局基准丢弃概率
DEGREE_DROPOUT_PROTECTION_BETA = 2.0     # 度数保护阈值——度数 <= beta 的边受保护
DEGREE_DROPOUT_SPARSE_ADAPTIVE = True    # 稀疏度自适应因子开关

# --- 子寄存器污点追踪 (SubRegTaintState) ---
# ref: Intel SDM Vol.1 §3.4.1.1; Brumley et al. BAP (CMU)
# 字节级寄存器污点——将 RAX 拆分为 8 个独立槽位
SUBREG_TAINT_MERGE_MODE = 'union'       # 'union' | 'max_conf' | 'last_writer'

# --- 漂移校准器 (DriftCalibrator) ---
# ref: Gama et al. (2014) ACM CSUR; Page (1954) Biometrika
# CUSUM 漂移检测 + 自动 SGD 重校准
DRIFT_CUSUM_DECAY = 0.95                # 指数衰减因子
DRIFT_CUSUM_OMEGA_AUTO = True           # 自动 ω 校准开关
DRIFT_MIN_SAMPLES = 30                  # 漂移检测启动的最小样本数
DRIFT_COOLDOWN_PERIOD = 50              # 重校准后的冷却样本数

# --- CFG 熵指纹 (cfg_entropy_fingerprint) ---
# ref: Spielman (2007) "Spectral Graph Theory" — 图拉普拉斯正则化的数学基础
# 将字节熵嵌入 CFG 结构，提取拉普拉斯谱特征
CFG_ENTROPY_FINGERPRINT_K = 5           # 保留的特征值数量
CFG_ENTROPY_POWER_ITER_THRESHOLD = 1000 # 超过此节点数使用幂迭代近似
CFG_ENTROPY_SIMILARITY_METHOD = 'cosine'  # 'cosine' | 'euclidean'

# --- 编译器产物归一化器 (CompilerArtifactNormalizer) ---
COMPILER_NORMALIZE_UNROLL = True        # 循环展开折叠开关
COMPILER_NORMALIZE_IDIOM = True         # 惯用法替换开关

# --- 跨层污点路由器 (CrossLayerTaintRouter) ---
# ref: Caballero et al. USENIX Security 2009
CROSS_LAYER_TAINT_BINDING_PATH = ''     # ProtocolFieldBinding JSON 路径 (空=内置默认)

# --- 堆原语链搜索 (primitive_chain) ---
# A* 堆原语链搜索，补全 exploit 管线的"需要什么布局"阶段
HEAP_CHAIN_MAX_DEPTH = 15               # 最大搜索深度（原语步数）
HEAP_CHAIN_MAX_STATES = 5000            # 最大探索状态数
HEAP_CHAIN_GOAL_CAPABILITY = 'arb_write'  # 目标能力
HEAP_CHAIN_DEFAULT_ALLOCATOR = 'ptmalloc2'

# --- 二进制级常量时间验证 (const_time) ---
# 无源码二进制文件的秘密依赖分支/访存/循环检测
CONST_TIME_MIN_CONFIDENCE = 0.6         # 秘密源的最低置信度
CONST_TIME_TAINT_MAX_ITER = 50          # 污点传播的最大迭代轮数
CONST_TIME_CI_FAIL_ON = 'HIGH'          # CI 中断的最低严重度 (CRITICAL|HIGH|MEDIUM|LOW|NONE)

# --- 污点约束符号探索器 (TaintConstrainedExplorer) ---
# 字节级污点 -> 符号执行路径优先级的跨层桥接
TAINT_EXPLORER_DECAY_FACTOR = 0.85      # 间接污点置信度衰减因子
TAINT_EXPLORER_DIVERSITY_WEIGHT = 0.6   # 多样性评分在融合优先级中的权重

# --- ptmalloc2 堆状态机 (Ptmalloc2StateMachine) ---
# 确定性 DFA 预测 malloc/free 序列的堆布局
# ref: glibc malloc/malloc.c; He et al. IEEE S&P 2023
PTMALLOC2_START_ADDRESS = 0x100000      # 模拟堆的起始地址

# --- 分布式工作窃取 ---
WORK_STEALING_IDLE_THRESHOLD = 5
WORK_STEALING_HEARTBEAT_INTERVAL = 5.0
WORK_STEALING_STATE_TTL = 15.0

# --- 二进制语义差异分析 (binary_diff) ---
# 指令语义哈希
BINDIFF_HASH_FLAGS_GRANULARITY = 'class'   # 'class' | 'detailed' —— 标志位等价类的聚合级别
BINDIFF_IMM_TRUNCATE_THRESHOLD = 256       # 立即数折叠粒度——小于此值的立即数视为等价
# 基本块匹配
BINDIFF_BLOCK_MATCH_THRESHOLD = 0.45       # 块级最小匹配分数——O2 vs O0 场景下校准
BINDIFF_KGRAM_SIZE = 3                     # k-gram 预过滤的 k 值
BINDIFF_MAX_MATCHES_PER_BLOCK = 3          # 每条块的最大匹配对数量——防止大块垄断
# Patch 分类
BINDIFF_EXPLOITABILITY_MIN_SCORE = 30.0    # exploitability 报告的最低分数阈值
BINDIFF_PATCH_AGE_WEIGHT_DECAY = 0.001     # 补丁年龄的指数衰减因子

# --- 静态并发缺陷检测 (concurrency_analysis) ---
# 锁图分析
CONCURRENCY_MAX_LOCK_NESTING = 8           # 锁嵌套深度上限——超过视为潜在设计缺陷
CONCURRENCY_MIN_SCC_SIZE = 2               # 死锁检测的最小 SCC 大小
# 数据竞争检测
CONCURRENCY_MIN_ACCESSORS_FOR_RACE = 2     # 至少 N 个访问者才触发竞争检查
CONCURRENCY_RACE_SEVERITY_THRESHOLD = 'MEDIUM'  # CI 中断的最小严重度
# 线程入口推断
CONCURRENCY_INFER_THREADS_FROM_LOCKS = True  # 无显式线程创建时从锁使用推断并发性