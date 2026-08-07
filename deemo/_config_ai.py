# AI 客户端与工具函数
import os
import logging
from typing import Optional, Dict, Any

from _config_sensitive import (
    mask_api_key,
    mask_sensitive_data,
    SensitiveFilter,
    AI_PROVIDER_OPENAI,
    AI_PROVIDER_AZURE,
    AI_PROVIDER_OLLAMA,
    AI_PROVIDER_LLAMACPP,
    AI_PROVIDER_CUSTOM,
)
from _config_base import Config

logger = logging.getLogger('config')


def check_openai_api_key() -> bool:
    """检查 OpenAI API Key 是否已配置"""
    api_key = Config.OPENAI_API_KEY
    if not api_key or api_key.strip() == '':
        return False
    return True


def get_openai_client():
    """获取 AI 客户端实例，支持多种 AI 提供商"""
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
    """创建标准 OpenAI 客户端"""
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
    """创建 Azure OpenAI 客户端"""
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
    """创建 Ollama 本地模型客户端"""
    from openai import OpenAI

    ollama_base = f"{Config.OLLAMA_HOST}/v1"

    client = OpenAI(
        api_key="ollama",
        base_url=ollama_base
    )

    logger.info(f"Ollama 客户端初始化成功，Host: {Config.OLLAMA_HOST}, Model: {Config.OLLAMA_MODEL}")
    return client


def _create_llamacpp_client():
    """创建 llama.cpp 本地模型客户端"""
    from openai import OpenAI

    llamacpp_base = f"{Config.LLAMACPP_HOST}/v1"

    client = OpenAI(
        api_key="llama-cpp",
        base_url=llamacpp_base
    )

    logger.info(f"llama.cpp 客户端初始化成功，Host: {Config.LLAMACPP_HOST}")
    return client


def _create_custom_client():
    """创建自定义 API 客户端"""
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
    """确保所需目录存在"""
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
    """校验 SANDBOX_MODE / docker / podman 可用性"""
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
    """拼装 postgresql:// 连接串"""
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
    """返回标准格式的崩溃数据样本"""
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
    """AI API 调用——指数退避重试（最多3次），全部失败后降级为启发式分析"""
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
    """发送一条简短的 chat completion 请求确认 AI API 连通性"""
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
