import json
import re
import os
import logging
import hashlib
from typing import Optional, Dict, Any, List, Callable

# 提示词版本号，用于调用记录追溯
try:
    from prompts import PROMPT_VERSION
except Exception:
    PROMPT_VERSION = "unknown"

logger = logging.getLogger(__name__)

# 统一 Finding 字段定义
FINDING_FIELDS = [
    'function',           # 函数名
    'evidence_address',   # 证据地址
    'input_source',       # 输入源
    'dangerous_op',       # 危险操作
    'confidence',         # 置信度 0.0-1.0
    'evidence_snippet',   # 证据片段
    'review_status',      # 审核状态: pending / confirmed / false_positive
]

# 审核状态枚举
REVIEW_PENDING = 'pending'
REVIEW_CONFIRMED = 'confirmed'
REVIEW_FALSE_POSITIVE = 'false_positive'

# 置信度阈值
CONFIDENCE_CANDIDATE = 0.4   # 候选漏洞
CONFIDENCE_VERIFIED = 0.7    # 已验证

# 分级
TIER_CLUE = 'clue'            # 线索
TIER_CANDIDATE = 'candidate'  # 候选漏洞
TIER_VERIFIED = 'verified'    # 已验证


def classify_tier(confidence: float, review_status: str = REVIEW_PENDING) -> str:
    """根据置信度和审核状态划分三档"""
    if review_status == REVIEW_CONFIRMED:
        return TIER_VERIFIED
    if review_status == REVIEW_FALSE_POSITIVE:
        return TIER_CLUE
    if confidence >= CONFIDENCE_VERIFIED:
        return TIER_VERIFIED
    if confidence >= CONFIDENCE_CANDIDATE:
        return TIER_CANDIDATE
    return TIER_CLUE


def make_finding(
    function: str = '',
    evidence_address: str = '',
    input_source: str = '',
    dangerous_op: str = '',
    confidence: float = 0.0,
    evidence_snippet: str = '',
    vuln_type: str = '',
    description: str = '',
    severity: str = '',
) -> Dict[str, Any]:
    """构造统一 Finding dict"""
    review = REVIEW_PENDING
    tier = classify_tier(confidence, review)
    return {
        'function': function,
        'evidence_address': evidence_address,
        'input_source': input_source,
        'dangerous_op': dangerous_op,
        'confidence': round(confidence, 3),
        'evidence_snippet': evidence_snippet,
        'review_status': review,
        'tier': tier,
        'vuln_type': vuln_type,
        'description': description,
        'severity': severity,
    }


def validate_finding(finding: Dict[str, Any]) -> bool:
    """校验 finding 是否包含必要字段"""
    if not isinstance(finding, dict):
        return False
    for field in FINDING_FIELDS:
        if field not in finding:
            return False
    if not isinstance(finding.get('confidence'), (int, float)):
        return False
    return True


def parse_llm_json(raw_text: str) -> Optional[Dict[str, Any]]:
    """解析 LLM 返回的 JSON，容忍 markdown 代码块包裹"""
    if not raw_text:
        return None

    text = raw_text.strip()

    # 尝试直接解析
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 尝试提取 ```json ... ``` 代码块
    code_block_re = re.compile(r'```(?:json)?\s*\n(.*?)\n```', re.DOTALL)
    match = code_block_re.search(text)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 尝试提取第一个 { 到最后一个 } 之间的内容
    first_brace = text.find('{')
    last_brace = text.rfind('}')
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except json.JSONDecodeError:
            pass

    return None


def normalize_findings(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """将 LLM 解析结果归一化为统一 Finding 列表"""
    findings = []

    if not parsed or not isinstance(parsed, dict):
        return findings

    raw_vulns = parsed.get('vulnerabilities', [])
    if not isinstance(raw_vulns, list):
        raw_vulns = []

    for raw in raw_vulns:
        if not isinstance(raw, dict):
            continue

        confidence_raw = raw.get('confidence', 0.5)
        try:
            confidence = float(confidence_raw)
        except (ValueError, TypeError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        f = make_finding(
            function=raw.get('function', raw.get('function_name', '')),
            evidence_address=raw.get('location', raw.get('evidence_address', '')),
            input_source=raw.get('input_source', ''),
            dangerous_op=raw.get('dangerous_op', raw.get('type', '')),
            confidence=confidence,
            evidence_snippet=raw.get('code_snippet', raw.get('evidence_snippet', '')),
            vuln_type=raw.get('type', ''),
            description=raw.get('description', ''),
            severity=raw.get('severity', ''),
        )
        findings.append(f)

    return findings


def get_cache_dir() -> str:
    """返回 API 缓存目录"""
    cache_dir = os.environ.get('API_CACHE_DIR', './.api_cache')
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def _cache_key(prompt: str, model: str) -> str:
    """生成缓存键"""
    h = hashlib.sha256(f"{model}:{prompt}".encode('utf-8')).hexdigest()
    return h


def cache_get(prompt: str, model: str) -> Optional[str]:
    """读取缓存"""
    key = _cache_key(prompt, model)
    cache_dir = get_cache_dir()
    path = os.path.join(cache_dir, f'{key}.txt')
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            pass
    return None


def cache_put(prompt: str, model: str, response: str):
    """写入缓存"""
    key = _cache_key(prompt, model)
    cache_dir = get_cache_dir()
    path = os.path.join(cache_dir, f'{key}.txt')
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(response)
    except Exception as e:
        logger.warning(f"缓存写入失败: {e}")


def _log_llm_call(record: Dict[str, Any]):
    """将本次 LLM 调用记录追加写入 llm_calls.jsonl"""
    record.setdefault('prompt_version', PROMPT_VERSION)
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, 'llm_calls.jsonl')
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    except Exception as e:
        logger.warning(f"LLM 调用记录写入失败: {e}")


def call_llm(
    messages: List[Dict[str, str]],
    model: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """统一 LLM 调用入口

    返回 dict:
      text: str          — 原始响应文本
      findings: list     — 归一化后的 Finding 列表
      simulation: bool   — 是否为模拟模式（未配置模型或调用失败）
      model: str         — 使用的模型名称
      error: str|None    — 错误信息
    """
    from config import get_openai_client, get_current_ai_model, call_ai_with_retry, mask_sensitive_data

    result = {
        'text': '',
        'findings': [],
        'simulation': False,
        'model': '',
        'error': None,
    }

    active_model = model or get_current_ai_model()
    result['model'] = active_model

    # 安全脱敏：日志中不出现完整密钥
    prompt_for_log = mask_sensitive_data(str(messages)[:200])
    logger.info(f"[LLM] 调用模型 {active_model}, prompt: {prompt_for_log}...")

    # 尝试获取客户端
    client = get_openai_client()

    if client is None:
        logger.warning("[LLM] AI 客户端不可用，进入模拟模式")
        result['simulation'] = True
        result['error'] = 'AI client not configured'
        _log_llm_call({'model': active_model, 'status': 'simulation', 'error': result['error'],
                       'prompt_preview': prompt_for_log})
        return result

    # 缓存
    cache_prompt = json.dumps(messages, ensure_ascii=False)
    if use_cache:
        cached = cache_get(cache_prompt, active_model)
        if cached is not None:
            logger.info("[LLM] 命中缓存")
            result['text'] = cached
            parsed = parse_llm_json(cached)
            if parsed:
                result['findings'] = normalize_findings(parsed)
            _log_llm_call({'model': active_model, 'status': 'cache_hit',
                           'prompt_preview': prompt_for_log})
            return result

    # 真实调用
    try:
        response_text = call_ai_with_retry(
            lambda: client.chat.completions.create(
                model=active_model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        )
    except TypeError as e:
        logger.error(f"[LLM] 调用类型错误: {e}")
        result['simulation'] = True
        result['error'] = str(e)
        _log_llm_call({'model': active_model, 'status': 'error', 'error': str(e),
                       'prompt_preview': prompt_for_log})
        return result

    if response_text is None:
        logger.warning("[LLM] API 调用失败，进入模拟模式")
        result['simulation'] = True
        result['error'] = 'API call failed after retries'
        _log_llm_call({'model': active_model, 'status': 'error', 'error': result['error'],
                       'prompt_preview': prompt_for_log})
        return result

    result['text'] = response_text

    if use_cache:
        cache_put(cache_prompt, active_model, response_text)

    parsed = parse_llm_json(response_text)
    if parsed:
        result['findings'] = normalize_findings(parsed)
    else:
        logger.warning("[LLM] JSON 解析失败")

    _log_llm_call({'model': active_model, 'status': 'ok', 'prompt_preview': prompt_for_log})
    return result


def call_llm_simple(
    prompt: str,
    system_prompt: str = '',
    model: Optional[str] = None,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """简化接口：传入 prompt 字符串，自动构造 messages"""
    messages = []
    if system_prompt:
        messages.append({'role': 'system', 'content': system_prompt})
    messages.append({'role': 'user', 'content': prompt})
    return call_llm(messages, model=model, temperature=temperature,
                    max_tokens=max_tokens, use_cache=use_cache)


# 探测结果缓存: 成功和失败都进程内缓存, 避免逐函数探测都等满超时;
# 需要强制重探时调用 refresh_ai_config_cache()
_AI_CONFIGURED_CACHE: dict = {}


def refresh_ai_config_cache() -> None:
    """清除探测缓存, 供需要强制重探的场景."""
    _AI_CONFIGURED_CACHE.clear()


def _probe_ai_backend(provider: str) -> bool:
    """实际探测后端可达性(原 is_ai_configured 逻辑整体保留)."""
    from config import Config

    if provider == 'ollama':
        base_url = Config.OLLAMA_BASE_URL or f"{Config.OLLAMA_HOST}/v1"
        try:
            import urllib.request
            req = urllib.request.Request(base_url, method='GET')
            urllib.request.urlopen(req, timeout=3)
            return True
        except Exception:
            return False
    if provider == 'deepseek':
        return bool(os.environ.get('API_KEY') or os.environ.get('CUSTOM_API_KEY') or os.environ.get('OPENAI_API_KEY'))
    if provider == 'openai':
        return bool(os.environ.get('API_KEY') or os.environ.get('OPENAI_API_KEY') or Config.OPENAI_API_KEY)
    if provider == 'custom':
        return bool(Config.CUSTOM_BASE_URL)
    if provider == 'azure':
        return bool(Config.AZURE_API_KEY and Config.AZURE_ENDPOINT)

    return False


def is_ai_configured() -> bool:
    """检查是否配置了可用的 AI 后端(带进程内缓存).

    pipeline 对每个函数调用一次本探测, 后端不可达时逐函数等满
    3 秒超时会拖死批量评测; 探测结果(成功/失败)均进程内缓存.
    需要强制重探时调用 refresh_ai_config_cache().
    """
    from config import Config
    provider = Config.AI_PROVIDER
    if provider in _AI_CONFIGURED_CACHE:
        return _AI_CONFIGURED_CACHE[provider]
    ok = _probe_ai_backend(provider)
    _AI_CONFIGURED_CACHE[provider] = ok
    return ok
