"""LLM 初始种子语料供给接口 (RL-SeedFuzz 核心组件 2 / ISC4DGF)。

意图:
  定向模糊测试冷启动阶段，初始语料质量直接决定目标命中概率。
  ISC4DGF (arXiv:2409.14329) 提出用 LLM 为目标位置构建初始种子，
  大幅提升冷启动命中率。本模块界定可插拔的 LLM 种子构造器接口:

    LLMSeedConfig         -- base_url / model / api_key 等配置
    SeedGenerator (ABC)   -- generate(target, count) -> List[bytes]
    LLMSeedGenerator      -- OpenAI 兼容 /chat/completions 实现 (requests/urllib)
    TemplateSeedGenerator -- 内置语法结构种子 (LLM 未配置时的降级路径)
    HybridSeedGenerator   -- LLM + 结构种子合并，按内容哈希消重
    build_seed_generator()-- 工厂，从环境变量/配置读取 LLM 设置

  关键约束: LLM 构造器是可选依赖。base_url/model 缺失时，
  LLMSeedGenerator 直接不可用，HybridSeedGenerator 仅使用结构化种子，
  程序照常运行。

文献:
  ISC4DGF (arXiv:2409.14329) -- LLM 驱动的定向模糊测试初始种子构建
  LLAMAFUZZ (arXiv:2406.07714) -- LLM 产出的贴近语料分布的测试输入
"""

import base64
import json
import os
import re
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import logging

_log = logging.getLogger(__name__)


# ============================================================================
# 参数配置
# ============================================================================

@dataclass
class LLMSeedConfig:
    """LLM 种子构造器参数集。

    enabled:  主开关，False 时 LLMSeedGenerator 不可用
    base_url: OpenAI 兼容服务根地址，示例 https://api.openai.com/v1 或
              http://localhost:11434/v1 (Ollama 兼容端点)
    model:    模型标识，例如 qwen2.5-coder:7b / gpt-4o-mini
    api_key:  Bearer 鉴权密钥 (本地服务可留空)
    api_path: 补全 base_url 后的请求路径，默认 /chat/completions
    """
    enabled: bool = True
    base_url: str = ""
    model: str = "qwen2.5-coder:7b"
    api_key: str = ""
    timeout: float = 120.0
    max_tokens: int = 1024
    temperature: float = 0.7
    api_path: str = "/chat/completions"
    fallback_templates: bool = True
    max_seed_bytes: int = 4096
    retry_attempts: int = 2


# ============================================================================
# 构造器抽象
# ============================================================================

class SeedGenerator(ABC):
    """种子构造器基类。

    target: 接受鸭子类型的目标对象 (至少含 label / function_name / address
            三个可选属性)，不强制依赖 fuzz_directed.TargetSite，避免
            模块间强耦合。
    """

    name: str = "abstract"

    @abstractmethod
    def generate(self, target: Any, count: int, **kw) -> List[bytes]:
        """为目标产出至多 count 个候选种子。"""
        raise NotImplementedError

    def available(self) -> bool:
        return True


# ============================================================================
# 内置语法结构构造器 (LLM 不可用时的回退)
# ============================================================================

class TemplateSeedGenerator(SeedGenerator):
    """内置结构化种子构造器。

    按目标标签关键词匹配合适的格式族 (json/http/xml/tlv/kv/...)，
    构建带边界值、魔数、长度前缀、通用协议头的结构化种子。
    确保冷启动语料基础语法正确 (源自 AFL 手工语料实践)。
    """

    name = "template"

    # 每格式族变体数 (随机填充制造样本差异)
    _VARIATIONS = 4

    def __init__(self, max_seed_bytes: int = 4096):
        self._max_seed_bytes = max_seed_bytes

    def available(self) -> bool:
        return True

    def _infer_format(self, target: Any) -> str:
        """从目标标签/函数名推断格式族; 无法识别时返回 'raw'。"""
        blob = ""
        for attr in ("label", "function_name", "file", "description"):
            v = getattr(target, attr, None)
            if v:
                blob += " " + str(v).lower()
        if not blob:
            return "raw"
        fmt = "raw"
        if re.search(r"json|parse|deser", blob):
            fmt = "json"
        elif re.search(r"http|request|header|uri|url", blob):
            fmt = "http"
        elif re.search(r"xml|svg|html|markup", blob):
            fmt = "xml"
        elif re.search(r"tlv|ber|der|asn", blob):
            fmt = "tlv"
        elif re.search(r"dns|query|hostname", blob):
            fmt = "dns"
        elif re.search(r"cve|patch|checksum|length", blob):
            fmt = "boundary"
        elif re.search(r"image|png|gif|jpeg|magic|format", blob):
            fmt = "magic"
        return fmt

    def generate(self, target: Any, count: int, **kw) -> List[bytes]:
        fmt = self._infer_format(target)
        seeds: List[bytes] = []
        producers = {
            "json": self._tpl_json,
            "http": self._tpl_http,
            "xml": self._tpl_xml,
            "tlv": self._tpl_tlv,
            "dns": self._tpl_dns,
            "boundary": self._tpl_boundary,
            "magic": self._tpl_magic,
            "raw": self._tpl_raw,
        }
        n = max(1, int(count))
        # 主格式族与 boundary/raw 交错以拓宽多样性
        for i in range(n):
            if i % 5 == 4:
                b = producers["boundary"]()
            elif i % 3 == 2:
                b = producers["raw"]()
            else:
                b = producers[fmt]()
            if b and len(b) <= self._max_seed_bytes and b not in seeds:
                seeds.append(b)
            if len(seeds) >= n:
                break
        return seeds[:n]

    # ---- 格式族构造子程序 ----
    # 均通过随机填充或长度注入制造样本差异

    def _rand_fill(self, lo: int = 1, hi: int = 8) -> bytes:
        import random
        n = random.randint(lo, hi)
        return bytes(random.randint(32, 126) for _ in range(n))

    def _tpl_json(self) -> bytes:
        body = ('{"id":%d,"name":"%s","enabled":%s,"tags":["a","b"],'
                '"nested":{"k":"%s"}}' % (
                    0xFFFFFFFF, self._rand_fill(3, 10).decode("latin1"),
                    "true", self._rand_fill(3, 8).decode("latin1")))
        return body.encode("latin1")

    def _tpl_http(self) -> bytes:
        path = "/" + self._rand_fill(2, 8).decode("latin1")
        req = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               "Content-Length: 0\r\nContent-Type: application/x-www-form-urlencoded"
               "\r\n\r\n" % path)
        return req.encode("latin1")

    def _tpl_xml(self) -> bytes:
        xml = '<root><item key="%s">%s</item></root>' % (
            self._rand_fill(2, 6).decode("latin1"),
            self._rand_fill(2, 8).decode("latin1"))
        return xml.encode("latin1")

    def _tpl_tlv(self) -> bytes:
        # TLV: [tag][len][value], len 与实际 value 长度一致
        payload = self._rand_fill(2, 12)
        if len(payload) > 255:
            payload = payload[:255]
        return bytes([0x10, len(payload)]) + payload

    def _tpl_dns(self) -> bytes:
        import random
        name = ".".join(self._rand_fill(2, 5).decode("latin1") for _ in range(2))
        qid = random.randint(0, 0xFFFF)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(x)]) + x.encode("latin1")
                         for x in name.split(".")) + b"\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        return header + qname + qtype_qclass

    def _tpl_boundary(self) -> bytes:
        # 整型边界 + 长度字段: 覆盖 -1/0/MAX 等经典越界场景
        import random
        vals = [0, 1, -1, 255, 65535, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
        v = random.choice(vals)
        # 4字节小端 + 尾部填充
        return struct.pack("<I", v & 0xFFFFFFFF) + self._rand_fill(2, 16)

    def _tpl_magic(self) -> bytes:
        import random
        magics = [b"\x89PNG\r\n\x1a\n", b"GIF89a", b"%PDF-1.7\n", b"PK\x03\x04",
                  b"\x7fELF", b"II*\x00", b"\xff\xd8\xff\xe0"]
        return random.choice(magics) + self._rand_fill(4, 32)

    def _tpl_raw(self) -> bytes:
        # 低熵原始样本与常见危险模式 (路径穿越/格式化串)
        import random
        patterns = [b"/etc/passwd", b"%s%n%s", b"../../..", b"AAAA", b"\x00" * 8]
        return random.choice(patterns) + self._rand_fill(1, 16)


# ============================================================================
# LLM 构造器 (可选依赖，未配置时不可用)
# ============================================================================

class LLMSeedGenerator(SeedGenerator):
    """OpenAI 兼容 LLM 种子构造器。

    调用 {base_url}{api_path} (默认 /chat/completions)，要求返回 JSON，
    支持两种结构:
      {"seeds": ["...", "..."]} 或 ["...", "..."]
    每个元素为种子字符串 (UTF-8 编码为 bytes)；支持 "base64:<...>" 前缀
    以表达任意二进制种子。

    可选依赖: 优先 requests，缺失时回退 urllib.request。两者都不可用
    或未配置 base_url 时 available() 返回 False。
    """

    name = "llm"

    _PROMPT = (
        "You are generating initial seed inputs for directed greybox fuzzing.\n"
        "Target: label={label}; function={func}; address={addr}.\n"
        "Generate {count} diverse, semantically-valid seed inputs that are likely "
        "to reach the target code path. Favor boundary values, unusual lengths, "
        "and format-specific structures.\n"
        'Reply with STRICT JSON only: {"seeds": ["...", "..."]}.'
    )

    def __init__(self, config: Optional[LLMSeedConfig] = None):
        self._config = config or LLMSeedConfig()
        self._session = None
        try:
            import requests
            self._session = requests.Session()
            self._http = "requests"
        except ImportError:
            try:
                import urllib.request  # noqa: F401
                self._http = "urllib"
            except ImportError:
                self._http = None

    def available(self) -> bool:
        cfg = self._config
        return bool(cfg.enabled and cfg.base_url and self._http)

    def _endpoint(self) -> str:
        cfg = self._config
        base = cfg.base_url.rstrip("/")
        path = cfg.api_path if cfg.api_path.startswith("/") else "/" + cfg.api_path
        return base + path

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._config.api_key:
            h["Authorization"] = "Bearer " + self._config.api_key
        return h

    def _payload(self, prompt: str) -> dict:
        return {
            "model": self._config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
            "response_format": {"type": "json_object"},
            "stream": False,
        }

    def _post(self, body: bytes) -> str:
        cfg = self._config
        if self._http == "requests":
            r = self._session.post(self._endpoint(), data=body,
                                   headers=self._headers(),
                                   timeout=cfg.timeout)
            r.raise_for_status()
            return r.text
        import urllib.request
        req = urllib.request.Request(self._endpoint(), data=body,
                                     headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def generate(self, target: Any, count: int, **kw) -> List[bytes]:
        if not self.available():
            return []
        label = str(getattr(target, "label", "") or "")
        func = str(getattr(target, "function_name", "") or "")
        addr = str(getattr(target, "address", 0) or 0)
        prompt = self._PROMPT.format(label=label, func=func, addr=addr,
                                     count=max(1, int(count)))
        body = json.dumps(self._payload(prompt)).encode("utf-8")
        last_err: Optional[Exception] = None
        for attempt in range(max(1, self._config.retry_attempts + 1)):
            try:
                text = self._post(body)
                return _parse_llm_seeds(text, self._config.max_seed_bytes)
            except Exception as e:  # 网络/鉴权/解析失败统一降级
                last_err = e
                _log.warning("LLM 种子构造第 %d 次尝试失败: %s", attempt + 1, e)
                if attempt < self._config.retry_attempts:
                    time.sleep(0.5 * (attempt + 1))
        _log.warning("LLM 种子构造最终失败: %s", last_err)
        return []


def _parse_llm_seeds(text: str, max_seed_bytes: int) -> List[bytes]:
    """将 LLM 的 JSON 响应解译为字节种子列表。

    边界处置: 容忍被 markdown 代码块包裹的模型输出 (```json ... ```)，
    优先整体 json.loads，失败后剥离代码块再尝试。
    """
    content = text.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    data: Any = None
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", content, re.S)
        if m:
            try:
                data = json.loads(m.group(0))
            except json.JSONDecodeError:
                return []
    if isinstance(data, dict):
        data = data.get("seeds", data.get("data", []))
    if not isinstance(data, list):
        return []
    seeds: List[bytes] = []
    for item in data:
        if not isinstance(item, str):
            continue
        if item.startswith("base64:"):
            try:
                b = base64.b64decode(item[len("base64:"):])
            except Exception:
                continue
        else:
            b = item.encode("utf-8", errors="replace")
        if 0 < len(b) <= max_seed_bytes and b not in seeds:
            seeds.append(b)
    return seeds


# ============================================================================
# 混合构造器 (LLM + 结构化种子)
# ============================================================================

class HybridSeedGenerator(SeedGenerator):
    """LLM 与结构化种子构造器的混合门面。

    流程:
      1. LLM 就绪时先获取 LLM 种子 (语义质量高，贴近目标)。
      2. 始终追加结构化种子 (语法兜底)，确保语料非空。
      3. 按内容哈希排重，裁剪至 count。

    无论 LLM 配置与否，本构造器均可用 (fallback_templates 关闭
    且 LLM 不可用时才返回空)。
    """

    name = "hybrid"

    def __init__(self, llm: Optional[LLMSeedGenerator] = None,
                 template: Optional[TemplateSeedGenerator] = None,
                 fallback_templates: bool = True):
        self._llm = llm or LLMSeedGenerator()
        self._template = template or TemplateSeedGenerator()
        self._fallback_templates = fallback_templates

    def available(self) -> bool:
        return self._llm.available() or self._fallback_templates

    def generate(self, target: Any, count: int, **kw) -> List[bytes]:
        n = max(1, int(count))
        seeds: List[bytes] = []
        if self._llm.available():
            seeds.extend(self._llm.generate(target, max(2, n), **kw))
        if self._fallback_templates:
            # 结构化种子按剩余名额补齐，总容量不超 count
            remain = max(0, n - len(seeds))
            seeds.extend(self._template.generate(target, max(1, remain), **kw))
        # 按内容哈希消重
        seen = set()
        out: List[bytes] = []
        for b in seeds:
            h = hash(b)
            if h not in seen:
                seen.add(h)
                out.append(b)
            if len(out) >= n:
                break
        return out[:n]


# ============================================================================
# 工厂与便捷函数
# ============================================================================

def build_seed_generator(config: Optional[LLMSeedConfig] = None,
                         env_overrides: Optional[Dict[str, str]] = None) -> HybridSeedGenerator:
    """从配置对象与环境变量组装混合种子构造器。

    环境变量 (BINMIND_LLM_*):
      BINMIND_LLM_ENABLED   -- 0/1
      BINMIND_LLM_BASE_URL  -- OpenAI 兼容服务地址
      BINMIND_LLM_MODEL     -- 模型名
      BINMIND_LLM_API_KEY   -- API 密钥
    base_url 缺失时 LLM 分支自动不可用，程序仅用结构化种子。
    """
    cfg = config or LLMSeedConfig()
    env = os.environ if env_overrides is None else {**os.environ, **env_overrides}
    if env.get("BINMIND_LLM_ENABLED") is not None:
        cfg.enabled = env["BINMIND_LLM_ENABLED"] not in ("0", "false", "False", "")
    if env.get("BINMIND_LLM_BASE_URL"):
        cfg.base_url = env["BINMIND_LLM_BASE_URL"]
    if env.get("BINMIND_LLM_MODEL"):
        cfg.model = env["BINMIND_LLM_MODEL"]
    if env.get("BINMIND_LLM_API_KEY") is not None:
        cfg.api_key = env["BINMIND_LLM_API_KEY"]
    llm = LLMSeedGenerator(cfg)
    template = TemplateSeedGenerator(max_seed_bytes=cfg.max_seed_bytes)
    return HybridSeedGenerator(llm=llm, template=template,
                               fallback_templates=cfg.fallback_templates)


def generate_initial_seed_corpus(target_sites: List[Any],
                                 generator: Optional[SeedGenerator] = None,
                                 per_target: int = 8) -> List[bytes]:
    """为定向目标列表产出初始种子语料。

    参数 target_sites: 鸭子类型目标对象列表 (含 label/function_name 等)，
    或直接传入字符串标签 (自动包装)。返回合并排重后的种子列表。
    """
    gen = generator or build_seed_generator()
    seeds: List[bytes] = []
    for t in target_sites:
        if isinstance(t, str):
            t = _LabelTarget(t)
        try:
            seeds.extend(gen.generate(t, per_target))
        except Exception as e:
            _log.warning("目标 %s 种子产出失败: %s",
                         getattr(t, "label", t), e)
    seen = set()
    out = [b for b in seeds if not (hash(b) in seen or seen.add(hash(b)))]
    return out


class _LabelTarget:
    """字符串标签目标的轻量包装，使 generate_initial_seed_corpus 可接受裸标签。"""

    def __init__(self, label: str):
        self.label = label
        self.function_name = ""
        self.address = 0
        self.description = label


__all__ = [
    "LLMSeedConfig", "SeedGenerator", "TemplateSeedGenerator",
    "LLMSeedGenerator", "HybridSeedGenerator", "build_seed_generator",
    "generate_initial_seed_corpus",
]
