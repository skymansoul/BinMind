import logging
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# 插件管理器导入桩 — 基础设施就绪后启用

logger = logging.getLogger(__name__)


class PatchType(Enum):
    BOUND_CHECK = "bound_check"
    NULL_CHECK = "null_check"
    AUTH_CHECK = "auth_check"
    SANITIZATION = "sanitization"
    CODE_REPLACEMENT = "code_replacement"
    NOP_SLIDE = "nop_slide"
    FUNCTION_HOOK = "function_hook"

class PatchLocation(Enum):
    FUNCTION_ENTRY = "function_entry"
    FUNCTION_EXIT = "function_exit"
    BEFORE_INSTRUCTION = "before_instruction"
    AFTER_INSTRUCTION = "after_instruction"
    REPLACE_INSTRUCTION = "replace_instruction"


@dataclass
class VulnerabilityContext:
    vulnerability_type: str
    vulnerability_description: str
    affected_function: str
    affected_address: int
    vulnerable_code: str
    root_cause: str
    severity: str = "high"
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class PatchSpecification:
    patch_id: str
    vulnerability_context: VulnerabilityContext
    patch_type: PatchType
    patch_location: PatchLocation
    target_address: int
    target_function: str
    specification: str
    implementation_details: Dict[str, str] = field(default_factory=dict)
    estimated_size: int = 0
    is_safe: bool = True
    requires_rebase: bool = False
    verification_checks: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.estimated_size = min(max(self.estimated_size, 0), 65536)


@dataclass
class BinaryPatch:
    patch_spec: PatchSpecification
    raw_bytes: bytes
    target_offset: int
    original_bytes: Optional[bytes] = None
    relocation_info: Dict[str, Any] = field(default_factory=dict)
    applied: bool = False


# ── spec 缓存 ──────────────────────────────────────────────────────────
# CWE + affected_function + vuln_type 组成复合键，避免同漏洞重复推演。
# 容量 64 条，LRU 淘汰。规则路径命中则跳过远程调用。

_spec_cache = {}
_SPEC_CACHE_MAX = 64


def _cache_key(vuln_context):
    if vuln_context is None:
        return None
    return (vuln_context.cwe_id or '', vuln_context.affected_function or '',
            vuln_context.vulnerability_type or '')


def _cache_get(vuln_context):
    k = _cache_key(vuln_context)
    if k is None:
        return None
    return _spec_cache.get(k)


def _cache_put(vuln_context, spec):
    k = _cache_key(vuln_context)
    if k is None:
        return
    if len(_spec_cache) >= _SPEC_CACHE_MAX:
        # 淘汰最旧条目 — 简单弹出首键
        _spec_cache.pop(next(iter(_spec_cache)), None)
    _spec_cache[k] = spec


# ── 规则驱动 spec 构造 ────────────────────────────────────────────────
# 查表直出：CWE ID + vuln type 映射预置 spec，零远程开销。
# 覆盖 CWE-121, CWE-122, CWE-416, CWE-476, CWE-190, CWE-134。

_RULE_SPECS = {
    'CWE-121': {
        'patch_type': PatchType.BOUND_CHECK,
        'patch_location': PatchLocation.FUNCTION_ENTRY,
        'specification': 'Insert bounds check before vulnerable buffer operation. '
                         'Verify destination size against source length; truncate or reject oversized input.',
        'verification_checks': ['bounds-assertion', 'no-oob-write'],
    },
    'CWE-122': {
        'patch_type': PatchType.BOUND_CHECK,
        'patch_location': PatchLocation.BEFORE_INSTRUCTION,
        'specification': 'Validate allocation size and copy length before heap operation. '
                         'Add integer overflow guard on size calculation.',
        'verification_checks': ['heap-size-guard', 'no-oob-write'],
    },
    'CWE-416': {
        'patch_type': PatchType.NULL_CHECK,
        'patch_location': PatchLocation.AFTER_INSTRUCTION,
        'specification': 'Nullify pointer immediately after free(). '
                         'Add poison value to detect dangling pointer dereference.',
        'verification_checks': ['post-free-null', 'no-dangling-ref'],
    },
    'CWE-476': {
        'patch_type': PatchType.NULL_CHECK,
        'patch_location': PatchLocation.BEFORE_INSTRUCTION,
        'specification': 'Insert NULL check before pointer dereference. '
                         'Return error code or early-exit on NULL.',
        'verification_checks': ['null-guard-present'],
    },
    'CWE-190': {
        'patch_type': PatchType.BOUND_CHECK,
        'patch_location': PatchLocation.BEFORE_INSTRUCTION,
        'specification': 'Add overflow check before arithmetic operation. '
                         'Use __builtin_add_overflow / __builtin_mul_overflow or manual range validation.',
        'verification_checks': ['overflow-guard', 'saturated-arithmetic'],
    },
    'CWE-134': {
        'patch_type': PatchType.SANITIZATION,
        'patch_location': PatchLocation.REPLACE_INSTRUCTION,
        'specification': 'Replace user-controlled format string with compile-time constant. '
                         'Use "%s" as format string and pass user input as argument.',
        'verification_checks': ['format-literal', 'no-user-controlled-fmt'],
    },
}


class PatchSpecGenerator:
    def generate_specification(self, vulnerability_context):
        pass


class RuleBasedSpecGenerator(PatchSpecGenerator):
    """查表直出预置 spec — O(1) 恒定开销。
    命中常见 CWE 即返回；未命中回退至通用 CODE_REPLACEMENT。"""

    def generate_specification(self, vulnerability_context):
        if vulnerability_context is None:
            return self._default(vulnerability_context)

        cwe = vulnerability_context.cwe_id or ''
        rule = _RULE_SPECS.get(cwe)

        if rule is None:
            # vuln type 关键词推断 CWE 归类
            vt = (vulnerability_context.vulnerability_type or '').lower()
            if 'overflow' in vt or 'buffer' in vt:
                rule = _RULE_SPECS.get('CWE-121')
            elif 'format' in vt:
                rule = _RULE_SPECS.get('CWE-134')
            elif 'free' in vt or 'uaf' in vt:
                rule = _RULE_SPECS.get('CWE-416')
            elif 'null' in vt:
                rule = _RULE_SPECS.get('CWE-476')

        if rule is None:
            return self._default(vulnerability_context)

        return PatchSpecification(
            patch_id=self._generate_patch_id(),
            vulnerability_context=vulnerability_context or VulnerabilityContext(
                vulnerability_type="", vulnerability_description="",
                affected_function="", affected_address=0,
                vulnerable_code="", root_cause=""),
            patch_type=rule['patch_type'],
            patch_location=rule['patch_location'],
            target_address=vulnerability_context.affected_address if vulnerability_context else 0,
            target_function=vulnerability_context.affected_function if vulnerability_context else 'unknown',
            specification=rule['specification'],
            estimated_size=32,
            is_safe=True,
            verification_checks=list(rule.get('verification_checks', [])),
        )

    def _default(self, vuln_context):
        addr = vuln_context.affected_address if vuln_context else 0
        func = vuln_context.affected_function if vuln_context else 'unknown'
        return PatchSpecification(
            patch_id=self._generate_patch_id(),
            vulnerability_context=vuln_context or VulnerabilityContext(
                vulnerability_type="unknown", vulnerability_description="unknown",
                affected_function="unknown", affected_address=0,
                vulnerable_code="", root_cause="unknown"),
            patch_type=PatchType.CODE_REPLACEMENT,
            patch_location=PatchLocation.FUNCTION_ENTRY,
            target_address=addr, target_function=func,
            specification="Default patch spec (rule-based fallback)",
            estimated_size=0, is_safe=True, requires_rebase=False,
            verification_checks=[])

    @staticmethod
    def _generate_patch_id():
        return "patch_" + uuid.uuid4().hex[:8]


class LLMPatchSpecGenerator(PatchSpecGenerator):
    def __init__(self, ai_provider="openai"):
        self._ai_provider = ai_provider
        self.ai = None
        self._init_ai_client()

    def _init_ai_client(self):
        try:
            # 远程推理客户端 — 模块就绪后取消注释
            # from modules.decomp_ai import DecompAI
            # self.ai = DecompAI()
            # if self.ai:
            #     logger.info("远程 spec 构造器初始化完成")
            # else:
            #     logger.warning("远程推理客户端初始化返回 None")
            pass
        except ImportError as e:
            logger.warning("Cannot initialize AI client: %s", e)
            self.ai = None

    def _build_prompt(self, vulnerability_context):
        if not vulnerability_context:
            return ""

        cwe = vulnerability_context.cwe_id
        if cwe is None:
            cwe = "unknown"

        addr = vulnerability_context.affected_address
        if addr is None:
            addr = 0

        prompt = """
You are a senior binary security researcher and patch development expert.
Please analyze the following vulnerability and generate a precise patch specification.

Vulnerability Info:
- Type: """ + str(vulnerability_context.vulnerability_type) + """
- Severity: """ + str(vulnerability_context.severity) + """
- CWE ID: """ + str(cwe) + """
- Affected Function: """ + str(vulnerability_context.affected_function) + """
- Affected Address: 0x""" + format(addr, 'x') + """

Vulnerability Description:
""" + str(vulnerability_context.vulnerability_description) + """

Root Cause:
""" + str(vulnerability_context.root_cause) + """

Vulnerable Code:
""" + str(vulnerability_context.vulnerable_code) + """

Please output patch spec in the following format:

PATCH_TYPE: <bound_check| null_check| auth_check| sanitization| code_replacement| nop_slide| function_hook>
PATCH_LOCATION: <function_entry| function_exit| before_instruction| after_instruction| replace_instruction>
TARGET_ADDRESS: <hex address, e.g. 0x401000>
TARGET_FUNCTION: <target function name>
SPECIFICATION: <detailed spec description>
IMPLEMENTATION_DETAILS: <implementation details>
ESTIMATED_SIZE: <estimated bytes>
IS_SAFE: <True/False>
REQUIRES_REBASE: <True/False>
VERIFICATION_CHECKS: <comma-separated list>

Patch specification requirements:
1. Must be precise and executable
2. Guarantee binary compatibility
3. Minimize code changes
4. Consider stack frame layout
5. Handle possible side effects
"""
        return prompt.strip()

    def _parse_response(self, response):
        if not response:
            return self._create_default_spec()

        try:
            patch_type_str = self._extract_field(response, "PATCH_TYPE")
            patch_loc_str = self._extract_field(response, "PATCH_LOCATION")
            target_addr = self._extract_address(response, "TARGET_ADDRESS")
            target_func = self._extract_field(response, "TARGET_FUNCTION")
            spec = self._extract_multiline_field(response, "SPECIFICATION")
            impl_details = self._extract_implementation_details(response)
            est_size = self._extract_int(response, "ESTIMATED_SIZE")
            is_safe = self._extract_bool(response, "IS_SAFE")
            requires_rebase = self._extract_bool(response, "REQUIRES_REBASE")
            verification_checks = self._extract_list(response, "VERIFICATION_CHECKS")

            if verification_checks:
                verification_checks = sorted(verification_checks)

            return PatchSpecification(
                patch_id=self._generate_patch_id(),
                vulnerability_context=VulnerabilityContext(
                    vulnerability_type="", vulnerability_description="",
                    affected_function=target_func, affected_address=target_addr,
                    vulnerable_code="", root_cause=""),
                patch_type=self._parse_patch_type(patch_type_str),
                patch_location=self._parse_patch_location(patch_loc_str),
                target_address=target_addr, target_function=target_func,
                specification=spec, implementation_details=impl_details,
                estimated_size=est_size, is_safe=is_safe,
                requires_rebase=requires_rebase, verification_checks=verification_checks)

        except Exception as e:
            logger.error("Failed to parse LLM response: %s", e)
            return self._create_default_spec()

    def _extract_field(self, response, key):
        if response is None or key is None:
            return ""
        lines = response.split('\n')
        for line in lines:
            if line is not None and line.startswith(key):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    return parts[1].strip()
                return ""
        return ""

    def _extract_multiline_field(self, response, key):
        if response is None or key is None:
            return ""
        lines = response.split('\n')
        capturing = False
        result = []
        stop_keys = [
            "PATCH_TYPE", "PATCH_LOCATION", "TARGET_ADDRESS", "TARGET_FUNCTION",
            "IMPLEMENTATION_DETAILS", "ESTIMATED_SIZE", "IS_SAFE",
            "REQUIRES_REBASE", "VERIFICATION_CHECKS"
        ]

        for line in lines:
            if line is None:
                continue

            if line.startswith(key):
                capturing = True
                parts = line.split(':', 1)
                if len(parts) > 1:
                    result.append(parts[1].strip())
                continue

            if capturing and line.strip():
                is_header = any(line.startswith(k) for k in stop_keys)
                if is_header:
                    capturing = False
                else:
                    result.append(line.strip())
            elif capturing and not line.strip():
                pass

        return '\n'.join(result)

    def _extract_address(self, response, key):
        value = self._extract_field(response, key)
        if value is None or value == "":
            return 0
        try:
            return int(value, 16)
        except ValueError:
            return 0

    def _extract_int(self, response, key):
        value = self._extract_field(response, key)
        if value is None or value == "":
            return 0
        try:
            return int(value)
        except ValueError:
            return 0

    def _extract_bool(self, response, key):
        value = self._extract_field(response, key)
        if value is None or value == "":
            return False
        return value.lower() == "true"

    def _extract_list(self, response, key):
        value = self._extract_field(response, key)
        if value is None or not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def _extract_implementation_details(self, response):
        details_str = self._extract_multiline_field(response, "IMPLEMENTATION_DETAILS")
        details = {}

        if details_str is None or details_str == "":
            return details

        for line in details_str.split('\n'):
            if line is not None and ':' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    details[parts[0].strip()] = parts[1].strip()
        return details

    def _parse_patch_type(self, patch_type_str):
        if patch_type_str is None:
            return PatchType.CODE_REPLACEMENT
        try:
            return PatchType(patch_type_str.strip())
        except ValueError:
            return PatchType.CODE_REPLACEMENT

    def _parse_patch_location(self, location_str):
        if location_str is None:
            return PatchLocation.FUNCTION_ENTRY
        try:
            return PatchLocation(location_str.strip())
        except ValueError:
            return PatchLocation.FUNCTION_ENTRY

    def _generate_patch_id(self):
        return "patch_" + uuid.uuid4().hex[:8]

    def _create_default_spec(self):
        return PatchSpecification(
            patch_id=self._generate_patch_id(),
            vulnerability_context=VulnerabilityContext(
                vulnerability_type="unknown", vulnerability_description="unknown",
                affected_function="unknown", affected_address=0,
                vulnerable_code="", root_cause="unknown"),
            patch_type=PatchType.CODE_REPLACEMENT,
            patch_location=PatchLocation.FUNCTION_ENTRY,
            target_address=0, target_function="unknown",
            specification="Default patch spec (LLM unavailable)",
            implementation_details={}, estimated_size=0,
            is_safe=True, requires_rebase=False, verification_checks=[])

    def generate_specification(self, vulnerability_context):
        if self.ai is None:
            logger.warning("AI client unavailable, using default patch spec")
            spec = self._create_default_spec()
            spec.vulnerability_context = vulnerability_context
            return spec

        try:
            prompt = self._build_prompt(vulnerability_context)
            if prompt is None or prompt == "":
                spec = self._create_default_spec()
                spec.vulnerability_context = vulnerability_context
                return spec

            response = self.ai.ask_llm(prompt)

            if response is not None and response != "":
                spec = self._parse_response(response)
                spec.vulnerability_context = vulnerability_context
                logger.debug("LLM patch spec generated: %s", spec.patch_id)
                return spec
            else:
                spec = self._create_default_spec()
                spec.vulnerability_context = vulnerability_context
                return spec

        except Exception as e:
            logger.error("LLM patch spec generation failed: %s", e)
            spec = self._create_default_spec()
            spec.vulnerability_context = vulnerability_context
            return spec


class AutoPatchSpecAnalyzer:
    def __init__(self):
        self._generator = LLMPatchSpecGenerator()
        self._rule_generator = RuleBasedSpecGenerator()  # 查表直出，远程不可用时兜底
        self._generated_specs = []

    def analyze(self, **kwargs):
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}

        vuln_type = kwargs.get("vulnerability_type", "unknown")
        vuln_desc = kwargs.get("vulnerability_description", "")
        affected_func = kwargs.get("affected_function", "unknown")

        affected_addr = kwargs.get("affected_address", 0)
        if isinstance(affected_addr, str):
            try:
                if affected_addr.startswith("0x"):
                    affected_addr = int(affected_addr, 16)
                else:
                    affected_addr = int(affected_addr)
            except ValueError:
                affected_addr = 0

        vuln_code = kwargs.get("vulnerable_code", "")
        root_cause = kwargs.get("root_cause", "")
        severity = kwargs.get("severity", "high")
        cwe_id = kwargs.get("cwe_id", None)

        vuln_context = VulnerabilityContext(
            vulnerability_type=vuln_type, vulnerability_description=vuln_desc,
            affected_function=affected_func, affected_address=affected_addr,
            vulnerable_code=vuln_code, root_cause=root_cause,
            severity=severity, cwe_id=cwe_id)

        logger.info("Generating patch spec: %s", vuln_type)

        # 缓存优先 — 命中则跳过构造
        cached = _cache_get(vuln_context)
        if cached is not None:
            logger.debug("cache hit for %s", vuln_type)
            self._generated_specs.append(cached)
            return self._spec_to_result(cached)

        try:
            # 规则路径优先 — 查表 O(1)，命中即出
            if cwe_id and cwe_id in _RULE_SPECS:
                spec = self._rule_generator.generate_specification(vuln_context)
                logger.debug("rule-based spec generated for %s", cwe_id)
            else:
                spec = self._generator.generate_specification(vuln_context)

            if spec is None:
                logger.error("Patch spec generation returned None")
                return {"success": False, "error": "spec generation returned None"}

            _cache_put(vuln_context, spec)
            self._generated_specs.append(spec)
            return self._spec_to_result(spec)

        except Exception as e:
            logger.error("Patch spec generation failed: %s", e)
            return {"success": False, "error": str(e)}

    def _spec_to_result(self, spec):
        return {
            "success": True,
            "result": {
                "patch_id": spec.patch_id,
                "patch_type": spec.patch_type.value,
                "patch_location": spec.patch_location.value,
                "target_address": hex(spec.target_address),
                "target_function": spec.target_function,
                "specification": spec.specification,
                "implementation_details": spec.implementation_details,
                "estimated_size": spec.estimated_size,
                "is_safe": spec.is_safe,
                "requires_rebase": spec.requires_rebase,
                "verification_checks": spec.verification_checks
            }
        }

    def generate_multiple_specs(self, vulnerability_contexts):
        specs = []

        if vulnerability_contexts is None:
            return specs

        seen = set()  # 去重：同 CWE+函数+vuln_type 仅留一份
        for context in vulnerability_contexts:
            if context is not None:
                # 去重键: (CWE, function, vuln_type)
                dedup_key = _cache_key(context)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # 查缓存
                cached = _cache_get(context)
                if cached is not None:
                    specs.append(cached)
                    self._generated_specs.append(cached)
                    continue

                # 规则路径优先
                if context.cwe_id and context.cwe_id in _RULE_SPECS:
                    spec = self._rule_generator.generate_specification(context)
                else:
                    spec = self._generator.generate_specification(context)

                if spec is not None:
                    _cache_put(context, spec)
                    specs.append(spec)
                    self._generated_specs.append(spec)

        if len(specs) > 0:
            specs = sorted(specs, key=lambda s: s.target_address if s is not None else 0)

        return specs

    @classmethod
    def get_metadata(cls):
        # 元数据桩；插件基础设施就绪后引入 AnalyzerMetadata
        return {}

    def validate_input(self, **kwargs):
        required_fields = ["vulnerability_type", "affected_function", "root_cause"]

        for field in required_fields:
            if field not in kwargs:
                return False, f"{field} is a required parameter"
            if kwargs[field] is None or kwargs[field] == "":
                return False, f"{field} cannot be empty"

        affected_addr = kwargs.get("affected_address", 0)
        if affected_addr is not None and affected_addr != 0:
            if isinstance(affected_addr, str):
                try:
                    if affected_addr.startswith("0x"):
                        int(affected_addr, 16)
                    else:
                        int(affected_addr)
                except ValueError:
                    return False, "affected_address must be a valid integer or hex string"

        return True, None

    def cleanup(self):
        if self._generated_specs is not None:
            self._generated_specs.clear()
        if self._generator is not None:
            if self._generator.ai is not None:
                self._generator.ai = None
