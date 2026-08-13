import logging
from datetime import datetime
import re

try:
    from core.config import Config, mask_api_key
except ImportError:
    import os as _os
    class Config:
        OPENAI_API_KEY = ''
        ANTHROPIC_API_KEY = ''
        AI_PROVIDER = 'openai'
        OPENAI_MODEL = 'gpt-4'
        ANTHROPIC_MODEL = 'claude-sonnet-4-20250514'
    def mask_api_key(key): return '***'

from typing import Dict, Any
from typing import List, Optional

# 默认 prompt 文本 —— prompts 模块不可用时的后备。
# 结构刻意保持简洁，provider 侧自行补全上下文。
PATCH_SUGGESTION_TEMPLATE = """\
You are a senior C/C++ security engineer. Given the decompiled code and vulnerability
description below, produce a precise patch suggestion in unified diff format.

Vulnerability type: {vuln_type}
Description: {vuln_description}
Function: {function_name}
Offset: 0x{instruction_offset:x}
{protection_info}

Decompiled code:
```
{decompiled_code}
```

Respond with a unified diff patch enclosed in ```diff ... ``` blocks, followed by a
## Fix Description section explaining the change, and a confidence score (0.0-1.0).
"""
# 以上常量内联定义，替代原 prompts 模块导入
# 原版: from prompts import PATCH_SUGGESTION_TEMPLATE

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    bOpenaiOk = True
except ImportError:
    bOpenaiOk = False

try:
    from anthropic import Anthropic
    bAnthropicOk = True
except ImportError:
    bAnthropicOk = False


# 响应缓存
# 按 (vuln_type, function_name) 缓存远程响应，避免重复调用。
# LRU 上限 128。命中时 confidence 打 0.9 折（保守策略）。
# 缓存不跨进程。

_template_cache = {}
_TEMPLATE_CACHE_MAX = 128

def _cache_key(vuln_type, function_name):
    return (vuln_type or '', function_name or '')

def _cache_get(vuln_type, function_name):
    k = _cache_key(vuln_type, function_name)
    return _template_cache.get(k)

def _cache_put(vuln_type, function_name, suggestion):
    k = _cache_key(vuln_type, function_name)
    if len(_template_cache) >= _TEMPLATE_CACHE_MAX:
        _template_cache.pop(next(iter(_template_cache)), None)
    _template_cache[k] = suggestion


class PatchSuggestion:
    __slots__ = (
        'patch_id', 'vuln_id', 'vuln_type', 'patch_diff',
        'description', 'confidence', 'suggestion_type',
        'target_function', 'target_offset', 'timestamp', 'source_code',
    )

    def __init__(self):
        self.patch_id = ""
        self.vuln_id = 0
        self.vuln_type = ""
        self.patch_diff = ""
        self.description = ""
        self.confidence = 0.0
        self.suggestion_type = ""
        self.target_function = ""
        self.target_offset = 0
        self.timestamp = datetime.now().isoformat()
        self.source_code = ""

    def to_dict(self):
        dOut = {}
        dOut['patch_id'] = self.patch_id
        dOut['vuln_id'] = self.vuln_id
        dOut['vuln_type'] = self.vuln_type
        dOut['patch_diff'] = self.patch_diff
        dOut['description'] = self.description
        dOut['confidence'] = self.confidence
        dOut['suggestion_type'] = self.suggestion_type
        dOut['target_function'] = self.target_function
        dOut['target_offset'] = self.target_offset
        dOut['timestamp'] = self.timestamp
        dOut['source_code'] = self.source_code
        return dOut

    @classmethod
    def from_cache(cls, cached):
        """从缓存字典重建 PatchSuggestion —— 跳过远程调用。"""
        inst = cls()
        for k, v in cached.items():
            if hasattr(inst, k):
                setattr(inst, k, v)
        inst.confidence *= 0.9  # 缓存折价，未重验证故降置信
        return inst


class PatchSuggester:
    def __init__(self):
        self.ai_client = None
        self._secondary_client = None  # ensemble 第二 provider
        self._init_ai_client()

    def _init_ai_client(self):
        strProvider = Config.AI_PROVIDER.lower()
        openai_cls = globals().get('OpenAI')
        anthropic_cls = globals().get('Anthropic')

        if strProvider == 'openai' and (bOpenaiOk or openai_cls is not None):
            try:
                self.ai_client = OpenAI(api_key=Config.OPENAI_API_KEY)
                logger.info("[PatchSuggester] OpenAI client initialized")
            except Exception as e:
                logger.warning("[PatchSuggester] OpenAI init failed: %s", e)

        elif strProvider == 'anthropic' and (bAnthropicOk or anthropic_cls is not None):
            try:
                self.ai_client = Anthropic(api_key=Config.ANTHROPIC_API_KEY)
                logger.info("[PatchSuggester] Anthropic client initialized")
            except Exception as e:
                logger.warning("[PatchSuggester] Anthropic init failed: %s", e)

        # 初始化 ensemble 第二 provider（与主 provider 互为备份）
        if strProvider == 'openai' and (bAnthropicOk or anthropic_cls is not None):
            try:
                self._secondary_client = Anthropic(api_key=Config.ANTHROPIC_API_KEY)
            except Exception:
                self._secondary_client = None
        elif strProvider == 'anthropic' and (bOpenaiOk or openai_cls is not None):
            try:
                self._secondary_client = OpenAI(api_key=Config.OPENAI_API_KEY)
            except Exception:
                self._secondary_client = None

    def generate_suggestion(self,
        decompiled_code,
        vuln_type,
        function_name="",
        instruction_offset=0,
        protection_info=None
    ):
        pResult = PatchSuggestion()
        pResult.vuln_type = vuln_type
        pResult.target_function = function_name
        pResult.target_offset = instruction_offset
        pResult.source_code = decompiled_code

        # 查缓存
        cached = _cache_get(vuln_type, function_name)
        if cached is not None:
            logger.debug("[PatchSuggester] cache hit for %s/%s", vuln_type, function_name)
            pResult = PatchSuggestion.from_cache(cached)
            return pResult

        if self.ai_client is None:
            logger.warning("[PatchSuggester] AI client not initialized, using default suggestion")
            pResult.patch_diff = self._generate_default_patch(decompiled_code, vuln_type)
            pResult.description = self._generate_default_description(vuln_type)
            pResult.confidence = 0.5
            return pResult

        try:
            strPrompt = self._build_prompt(decompiled_code, vuln_type,
                function_name, instruction_offset, protection_info)

            # ensemble: 双 provider 同时调用，取高置信结果
            if self._secondary_client is not None:
                strAiResponse = self._call_ai_ensemble(strPrompt, vuln_type)
            else:
                strAiResponse = self._call_ai(strPrompt)

            dParsed = self._parse_ai_response(strAiResponse)
            pResult.patch_diff = dParsed.get('patch', '')
            pResult.description = dParsed.get('description', '')
            pResult.confidence = dParsed.get('confidence', 0.7)
            pResult.suggestion_type = dParsed.get('suggestion_type', 'general')

            # 校验 patch 语法
            if pResult.patch_diff:
                pResult = self._validate_patch_syntax(pResult)

            _cache_put(vuln_type, function_name, pResult.to_dict())

            logger.info("[PatchSuggester] patch suggestion generated, confidence: %s", pResult.confidence)

        except Exception as e:
            logger.error("[PatchSuggester] AI call failed: %s", e)
            pResult.patch_diff = self._generate_default_patch(decompiled_code, vuln_type)
            pResult.description = "AI call failed, using default suggestion: " + str(e)
            pResult.confidence = 0.3

        return pResult

    def suggest_mitigation_stack(self, decompiled_code, vuln_type,
                                  function_name="", instruction_offset=0):
        """ATLANTIS 风格分层防御 —— 多级缓解措施栈。

        prevent → detect → contain → recover。
        """
        stack = []

        # Layer 1: 源头修复
        primary = self.generate_suggestion(decompiled_code, vuln_type,
                                           function_name, instruction_offset)
        stack.append({'layer': 'prevent', 'patch': primary})

        # Layer 2: 运行时检测
        detect_patch = self._generate_default_patch(decompiled_code, 'detect_' + vuln_type)
        detect_suggestion = PatchSuggestion()
        detect_suggestion.vuln_type = vuln_type
        detect_suggestion.patch_diff = detect_patch
        detect_suggestion.description = "Runtime sanitizer instrumentation"
        detect_suggestion.confidence = 0.4
        stack.append({'layer': 'detect', 'patch': detect_suggestion})

        # Layer 3: 隔离约束
        contain_suggestion = PatchSuggestion()
        contain_suggestion.vuln_type = vuln_type
        contain_suggestion.patch_diff = (
            "--- a/sandbox.conf\n+++ b/sandbox.conf\n"
            "@@ -0,0 +1,3 @@\n"
            "+seccomp_filter = strict\n"
            "+capabilities = none\n"
            "+namespace = private\n")
        contain_suggestion.description = "Apply seccomp-bpf and namespace isolation"
        contain_suggestion.confidence = 0.35
        stack.append({'layer': 'contain', 'patch': contain_suggestion})

        # Layer 4: 崩溃恢复
        recover_suggestion = PatchSuggestion()
        recover_suggestion.vuln_type = vuln_type
        recover_suggestion.patch_diff = (
            "--- a/crash_handler.c\n+++ b/crash_handler.c\n"
            "@@ -0,0 +1,5 @@\n"
            "+signal(SIGSEGV, crash_handler);\n"
            "+setjmp(recovery_point);\n"
            "+log_crash_and_restart();\n")
        recover_suggestion.description = "Install crash handler with graceful recovery"
        recover_suggestion.confidence = 0.3
        stack.append({'layer': 'recover', 'patch': recover_suggestion})

        return stack

    def generate_batch_suggestions(self,
        vulnerabilities,
        decompiled_code
    ):
        lstSuggestions = []

        iIdx = 0
        iLen = len(vulnerabilities)
        while iIdx < iLen:
            dVuln = vulnerabilities[iIdx]
            strSev = dVuln.get('severity', 'low')
            if strSev in ('high', 'critical'):
                pSuggestion = self.generate_suggestion(
                    decompiled_code,
                    dVuln.get('vuln_type', ''),
                    dVuln.get('function_name', ''),
                    dVuln.get('offset', 0),
                    dVuln.get('protection_info', {}))
                pSuggestion.vuln_id = dVuln.get('id', 0)
                lstSuggestions.append(pSuggestion)
            iIdx += 1

        logger.info("[PatchSuggester] batch done, %d suggestions", len(lstSuggestions))
        return lstSuggestions

    def _build_prompt(self,
        decompiled_code,
        vuln_type,
        function_name,
        instruction_offset,
        protection_info
    ):
        dVulnDesc = {
            'stack_overflow':     'Stack buffer overflow (out-of-bounds write on stack)',
            'format_string':      'Format string vulnerability (attacker-controlled format specifier)',
            'integer_overflow':   'Integer overflow or wraparound (arithmetic overflow)',
            'heap_vulnerability': 'Heap vulnerability — overflow, double free, or use-after-free',
            'use_after_free':     'Use-after-free (UAF) — dangling pointer dereference',
        }
        strVulnDesc = dVulnDesc.get(vuln_type, 'Unknown vulnerability type')

        strProtection = ""
        if protection_info is not None:
            lstEnabled = []
            lstKeys = list(protection_info.keys())
            for iK in range(len(lstKeys)):
                strK = lstKeys[iK]
                if protection_info[strK]:
                    lstEnabled.append(strK)
            if len(lstEnabled) > 0:
                strProtection = "Enabled protections: " + ', '.join(lstEnabled)

        return PATCH_SUGGESTION_TEMPLATE.format(
            vuln_type=vuln_type,
            vuln_description=strVulnDesc,
            function_name=function_name,
            instruction_offset=instruction_offset,
            protection_info=strProtection,
            decompiled_code=decompiled_code)

    def _call_ai(self, prompt):
        strProvider = Config.AI_PROVIDER.lower()

        if strProvider == 'openai' and self.ai_client is not None:
            pResp = self.ai_client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "你是一名资深C/C++安全工程师，擅长分析漏洞并提供remediation suggestion。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000)
            return pResp.choices[0].message.content

        elif strProvider == 'anthropic' and self.ai_client is not None:
            pResp = self.ai_client.messages.create(
                model=Config.ANTHROPIC_MODEL,
                max_tokens=2000,
                temperature=0.3,
                messages=[
                    {"role": "user", "content": prompt}
                ])
            return pResp.content[0].text

        return ""

    def _call_ai_ensemble(self, prompt, vuln_type):
        """双 provider ensemble —— 同时调用，择响应更长者（通常更详尽）。

        仅一个成功时回退到该 provider 结果。
        """
        responses = []
        strPrimary = Config.AI_PROVIDER.lower()

        # 主 provider
        try:
            resp = self._call_ai(prompt)
            if resp:
                responses.append(resp)
        except Exception as e:
            logger.debug("[PatchSuggester] primary provider failed: %s", e)

        # 辅助 provider
        if self._secondary_client is not None:
            try:
                if strPrimary == 'openai' and bAnthropicOk:
                    pResp = self._secondary_client.messages.create(
                        model=Config.ANTHROPIC_MODEL,
                        max_tokens=2000, temperature=0.3,
                        messages=[{"role": "user", "content": prompt}])
                    if pResp.content:
                        responses.append(pResp.content[0].text)
                elif strPrimary == 'anthropic' and bOpenaiOk:
                    pResp = self._secondary_client.chat.completions.create(
                        model=Config.OPENAI_MODEL,
                        messages=[
                            {"role": "system", "content": "你是一名资深C/C++安全工程师。"},
                            {"role": "user", "content": prompt}],
                        temperature=0.3, max_tokens=2000)
                    if pResp.choices:
                        responses.append(pResp.choices[0].message.content)
            except Exception as e:
                logger.debug("[PatchSuggester] secondary provider failed: %s", e)

        if not responses:
            return ""

        # 取长度更长者（信息量更多）
        if len(responses) == 1:
            return responses[0]
        return responses[0] if len(responses[0]) >= len(responses[1]) else responses[1]

    def _parse_ai_response(self, response):
        dResult = {
            'patch': '',
            'description': '',
            'confidence': 0.7,
            'suggestion_type': 'general'
        }

        # ```diff 块
        mPatch = re.search(r'```diff\n(.*?)```', response, re.DOTALL)
        if mPatch is not None:
            dResult['patch'] = mPatch.group(1).strip()
        else:
            # 尝试 diff --git 格式
            mGit = re.search(r'(diff --git.*?)(?=\n##|\n```|$)', response, re.DOTALL)
            if mGit is not None:
                dResult['patch'] = mGit.group(1).strip()

        # 描述块：支持中英文标题，终止于空行后的小节标题或代码块边界
        mDesc = re.search(
            r'## (?:修复说明|Fix\s*Description)\s*\n(.*?)(?=\n\n#|\n##|\n```|```|\Z)',
            response, re.DOTALL)
        if mDesc is not None:
            dResult['description'] = mDesc.group(1).strip()
        else:
            dResult['description'] = response[:500]

        # 置信度：中英文关键字均可，仅取首个数值并夹取到 [0, 1]
        mConf = re.search(r'(?:置信度|confidence)\s*[:：]?\s*(\d+\.?\d*)', response)
        if mConf is not None:
            fRaw = float(mConf.group(1))
            dResult['confidence'] = min(max(fRaw, 0.0), 1.0)

        strResp = response
        # 关键词判定顺序固定：边界检查 → 安全函数 → free 后置空 → 参数化
        if ('边界检查' in strResp or '长度检查' in strResp
                or 'boundarycheck' in strResp or 'lengthcheck' in strResp):
            dResult['suggestion_type'] = 'boundary_check'
        elif ('安全函数' in strResp or 'strncpy' in strResp or 'snprintf' in strResp):
            dResult['suggestion_type'] = 'safe_function'
        elif ('free' in strResp and '置空' in strResp):
            dResult['suggestion_type'] = 'null_after_free'
        elif ('参数化' in strResp or '格式化' in strResp):
            dResult['suggestion_type'] = 'parameterized'

        return dResult

    def _validate_patch_syntax(self, suggestion):
        """对生成的 diff 做基本语法检查 —— 确保有 hunk header 与实质变更。"""
        if not suggestion.patch_diff:
            suggestion.confidence *= 0.7
            return suggestion

        diff = suggestion.patch_diff
        issues = []

        # 至少一个 hunk header
        if '@@' not in diff:
            issues.append('missing hunk header')
            suggestion.confidence *= 0.6

        # 至少一行实质变更（非元数据行）
        non_meta_lines = [l for l in diff.split('\n')
                         if l.strip() and not l.startswith('---') and not l.startswith('+++')
                         and not l.startswith('@@') and not l.startswith('diff')]
        if not non_meta_lines:
            issues.append('no actual change lines')
            suggestion.confidence *= 0.5

        # 至少一行以 + 或 - 开头
        has_change = any(l.startswith('+') or l.startswith('-') for l in non_meta_lines)
        if not has_change:
            issues.append('no add/remove lines')
            suggestion.confidence *= 0.7

        if issues:
            logger.debug("[PatchSuggester] validation issues: %s", ', '.join(issues))

        return suggestion

    def _generate_default_patch(self, decompiled_code, vuln_type):
        dPatches = {
            'stack_overflow': """--- a/source.c
+++ b/source.c
@@ -1,5 +1,8 @@
 void vulnerable_function(char *input) {
+    if (strlen(input) >= BUFFER_SIZE) {
+        return;  // 防止栈溢出
+    }
    char buffer[BUFFER_SIZE];
    strcpy(buffer, input);
 }""",
            'format_string': """--- a/source.c
+++ b/source.c
@@ -1,5 +1,5 @@
 void vulnerable_function(char *user_input) {
-    printf(user_input);
+    printf("%s", user_input);
 }""",
            'integer_overflow': """--- a/source.c
+++ b/source.c
@@ -1,5 +1,8 @@
int calculate_size(int a, int b) {
+    if (a > INT_MAX - b) {
+        return -1;  // 防止整数溢出
+    }
    return a + b;
 }""",
            'heap_vulnerability': """--- a/source.c
+++ b/source.c
@@ -1,5 +1,8 @@
void allocate_buffer(size_t size) {
+    if (size > MAX_ALLOC_SIZE) {
+        return NULL;  // 防止堆溢出
+    }
    char *buf = malloc(size);
 }""",
            'use_after_free': """--- a/source.c
+++ b/source.c
@@ -1,8 +1,10 @@
void process_data() {
       char *data = malloc(100);
       // 使用 data...
       free(data);
+   data = NULL;  // 防止UAF
       // 后续代码不会意外使用data
 }""",
            # detect layers
            'detect_stack_overflow': """--- a/build.sh
+++ b/build.sh
@@ -0,0 +1,2 @@
+CFLAGS="$CFLAGS -fsanitize=address -fstack-protector-strong"
""",
            'detect_format_string': """--- a/build.sh
+++ b/build.sh
@@ -0,0 +1,2 @@
+CFLAGS="$CFLAGS -Wformat -Wformat-security -Werror=format-security"
""",
            'detect_integer_overflow': """--- a/build.sh
+++ b/build.sh
@@ -0,0 +1,2 @@
+CFLAGS="$CFLAGS -fsanitize=undefined -ftrapv"
""",
            'detect_heap_vulnerability': """--- a/build.sh
+++ b/build.sh
@@ -0,0 +1,2 @@
+CFLAGS="$CFLAGS -fsanitize=address"
+LDFLAGS="$LDFLAGS -lasan"
""",
            'detect_use_after_free': """--- a/build.sh
+++ b/build.sh
@@ -0,0 +1,2 @@
+CFLAGS="$CFLAGS -fsanitize=address"
""",
        }
        return dPatches.get(vuln_type, "# Default patch suggestion\n# Manual analysis and remediation required")

    def _generate_default_description(self, vuln_type):
        dDescs = {
            'stack_overflow':
                '建议在复制数据前添加边界检查，或使用安全的字符串操作函数（如strncpy、snprintf等）替代不安全的函数（如strcpy、sprintf）。',
            'format_string':
                '建议使用参数化格式化输出，避免直接使用用户可控的字符串作为格式字符串。',
            'integer_overflow':
                '建议在进行算术运算前检查操作数范围，防止整数溢出导致的缓冲区溢出或逻辑错误。',
            'heap_vulnerability':
                '建议在分配内存前检查请求大小是否合理，避免堆溢出。对于double free漏洞，建议使用内存安全库或添加释放检查。',
            'use_after_free':
                '建议在free()调用后立即将指针置为NULL，防止后续代码意外引用已释放的内存。'
        }
        return dDescs.get(vuln_type, '请分析漏洞上下文并提供适当的修复方案。')

    def format_patch_for_report(self, suggestion):
        strPatchId = suggestion.patch_id
        if strPatchId == "":
            strPatchId = 'N/A'

        lstLines = []
        lstLines.append("## 补丁建议 ID: " + strPatchId)
        lstLines.append("**漏洞类型:** " + suggestion.vuln_type)
        lstLines.append("**目标函数:** " + suggestion.target_function)
        lstLines.append("**漏洞位置:** 偏移 0x{:x}".format(suggestion.target_offset))
        lstLines.append("**置信度:** {:.1f}%".format(suggestion.confidence * 100.0))
        lstLines.append("**修复说明:**\n" + suggestion.description)
        lstLines.append("\n**建议补丁 (unified diff):**\n```diff\n" + suggestion.patch_diff + "\n```")
        lstLines.append("\n---\n")
        return '\n'.join(lstLines)

    def save_suggestion(self,
        suggestion,
        vuln_db,
        vuln_id=None
    ):
        if vuln_db is None:
            logger.warning("[PatchSuggester] vuln_db is None, skip save")
            return None

        if vuln_db.connection is None:
            logger.warning("[PatchSuggester] db not connected, skip save")
            return None

        try:
            pCursor = vuln_db.connection.cursor()

            iEffVulnId = vuln_id
            if iEffVulnId is None:
                iEffVulnId = suggestion.vuln_id

            pCursor.execute(
                """
                INSERT INTO patch_suggestions (
                    vuln_id, vuln_type, patch_diff, description, confidence,
                    suggestion_type, target_function, target_offset, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    iEffVulnId,
                    suggestion.vuln_type,
                    suggestion.patch_diff,
                    suggestion.description,
                    suggestion.confidence,
                    suggestion.suggestion_type,
                    suggestion.target_function,
                    suggestion.target_offset,
                    datetime.now().isoformat()
                ))

            vuln_db.connection.commit()
            iNewId = pCursor.lastrowid
            suggestion.patch_id = str(iNewId)
            logger.info("[PatchSuggester] patch suggestion saved, ID: %d", iNewId)
            return iNewId

        except Exception as e:
            logger.error("[PatchSuggester] save failed: %s", e)
            return None

    def is_ai_available(self):
        return self.ai_client is not None
