import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from config import Config, mask_api_key
from prompts import PATCH_SUGGESTION_TEMPLATE

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class PatchSuggestion:
    """
    补丁建议结果类
    """
    
    def __init__(self):
        self.patch_id: str = ""
        self.vuln_id: int = 0
        self.vuln_type: str = ""
        self.patch_diff: str = ""
        self.description: str = ""
        self.confidence: float = 0.0
        self.suggestion_type: str = ""
        self.target_function: str = ""
        self.target_offset: int = 0
        self.timestamp: str = datetime.now().isoformat()
        self.source_code: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'patch_id': self.patch_id,
            'vuln_id': self.vuln_id,
            'vuln_type': self.vuln_type,
            'patch_diff': self.patch_diff,
            'description': self.description,
            'confidence': self.confidence,
            'suggestion_type': self.suggestion_type,
            'target_function': self.target_function,
            'target_offset': self.target_offset,
            'timestamp': self.timestamp,
            'source_code': self.source_code
        }


class PatchSuggester:
    """
    智能补丁建议生成器 - 利用AI分析漏洞上下文，自动生成源码级补丁建议
    
    支持的漏洞类型：
        - 栈溢出 (stack_overflow)
        - 格式化字符串 (format_string)
        - 整数溢出 (integer_overflow)
        - 堆漏洞 (heap_vulnerability)
        - UAF (use_after_free)
    """
    
    def __init__(self):
        """初始化补丁建议器"""
        self.ai_client = None
        self._init_ai_client()
    
    def _init_ai_client(self):
        """初始化AI客户端"""
        provider = Config.AI_PROVIDER.lower()
        
        if provider == 'openai' and OPENAI_AVAILABLE:
            try:
                self.ai_client = OpenAI(api_key=Config.OPENAI_API_KEY)
                logger.info("[PatchSuggester] OpenAI 客户端已初始化")
            except Exception as e:
                logger.warning(f"[PatchSuggester] OpenAI 初始化失败: {e}")
        
        elif provider == 'anthropic' and ANTHROPIC_AVAILABLE:
            try:
                self.ai_client = Anthropic(api_key=Config.ANTHROPIC_API_KEY)
                logger.info("[PatchSuggester] Anthropic 客户端已初始化")
            except Exception as e:
                logger.warning(f"[PatchSuggester] Anthropic 初始化失败: {e}")
    
    def generate_suggestion(
        self,
        decompiled_code: str,
        vuln_type: str,
        function_name: str = "",
        instruction_offset: int = 0,
        protection_info: Dict[str, Any] = None
    ) -> PatchSuggestion:
        """
        为单个漏洞生成补丁建议
        
        Args:
            decompiled_code: 反编译伪代码
            vuln_type: 漏洞类型 (stack_overflow/format_string/integer_overflow/heap_vulnerability/use_after_free)
            function_name: 包含漏洞的函数名
            instruction_offset: 漏洞位置的指令偏移
            protection_info: 保护机制信息（ASLR、DEP、PIE等）
            
        Returns:
            补丁建议对象
        """
        result = PatchSuggestion()
        result.vuln_type = vuln_type
        result.target_function = function_name
        result.target_offset = instruction_offset
        result.source_code = decompiled_code
        
        if not self.ai_client:
            logger.warning("[PatchSuggester] AI客户端未初始化，使用默认建议")
            result.patch_diff = self._generate_default_patch(decompiled_code, vuln_type)
            result.description = self._generate_default_description(vuln_type)
            result.confidence = 0.5
            return result
        
        try:
            prompt = self._build_prompt(decompiled_code, vuln_type, function_name, instruction_offset, protection_info)
            ai_response = self._call_ai(prompt)
            
            parsed_result = self._parse_ai_response(ai_response)
            result.patch_diff = parsed_result.get('patch', '')
            result.description = parsed_result.get('description', '')
            result.confidence = parsed_result.get('confidence', 0.7)
            result.suggestion_type = parsed_result.get('suggestion_type', 'general')
            
            logger.info(f"[PatchSuggester] 补丁建议生成成功，置信度: {result.confidence}")
            
        except Exception as e:
            logger.error(f"[PatchSuggester] AI调用失败: {e}")
            result.patch_diff = self._generate_default_patch(decompiled_code, vuln_type)
            result.description = f"AI生成失败，使用默认建议: {str(e)}"
            result.confidence = 0.3
        
        return result
    
    def generate_batch_suggestions(
        self,
        vulnerabilities: List[Dict[str, Any]],
        decompiled_code: str
    ) -> List[PatchSuggestion]:
        """
        为多个漏洞批量生成补丁建议
        
        Args:
            vulnerabilities: 漏洞列表，每个漏洞包含 vuln_type, function_name, offset
            decompiled_code: 完整的反编译代码
            
        Returns:
            补丁建议列表
        """
        suggestions = []
        
        for vuln in vulnerabilities:
            if vuln.get('severity', 'low') in ['high', 'critical']:
                suggestion = self.generate_suggestion(
                    decompiled_code,
                    vuln.get('vuln_type', ''),
                    vuln.get('function_name', ''),
                    vuln.get('offset', 0),
                    vuln.get('protection_info', {})
                )
                suggestion.vuln_id = vuln.get('id', 0)
                suggestions.append(suggestion)
        
        logger.info(f"[PatchSuggester] 批量生成完成，共 {len(suggestions)} 个补丁建议")
        return suggestions
    
    def _build_prompt(
        self,
        decompiled_code: str,
        vuln_type: str,
        function_name: str,
        instruction_offset: int,
        protection_info: Dict[str, Any]
    ) -> str:
        """构建AI提示词"""
        vuln_description = {
            'stack_overflow': '栈缓冲区溢出漏洞',
            'format_string': '格式化字符串漏洞',
            'integer_overflow': '整数溢出漏洞',
            'heap_vulnerability': '堆漏洞（如堆溢出、double free等）',
            'use_after_free': '释放后使用漏洞（UAF）'
        }.get(vuln_type, '未知漏洞')
        
        protection_str = ""
        if protection_info:
            enabled_protections = [k for k, v in protection_info.items() if v]
            if enabled_protections:
                protection_str = f"已启用保护机制: {', '.join(enabled_protections)}"
        
        return PATCH_SUGGESTION_TEMPLATE.format(
            vuln_type=vuln_type,
            vuln_description=vuln_description,
            function_name=function_name,
            instruction_offset=instruction_offset,
            protection_info=protection_str,
            decompiled_code=decompiled_code
        )
    
    def _call_ai(self, prompt: str) -> str:
        """调用AI生成补丁建议"""
        provider = Config.AI_PROVIDER.lower()
        
        if provider == 'openai' and self.ai_client:
            response = self.ai_client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "你是一名资深C/C++安全工程师，擅长分析漏洞并提供修复建议。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            return response.choices[0].message.content
        
        elif provider == 'anthropic' and self.ai_client:
            response = self.ai_client.messages.create(
                model=Config.ANTHROPIC_MODEL,
                max_tokens=2000,
                temperature=0.3,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        
        return ""
    
    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """解析AI响应"""
        result = {
            'patch': '',
            'description': '',
            'confidence': 0.7,
            'suggestion_type': 'general'
        }
        
        patch_match = re.search(r'```diff\n(.*?)```', response, re.DOTALL)
        if patch_match:
            result['patch'] = patch_match.group(1).strip()
        
        desc_match = re.search(r'## 修复说明\n(.*?)(?=\n##|```|$)', response, re.DOTALL)
        if desc_match:
            result['description'] = desc_match.group(1).strip()
        else:
            result['description'] = response[:500]
        
        conf_match = re.search(r'置信度[:：]?\s*(\d+\.?\d*)', response)
        if conf_match:
            result['confidence'] = min(float(conf_match.group(1)), 1.0)
        
        if '边界检查' in response or '长度检查' in response:
            result['suggestion_type'] = 'boundary_check'
        elif '安全函数' in response or 'strncpy' in response or 'snprintf' in response:
            result['suggestion_type'] = 'safe_function'
        elif 'free' in response and '置空' in response:
            result['suggestion_type'] = 'null_after_free'
        elif '参数化' in response or '格式化' in response:
            result['suggestion_type'] = 'parameterized'
        
        return result
    
    def _generate_default_patch(self, decompiled_code: str, vuln_type: str) -> str:
        """生成默认补丁建议（当AI不可用时）"""
        patches = {
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
+    data = NULL;  // 防止UAF
     // 后续代码不会意外使用data
 }"""
        }
        
        return patches.get(vuln_type, "# 默认补丁建议\n# 请手动分析漏洞并修复")
    
    def _generate_default_description(self, vuln_type: str) -> str:
        """生成默认修复说明"""
        descriptions = {
            'stack_overflow': '建议在复制数据前添加边界检查，或使用安全的字符串操作函数（如strncpy、snprintf等）替代不安全的函数（如strcpy、sprintf）。',
            'format_string': '建议使用参数化格式化输出，避免直接使用用户可控的字符串作为格式字符串。',
            'integer_overflow': '建议在进行算术运算前检查操作数范围，防止整数溢出导致的缓冲区溢出或逻辑错误。',
            'heap_vulnerability': '建议在分配内存前检查请求大小是否合理，避免堆溢出。对于double free漏洞，建议使用内存安全库或添加释放检查。',
            'use_after_free': '建议在free()调用后立即将指针置为NULL，防止后续代码意外引用已释放的内存。'
        }
        return descriptions.get(vuln_type, '请分析漏洞上下文并提供适当的修复方案。')
    
    def format_patch_for_report(self, suggestion: PatchSuggestion) -> str:
        """
        格式化补丁建议用于报告输出
        
        Args:
            suggestion: 补丁建议对象
            
        Returns:
            格式化后的补丁文本
        """
        lines = [
            f"## 补丁建议 ID: {suggestion.patch_id or 'N/A'}",
            f"**漏洞类型:** {suggestion.vuln_type}",
            f"**目标函数:** {suggestion.target_function}",
            f"**漏洞位置:** 偏移 0x{suggestion.target_offset:x}",
            f"**置信度:** {suggestion.confidence * 100:.1f}%",
            f"**修复说明:**\n{suggestion.description}",
            f"\n**建议补丁 (unified diff):**\n```diff\n{suggestion.patch_diff}\n```",
            f"\n---\n"
        ]
        return '\n'.join(lines)
    
    def save_suggestion(
        self,
        suggestion: PatchSuggestion,
        vuln_db,
        vuln_id: int = None
    ) -> Optional[int]:
        """
        将补丁建议保存到数据库
        
        Args:
            suggestion: 补丁建议对象
            vuln_db: 漏洞数据库实例
            vuln_id: 关联的漏洞记录ID
            
        Returns:
            新记录ID，失败返回None
        """
        if not vuln_db or not vuln_db.connection:
            logger.warning("[PatchSuggester] 数据库未连接，跳过保存")
            return None
        
        try:
            cursor = vuln_db.connection.cursor()
            
            cursor.execute(
                """
                INSERT INTO patch_suggestions (
                    vuln_id, vuln_type, patch_diff, description, confidence,
                    suggestion_type, target_function, target_offset, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln_id or suggestion.vuln_id,
                    suggestion.vuln_type,
                    suggestion.patch_diff,
                    suggestion.description,
                    suggestion.confidence,
                    suggestion.suggestion_type,
                    suggestion.target_function,
                    suggestion.target_offset,
                    datetime.now().isoformat()
                )
            )
            
            vuln_db.connection.commit()
            new_id = cursor.lastrowid
            suggestion.patch_id = str(new_id)
            logger.info(f"[PatchSuggester] 补丁建议已保存，ID: {new_id}")
            return new_id
            
        except Exception as e:
            logger.error(f"[PatchSuggester] 保存补丁建议失败: {e}")
            return None
    
    def is_ai_available(self) -> bool:
        """检查AI客户端是否可用"""
        return self.ai_client is not None
