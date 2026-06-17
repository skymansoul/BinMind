"""
AI 提示模板模块

定义用于各种分析功能的 AI 提示模板
"""
from typing import Dict, Any, Optional


# ==================== 托管代码分析提示模板 ====================

MANAGED_CODE_DECOMPILE_TEMPLATE = """
你是一名资深的.NET/Java逆向工程师。请分析以下托管代码的字节码/IL代码，并将其反编译为等效的高级语言伪代码。

代码类型: {code_type}
类名: {class_name}
方法名: {method_name}
字节码/IL代码:
{bytecode}

请提供:
1. 反编译后的伪代码（使用C#或Java语法）
2. 方法功能描述
3. 识别的潜在安全风险（如反序列化、不安全反射、命令执行等）
4. 调用的敏感API列表

输出格式:
```pseudo_code
// 反编译伪代码
...
```

安全分析:
- 风险类型: ...
- 危险调用: ...
- 建议: ...
"""

MANAGED_CODE_VULNERABILITY_TEMPLATE = """
你是一名安全研究员，请分析以下托管代码方法的安全漏洞。

代码类型: {code_type}
类名: {class_name}
方法名: {method_name}
伪代码:
{pseudo_code}

已知危险方法调用:
{dangerous_calls}

请分析:
1. 是否存在反序列化漏洞（BinaryFormatter、ObjectInputStream等）
2. 是否存在不安全反射（Type.InvokeMember、Class.forName等）
3. 是否存在命令注入（Process.Start、Runtime.exec等）
4. 是否存在SQL注入痕迹
5. 是否存在路径遍历风险
6. 其他潜在安全问题

输出JSON格式:
{
    "vulnerabilities": [
        {
            "type": "漏洞类型",
            "severity": "Critical/High/Medium/Low",
            "description": "详细描述",
            "location": "代码位置",
            "recommendation": "修复建议"
        }
    ],
    "overall_risk": "整体风险评估"
}
"""


# ==================== 补丁差异分析提示模板 ====================

PATCH_DIFF_ANALYSIS_TEMPLATE = """
你是一名漏洞研究专家，请分析以下补丁差异，识别被修复的安全漏洞。

原始函数伪代码:
{original_code}

补丁后函数伪代码:
{patched_code}

差异详情:
{diff_details}

请分析:
1. 补丁添加了哪些安全检查？
2. 修改了哪些可能导致漏洞的代码逻辑？
3. 推测原始漏洞的类型和触发条件
4. 评估漏洞的严重程度

输出JSON格式:
{
    "vulnerability_type": "漏洞类型（如buffer_overflow、use_after_free等）",
    "cwe_id": "CWE编号",
    "severity": "严重程度",
    "description": "漏洞描述",
    "trigger_condition": "触发条件",
    "patch_analysis": {
        "added_checks": ["添加的安全检查列表"],
        "modified_logic": ["修改的逻辑列表"],
        "fixed_behavior": "修复后的行为"
    },
    "exploitation_hint": "利用提示（如控制点、溢出长度等）"
}
"""

PATCH_SOURCE_TO_BINARY_TEMPLATE = """
你是一名逆向工程师，请将以下源码补丁映射到二进制函数。

源码补丁内容:
{source_patch}

反编译函数列表:
{decompiled_functions}

请找出:
1. 补丁修改的函数在二进制中的对应函数
2. 源码修改点在伪代码中的对应位置
3. 映射的置信度

输出JSON格式:
{
    "mappings": [
        {
            "source_function": "源码函数名",
            "binary_function": "二进制函数名/地址",
            "confidence": 0.0-1.0,
            "modification_points": [
                {
                    "source_line": "源码行号",
                    "pseudo_code_location": "伪代码位置描述"
                }
            ]
        }
    ]
}
"""


# ==================== 跨架构利用移植提示模板 ====================

EXPLOIT_TRANSPILE_TEMPLATE = """
你是一名漏洞利用开发专家，请将以下源架构的利用代码转换为目标架构。

源架构: {source_arch}
目标架构: {target_arch}
原始利用代码:
{source_exploit}

漏洞信息:
- 类型: {vuln_type}
- 偏移: {offset}

请提供:
1. 调整后的利用代码（pwntools格式）
2. 寄存器映射说明
3. ROP gadget替换方案
4. Shellcode转换（如需要）
5. 系统调用号调整

注意事项:
- ARM64使用x0-x7作为参数寄存器，x30作为返回地址
- ARM使用r0-r3作为参数寄存器，lr作为返回地址
- MIPS使用a0-a3作为参数寄存器
- RISC-V使用a0-a7作为参数寄存器，ra作为返回地址

输出格式:
```python
# {target_arch} 架构利用代码
from pwn import *

...
```

转换说明:
- 寄存器映射: ...
- Gadget替换: ...
- 系统调用调整: ...
"""

ROP_GADGET_SEARCH_TEMPLATE = """
请根据以下功能需求，从目标架构的gadget数据库中搜索合适的gadget。

目标架构: {target_arch}
所需功能:
{required_functions}

可用gadget列表:
{available_gadgets}

请推荐:
1. 每个功能对应的最佳gadget
2. 替代方案（如有）
3. gadget组合顺序

输出JSON格式:
{
    "gadget_chain": [
        {
            "function": "所需功能",
            "gadget_address": "地址",
            "gadget_asm": "汇编代码",
            "alternatives": ["替代gadget列表"]
        }
    ],
    "chain_order": ["推荐顺序"]
}
"""

SHELLCODE_TRANSPILE_TEMPLATE = """
请将以下源架构的shellcode转换为目标架构的等效shellcode。

源架构: {source_arch}
目标架构: {target_arch}
原始shellcode:
{source_shellcode}

shellcode功能: {shellcode_function}

请提供:
1. 目标架构的shellcode（十六进制格式）
2. 对应的汇编代码
3. 功能验证说明

输出格式:
Shellcode (hex): ...
Assembly:
...
"""


# ==================== 恶意软件聚类提示模板 ====================

MALWARE_CLUSTER_NAMING_TEMPLATE = """
你是一名恶意软件分析专家，请根据以下行为特征为恶意软件家族生成描述性名称。

簇内样本行为特征:
{cluster_features}

高频ATT&CK技术:
{attack_techniques}

常见API调用模式:
{api_patterns}

请生成:
1. 家族名称（格式：行为类型-技术特征，如Downloader-Persistence）
2. 家族描述（2-3句话）
3. 关键行为标签
4. 建议的YARA规则关键词

输出JSON格式:
{
    "family_name": "家族名称",
    "description": "家族描述",
    "behavior_tags": ["标签列表"],
    "yara_keywords": ["YARA关键词"],
    "similar_families": ["可能相似的已知家族"]
}
"""

MALWARE_BEHAVIOR_SUMMARY_TEMPLATE = """
请为以下恶意软件样本生成行为摘要报告。

样本信息:
- 文件名: {filename}
- 文件类型: {file_type}
- 大小: {size}

行为追踪数据:
{behavior_trace}

请分析:
1. 主要恶意行为（进程注入、持久化、数据窃取等）
2. 网络通信特征（C2地址、协议、端口）
3. 文件系统操作（创建、修改、删除的文件）
4. 注册表/配置修改
5. 反分析技术（如有）
6. MITRE ATT&CK技术映射

输出JSON格式:
{
    "summary": "行为摘要",
    "malicious_behaviors": ["恶意行为列表"],
    "network_activity": {
        "c2_servers": ["C2地址"],
        "protocols": ["协议"],
        "ports": ["端口"]
    },
    "file_operations": ["文件操作列表"],
    "registry_operations": ["注册表操作"],
    "anti_analysis": ["反分析技术"],
    "attack_techniques": [
        {
            "technique_id": "Txxxx",
            "technique_name": "技术名称",
            "confidence": 0.0-1.0
        }
    ]
}
"""


# ==================== 并发分析提示模板 ====================

CONCURRENCY_RACE_ANALYSIS_TEMPLATE = """
你是一名并发安全专家，请分析以下代码中的潜在数据竞争。

函数伪代码:
{pseudo_code}

并发分析结果:
{concurrency_analysis}

请分析:
1. 竞争条件的具体位置
2. 共享变量的访问模式
3. 缺少的同步机制
4. 可能的触发场景
5. 攻击者如何利用此竞争

输出JSON格式:
{
    "race_conditions": [
        {
            "location": "代码位置",
            "shared_variable": "共享变量",
            "access_pattern": "访问模式",
            "missing_sync": "缺少的同步",
            "trigger_scenario": "触发场景",
            "exploitation": "利用方法"
        }
    ],
    "severity": "严重程度",
    "recommendation": "修复建议"
}
"""

CONCURRENCY_REPRO_SCRIPT_TEMPLATE = """
请生成一个可以触发以下竞争条件的测试脚本。

竞争条件详情:
{race_condition}

程序信息:
- 路径: {binary_path}
- 架构: {architecture}

请生成:
1. 多线程测试脚本（Python）
2. 线程调度策略
3. 预期触发概率
4. 检测方法

输出格式:
```python
# 竞争条件复现脚本
import threading
import time
...
```
"""


# ==================== 沙箱策略生成提示模板 ====================

SANDBOX_POLICY_ANALYSIS_TEMPLATE = """
请分析以下二进制的安全需求，生成最小权限沙箱策略建议。

二进制信息:
- 名称: {binary_name}
- 类型: {binary_type}
- 导入函数: {imported_functions}

静态分析结果:
{static_analysis}

动态追踪结果（如有）:
{dynamic_trace}

请建议:
1. 必需的系统调用列表
2. 必需的文件访问路径
3. 必需的网络权限
4. 应禁止的危险操作
5. seccomp/AppArmor策略建议

输出JSON格式:
{
    "required_syscalls": ["必需syscall列表"],
    "required_files": ["必需文件路径"],
    "required_network": {
        "outbound": ["允许的出站连接"],
        "inbound": ["允许的入站连接"]
    },
    "denied_operations": ["禁止的操作"],
    "policy_recommendation": {
        "seccomp": "seccomp策略建议",
        "apparmor": "AppArmor策略建议"
    },
    "risk_assessment": "风险评估"
}
"""


# ==================== 提示模板管理类 ====================

class PromptTemplateManager:
    """
    提示模板管理器
    
    提供统一的提示模板访问和管理接口
    """
    
    _templates: Dict[str, str] = {}
    
    @classmethod
    def register_template(cls, name: str, template: str) -> None:
        """
        注册提示模板
        
        Args:
            name: 模板名称
            template: 模板内容
        """
        cls._templates[name] = template
    
    @classmethod
    def get_template(cls, name: str) -> Optional[str]:
        """
        获取提示模板
        
        Args:
            name: 模板名称
            
        Returns:
            模板内容，不存在返回None
        """
        return cls._templates.get(name)
    
    @classmethod
    def format_template(cls, name: str, **kwargs) -> Optional[str]:
        """
        格式化提示模板
        
        Args:
            name: 模板名称
            **kwargs: 模板变量
            
        Returns:
            格式化后的提示内容
        """
        template = cls.get_template(name)
        if template is None:
            return None
        
        try:
            return template.format(**kwargs)
        except KeyError as e:
            return None
    
    @classmethod
    def list_templates(cls) -> list:
        """
        列出所有已注册的模板名称
        
        Returns:
            模板名称列表
        """
        return list(cls._templates.keys())


# ==================== 时间侧信道检测提示模板 ====================

TIMING_SIDECHANNEL_TEMPLATE = """
你是一名密码学安全专家，请分析以下代码中的时间侧信道漏洞。

函数伪代码:
{pseudo_code}

检测到的可疑模式:
{suspicious_patterns}

密钥相关变量:
{key_variables}

请分析:
1. 是否存在密钥依赖的条件分支（如 if (key[i] == ...)）
2. 是否存在秘密相关的循环边界（如 for (i < secret_len)）
3. 是否存在未掩码的查找表访问（如 sbox[key_byte]）
4. 是否使用了危险的比较函数（如 strcmp 比较秘密数据）
5. 是否存在缓存时间攻击模式

对于每个问题，请提供:
- 漏洞类型
- 严重程度
- 具体位置
- 攻击向量描述
- 修复建议

输出JSON格式:
{
    "timing_vulnerabilities": [
        {
            "type": "漏洞类型（key_dependent_branch/secret_loop_boundary/unmasked_lookup/secret_comparison/cache_timing）",
            "severity": "High/Medium/Low",
            "location": "代码位置",
            "description": "漏洞描述",
            "attack_vector": "攻击向量",
            "recommendation": "修复建议"
        }
    ],
    "overall_risk": "整体风险评估",
    "mitigation_summary": "缓解措施总结"
}
"""


# ==================== 移动平台漏洞分析提示模板 ====================

MOBILE_VULN_ANALYSIS_TEMPLATE = """
你是一名移动安全专家，请分析以下移动平台二进制文件的安全漏洞。

平台类型: {platform}
二进制类型: {binary_type}

分析数据:
- JNI函数列表: {jni_functions}
- Objective-C类结构: {objc_classes}
- 敏感字符串: {sensitive_strings}
- 危险API调用: {dangerous_calls}

请识别以下移动平台特有的漏洞模式:

1. **JNI相关漏洞**:
   - JNI参数验证不足
   - 从不受信任来源获取Java对象
   - 类型转换不安全
   - 数组越界访问

2. **Android特有漏洞**:
   - Intent劫持/欺骗
   - Binder事务校验绕过
   - IPC通信滥用
   - URL Scheme劫持
   - 硬编码密钥/证书
   - 不安全的WebView配置
   - 外部存储敏感数据泄露

3. **iOS特有漏洞**:
   - 不安全的NSUserDefaults使用
   - 明文SQLite数据库
   - 越狱检测绕过（可被攻击者利用）
   - 私有API调用
   - 钥匙串访问控制不当
   - 应用间通信漏洞

4. **通用移动端漏洞**:
   - SSL/TLS证书验证缺失
   - 不安全的加密实现
   - C2服务器域名硬编码
   - 调试接口暴露

请输出详细的JSON格式分析结果:
{
    "mobile_vulnerabilities": [
        {
            "type": "漏洞类型",
            "severity": "Critical/High/Medium/Low",
            "description": "漏洞详细描述",
            "location": "代码位置/函数名",
            "platform_specific": "android/ios/both",
            "attack_vector": "攻击向量描述",
            "recommendation": "修复建议"
        }
    ],
    "sensitive_data_found": [
        {
            "type": "数据类型（如hardcoded_key/c2_domain/password）",
            "value": "脱敏后的值",
            "location": "发现位置"
        }
    ],
    "overall_risk": "整体风险评估",
    "security_summary": "安全总结"
}
"""


# ==================== 漏洞利用链分析提示模板 ====================

EXPLOIT_CHAIN_ANALYSIS_TEMPLATE = """
你是一名漏洞利用开发专家，请分析以下漏洞集合，评估它们能否组合成攻击链。

漏洞列表:
{vulnerabilities}

攻击目标: {target}

每个漏洞的能力标签说明:
- info_leak:stack - 可泄露栈内存信息
- info_leak:heap - 可泄露堆内存信息
- info_leak:libc - 可泄露libc基址
- arbitrary_write:stack - 可任意写栈
- arbitrary_write:heap - 可任意写堆
- arbitrary_write:global - 可任意写全局变量
- control_pc - 可控制程序计数器
- bypass_aslr - 可绕过ASLR
- bypass_dep - 可绕过DEP
- privilege_escalation - 可提权

请分析:
1. 这些漏洞能否按顺序组合形成完整攻击链？
2. 组合顺序是什么？说明每个漏洞的作用
3. 攻击链的最终效果是什么？
4. 是否存在缺失的环节？
5. 攻击链的可行性评估（高/中/低）

输出JSON格式:
{
    "chain_possible": true/false,
    "chains": [
        {
            "path": ["漏洞ID1", "漏洞ID2", "漏洞ID3"],
            "capabilities_chain": ["info_leak:libc", "arbitrary_write:got", "control_pc"],
            "final_effect": "攻击效果描述（如代码执行、提权等）",
            "feasibility": "High/Medium/Low",
            "risk_score": 0-10,
            "description": "攻击链描述"
        }
    ],
    "missing_links": ["缺失的能力/前置条件"],
    "recommendations": ["加固建议"]
}
"""


# 注册所有默认模板
def _register_default_templates():
    """注册默认提示模板"""
    templates = {
        'managed_code_decompile': MANAGED_CODE_DECOMPILE_TEMPLATE,
        'managed_code_vulnerability': MANAGED_CODE_VULNERABILITY_TEMPLATE,
        'patch_diff_analysis': PATCH_DIFF_ANALYSIS_TEMPLATE,
        'patch_source_to_binary': PATCH_SOURCE_TO_BINARY_TEMPLATE,
        'exploit_transpile': EXPLOIT_TRANSPILE_TEMPLATE,
        'rop_gadget_search': ROP_GADGET_SEARCH_TEMPLATE,
        'shellcode_transpile': SHELLCODE_TRANSPILE_TEMPLATE,
        'malware_cluster_naming': MALWARE_CLUSTER_NAMING_TEMPLATE,
        'malware_behavior_summary': MALWARE_BEHAVIOR_SUMMARY_TEMPLATE,
        'concurrency_race_analysis': CONCURRENCY_RACE_ANALYSIS_TEMPLATE,
        'concurrency_repro_script': CONCURRENCY_REPRO_SCRIPT_TEMPLATE,
        'sandbox_policy_analysis': SANDBOX_POLICY_ANALYSIS_TEMPLATE,
        'timing_sidechannel': TIMING_SIDECHANNEL_TEMPLATE,
        'mobile_vuln_analysis': MOBILE_VULN_ANALYSIS_TEMPLATE,
        'exploit_chain_analysis': EXPLOIT_CHAIN_ANALYSIS_TEMPLATE,
    }
    
    for name, template in templates.items():
        PromptTemplateManager.register_template(name, template)


# 自动注册默认模板
_register_default_templates()


def get_prompt(template_name: str, **kwargs) -> Optional[str]:
    """
    获取并格式化提示模板的便捷函数
    
    Args:
        template_name: 模板名称
        **kwargs: 模板变量
        
    Returns:
        格式化后的提示内容
    """
    return PromptTemplateManager.format_template(template_name, **kwargs)


def list_available_prompts() -> list:
    """
    列出所有可用的提示模板
    
    Returns:
        模板名称列表
    """
    return PromptTemplateManager.list_templates()