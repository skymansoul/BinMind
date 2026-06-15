import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class TypeConfusionAnalyzer:
    """
    类型混淆漏洞分析器
    
    针对C++程序中的类型混淆漏洞进行检测，识别可疑的类型转换操作，
    评估是否可导致虚函数指针劫持，并生成利用脚本。
    
    Attributes:
        binary_path: 目标二进制文件路径
        decompiler: 反编译器实例
        suspicious_casts: 检测到的可疑类型转换列表
        vtable_hijack_risk: 虚表劫持风险列表
        type_info: 收集到的类型信息
    """
    
    def __init__(self, binary_path: str = None):
        """
        初始化类型混淆分析器
        
        Args:
            binary_path: 目标二进制文件路径
        """
        self.binary_path = binary_path
        self.suspicious_casts: List[Dict[str, Any]] = []
        self.vtable_hijack_risk: List[Dict[str, Any]] = []
        self.type_info: Dict[str, Dict[str, Any]] = {}
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的类型混淆分析
        
        Returns:
            分析结果字典
        """
        logger.info("开始类型混淆分析")
        
        # 收集类型信息
        self._collect_type_info()
        
        # 检测可疑的类型转换
        self._detect_suspicious_casts()
        
        # 检测虚表劫持风险
        self._detect_vtable_hijack()
        
        # 分析类型混淆路径
        self._analyze_type_confusion_paths()
        
        result = {
            'suspicious_casts': self.suspicious_casts,
            'vtable_hijack_risk': self.vtable_hijack_risk,
            'type_info': self.type_info,
            'risk_level': self._calculate_risk_level()
        }
        
        return result
    
    def _collect_type_info(self):
        """收集类型信息"""
        if not self.binary_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            
            for func_name in functions[:20]:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    # 提取类型信息
                    types = self._extract_types_from_pseudocode(pseudocode)
                    if types:
                        self.type_info[func_name] = types
                    
                except Exception as e:
                    logger.debug(f"分析函数 {func_name} 失败: {e}")
        
        except Exception as e:
            logger.warning(f"收集类型信息失败: {e}")
    
    def _extract_types_from_pseudocode(self, pseudocode: str) -> Dict[str, Any]:
        """从伪代码中提取类型信息"""
        types = {}
        
        # 查找类定义和结构体
        class_pattern = r'(class|struct)\s+(\w+)'
        matches = re.findall(class_pattern, pseudocode)
        for class_type, class_name in matches:
            if class_name not in types:
                types[class_name] = {
                    'type': class_type,
                    'methods': [],
                    'size': 0
                }
        
        # 从类定义中提取方法声明
        method_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*;'
        lines = pseudocode.split('\n')
        for line in lines:
            # 查找类或结构体内部的方法声明
            if 'class' in line or 'struct' in line:
                # 进入类定义区域
                pass
            else:
                # 在类定义内部查找方法
                match = re.search(method_pattern, line)
                if match:
                    return_type = match.group(1)
                    method_name = match.group(2)
                    # 找到包含这个方法的类（假设方法在最近的类定义中）
                    for class_name in reversed(list(types.keys())):
                        if types[class_name]['type'] in ['class', 'struct']:
                            if method_name not in types[class_name]['methods']:
                                types[class_name]['methods'].append(method_name)
                            break
        
        # 查找虚函数表引用
        vtable_pattern = r'(\w+)\s*\-\>\s*(\w+)\s*\('
        matches = re.findall(vtable_pattern, pseudocode)
        for obj_name, method_name in matches:
            if obj_name not in types:
                types[obj_name] = {'type': 'object', 'methods': [], 'size': 0}
            types[obj_name]['methods'].append(method_name)
        
        return types
    
    def _detect_suspicious_casts(self):
        """检测可疑的类型转换"""
        if not self.binary_path:
            return
        
        try:
            from modules.decomp_ai import DecompilerAI
            
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            
            for func_name in functions[:30]:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    
                    casts = self._find_suspicious_casts(func_name, pseudocode)
                    self.suspicious_casts.extend(casts)
                    
                except Exception as e:
                    logger.debug(f"分析函数 {func_name} 失败: {e}")
        
        except Exception as e:
            logger.warning(f"检测可疑类型转换失败: {e}")
    
    def _find_suspicious_casts(self, func_name: str, pseudocode: str) -> List[Dict[str, Any]]:
        """在伪代码中查找可疑的类型转换"""
        casts = []
        
        # 查找 static_cast
        static_cast_pattern = r'static_cast<([^>]+)>\s*\(\s*(\w+)\s*\)'
        matches = re.findall(static_cast_pattern, pseudocode)
        for target_type, expr in matches:
            if self._is_suspicious_conversion(target_type, expr):
                casts.append({
                    'function': func_name,
                    'cast_type': 'static_cast',
                    'target_type': target_type,
                    'expression': expr,
                    'risk': 'high' if self._is_high_risk(target_type) else 'medium'
                })
        
        # 查找 reinterpret_cast
        reinterpret_pattern = r'reinterpret_cast<([^>]+)>\s*\(\s*(\w+)\s*\)'
        matches = re.findall(reinterpret_pattern, pseudocode)
        for target_type, expr in matches:
            casts.append({
                'function': func_name,
                'cast_type': 'reinterpret_cast',
                'target_type': target_type,
                'expression': expr,
                'risk': 'high'
            })
        
        # 查找 C风格转换
        c_cast_pattern = r'\(\s*(\w+)\s*\)\s*(\w+)'
        matches = re.findall(c_cast_pattern, pseudocode)
        for target_type, expr in matches:
            if target_type.isalpha() and not target_type.startswith('_'):
                casts.append({
                    'function': func_name,
                    'cast_type': 'c_style_cast',
                    'target_type': target_type,
                    'expression': expr,
                    'risk': 'medium'
                })
        
        return casts
    
    def _is_suspicious_conversion(self, target_type: str, expr: str) -> bool:
        """判断类型转换是否可疑"""
        suspicious_patterns = [
            r'void\s*\*',
            r'char\s*\*',
            r'unsigned\s+char\s*\*',
            r'__int8\s*\*',
            r'__int16\s*\*',
            r'__int32\s*\*',
            r'__int64\s*\*'
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, target_type):
                return True
        
        return False
    
    def _is_high_risk(self, target_type: str) -> bool:
        """判断是否为高风险类型转换"""
        high_risk_types = ['void*', 'char*', 'unsigned char*']
        return target_type in high_risk_types
    
    def _detect_vtable_hijack(self):
        """检测虚表劫持风险"""
        if not self.binary_path:
            return
        
        try:
            # 使用radare2查找虚表指针操作
            import subprocess
            
            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c', 'izz | grep -i vtable',
                self.binary_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[0]
                        size = parts[2]
                        name = ' '.join(parts[3:])
                        
                        self.vtable_hijack_risk.append({
                            'address': addr,
                            'size': size,
                            'name': name,
                            'risk': 'high' if 'vtable' in name.lower() else 'medium'
                        })
        
        except Exception as e:
            logger.warning(f"检测虚表劫持风险失败: {e}")
    
    def _analyze_type_confusion_paths(self):
        """分析类型混淆路径"""
        pass
    
    def _calculate_risk_level(self) -> str:
        """计算总体风险等级"""
        high_risk_casts = [c for c in self.suspicious_casts if c['risk'] == 'high']
        vtable_risks = len(self.vtable_hijack_risk)
        
        if len(high_risk_casts) >= 2 or vtable_risks >= 1:
            return 'high'
        elif len(high_risk_casts) == 1 or len(self.suspicious_casts) >= 3:
            return 'medium'
        elif len(self.suspicious_casts) > 0:
            return 'low'
        else:
            return 'none'
    
    def generate_exploit(self, target_vuln: Dict[str, Any]) -> str:
        """
        生成类型混淆利用代码
        
        Args:
            target_vuln: 目标漏洞信息
        
        Returns:
            利用代码字符串
        """
        return f"""// 类型混淆漏洞利用
// CWE-843: Type Confusion
// 目标函数: {target_vuln.get('function', 'unknown')}
// 转换类型: {target_vuln.get('target_type', 'unknown')}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 伪造的虚函数表
typedef void (*vfunc_t)(void);

struct FakeVTable {{
    vfunc_t func1;
    vfunc_t func2;
    vfunc_t malicious_func;
}};

struct VulnerableObject {{
    struct FakeVTable *vtable;
    int data;
}};

void malicious_function() {{
    printf("[+] 虚函数表劫持成功!\\n");
    system("/bin/sh");
}}

int main() {{
    struct VulnerableObject *obj;
    struct FakeVTable *fake_vtable;
    
    // 分配伪造的虚函数表
    fake_vtable = (struct FakeVTable *)malloc(sizeof(struct FakeVTable));
    fake_vtable->func1 = (vfunc_t)0xdeadbeef;
    fake_vtable->func2 = (vfunc_t)0xdeadbeef;
    fake_vtable->malicious_func = malicious_function;
    
    // 触发类型混淆漏洞
    // 通过某种方式控制对象指针，使其指向我们的伪造虚表
    obj = (struct VulnerableObject *)malloc(sizeof(struct VulnerableObject));
    
    // 这里假设存在类型混淆漏洞，可以将任意指针赋值给obj
    // 实际利用需要找到具体的漏洞点
    obj->vtable = fake_vtable;
    
    // 调用虚函数，触发劫持
    obj->vtable->malicious_func();
    
    return 0;
}}
"""


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='类型混淆漏洞分析器')
    parser.add_argument('--binary', required=True, help='目标二进制文件路径')
    parser.add_argument('--output', default='/tmp/type_confusion_report.txt', help='报告输出路径')
    
    args = parser.parse_args()
    
    analyzer = TypeConfusionAnalyzer(args.binary)
    result = analyzer.analyze()
    
    with open(args.output, 'w') as f:
        f.write("类型混淆分析报告\n")
        f.write("=" * 50 + "\n\n")
        
        f.write("风险等级: {}\n\n".format(result['risk_level']))
        
        f.write("可疑类型转换:\n")
        f.write("-" * 30 + "\n")
        for cast in result['suspicious_casts']:
            f.write(f"函数: {cast['function']}\n")
            f.write(f"  转换类型: {cast['cast_type']}\n")
            f.write(f"  目标类型: {cast['target_type']}\n")
            f.write(f"  表达式: {cast['expression']}\n")
            f.write(f"  风险: {cast['risk']}\n\n")
        
        f.write("虚表劫持风险:\n")
        f.write("-" * 30 + "\n")
        for vtable in result['vtable_hijack_risk']:
            f.write(f"地址: {vtable['address']}\n")
            f.write(f"  大小: {vtable['size']}\n")
            f.write(f"  名称: {vtable['name']}\n")
            f.write(f"  风险: {vtable['risk']}\n\n")
    
    print(f"分析报告已保存到: {args.output}")


if __name__ == '__main__':
    main()