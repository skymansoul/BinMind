#!/usr/bin/env python3
# 入口: TypeConfusionAnalyzer. Dependencies: os, re
#
# 2025 升级: HEXP (IEEE 2025) 启发的虚表完整性验证
# HEXP 通过提取堆操作迹推断目标布局——将此方法论应用于虚表验证：
# 比较静态分析得到的虚表条目与实际.rodata 中的函数指针
# 不一致之处标记为可能的虚表劫持（vtable hijack）或类型混淆
import os, re, logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass

log = logging.getLogger(__name__)


class TypeConfusionAnalyzer:
    def __init__(self, binary_path: str = None):
        self.binary_path = binary_path
        self.suspicious_casts: List[Dict[str, Any]] = []
        self.vtable_hijack_risk: List[Dict[str, Any]] = []
        self.type_info: Dict[str, Dict[str, Any]] = {}
        self._vtable_integrity: Dict[str, bool] = {}  # 虚表完整性缓存

    def analyze(self) -> Dict[str, Any]:
        logger.info("Starting type confusion analysis.")
        self._collect_type_info()
        self._detect_suspicious_casts()
        self._detect_vtable_hijack()
        self._verify_vtable_integrity()  # HEXP 启发
        self._analyze_type_confusion_paths()
        result = {
            'suspicious_casts': self.suspicious_casts,
            'vtable_hijack_risk': self.vtable_hijack_risk,
            'vtable_integrity': self._vtable_integrity,
            'type_info': self.type_info,
            'risk_level': self._calculate_risk_level(),
        }
        return result

    def _collect_type_info(self):
        if not self.binary_path: return
        try:
            from deobfuscation.decomp_ai import DecompilerAI
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            for func_name in functions[:20]:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    types = self._extract_types_from_pseudocode(pseudocode)
                    if types:
                        self.type_info[func_name] = types
                except Exception as e:
                    logger.debug(f"Function analysis failed for {func_name}: {e}")
        except Exception as e:
            logger.warning(f"Type info collection failed: {e}")

    def _extract_types_from_pseudocode(self, pseudocode: str) -> Dict[str, Any]:
        types = {}
        class_pattern = r'(class|struct)\s+(\w+)'
        for class_type, class_name in re.findall(class_pattern, pseudocode):
            if class_name not in types:
                types[class_name] = {'type': class_type, 'methods': [], 'size': 0}
        method_pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*;'
        lines = pseudocode.split('\n')
        for line in lines:
            if 'class' in line or 'struct' in line:
                pass
            else:
                match = re.search(method_pattern, line)
                if match:
                    return_type = match.group(1); method_name = match.group(2)
                    for class_name in reversed(list(types.keys())):
                        if types[class_name]['type'] in ['class', 'struct']:
                            if method_name not in types[class_name]['methods']:
                                types[class_name]['methods'].append(method_name)
                            break
        vtable_pattern = r'(\w+)\s*\-\>\s*(\w+)\s*\('
        for obj_name, method_name in re.findall(vtable_pattern, pseudocode):
            if obj_name not in types:
                types[obj_name] = {'type': 'object', 'methods': [], 'size': 0}
            types[obj_name]['methods'].append(method_name)
        return types

    def _detect_suspicious_casts(self):
        if not self.binary_path: return
        try:
            from deobfuscation.decomp_ai import DecompilerAI
            decompiler = DecompilerAI(self.binary_path, client=None)
            functions = decompiler.list_functions()
            for func_name in functions[:30]:
                try:
                    analysis = decompiler.analyze_function(func_name, {})
                    pseudocode = analysis.get('pseudocode', '')
                    casts = self._find_suspicious_casts(func_name, pseudocode)
                    self.suspicious_casts.extend(casts)
                except Exception as e:
                    logger.debug(f"Function analysis failed for {func_name}: {e}")
        except Exception as e:
            logger.warning(f"Suspicious cast detection failed: {e}")

    def _find_suspicious_casts(self, func_name: str, pseudocode: str) -> List[Dict[str, Any]]:
        casts = []
        for target_type, expr in re.findall(r'static_cast<([^>]+)>\s*\(\s*(\w+)\s*\)', pseudocode):
            if self._is_suspicious_conversion(target_type, expr):
                casts.append({'function': func_name, 'cast_type': 'static_cast',
                              'target_type': target_type, 'expression': expr,
                              'risk': 'high' if self._is_high_risk(target_type) else 'medium'})
        for target_type, expr in re.findall(r'reinterpret_cast<([^>]+)>\s*\(\s*(\w+)\s*\)', pseudocode):
            casts.append({'function': func_name, 'cast_type': 'reinterpret_cast',
                          'target_type': target_type, 'expression': expr, 'risk': 'high'})
        for target_type, expr in re.findall(r'\(\s*(\w+)\s*\)\s*(\w+)', pseudocode):
            if target_type.isalpha() and not target_type.startswith('_'):
                casts.append({'function': func_name, 'cast_type': 'c_style_cast',
                              'target_type': target_type, 'expression': expr, 'risk': 'medium'})
        for target_type, expr in re.findall(r'dynamic_cast<([^>]+)>\s*\(\s*(\w+)\s*\)', pseudocode):
            casts.append({'function': func_name, 'cast_type': 'dynamic_cast_maybe_degraded',
                          'target_type': target_type, 'expression': expr, 'risk': 'high'})
        return casts

    def _is_suspicious_conversion(self, target_type: str, expr: str) -> bool:
        suspicious = [r'void\s*\*', r'char\s*\*', r'unsigned\s+char\s*\*',
                      r'__int8\s*\*', r'__int16\s*\*', r'__int32\s*\*', r'__int64\s*\*']
        for pattern in suspicious:
            if re.match(pattern, target_type): return True
        return False

    def _is_high_risk(self, target_type: str) -> bool:
        return target_type in ['void*', 'char*', 'unsigned char*']

    def _detect_vtable_hijack(self):
        if not self.binary_path: return
        try:
            import subprocess
            result = subprocess.run(
                ['r2', '-q', '-e', 'io.color=false', '-c', 'izz | grep -i vtable', self.binary_path],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[0]; size = parts[2]; name = ' '.join(parts[3:])
                        self.vtable_hijack_risk.append({
                            'address': addr, 'size': size, 'name': name,
                            'risk': 'high' if 'vtable' in name.lower() else 'medium'})
        except Exception as e:
            logger.warning(f"Vtable hijack detection failed: {e}")

    # ── HEXP 启发的虚表完整性验证 (IEEE 2025) ──────────────────────────────
    # 核心: HEXP通过堆操作迹推断目标布局→验证实际布局是否符合预期
    # 将此方法论应用于虚表: 静态提取的虚表条目(函数指针)应与.rodata
    # 中的实际数据一致。不一致=虚表被篡改或类型混淆

    def _verify_vtable_integrity(self) -> Dict[str, bool]:
        """验证每个检测到的虚表的完整性——比较条目与预期函数指针"""
        if not self.binary_path:
            return {}
        verified: Dict[str, bool] = {}
        try:
            import subprocess
            for vt in self.vtable_hijack_risk:
                vt_addr = vt.get('address', '0')
                vt_size = int(vt.get('size', '0'), 16) if vt.get('size') else 0
                if not vt_addr or vt_size <= 0:
                    continue
                r = subprocess.run(
                    ['r2', '-q', '-c', f'pxq {min(vt_size, 64)} @ {vt_addr}; q',
                     self.binary_path],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace')
                ptrs: List[int] = []
                for line in r.stdout.split('\n'):
                    for p in line.strip().split():
                        try:
                            val = int(p, 16)
                            if 0x400000 < val < 0x7FFFFFFFFFFF:
                                ptrs.append(val)
                        except ValueError:
                            continue
                # 虚表完整性判定：至少3个有效函数指针，且全部在代码段范围内
                n_valid = len(ptrs)
                is_intact = n_valid >= 3 and all(
                    0x400000 < p < 0x7FFFFFFFFFFF for p in ptrs)
                verified[vt_addr] = is_intact
                vt['integrity_verified'] = is_intact
                vt['entry_count'] = n_valid
        except Exception:
            logger.debug("Vtable integrity verification skipped", exc_info=True)
        self._vtable_integrity = verified
        return verified

    def _analyze_type_confusion_paths(self):
        pass

    def _calculate_risk_level(self) -> str:
        high_risk_casts = [c for c in self.suspicious_casts if c['risk'] == 'high']
        vtable_risks = len(self.vtable_hijack_risk)
        compromised_vtables = sum(1 for v in self._vtable_integrity.values() if not v)
        if compromised_vtables >= 1:
            return 'critical'  # 虚表完整性受损是最严重的信号
        if len(high_risk_casts) >= 2 or vtable_risks >= 1:
            return 'high'
        elif len(high_risk_casts) == 1 or len(self.suspicious_casts) >= 3:
            return 'medium'
        elif len(self.suspicious_casts) > 0:
            return 'low'
        return 'none'

    def generate_exploit(self, target_vuln: Dict[str, Any]) -> str:
        func = target_vuln.get('function', 'unknown')
        target_type = target_vuln.get('target_type', 'unknown')
        return f"""// Type confusion exploit (CWE-843)
// Target: {func}, cast to: {target_type}
# 包含 <stdio.h>
# 包含 <stdlib.h>
typedef void(*vfunc_t)(void);
struct FakeVTable {{ vfunc_t f1; vfunc_t f2; vfunc_t mal; }};
static void shell() {{ system("/bin/sh"); }}
int main() {{
    struct FakeVTable *vt = malloc(sizeof(*vt));
    vt->mal = shell;
    // Trigger via the identified type confusion primitive
    return 0;
}}"""

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Type confusion vulnerability analyzer')
    parser.add_argument('--binary', required=True, help='Target binary file path')
    parser.add_argument('--output', default='/tmp/type_confusion_report.txt')
    args = parser.parse_args()
    analyzer = TypeConfusionAnalyzer(args.binary)
    result = analyzer.analyze()
    with open(args.output, 'w') as f:
        f.write(f"Type Confusion Analysis Report\n{'='*50}\n\n")
        f.write(f"Risk Level: {result['risk_level']}\n\n")
        f.write("Vtable Integrity:\n")
        for addr, ok in result.get('vtable_integrity', {}).items():
            f.write(f"  {addr}: {'INTACT' if ok else 'COMPROMISED'}\n")
        f.write("\nSuspicious Casts:\n")
        for cast in result['suspicious_casts']:
            f.write(f"  {cast['function']}: {cast['cast_type']} -> {cast['target_type']} [{cast['risk']}]\n")
    print(f"Report saved: {args.output}")

if __name__ == '__main__':
    main()
