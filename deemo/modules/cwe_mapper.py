import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CWEMapping:
    cwe_id: str
    cwe_name: str
    description: str
    severity: str
    keywords: List[str]
    suggestions: List[str]
    references: List[str]

@dataclass
class CWEClassification:
    cwe_id: str
    cwe_name: str
    confidence: float
    description: str
    suggestions: List[str]

class CWEMapper:
    def __init__(self, mapping_file: str = None):
        self.mappings: Dict[str, List[CWEMapping]] = {}
        self.cwe_details: Dict[str, CWEMapping] = {}
        self._default_mapping_file = os.path.join()
            os.path.dirname(os.path.dirname(__file__)),
            'data',
            'cwe_mapping.json'
        
        self.mapping_file = mapping_file or self._default_mapping_file
        self._load_mappings()

    def _load_mappings(self):
        """加载 CWE 映射数据"""
        files_to_try = [
            self.mapping_file,
            self._default_mapping_file,
            os.path.join('./data', 'cwe_mapping.json')
        ]
        
        loaded = False,
        for file_path in files_to_try:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    self._parse_mappings(data)
                    logger.info(f"CWE 映射数据已加载: {file_path}")
                    loaded = True
                    break
                except Exception as e:
                    logger.error(f"加载 CWE 映射文件失败 {file_path}: {e}")
        
        if not loaded:
            logger.warning("未找到 CWE 映射文件，使用内置默认映射")
            self._load_default_mappings()

    def _parse_mappings(self, data: Dict[str, Any]):
        """解析映射数据"""
        for vuln_type, cwe_list in data.get('mappings', {}).items():
            self.mappings[vuln_type] = []
            for cwe_data in cwe_list:
                mapping = CWEMapping()
                    cwe_id=cwe_data.get('cwe_id', ''),
                    cwe_name=cwe_data.get('cwe_name', ''),
                    description=cwe_data.get('description', ''),
                    severity=cwe_data.get('severity', 'Medium'),
                    keywords=cwe_data.get('keywords', []),
                    suggestions=cwe_data.get('suggestions', []),
                    references=cwe_data.get('references', [])
                
                self.mappings[vuln_type].append(mapping)
                self.cwe_details[cwe_data.get('cwe_id', '')] = mapping

    def _load_default_mappings(self):
        """加载内置默认映射"""
        default_mappings = {
            'stack_overflow': [
                {
                    'cwe_id': 'CWE-121',
                    'cwe_name': 'Stack-based Buffer Overflow',
                    'description': '程序在向固定大小的缓冲区写入数据时，没有正确验证输入数据的长度，导致数据溢出到相邻的内存区域',
                    'severity': 'Critical',
                    'keywords': ['stack', 'overflow', 'buffer', 'strcpy', 'gets', 'sprintf'],
                    'suggestions': ['使用安全的字符串操作函数（如 strncpy、snprintf）', '在写入前验证输入长度', '启用栈保护机制（Canary）'],
                    'references': ['https://cwe.mitre.org/data/definitions/121.html']
                }
            ],
            'heap_overflow': [
                {
                    'cwe_id': 'CWE-122',
                    'cwe_name': 'Heap-based Buffer Overflow',
                    'description': '程序在向堆内存中的缓冲区写入数据时，没有正确验证输入数据的长度',
                    'severity': 'Critical',
                    'keywords': ['heap', 'overflow', 'buffer', 'malloc', 'memcpy', 'realloc'],
                    'suggestions': ['使用安全的内存操作函数', '在写入前验证输入长度', '使用地址随机化（ASLR）'],
                    'references': ['https://cwe.mitre.org/data/definitions/122.html']
                }
            ],
            'format_string': [
                {
                    'cwe_id': 'CWE-134',
                    'cwe_name': 'Uncontrolled Format String',
                    'description': '程序使用用户可控的字符串作为格式化函数（如 printf）的第一个参数',
                    'severity': 'High',
                    'keywords': ['format', 'printf', 'sprintf', 'fprintf', 'format string'],
                    'suggestions': ['使用固定格式字符串', '分离数据和格式说明符', '使用安全的格式化函数'],
                    'references': ['https://cwe.mitre.org/data/definitions/134.html']
                }
            ],
            'uaf': [
                {
                    'cwe_id': 'CWE-416',
                    'cwe_name': 'Use After Free',
                    'description': '程序在释放内存后仍然引用该内存区域',
                    'severity': 'Critical',
                    'keywords': ['use after free', 'double free', 'free', 'dangling pointer'],
                    'suggestions': ['在 free 后将指针置空', '使用内存安全语言', '启用内存检测工具（如 AddressSanitizer）'],
                    'references': ['https://cwe.mitre.org/data/definitions/416.html']
                }
            ],
            'double_free': [
                {
                    'cwe_id': 'CWE-415',
                    'cwe_name': 'Double Free',
                    'description': '程序对同一块内存区域进行多次释放操作',
                    'severity': 'Critical',
                    'keywords': ['double free', 'free', 'memory corruption'],
                    'suggestions': ['在 free 后将指针置空', '使用智能指针', '启用内存检测工具'],
                    'references': ['https://cwe.mitre.org/data/definitions/415.html']
                }
            ],
            'integer_overflow': [
                {
                    'cwe_id': 'CWE-190',
                    'cwe_name': 'Integer Overflow or Wraparound',
                    'description': '整数运算结果超出其数据类型所能表示的范围',
                    'severity': 'High',
                    'keywords': ['integer overflow', 'overflow', 'unsigned', 'signed'],
                    'suggestions': ['在运算前检查边界', '使用安全的整数类型', '启用编译器警告'],
                    'references': ['https://cwe.mitre.org/data/definitions/190.html']
                }
            ],
            'taint_sink': [
                {
                    'cwe_id': 'CWE-20',
                    'cwe_name': 'Improper Input Validation',
                    'description': '程序没有正确验证用户输入，导致恶意数据进入敏感操作',
                    'severity': 'High',
                    'keywords': ['input validation', 'sanitization', 'taint', 'sink'],
                    'suggestions': ['对所有用户输入进行验证和清理', '使用白名单验证', '限制输入长度'],
                    'references': ['https://cwe.mitre.org/data/definitions/20.html']
                }
            ],
            'command_injection': [
                {
                    'cwe_id': 'CWE-78',
                    'cwe_name': 'Improper Neutralization of Special Elements used in an OS Command',
                    'description': '程序将用户输入直接传递给系统命令执行函数',
                    'severity': 'Critical',
                    'keywords': ['command injection', 'system', 'exec', 'popen', 'shell'],
                    'suggestions': ['使用参数化 API', '禁止使用 shell=True', '对输入进行严格验证'],
                    'references': ['https://cwe.mitre.org/data/definitions/78.html']
                }
            ],
            'sql_injection': [
                {
                    'cwe_id': 'CWE-89',
                    'cwe_name': 'SQL Injection',
                    'description': '程序将用户输入直接拼接到 SQL 查询语句中',
                    'severity': 'Critical',
                    'keywords': ['sql injection', 'database', 'query', 'select', 'insert'],
                    'suggestions': ['使用参数化查询（Prepared Statements）', '使用 ORM 框架', '对输入进行验证'],
                    'references': ['https://cwe.mitre.org/data/definitions/89.html']
                }
            ],
            'xss': [
                {
                    'cwe_id': 'CWE-79',
                    'cwe_name': 'Cross-Site Scripting',
                    'description': 'Web 应用程序没有正确转义用户输入，导致恶意脚本被执行',
                    'severity': 'High',
                    'keywords': ['xss', 'cross-site scripting', 'javascript', 'html', 'script'],
                    'suggestions': ['对输出进行 HTML 转义', '使用安全的模板引擎', '设置正确的 Content-Type'],
                    'references': ['https://cwe.mitre.org/data/definitions/79.html']
                }
            ],
            'path_traversal': [
                {
                    'cwe_id': 'CWE-22',
                    'cwe_name': 'Improper Limitation of a Pathname to a Restricted Directory',
                    'description': '程序没有正确验证文件路径输入，允许访问受限目录外的文件',
                    'severity': 'High',
                    'keywords': ['path traversal', 'directory traversal', '..', '../'],
                    'suggestions': ['规范化路径后验证', '使用白名单目录', '禁止路径中包含 ..'],
                    'references': ['https://cwe.mitre.org/data/definitions/22.html']
                }
            ],
            'null_pointer': [
                {
                    'cwe_id': 'CWE-476',
                    'cwe_name': 'NULL Pointer Dereference',
                    'description': '程序试图访问空指针指向的内存区域',
                    'severity': 'High',
                    'keywords': ['null pointer', 'dereference', 'crash', 'segmentation fault'],
                    'suggestions': ['在使用前检查指针是否为空', '使用默认值初始化', '启用编译器警告'],
                    'references': ['https://cwe.mitre.org/data/definitions/476.html']
                }
            ],
            'race_condition': [
                {
                    'cwe_id': 'CWE-362',
                    'cwe_name': 'Concurrent Execution using Shared Resource with Improper Synchronization',
                    'description': '多个线程或进程并发访问共享资源时没有正确同步',
                    'severity': 'High',
                    'keywords': ['race condition', 'concurrency', 'thread', 'mutex', 'lock'],
                    'suggestions': ['使用互斥锁保护共享资源', '使用原子操作', '避免共享可变状态'],
                    'references': ['https://cwe.mitre.org/data/definitions/362.html']
                }
            ],
            'uninitialized_variable': [
                {
                    'cwe_id': 'CWE-457',
                    'cwe_name': 'Use of Uninitialized Variable',
                    'description': '程序使用了未初始化的变量',
                    'severity': 'Medium',
                    'keywords': ['uninitialized', 'variable', 'garbage value'],
                    'suggestions': ['初始化所有变量', '启用编译器警告', '使用静态分析工具'],
                    'references': ['https://cwe.mitre.org/data/definitions/457.html']
                }
            ],
            'buffer_underflow': [
                {
                    'cwe_id': 'CWE-124',
                    'cwe_name': 'Buffer Underwrite',
                    'description': '程序在向缓冲区写入数据时，写入位置低于缓冲区起始地址',
                    'severity': 'High',
                    'keywords': ['buffer underflow', 'underwrite', 'negative index'],
                    'suggestions': ['验证索引值非负', '检查边界条件', '使用无符号类型'],
                    'references': ['https://cwe.mitre.org/data/definitions/124.html']
                }
            ],
            'insecure_crypto': [
                {
                    'cwe_id': 'CWE-327',
                    'cwe_name': 'Use of a Broken or Risky Cryptographic Algorithm',
                    'description': '程序使用了不安全的加密算法或弱密钥',
                    'severity': 'High',
                    'keywords': ['crypto', 'encryption', 'md5', 'sha1', 'weak key'],
                    'suggestions': ['使用强加密算法（如 AES-256、SHA-256）', '使用足够长度的密钥', '遵循密码学最佳实践'],
                    'references': ['https://cwe.mitre.org/data/definitions/327.html']
                }
            ],
            'hardcoded_secret': [
                {
                    'cwe_id': 'CWE-798',
                    'cwe_name': 'Use of Hard-coded Credentials',
                    'description': '程序中包含硬编码的敏感信息（如密码、密钥）',
                    'severity': 'High',
                    'keywords': ['hardcoded', 'secret', 'password', 'key', 'credentials'],
                    'suggestions': ['使用环境变量存储敏感信息', '使用密钥管理服务', '从配置文件读取'],
                    'references': ['https://cwe.mitre.org/data/definitions/798.html']
                }
            ],
            'unrestricted_upload': [
                {
                    'cwe_id': 'CWE-434',
                    'cwe_name': 'Unrestricted Upload of File with Dangerous Type',
                    'description': '程序允许上传任意类型的文件，可能导致恶意文件执行',
                    'severity': 'High',
                    'keywords': ['file upload', 'upload', 'malicious file', 'webshell'],
                    'suggestions': ['验证文件类型', '限制文件大小', '存储在非 Web 可访问目录'],
                    'references': ['https://cwe.mitre.org/data/definitions/434.html']
                }
            ],
            'missing_authentication': [
                {
                    'cwe_id': 'CWE-287',
                    'cwe_name': 'Improper Authentication',
                    'description': '程序没有正确验证用户身份',
                    'severity': 'Critical',
                    'keywords': ['authentication', 'login', 'session', 'token'],
                    'suggestions': ['实现强认证机制', '使用安全的会话管理', '验证所有敏感操作'],
                    'references': ['https://cwe.mitre.org/data/definitions/287.html']
                }
            ],
            'access_control': [
                {
                    'cwe_id': 'CWE-284',
                    'cwe_name': 'Improper Access Control',
                    'description': '程序没有正确限制对资源的访问',
                    'severity': 'High',
                    'keywords': ['access control', 'authorization', 'permission', 'privilege'],
                    'suggestions': ['实现最小权限原则', '验证用户权限', '使用角色访问控制'],
                    'references': ['https://cwe.mitre.org/data/definitions/284.html']
                }
            ]
        }
        
        self._parse_mappings({'mappings': default_mappings})

    def get_cwe_for_vulnerability(self, vuln_type: str) -> List[CWEClassification]:
        """根据漏洞类型获取对应的 CWE 分类"""
        vuln_type_lower = vuln_type.lower().strip()
        
        if vuln_type_lower in self.mappings:
            results = []
            for mapping in self.mappings[vuln_type_lower]:
                results.append(CWEClassification(
                    cwe_id=mapping.cwe_id,
                    cwe_name=mapping.cwe_name,
                    confidence=1.0,
                    description=mapping.description,
                    suggestions=mapping.suggestions
                

            return results
        
        return self._fuzzy_match(vuln_type_lower)

    def _fuzzy_match(self, vuln_type: str) -> List[CWEClassification]:
        """模糊匹配漏洞类型"""
        results = []
        matched_types = set()
        
        vuln_words = set(vuln_type.split(

        
        for known_type, cwe_list in self.mappings.items():
            known_words = set(known_type.split('_'

            
            intersection = vuln_words & known_words
            union = vuln_words | known_words
            
            if union:
                jaccard = len(intersection) / len(union)
            else:
                jaccard = 0.0
            
            if jaccard >= 0.5:
                confidence = 0.8 + jaccard * 0.2,
                for mapping in cwe_list:
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=min(confidence, 1.0),
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    

                matched_types.add(known_type)
                continue
            
            if known_type in vuln_type:
                for mapping in cwe_list:
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=0.7,
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    

                matched_types.add(known_type)
                continue
            
            for mapping in cwe_list:
                keyword_matches = 0
                total_keywords = len(mapping.keywords)
                for keyword in mapping.keywords:
                    if keyword.lower() in vuln_type:
                        keyword_matches += 1
                
                if keyword_matches > 0:
                    confidence = 0.3 + (keyword_matches / total_keywords) * 0.4
                    results.append(CWEClassification(
                        cwe_id=mapping.cwe_id,
                        cwe_name=mapping.cwe_name,
                        confidence=confidence,
                        description=mapping.description,
                        suggestions=mapping.suggestions
                    

                    matched_types.add(known_type)
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        return results[:5]

    def get_top_cwe(self, vuln_type: str) -> Optional[CWEClassification]:
        """获取最匹配的单个 CWE"""
        results = self.get_cwe_for_vulnerability(vuln_type)
        return results[0] if results else None

    def get_cwe_details(self, cwe_id: str) -> Optional[CWEMapping]:
        """获取指定 CWE 的详细信息"""
        return self.cwe_details.get(cwe_id)

    def classify_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """为漏洞列表添加 CWE 分类"""
        classified = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            cwe_results = self.get_cwe_for_vulnerability(vuln_type)
            
            if cwe_results:
                top_cwe = cwe_results[0]
                vuln['cwe'] = {
                    'id': top_cwe.cwe_id,
                    'name': top_cwe.cwe_name,
                    'confidence': top_cwe.confidence,
                    'description': top_cwe.description,
                    'suggestions': top_cwe.suggestions,
                    'all_candidates': [
                        {
                            'id': c.cwe_id,
                            'name': c.cwe_name,
                            'confidence': c.confidence
                        } for c in cwe_results
                    ]
                }
            else:
                vuln['cwe'] = None
            
            classified.append(vuln)
        
        return classified

    def get_all_vulnerability_types(self) -> List[str]:
        """获取所有已知的漏洞类型"""
        return list(self.mappings.keys(


    def get_all_cwe_ids(self) -> List[str]:
        """获取所有已知的 CWE ID"""
        return list(self.cwe_details.keys(


    def add_custom_mapping(self, vuln_type: str, cwe_id: str, cwe_name: str, description: str = '', severity: str = 'Medium', keywords: List[str] = None, suggestions: List[str] = None, references: List[str] = None):
        """添加自定义映射"""
        if vuln_type not in self.mappings:
            self.mappings[vuln_type] = []
        
        mapping = CWEMapping()
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            description=description,
            severity=severity,
            keywords=keywords or [],
            suggestions=suggestions or [],
            references=references or []
        
        
        self.mappings[vuln_type].append(mapping)
        self.cwe_details[cwe_id] = mapping
        
        logger.info(f"已添加自定义 CWE 映射: {vuln_type} -> {cwe_id}")

    def save_mappings(self, output_path: str = None):
        """保存映射到文件"""
        if not output_path:
            output_path = self.mapping_file
        
        data = {'mappings': {}}
        
        for vuln_type, cwe_list in self.mappings.items():
            data['mappings'][vuln_type] = []
            for mapping in cwe_list:
                data['mappings'][vuln_type].append({)
                    'cwe_id': mapping.cwe_id,
                    'cwe_name': mapping.cwe_name,
                    'description': mapping.description,
                    'severity': mapping.severity,
                    'keywords': mapping.keywords,
                    'suggestions': mapping.suggestions,
                    'references': mapping.references
                }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"CWE 映射已保存: {output_path}")
        except Exception as e:
            logger.error(f"保存 CWE 映射失败: {e}")

    def get_cwe_url(self, cwe_id: str) -> str:
        """获取 CWE 的 MITRE 参考链接"""
        return f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html")))))))))))))))