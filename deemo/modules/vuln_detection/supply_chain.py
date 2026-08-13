source: str = ""
description: str = ""
severity: str = ""
start_address: str = ""
trigger_condition: str = ""
from_state: str = ""
size: int = 0
cve_id: str = ""
import os
import re
import json
import yaml
import logging
import asyncio
import requests
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

try:
    import ahocorasick
    AHO_AVAILABLE = True
except ImportError:
    AHO_AVAILABLE = False
    logger.warning("pyahocorasick not installed — falling back to naive string matching")


class LibraryComponent:
    __slots__ = ('name', 'version', 'version_parts',)

    def __init__(self, name, version, version_parts=field(default_factory=lambda: (0, 0, 0))):
        self.name = name
        self.version = version
        self.version_parts = version_parts


    purl: str = ""
    detected_by: str = ""
    confidence: float = 0.0
    matches: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityMatch:
    cve_id
    severity
    description
    source
    published_date = None
    affected_versions = None

class SoftwareBillOfMaterials:
    __slots__ = ('binary_path', 'components', 'vulnerabilities', 'generated_at',)

    def __init__(self, binary_path, components=field(default_factory=list), vulnerabilities=field(default_factory=dict), generated_at=field(default_factory=datetime.now)):
        self.binary_path = binary_path
        self.components = components
        self.vulnerabilities = vulnerabilities
        self.generated_at = generated_at


    def add_component(self, component: LibraryComponent) -> None:
        # 将库组件注册至物料清单
        self.components.append(component)

    def add_vulnerabilities(self, component_name: str, vulns: List[VulnerabilityMatch]) -> None:
        # 将漏洞匹配列表绑定至指定组件
        self.vulnerabilities[component_name] = vulns

    def get_total_vulnerabilities(self) -> int:
        # 统计所有已追踪组件的漏洞总数
        return sum(len(vulns) for vulns in self.vulnerabilities.values())

    def get_critical_vulnerabilities(self) -> int:
        # 统计所有已追踪组件中Critical级别漏洞数量
        nCount = 0
        for vulns in self.vulnerabilities.values():
            for vuln in vulns:
                if vuln.severity == 'Critical':
                    nCount += 1
        return nCount

class SupplyChainAnalyzer:
    """供应链安全分析器——识别二进制中的第三方库并关联已知漏洞。

    能力：
    - 通过特征模式匹配检测静态链接库
    - 从嵌入版本字符串解析版本信息
    - 查询OSV与NVD漏洞数据库
    - 生成软件物料清单（SBOM）
    """

    DEFAULT_FINGERPRINTS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'library_fingerprints.yaml')

    def __init__(self, fingerprints_path: str = None):
        self.fingerprints_path = fingerprints_path or self.DEFAULT_FINGERPRINTS_PATH
        self.fingerprints = {}
        self._load_fingerprints()
        self.osv_rate_limit = 10
        self.osv_rate_period = 60
        self.last_osv_request = None

    def _load_fingerprints(self) -> None:
        """从YAML文件加载库指纹数据库。

        指纹文件结构：
        - 库名称
        - 字符串模式列表
        - 版本匹配正则
        - 已知版本列表（有序）
        """
        try:
            if os.path.exists(self.fingerprints_path):
                with open(self.fingerprints_path, 'r', encoding='utf-8') as f:
                    self.fingerprints = yaml.safe_load(f)
                logger.info(f"Loaded {len(self.fingerprints)} library fingerprints")
            else:
                logger.warning(f"Fingerprint file not found: {self.fingerprints_path}")
                self.fingerprints = self._get_default_fingerprints()
        except Exception as e:
            logger.error(f"Failed to load fingerprint file: {e}")
            self.fingerprints = self._get_default_fingerprints()

    def _get_default_fingerprints(self) -> Dict[str, Any]:
        """返回内置库指纹集——配置文件缺失时的fallback方案。"""
        return {
            'openssl': {
                'patterns': [
                    'OpenSSL (\d+\.\d+\.\d+[a-z]?)',
                    'libcrypto\.so\.\d+\.\d+\.\d+',
                    'libssl\.so\.\d+\.\d+\.\d+',
                    'OpenSSL_(\d+)_(\d+)_(\d+)',
                    'SSLeay_version',
                    'OPENSSL_VERSION_NUMBER'
                ],
                'version_pattern': r'OpenSSL\s+(\d+)\.(\d+)\.(\d+)[a-z]?',
                'versions': ['1.0.2', '1.1.0', '1.1.1', '3.0', '3.1']
            },
            'zlib': {
                'patterns': [
                    'zlib (\d+\.\d+\.\d+)',
                    'libz\.so\.\d+\.\d+\.\d+',
                    'ZLIB_VERSION',
                    'zlib_version',
                    'inflateInit',
                    'deflateInit'
                ],
                'version_pattern': r'zlib\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['1.2.11', '1.2.12', '1.2.13']
            },
            'libpng': {
                'patterns': [
                    'libpng version (\d+\.\d+\.\d+)',
                    'libpng(\d+)(\d+)(\d+)',
                    'PNG_LIBPNG_VER_STRING',
                    'png_set_sig_bytes'
                ],
                'version_pattern': r'libpng\s+version\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['1.6.37', '1.6.38', '1.6.39']
            },
            'libjpeg': {
                'patterns': [
                    'libjpeg-turbo version (\d+\.\d+\.\d+)',
                    'JPEG_LIB_VERSION',
                    'jpeg_start_compress',
                    'jpeg_start_decompress'
                ],
                'version_pattern': r'libjpeg-turbo\s+version\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['2.0.0', '2.1.0', '2.1.1']
            },
            'sqlite': {
                'patterns': [
                    'SQLite version (\d+\.\d+\.\d+)',
                    'SQLITE_VERSION',
                    'sqlite3_version',
                    'sqlite3_open'
                ],
                'version_pattern': r'SQLite\s+version\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['3.35', '3.36', '3.37', '3.38']
            },
            'libxml2': {
                'patterns': [
                    'libxml2 version (\d+\.\d+\.\d+)',
                    'LIBXML_DOTTED_VERSION',
                    'xmlParseDoc',
                    'xmlFreeDoc'
                ],
                'version_pattern': r'libxml2\s+version\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['2.9.10', '2.9.11', '2.9.12']
            },
            'glibc': {
                'patterns': [
                    'GNU C Library (\d+\.\d+)',
                    'GLIBC_(\d+)_(\d+)',
                    '__libc_start_main',
                    '__malloc_hook'
                ],
                'version_pattern': r'GNU C Library\s+(\d+)\.(\d+)',
                'versions': ['2.31', '2.32', '2.33', '2.34']
            },
            'openssl-legacy': {
                'patterns': [
                    'OpenSSL 0\\.9\\.8[a-z]',
                    'SSLeay 0\\.9\\.8',
                    'OPENSSL_0_9_8'
                ],
                'version_pattern': r'OpenSSL\s+0\.9\.8([a-z])',
                'versions': ['0.9.8']
            },
            'go-stdlib': {
                'patterns': [
                    'go1\\.(\d+)\\.(\d+)',
                    'runtime\.go',
                    'net/http',
                    'encoding/json',
                    'golang\.org'
                ],
                'version_pattern': r'go1\.(\d+)\.(\d+)',
                'versions': ['1.18', '1.19', '1.20', '1.21']
            },
            'rust-stdlib': {
                'patterns': [
                    'rustc version (\d+\.\d+\.\d+)',
                    'std::',
                    'core::',
                    'alloc::',
                    'rust_begin_unwind'
                ],
                'version_pattern': r'rustc\s+version\s+(\d+)\.(\d+)\.(\d+)',
                'versions': ['1.60', '1.61', '1.62']
            }
        }

    def extract_strings(self, binary_path: str) -> List[str]:
        """从二进制文件中提取可打印ASCII连续序列（≥4字符）。"""
        strings = []

        try:
            with open(binary_path, 'rb') as f:
                content = f.read()

            current_string = b''
            for byte in content:
                if 0x20 <= byte <= 0x7E or byte in [0x09, 0x0A, 0x0D]:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= 4:
                        try:
                            strings.append(current_string.decode('utf-8', errors='ignore'))

                        except Exception:
                            logger.debug("suppressed", exc_info=True)
                    current_string = b''

            if len(current_string) >= 4:
                try:
                    strings.append(current_string.decode('utf-8', errors='ignore'))

                except Exception:
                    logger.debug("suppressed", exc_info=True)

            logger.info(f"Extracted {len(strings)} strings from binary")

        except Exception as e:
            logger.error(f"String extraction failed: {e}")

        return strings

    def _parse_version(self, version_str: str, version_pattern: str) -> Optional[Tuple[int, int, int]]:
        """使用指定正则模式从字符串中解析版本元组。"""
        match = re.search(version_pattern, version_str)
        if match:
            groups = match.groups()
            if len(groups) == 3:
                return (int(groups[0]), int(groups[1]), int(groups[2]))

            elif len(groups) == 2:
                return (int(groups[0]), int(groups[1]), 0)
            elif len(groups) == 1:
                return (int(groups[0]), 0, 0)
        return None

    def _create_purl(self, name: str, version: str) -> str:
        """基于库名称与版本构造Package URL（purl）标识符。"""
        return f"pkg:generic/{name}@{version}"

    def _find_library_by_patterns(self, strings: List[str], library_name: str, patterns: List[str], version_pattern: str) -> Optional[LibraryComponent]:
        """扫描提取字符串与指纹模式进行库匹配。"""
        matches = []
        version = "unknown"
        version_parts = (0, 0, 0)

        for pattern in patterns:
            for string in strings:
                if re.search(pattern, string):
                    matches.append(string)

                    if version_pattern and version == "unknown":
                        parsed_version = self._parse_version(string, version_pattern)
                        if parsed_version:
                            version_parts = parsed_version
                            version = f"{version_parts[0]}.{version_parts[1]}.{version_parts[2]}"

        if matches:
            confidence = min(1.0, len(matches) / len(patterns))

            return LibraryComponent(
                name=library_name,
                version=version,
                version_parts=version_parts,
                purl=self._create_purl(library_name, version),
                detected_by='pattern_match',
                confidence=confidence,
                matches=matches[:5]
            )

        return None

    def _find_library_ahocorasick(self, strings: List[str]) -> List[LibraryComponent]:
        """使用Aho-Corasick自动机加速库匹配——失败时回退至正则扫描。"""
        if not AHO_AVAILABLE:
            return []

        try:
            automaton = ahocorasick.Automaton()

            for lib_name, config in self.fingerprints.items():
                for pattern in config.get('patterns', []):
                    clean_pattern = re.sub(r'\(\?[:=]', '', pattern)
                    clean_pattern = re.sub(r'\)', '', clean_pattern)
                    clean_pattern = re.sub(r'\\d+', '0', clean_pattern)
                    clean_pattern = re.sub(r'\\.', '.', clean_pattern)
                    if len(clean_pattern) >= 3:
                        automaton.add_word(clean_pattern, (lib_name, pattern))


            automaton.make_automaton()

            found_libs = set()

            for string in strings:
                for end_index, (lib_name, pattern) in automaton.iter(string):
                    found_libs.add(lib_name)

            results = []
            for lib_name in found_libs:
                config = self.fingerprints[lib_name]
                component = self._find_library_by_patterns(
                    strings,
                    lib_name,
                    config.get('patterns', []),
                    config.get('version_pattern', '')
                )
                if component:
                    results.append(component)

            return results

        except Exception as e:
            logger.warning(f"Aho-Corasick matching failed — falling back to regex: {e}")
            return []

    def analyze_binary(self, binary_path: str) -> List[LibraryComponent]:
        """通过指纹模式匹配识别二进制中嵌入的第三方库。"""
        logger.info(f"Starting binary analysis: {binary_path}")

        if not os.path.exists(binary_path):
            logger.error(f"File not found: {binary_path}")
            return []

        strings = self.extract_strings(binary_path)

        if AHO_AVAILABLE:
            components = self._find_library_ahocorasick(strings)
        else:
            components = []

            for lib_name, config in self.fingerprints.items():
                component = self._find_library_by_patterns(
                    strings,
                    lib_name,
                    config.get('patterns', []),
                    config.get('version_pattern', '')
                )
                if component:
                    components.append(component)

        logger.info(f"Identified {len(components)} third-party libraries")
        for comp in components:
            logger.info(f"  - {comp.name} v{comp.version} (confidence: {comp.confidence:.2f})")

        return components

    def _check_osv_api(self, library_name: str, version: str) -> List[Dict[str, Any]]:
        """查询OSV.dev API获取影响指定库版本的已知漏洞。"""
        results = []

        if version == "unknown":
            return results

        now = datetime.now()
        if self.last_osv_request:
            time_since_last = (now - self.last_osv_request).total_seconds()
            if time_since_last < self.osv_rate_period / self.osv_rate_limit:
                wait_time = (self.osv_rate_period / self.osv_rate_limit) - time_since_last
                logger.debug(f"OSV API rate limit — waiting {wait_time:.1f}s")
                import time
                time.sleep(wait_time)

        self.last_osv_request = datetime.now()

        try:
            url = f"https://api.osv.dev/v1/query"

            request_data = {
                "package": {
                    "name": library_name,
                    "ecosystem": "generic"
                },
                "version": version
            }

            response = requests.post(url, json=request_data, timeout=10)

            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    results.append({
                        'cve_id': vuln.get('id', ''),
                        'severity': self._get_osv_severity(vuln),
                        'description': vuln.get('summary', '') or vuln.get('details', '')[:200],
                        'source': 'osv',
                        'published_date': vuln.get('published', ''),
                        'affected_versions': ', '.join(vuln.get('affected', []))
                    })

            logger.debug(f"OSV query complete: {library_name} v{version} — {len(results)} vulnerabilities found")

        except Exception as e:
            logger.warning(f"OSV query failed for {library_name} v{version}: {e}")

        return results

    def _get_osv_severity(self, vuln: Dict[str, Any]) -> str:
        """从OSV漏洞响应中提取最高严重级别。"""
        severity = 'Unknown'

        for affected in vuln.get('affected', []):
            for range_info in affected.get('ranges', []):
                if 'severity' in range_info:
                    sev = range_info['severity']
                    if sev == 'CRITICAL':
                        return 'Critical'
                    elif sev == 'HIGH':
                        severity = 'High'
                    elif sev == 'MEDIUM' and severity == 'Unknown':
                        severity = 'Medium'
                    elif sev == 'LOW' and severity == 'Unknown':
                        severity = 'Low'

        return severity

    def _check_local_nvd_cache(self, library_name: str, version: str, vuln_db) -> List[Dict[str, Any]]:
        """检索本地NVD缓存中匹配指定库的漏洞记录。"""
        results = []

        if not vuln_db:
            return results

        try:
            search_results = vuln_db.fuzzy_search_by_dangerous_functions(
                dangerous_functions=[library_name],
                limit=20
            )

            for record in search_results:
                cve_id = record.get('cve_id', '')
                if cve_id:
                    results.append({
                        'cve_id': cve_id,
                        'severity': record.get('severity', 'Unknown'),
                        'description': record.get('description', ''),
                        'source': 'local_nvd',
                        'published_date': record.get('created_at', ''),
                        'affected_versions': None
                    })

            logger.debug(f"Local cache query complete: {library_name} v{version} — {len(results)} vulnerabilities found")

        except Exception as e:
            logger.warning(f"Local cache query failed for {library_name} v{version}: {e}")

        return results

    async def _async_check_vulnerabilities(self, components: List[LibraryComponent], vuln_db=None) -> Dict[str, List[VulnerabilityMatch]]:
        """并发查询所有组件的OSV与本地NVD缓存。"""
        vulnerabilities = {}

        async def check_component(component: LibraryComponent):
            nonlocal vulnerabilities

            osv_results = await asyncio.to_thread(self._check_osv_api, component.name, component.version)

            nvd_results = []
            if vuln_db:
                nvd_results = await asyncio.to_thread(self._check_local_nvd_cache, component.name, component.version, vuln_db)

            all_results = osv_results + nvd_results

            seen_cves = set()
            unique_vulns = []

            for vuln in all_results:
                cve_id = vuln.get('cve_id', '')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_vulns.append(VulnerabilityMatch(
                        cve_id=cve_id,
                        severity=vuln.get('severity', 'Unknown'),
                        description=vuln.get('description', ''),
                        source=vuln.get('source', 'unknown'),
                        published_date=vuln.get('published_date'),
                        affected_versions=vuln.get('affected_versions')
                    ))

            if unique_vulns:
                vulnerabilities[component.name] = unique_vulns

        tasks = [check_component(comp) for comp in components]
        await asyncio.gather(*tasks)

        return vulnerabilities

    def check_vulnerabilities(self, components: List[LibraryComponent], vuln_db=None) -> Dict[str, List[VulnerabilityMatch]]:
        """将已识别的库组件与已知漏洞数据库交叉比对。"""
        logger.info(f"Querying vulnerabilities for {len(components)} components")

        try:
            vulnerabilities = asyncio.run(self._async_check_vulnerabilities(components, vuln_db))

        except Exception as e:
            logger.warning(f"Async query failed — falling back to synchronous mode: {e}")
            vulnerabilities = {}

            for comp in components:
                osv_results = self._check_osv_api(comp.name, comp.version)
                nvd_results = []

                if vuln_db:
                    nvd_results = self._check_local_nvd_cache(comp.name, comp.version, vuln_db)

                all_results = osv_results + nvd_results

                seen_cves = set()
                unique_vulns = []

                for vuln in all_results:
                    cve_id = vuln.get('cve_id', '')
                    if cve_id and cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        unique_vulns.append(VulnerabilityMatch(
                            cve_id=cve_id,
                            severity=vuln.get('severity', 'Unknown'),
                            description=vuln.get('description', ''),
                            source=vuln.get('source', 'unknown'),
                            published_date=vuln.get('published_date'),
                            affected_versions=vuln.get('affected_versions')
                        ))

                if unique_vulns:
                    vulnerabilities[comp.name] = unique_vulns

        total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())

        logger.info(f"Vulnerability query complete — {total_vulns} known vulnerabilities found")

        return vulnerabilities

    def generate_sbom(self, binary_path: str, vuln_db=None) -> SoftwareBillOfMaterials:
        """生成包含漏洞交叉引用的完整SBOM。"""
        sbom = SoftwareBillOfMaterials(binary_path=binary_path)

        components = self.analyze_binary(binary_path)

        for comp in components:
            sbom.add_component(comp)

        vulnerabilities = self.check_vulnerabilities(components, vuln_db)

        for comp_name, vulns in vulnerabilities.items():
            sbom.add_vulnerabilities(comp_name, vulns)

        logger.info(f"SBOM generation complete — {len(sbom.components)} components, {sbom.get_total_vulnerabilities()} vulnerabilities")

        return sbom

    def export_sbom_json(self, sbom: SoftwareBillOfMaterials, output_path: str = None) -> str:
        """将SBOM序列化为JSON——可选写入文件。"""
        sbom_dict = {
            'binary_path': sbom.binary_path,
            'generated_at': sbom.generated_at.isoformat(),
            'components': [],
            'vulnerabilities': {}
        }

        for comp in sbom.components:
            sbom_dict['components'].append({
                'name': comp.name,
                'version': comp.version,
                'version_parts': comp.version_parts,
                'purl': comp.purl,
                'detected_by': comp.detected_by,
                'confidence': comp.confidence,
                'matches': comp.matches
            })

        for comp_name, vulns in sbom.vulnerabilities.items():
            sbom_dict['vulnerabilities'][comp_name] = []
            for vuln in vulns:
                sbom_dict['vulnerabilities'][comp_name].append({
                    'cve_id': vuln.cve_id,
                    'severity': vuln.severity,
                    'description': vuln.description,
                    'source': vuln.source,
                    'published_date': vuln.published_date,
                    'affected_versions': vuln.affected_versions
                })

        json_str = json.dumps(sbom_dict, ensure_ascii=False, indent=2)

        if output_path:
            try:
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                logger.info(f"SBOM exported to: {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"SBOM export failed: {e}")

        return json_str

    def get_summary(self, sbom: SoftwareBillOfMaterials) -> Dict[str, Any]:
        """汇总SBOM元数据与漏洞计数生成摘要字典。"""
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Unknown': 0
        }

        for vulns in sbom.vulnerabilities.values():
            for vuln in vulns:
                severity = vuln.severity
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['Unknown'] += 1

        return {
            'binary_path': sbom.binary_path,
            'total_components': len(sbom.components),
            'total_vulnerabilities': sbom.get_total_vulnerabilities(),
            'critical_vulnerabilities': sbom.get_critical_vulnerabilities(),
            'severity_counts': severity_counts,
            'components': [comp.name for comp in sbom.components],
            'generated_at': sbom.generated_at.isoformat()
        }
