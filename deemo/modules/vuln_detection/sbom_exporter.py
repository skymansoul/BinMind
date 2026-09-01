from __future__ import annotations

import os
import json
import logging
import hashlib
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


@dataclass
class SBOMComponent:
    name: str = ""
    version: str = ""
    purl: str = ""
    supplier: str = ""
    license: str = "NOASSERTION"
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    description: str = ""
    dependencies: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    external_references: list = field(default_factory=list)
    properties: dict = field(default_factory=dict)

@dataclass
class SBOMDocument:
    name: str = ""
    version: str = "1.0"
    author: str = "binmind-analyzer"
    tool: str = "Binary Vulnerability Analysis Tool"
    tool_version: str = "1.3.1"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    components: List[SBOMComponent] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


class SBOMExporter:

    SPDX_LICENSE_MAP = {
        'apache': 'Apache-2.0',
        'apache-2.0': 'Apache-2.0',
        'apache 2.0': 'Apache-2.0',
        'mit': 'MIT',
        'bsd': 'BSD-3-Clause',
        'bsd-2': 'BSD-2-Clause',
        'bsd-3': 'BSD-3-Clause',
        'gpl': 'GPL-3.0',
        'gpl-2': 'GPL-2.0',
        'gpl-3': 'GPL-3.0',
        'lgpl': 'LGPL-3.0',
        'mozilla': 'MPL-2.0',
        'boost': 'BSL-1.0',
        'creative': 'CC-BY-4.0',
        'public': 'Public-Domain',
        'unlicense': 'Unlicense',
        'isc': 'ISC',
        'zlib': 'Zlib',
        'openssl': 'OpenSSL',
        'proprietary': 'Proprietary',
        'commercial': 'Proprietary',
    }

    SEVERITY_MAP = {
        'Critical': 'critical',
        'High': 'high',
        'Medium': 'medium',
        'Low': 'low',
        'Unknown': 'unknown',
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'unknown': 'unknown',
    }

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or './reports'
        os.makedirs(self.output_dir, exist_ok=True)

        logger.info(f"SBOM exporter initialized, output directory: {self.output_dir}")

    def _generate_spdx_id(self, name: str) -> str:
        safe_name = name.replace(' ', '-').replace('.', '-').replace('_', '-')
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c == '-')
        return f"SPDXRef-{safe_name}"

    def _generate_cyclonedx_bom_ref(self, name: str, version: str = "") -> str:
        return str(uuid.uuid4())

    def _normalize_license(self, license_str: str) -> str:
        if not license_str:
            return "NOASSERTION"

        license_lower = license_str.lower().strip()

        if license_lower in self.SPDX_LICENSE_MAP:
            return self.SPDX_LICENSE_MAP[license_lower]

        if license_str.startswith('LicenseRef-') or license_str in self.SPDX_LICENSE_MAP.values():
            return license_str

        for key, value in self.SPDX_LICENSE_MAP.items():
            if key in license_lower:
                return value

        return "NOASSERTION"

    def _normalize_severity(self, severity: str) -> str:
        return self.SEVERITY_MAP.get(severity, 'unknown')

    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        hashes = {'sha256': '', 'sha1': '', 'md5': ''}

        if not file_path or not os.path.exists(file_path):
            return hashes

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['md5'] = hashlib.md5(content).hexdigest()

        except Exception as e:
            logger.warning(f"File hash computation failed: {file_path} - {e}")

        return hashes

    def build_sbom_document(self,
        binary_path: str,
        binary_info: Dict[str, Any],
        supply_chain_result: Dict[str, Any] = None,
        vulnerabilities: List[Dict[str, Any]] = None
    ) -> SBOMDocument:
        binary_name = os.path.basename(binary_path)

        hashes = self._calculate_file_hashes(binary_path)

        main_component = SBOMComponent(
            name=binary_name,
            version=binary_info.get('version', ''),
            supplier=binary_info.get('vendor', 'Unknown'),
            license=self._normalize_license(binary_info.get('license', '')),
            sha256=hashes['sha256'],
            sha1=hashes['sha1'],
            md5=hashes['md5'],
            description=f"Binary file: {binary_name}",
            properties={
                'architecture': binary_info.get('arch', 'unknown'),
                'bits': binary_info.get('bits', 0),
                'format': binary_info.get('format', 'unknown'),
                'language': binary_info.get('language', 'unknown'),
            }
        )

        components = [main_component]

        if supply_chain_result:
            sbom_components = supply_chain_result.get('components', [])

            for comp in sbom_components:
                if isinstance(comp, dict):
                    component = SBOMComponent(
                        name=comp.get('name', 'Unknown'),
                        version=comp.get('version', ''),
                        purl=comp.get('purl', ''),
                        supplier=comp.get('supplier', ''),
                        license=self._normalize_license(comp.get('license', '')),
                        description=comp.get('description', ''),
                        dependencies=comp.get('dependencies', []),
                        properties={
                            'confidence': comp.get('confidence', 0),
                            'detected_by': comp.get('detected_by', ''),
                        }
                    )
                    components.append(component)
                else:
                    try:
                        component = SBOMComponent(
                            name=comp.name,
                            version=comp.version,
                            purl=comp.purl,
                            license="NOASSERTION",
                            properties={
                                'confidence': comp.confidence,
                                'detected_by': comp.detected_by,
                            }
                        )
                        components.append(component)
                    except Exception:
                        logger.debug("suppressed", exc_info=True)

            vulns = supply_chain_result.get('vulnerabilities', {})
            for comp_name, vuln_list in vulns.items():
                for comp in components:
                    if comp.name == comp_name:
                        for vuln in vuln_list:
                            if isinstance(vuln, dict):
                                comp.vulnerabilities.append({
                                    'cve_id': vuln.get('cve_id', ''),
                                    'severity': vuln.get('severity', 'Unknown'),
                                    'description': vuln.get('description', ''),
                                    'source': vuln.get('source', ''),
                                })
                            else:
                                try:
                                    comp.vulnerabilities.append({
                                        'cve_id': vuln.cve_id,
                                        'severity': vuln.severity,
                                        'description': vuln.description,
                                        'source': vuln.source,
                                    })
                                except Exception:
                                    logger.debug("suppressed", exc_info=True)

        if vulnerabilities:
            for vuln in vulnerabilities:
                location = vuln.get('location', '')
                for comp in components:
                    if location and comp.name in location:
                        comp.vulnerabilities.append({
                            'cve_id': vuln.get('cve_id', vuln.get('id', '')),
                            'severity': vuln.get('severity', 'Unknown'),
                            'description': vuln.get('description', ''),
                            'source': vuln.get('source', 'internal'),
                        })

        document = SBOMDocument(
            name=binary_name,
            components=components
        )

        document.relationships = self._build_relationships(components)

        logger.info(f"SBOM document built, {len(components)} components")
        return document

    def _build_relationships(self,
        components: List[SBOMComponent]
    ) -> List[Dict[str, Any]]:
        relationships = []

        if len(components) < 2:
            return relationships

        main_component = components[0]

        for i, comp in enumerate(components[1:], 1):
            relationships.append({
                'type': 'DEPENDS_ON',
                'source': main_component.name,
                'target': comp.name,
                'relationship': f"{main_component.name} depends on {comp.name}"
            })

        return relationships

    def export_spdx_json(self,
        document: SBOMDocument,
        output_path: str = None
    ) -> str:
        spdx_doc = {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': 'SPDXRef-DOCUMENT',
            'name': document.name,
            'documentNamespace': f"https://binmind-analyzer.org/spdx/{uuid.uuid4()}",
            'creationInfo': {
                'created': document.created_at,
                'creators': [
                    f"Tool: {document.tool} - {document.tool_version}",
                    f"Person: {document.author}"
                ],
                'licenseListVersion': '3.22'
            },
            'packages': [],
            'relationships': [],
            'externalDocumentRefs': [],
            'hasExtractedLicensingInfos': []
        }

        for comp in document.components:
            package = {
                'SPDXID': self._generate_spdx_id(comp.name),
                'name': comp.name,
                'versionInfo': comp.version,
                'downloadLocation': 'NOASSERTION',
                'filesAnalyzed': False,
                'licenseConcluded': comp.license,
                'licenseDeclared': comp.license,
                'copyrightText': 'NOASSERTION',
                'supplier': {
                    'name': comp.supplier,
                    'type': 'Organization' if comp.supplier else 'NOASSERTION'
                }
            }

            if comp.sha256:
                package['checksums'] = []
                if comp.sha256:
                    package['checksums'].append({
                        'algorithm': 'SHA256',
                        'checksumValue': comp.sha256
                    })
                if comp.sha1:
                    package['checksums'].append({
                        'algorithm': 'SHA1',
                        'checksumValue': comp.sha1
                    })
                if comp.md5:
                    package['checksums'].append({
                        'algorithm': 'MD5',
                        'checksumValue': comp.md5
                    })

            if comp.purl:
                package['externalRefs'] = [
                    {
                        'referenceCategory': 'PACKAGE-MANAGER',
                        'referenceType': 'purl',
                        'referenceLocator': comp.purl
                    }
                ]

            if comp.description:
                package['description'] = comp.description

            spdx_doc['packages'].append(package)

        for rel in document.relationships:
            spdx_rel = {
                'spdxElementId': self._generate_spdx_id(rel['source']),
                'relationshipType': rel['type'],
                'relatedSpdxElement': self._generate_spdx_id(rel['target']),
                'comment': rel.get('relationship', '')
            }
            spdx_doc['relationships'].append(spdx_rel)

        for comp in document.components:
            for vuln in comp.vulnerabilities:
                if vuln.get('cve_id'):
                    spdx_doc['externalDocumentRefs'].append({
                        'externalDocumentId': f"SPDXRef-{vuln['cve_id']}",
                        'spdxDocument': f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}",
                        'checksum': {
                            'algorithm': 'SHA256',
                            'checksumValue': 'NOASSERTION'
                        }
                    })

        json_str = json.dumps(spdx_doc, ensure_ascii=False, indent=2)

        if output_path:
            try:
                os.makedirs(os.path.dirname(output_path) or self.output_dir, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                logger.info(f"SPDX JSON exported: {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"export SPDX JSON failed: {e}")

        return json_str

    def export_cyclonedx_json(self,
        document: SBOMDocument,
        output_path: str = None
    ) -> str:
        cyclonedx_doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': {
                'timestamp': document.created_at,
                'tool': {
                    'vendor': 'BinMind Analyzer',
                    'name': document.tool,
                    'version': document.tool_version,
                    'externalReferences': [
                        {
                            'type': 'website',
                            'url': 'https://github.com/binmind-analyzer'
                        }
                    ]
                },
                'component': {
                    'type': 'application',
                    'bom-ref': self._generate_cyclonedx_bom_ref(document.name),
                    'name': document.name,
                    'version': document.version,
                    'author': document.author,
                    'description': f"SBOM for {document.name}"
                },
                'authors': [
                    {
                        'name': document.author
                    }
                ]
            },
            'components': [],
            'dependencies': [],
            'vulnerabilities': []
        }

        bom_refs = {}
        for comp in document.components:
            bom_ref = self._generate_cyclonedx_bom_ref(comp.name, comp.version)
            bom_refs[comp.name] = bom_ref

            component = {
                'bom-ref': bom_ref,
                'type': 'library',
                'name': comp.name,
                'version': comp.version,
                'description': comp.description,
                'supplier': {
                    'name': comp.supplier,
                    'type': 'organization' if comp.supplier else 'unknown'
                },
                'licenses': [
                    {
                        'license': {
                            'id': comp.license if comp.license in self.SPDX_LICENSE_MAP.values() else None,
                            'name': comp.license if comp.license not in self.SPDX_LICENSE_MAP.values() else None
                        }
                    }
                ],
                'hashes': [],
                'purl': comp.purl,
                'properties': []
            }

            if comp.sha256:
                component['hashes'].append({'alg': 'SHA-256', 'content': comp.sha256})
            if comp.sha1:
                component['hashes'].append({'alg': 'SHA-1', 'content': comp.sha1})
            if comp.md5:
                component['hashes'].append({'alg': 'MD5', 'content': comp.md5})

            for key, value in comp.properties.items():
                if value:
                    component['properties'].append({
                        'name': f"binmind.{key}",
                        'value': str(value)
                    })

            cyclonedx_doc['components'].append(component)

        if bom_refs:
            main_ref = bom_refs.get(document.components[0].name, '')
            depends_on = [bom_refs.get(comp.name, '') for comp in document.components[1:]]

            cyclonedx_doc['dependencies'] = [
                {
                    'ref': main_ref,
                    'dependsOn': depends_on
                }
            ]

        vuln_id = 1
        for comp in document.components:
            for vuln in comp.vulnerabilities:
                if vuln.get('cve_id'):
                    vulnerability = {
                        'bom-ref': f"vuln-{vuln_id}",
                        'id': vuln['cve_id'],
                        'source': {
                            'name': vuln.get('source', 'NVD'),
                            'url': f"https://nvd.nist.gov/vuln/detail/{vuln['cve_id']}"
                        },
                        'ratings': [
                            {
                                'source': {
                                    'name': vuln.get('source', 'NVD')
                                },
                                'severity': self._normalize_severity(vuln.get('severity', 'unknown')),
                            }
                        ],
                        'description': vuln.get('description', ''),
                        'affects': [
                            {
                                'ref': bom_refs.get(comp.name, '')
                            }
                        ]
                    }
                    cyclonedx_doc['vulnerabilities'].append(vulnerability)
                    vuln_id += 1

        json_str = json.dumps(cyclonedx_doc, ensure_ascii=False, indent=2)

        if output_path:
            try:
                os.makedirs(os.path.dirname(output_path) or self.output_dir, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                logger.info(f"CycloneDX JSON exported: {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"export CycloneDX JSON failed: {e}")

        return json_str

    def export_sbom(self,
        binary_path: str,
        binary_info: Dict[str, Any],
        supply_chain_result: Dict[str, Any] = None,
        vulnerabilities: List[Dict[str, Any]] = None,
        format: str = 'both',
        output_dir: str = None
    ) -> Dict[str, str]:
        output_dir = output_dir or self.output_dir

        document = self.build_sbom_document(
            binary_path=binary_path,
            binary_info=binary_info,
            supply_chain_result=supply_chain_result,
            vulnerabilities=vulnerabilities
        )

        results = {}

        binary_name = os.path.basename(binary_path)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format in ('spdx', 'both'):
            spdx_path = os.path.join(output_dir, f"{binary_name}_spdx_{timestamp}.json")
            spdx_result = self.export_spdx_json(document, spdx_path)
            if spdx_result:
                results['spdx'] = spdx_result

        if format in ('cyclonedx', 'both'):
            cyclonedx_path = os.path.join(output_dir, f"{binary_name}_cyclonedx_{timestamp}.json")
            cyclonedx_result = self.export_cyclonedx_json(document, cyclonedx_path)
            if cyclonedx_result:
                results['cyclonedx'] = cyclonedx_result

        logger.info(f"SBOM export complete, format: {format}")
        return results

    def validate_spdx_json(self, json_str: str) -> Dict[str, Any]:
        result = {
            'valid': False,
            'errors': [],
            'warnings': []
        }

        try:
            data = json.loads(json_str)

            required_fields = ['spdxVersion', 'dataLicense', 'SPDXID', 'name', 'documentNamespace', 'creationInfo']
            for field in required_fields:
                if field not in data:
                    result['errors'].append(f"Missing required field: {field}")

            if data.get('spdxVersion') != 'SPDX-2.3':
                result['warnings'].append(f"SPDX version is not 2.3: {data.get('spdxVersion')}")

            packages = data.get('packages', [])
            if not packages:
                result['warnings'].append("No packages defined")
            else:
                for pkg in packages:
                    pkg_required = ['SPDXID', 'name', 'downloadLocation', 'licenseConcluded']
                    for field in pkg_required:
                        if field not in pkg:
                            result['errors'].append(f"包缺少必需field: {field}")

            result['valid'] = len(result['errors']) == 0

        except json.JSONDecodeError as e:
            result['errors'].append(f"JSON parse error: {e}")

        return result

    def validate_cyclonedx_json(self, json_str: str) -> Dict[str, Any]:
        result = {
            'valid': False,
            'errors': [],
            'warnings': []
        }

        try:
            data = json.loads(json_str)

            required_fields = ['bomFormat', 'specVersion', 'serialNumber', 'version', 'metadata']
            for field in required_fields:
                if field not in data:
                    result['errors'].append(f"Missing required field: {field}")

            if data.get('bomFormat') != 'CycloneDX':
                result['errors'].append(f"Format is not CycloneDX: {data.get('bomFormat')}")

            if data.get('specVersion') != '1.4':
                result['warnings'].append(f"Spec version is not 1.4: {data.get('specVersion')}")

            components = data.get('components', [])
            if not components:
                result['warnings'].append("No components defined")
            else:
                for comp in components:
                    comp_required = ['type', 'name', 'bom-ref']
                    for field in comp_required:
                        if field not in comp:
                            result['errors'].append(f"组件缺少必需field: {field}")

            result['valid'] = len(result['errors']) == 0

        except json.JSONDecodeError as e:
            result['errors'].append(f"JSON parse error: {e}")

        return result

    def get_sbom_summary(self,
        document: SBOMDocument
    ) -> Dict[str, Any]:
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

        for comp in document.components:
            for vuln in comp.vulnerabilities:
                total_vulns += 1
                severity = self._normalize_severity(vuln.get('severity', 'unknown'))

                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            'document_name': document.name,
            'created_at': document.created_at,
            'tool': document.tool,
            'tool_version': document.tool_version,
            'total_components': len(document.components),
            'total_relationships': len(document.relationships),
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_counts,
            'components': [comp.name for comp in document.components],
            'licenses': [comp.license for comp in document.components]
        }


def export_sbom_from_analysis(binary_path: str, binary_info: Dict[str, Any], supply_chain_result: Dict[str, Any] = None, vulnerabilities: List[Dict[str, Any]] = None, format: str = 'both', output_dir: str = None) -> Dict[str, str]:
    exporter = SBOMExporter(output_dir=output_dir)
    return exporter.export_sbom(
        binary_path=binary_path,
        binary_info=binary_info,
        supply_chain_result=supply_chain_result,
        vulnerabilities=vulnerabilities,
        format=format
    )
