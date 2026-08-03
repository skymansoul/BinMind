# SBOM导出器——SPDX 2.3 + CycloneDX 1.4双格式导出

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json as _json
import os
import uuid
from datetime import datetime

json = _json

# FIXME: SPDX license list incomplete — only 25 common licenses mapped
# 边界条件: unrecognized licenses default to NOASSERTION
_SPDX_LICENSE_MAP = {
    "mit": "MIT", "apache-2.0": "Apache-2.0", "apache2": "Apache-2.0",
    "gpl-2.0": "GPL-2.0-only", "gpl-3.0": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only", "bsd-2": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause", "mpl-2.0": "MPL-2.0",
    "isc": "ISC", "unlicense": "Unlicense",
    "cc0-1.0": "CC0-1.0", "bsl-1.0": "BSL-1.0",
    "agpl-3.0": "AGPL-3.0-only", "epl-2.0": "EPL-2.0",
    "zlib": "Zlib", "postgresql": "PostgreSQL",
    "0bsd": "0BSD", "wtfpl": "WTFPL",
    "artistic-2.0": "Artistic-2.0", "eupl-1.2": "EUPL-1.2",
    "cc-by-4.0": "CC-BY-4.0", "ofl-1.1": "OFL-1.1",
}


def _resolve_license(lic: str) -> str:
    key = lic.strip().lower()
    return _SPDX_LICENSE_MAP.get(key, "NOASSERTION")


@dataclass
class SBOMComponent:
    name: str
    version: str = ""
    supplier: str = ""
    licenses: List[str] = field(default_factory=list)
    purl: str = ""
    cpe: str = ""
    checksums: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


class SBOMExporter:
    """SBOM构造器——SPDX 2.3 + CycloneDX 1.4。

    支持组件增量添加，按需输出两种格式JSON。
    """

    def __init__(self):
        self._components: List[SBOMComponent] = []
        self._doc_name: str = "BinMind-SBOM"

    def add_component(self, name: str = "", version: str = "",
                      supplier: str = "", license: str = "",
                      purl: str = "", cpe: str = "",
                      checksums: Dict = None) -> None:
        self._components.append(SBOMComponent(
            name=name, version=version, supplier=supplier,
            licenses=[license] if license else [],
            purl=purl, cpe=cpe,
            checksums=checksums or {},
        ))

    def to_spdx(self, version: str = "2.3") -> Dict:
        now = datetime.now().isoformat()
        return {
            "spdxVersion": f"SPDX-{version}",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": f"https://binmind.dev/spdx/{uuid.uuid4()}",
            "name": self._doc_name,
            "creationInfo": {
                "created": now,
                "creators": ["Tool: BinMind-SBOM-Exporter"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-{i}",
                    "name": c.name,
                    "versionInfo": c.version,
                    "supplier": f"Organization: {c.supplier}" if c.supplier else "NOASSERTION",
                    "licenseConcluded": _resolve_license(c.licenses[0]) if c.licenses else "NOASSERTION",
                    "licenseDeclared": _resolve_license(c.licenses[0]) if c.licenses else "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY",
                         "referenceType": "cpe23Type",
                         "referenceLocator": c.cpe}
                    ] if c.cpe else [],
                }
                for i, c in enumerate(self._components)
            ],
        }

    def to_cyclonedx(self, version: str = "1.4") -> Dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"vendor": "BinMind", "name": "SBOM-Exporter"}],
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": f"pkg:{c.purl}" if c.purl else str(i),
                    "name": c.name,
                    "version": c.version,
                    "publisher": c.supplier,
                    "licenses": [{"license": {"id": _resolve_license(lic)}}
                                 for lic in c.licenses] if c.licenses else [],
                    "purl": c.purl,
                    "cpe": c.cpe,
                }
                for i, c in enumerate(self._components)
            ],
        }

    def write(self, path: str, format: str = "spdx",
              version: str = "") -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if format == "spdx":
            data = self.to_spdx(version or "2.3")
        elif format == "cyclonedx":
            data = self.to_cyclonedx(version or "1.4")
        else:
            raise ValueError(f"unknown format: {format}")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return os.path.abspath(path)

    @property
    def component_count(self) -> int:
        return len(self._components)


def export_spdx(components: List[Dict], output_path: str,
                version: str = "2.3") -> str:
    exporter = SBOMExporter()
    for c in components:
        exporter.add_component(**c)
    return exporter.write(output_path, format="spdx", version=version)


def export_cyclonedx(components: List[Dict], output_path: str,
                     version: str = "1.4") -> str:
    exporter = SBOMExporter()
    for c in components:
        exporter.add_component(**c)
    return exporter.write(output_path, format="cyclonedx", version=version)
