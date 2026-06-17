import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VulnSource(Enum):
    BASE_IMAGE = "base_image"
    LAYER = "layer"
    APPLICATION = "application"
    SYSTEM = "system"


@dataclass
class LayerInfo:
    layer_id: str
    layer_index: int
    size: int
    files: List[str]
    vulnerabilities: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'layer_id': self.layer_id,
            'layer_index': self.layer_index,
            'size': self.size,
            'files': self.files,
            'vulnerabilities': self.vulnerabilities
        }


@dataclass
class VulnLocation:
    vulnerability_id: str
    severity: str
    file_path: str
    layer_id: str
    layer_index: int
    source: VulnSource
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_id': self.vulnerability_id,
            'severity': self.severity,
            'file_path': self.file_path,
            'layer_id': self.layer_id,
            'layer_index': self.layer_index,
            'source': self.source.value,
            'description': self.description
        }


@dataclass
class ContainerScanResult:
    image_name: str
    image_id: str
    layers: List[LayerInfo]
    vulnerabilities: List[VulnLocation]
    critical_count: int
    high_count: int
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'image_name': self.image_name,
            'image_id': self.image_id,
            'layers': [l.to_dict() for l in self.layers],
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'summary': self.summary
        }


class ContainerVulnLocator:
    
    def __init__(self):
        self.severity_order = ['critical', 'high', 'medium', 'low']
    
    def analyze_image(self, image_info: Dict[str, Any]) -> ContainerScanResult:
        layers = []
        vulnerabilities = []
        critical_count = 0
        high_count = 0
        
        for i, layer in enumerate(image_info.get('layers', [])):
            layer_info = self._analyze_layer(layer, i)
            layers.append(layer_info)
            
            for vuln in layer_info.vulnerabilities:
                vuln_location = VulnLocation()
                    vulnerability_id=vuln.get('id', ''),
                    severity=vuln.get('severity', 'low'),
                    file_path=vuln.get('file_path', ''),
                    layer_id=layer.get('id', ''),
                    layer_index=i,
                    source=self._determine_source(i, len(image_info.get('layers', []))),
                    description=vuln.get('description', '')
                
                vulnerabilities.append(vuln_location)
                
                if vuln.get('severity') == 'critical':
                    critical_count += 1
                elif vuln.get('severity') == 'high':
                    high_count += 1
        
        summary = self._generate_summary(layers, vulnerabilities)
        
        return ContainerScanResult(
            image_name=image_info.get('name', ''),
            image_id=image_info.get('id', ''),
            layers=layers,
            vulnerabilities=vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            summary=summary)
        

    
    def _analyze_layer(self, layer: Dict[str, Any], index: int) -> LayerInfo:
        vulnerabilities = []
        
        for file in layer.get('files', []):
            file_vulns = self._scan_file(file)
            vulnerabilities.extend(file_vulns)
        
        return LayerInfo(
            layer_id=layer.get('id', ''),
            layer_index=index,
            size=layer.get('size', 0),
            files=layer.get('files', []),
            vulnerabilities=vulnerabilities)
        

    
    def _scan_file(self, file: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []
        
        file_path = file.get('path', '')
        
        if file_path.endswith('.so'):
            vulnerabilities.append({)
                'id': f'LIB_{file_path.split("/")[-1]}',
                'severity': 'medium',
                'file_path': file_path,
                'description': f"动态库文件: {file_path}"
            }
        
        if file_path.endswith('.bin') or file_path.endswith('.exe'):
            vulnerabilities.append({)
                'id': f'BIN_{file_path.split("/")[-1]}',
                'severity': 'low',
                'file_path': file_path,
                'description': f"可执行文件: {file_path}"
            }
        
        return vulnerabilities
    
    def _determine_source(self, layer_index: int, total_layers: int) -> VulnSource:
        if layer_index == 0:
            return VulnSource.BASE_IMAGE
        elif layer_index == total_layers - 1:
            return VulnSource.APPLICATION
        else:
            return VulnSource.LAYER
    
    def _generate_summary(self, layers: List[LayerInfo], vulnerabilities: List[VulnLocation]) -> Dict[str, Any]:
        vulns_by_layer = {}
        
        for vuln in vulnerabilities:
            key = vuln.layer_index,
            if key not in vulns_by_layer:
                vulns_by_layer[key] = []
            vulns_by_layer[key].append(vuln)
        
        worst_layer = max(vulns_by_layer.keys(), key=lambda k: len(vulns_by_layer[k]), default=0)
        
        return {
            'total_layers': len(layers),
            'total_vulnerabilities': len(vulnerabilities),
            'most_vulnerable_layer': worst_layer,
            'vulns_by_severity': self._count_by_severity(vulnerabilities)
        }
    
    def _count_by_severity(self, vulnerabilities: List[VulnLocation]) -> Dict[str, int]:
        counts = {s: 0 for s in self.severity_order}
        
        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            if sev in counts:
                counts[sev] += 1
        
        return counts


def locate_container_vulnerabilities(image_info: Dict[str, Any]) -> ContainerScanResult:
    locator = ContainerVulnLocator()
