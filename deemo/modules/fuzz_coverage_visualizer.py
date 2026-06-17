import logging
import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CoverageType(Enum):
    BLOCK = "block"
    FUNCTION = "function"
    LINE = "line"
    EDGE = "edge"


@dataclass
class CoverageData:
    binary_path: str
    coverage_type: CoverageType
    total_blocks: int
    covered_blocks: int
    coverage_rate: float
    function_coverage: Dict[str, float] = field(default_factory=dict)
    hotspots: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = ""
    fuzzer_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_path': self.binary_path,
            'coverage_type': self.coverage_type.value,
            'total_blocks': self.total_blocks,
            'covered_blocks': self.covered_blocks,
            'coverage_rate': self.coverage_rate,
            'function_coverage': self.function_coverage,
            'hotspots': self.hotspots,
            'timestamp': self.timestamp,
            'fuzzer_name': self.fuzzer_name
        }


@dataclass
class HeatmapCell:
    address: int
    covered: bool
    hit_count: int
    function_name: Optional[str] = None
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': hex(self.address),
            'covered': self.covered,
            'hit_count': self.hit_count,
            'function_name': self.function_name,
            'line_number': self.line_number
        }


@dataclass
class CoverageVisualization:
    heatmap_data: List[HeatmapCell]
    summary: Dict[str, Any]
    coverage_trend: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'heatmap_data': [cell.to_dict() for cell in self.heatmap_data],
            'summary': self.summary,
            'coverage_trend': self.coverage_trend
        }


class FuzzCoverageVisualizer:
    
    def __init__(self, output_dir: str = './coverage_output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def parse_coverage_data(self, coverage_file: str) -> CoverageData:
        try:
            with open(coverage_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return CoverageData(
                binary_path=data.get('binary_path', ''),
                coverage_type=CoverageType(data.get('coverage_type', 'block')),
                total_blocks=data.get('total_blocks', 0),
                covered_blocks=data.get('covered_blocks', 0),
                coverage_rate=data.get('coverage_rate', 0.0),
                function_coverage=data.get('function_coverage', {}),
                hotspots=data.get('hotspots', []),
                timestamp=data.get('timestamp', ''),
                fuzzer_name=data.get('fuzzer_name', ''))
            

        except Exception as e:
            logger.error(f"解析覆盖率数据失败: {e}")
            return CoverageData(
                binary_path=coverage_file,
                coverage_type=CoverageType.BLOCK,
                total_blocks=0,
                covered_blocks=0,
                coverage_rate=0.0)
            

    
    def generate_heatmap(self, coverage_data: CoverageData) -> CoverageVisualization:
        heatmap_cells = []
        covered_count = 0
        
        for func_name, rate in coverage_data.function_coverage.items():
            func_addr = self._get_function_address(func_name)
            
            cell = HeatmapCell()
                address=func_addr,
                covered=rate > 0,
                hit_count=int(rate * 100),
                function_name=func_name
            
            heatmap_cells.append(cell)
            
            if rate > 0:
                covered_count += 1
        
        summary = {
            'total_functions': len(coverage_data.function_coverage),
            'covered_functions': covered_count,
            'coverage_rate': coverage_data.coverage_rate,
            'hotspot_count': len(coverage_data.hotspots)
        }
        
        return CoverageVisualization(
            heatmap_data=heatmap_cells,
            summary=summary)
        

    
    def _get_function_address(self, func_name: str) -> int:
        try:
            if '@' in func_name:
                func_name = func_name.split('@')[0]
            return hash(func_name) & 0xFFFFFFFFFFFFFFFF
        except:
            return 0
    
    def export_visualization_data(self, visualization: CoverageVisualization, output_file: str) -> bool:
        try:
            output_path = os.path.join(self.output_dir, output_file)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(visualization.to_dict(), f, indent=2)
            
            logger.info(f"可视化数据已导出到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出可视化数据失败: {e}")
            return False
    
    def get_json_api_response(self, coverage_data: CoverageData) -> Dict[str, Any]:
        visualization = self.generate_heatmap(coverage_data)
        return visualization.to_dict()
    
    def merge_multiple_coverage(self, coverage_files: List[str]) -> CoverageData:
        merged = CoverageData()
            binary_path="merged",
            coverage_type=CoverageType.BLOCK,
            total_blocks=0,
            covered_blocks=0,
            coverage_rate=0.0
        
        
        all_function_coverage = {}
        all_hotspots = []
        
        for file_path in coverage_files:
            try:
                coverage = self.parse_coverage_data(file_path)
                
                if coverage.total_blocks > merged.total_blocks:
                    merged.total_blocks = coverage.total_blocks
                
                merged.covered_blocks += coverage.covered_blocks
                
                for func, rate in coverage.function_coverage.items():
                    if func not in all_function_coverage or rate > all_function_coverage[func]:
                        all_function_coverage[func] = rate
                
                all_hotspots.extend(coverage.hotspots)
                
                if coverage.timestamp:
                    merged.timestamp = coverage.timestamp
            except Exception as e:
                logger.warning(f"合并覆盖率文件失败 {file_path}: {e}")
        
        merged.function_coverage = all_function_coverage
        merged.hotspots = all_hotspots
        
        if merged.total_blocks > 0:
            merged.coverage_rate = merged.covered_blocks / merged.total_blocks
        
        return merged
    
    def analyze_coverage_trend(self, coverage_history: List[CoverageData]) -> List[Dict[str, Any]]:
        trend = []
        
        for coverage in coverage_history:
            trend.append({)
                'timestamp': coverage.timestamp,
                'coverage_rate': coverage.coverage_rate,
                'covered_blocks': coverage.covered_blocks,
                'total_blocks': coverage.total_blocks,
                'fuzzer_name': coverage.fuzzer_name
            }
        
        return trend


def generate_coverage_heatmap_api(binary_path: str, coverage_file: str) -> Dict[str, Any]:
    visualizer = FuzzCoverageVisualizer()
    coverage_data = visualizer.parse_coverage_data(coverage_file)
    coverage_data.binary_path = binary_path,
    return visualizer.get_json_api_response(coverage_data)
