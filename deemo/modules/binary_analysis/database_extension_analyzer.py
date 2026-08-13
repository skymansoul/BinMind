#!/usr/bin/env python3
import logging
import os
import re
import subprocess
import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SQLInjectionPoint:
    function_name: str
    sql_input_pos: int
    is_vulnerable: bool
    sink_function: str = ""
    severity: str = "LOW"


@dataclass
class DBResult:
    success: bool
    injection_points: List[SQLInjectionPoint]
    total_taint_sources: int = 0
    total_sinks: int = 0
    extensions_scanned: List[str] = field(default_factory=list)


class DatabaseExtensionAnalyzer:
    """Database extension binary vulnerability analyzer."""

    PG_TAINT_SOURCES = [
        "SPI_getvalue", "SPI_getbinval", "SPI_getarg", "SPI_gettypeid",
        "PG_GETARG", "PG_GETARG_TEXT_P", "PG_GETARG_CSTRING",
        "PG_GETARG_INT32", "PG_GETARG_INT64", "PG_FUNCTION_ARGS",
        "SRF_RETURN_NEXT", "SRF_PERCALL_SETUP", "plpgsql_",
        "palloc", "pstrdup", "text_to_cstring", "DatumGet",
    ]

    MYSQL_TAINT_SOURCES = [
        "mysql_get_string", "mysql_get_int", "mysql_get_double",
        "udf_init", "udf_args", "UDF_ARGS", "args->",
    ]

    DANGEROUS_SINKS = [
        "sprintf", "vsprintf", "strcpy", "strcat", "gets",
        "memcpy", "memmove", "snprintf", "fprintf", "printf",
        "system", "popen", "exec", "dlopen",
    ]

    DB_EXTENSION_APIS = [
        "Pg_magic_func", "PG_MODULE_MAGIC", "Pg_Function_Info",
        "PG_FUNCTION_INFO_V1", "Datum", "fmgr_info",
        "mysql_udf_init", "udf_init", "my_bool",
        "RegisterXllFunction", "FunctionCall",
    ]

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self._disasm: str = ""
        self._func_list: List[Dict] = []
        self._strings: List[str] = []
        self._imports: List[str] = []

    def _load_analysis_data(self):
        """Load disassembly, imports, and strings."""
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            self._disasm = r.stdout

            r2 = subprocess.run(
                ['r2', '-q', '-c', 'aflj; q', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            self._func_list = json.loads(r2.stdout) if r2.stdout.strip() else []

            r3 = subprocess.run(
                ['r2', '-q', '-c', 'iij; q', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            imports = json.loads(r3.stdout) if r3.stdout.strip() else []
            self._imports = [i.get('name', '') for i in imports]

            r4 = subprocess.run(
                ['r2', '-q', '-c', 'izz; q', self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            for line in r4.stdout.split('\n'):
                if 'string=' in line:
                    s = line.split('string=')[1].strip().strip('"')
                    self._strings.append(s)

        except Exception as e:
            logger.warning("Failed to load analysis data: %s", e)

    def _is_db_extension(self) -> bool:
        if not self._imports and not self._disasm:
            self._load_analysis_data()

        indicators = (
            self.DB_EXTENSION_APIS +
            self.PG_TAINT_SOURCES[:5] +
            self.MYSQL_TAINT_SOURCES[:3]
        )
        return any(
            api.lower() in self._disasm.lower()
            for api in indicators
        )

    def _find_taint_sources(self) -> Dict[str, List[Tuple[int, str]]]:
        sources: Dict[str, List[Tuple[int, str]]] = {}
        all_sources = self.PG_TAINT_SOURCES + self.MYSQL_TAINT_SOURCES

        for src in all_sources:
            matches = list(re.finditer(
                re.escape(src), self._disasm, re.IGNORECASE
            ))
            for m in matches:
                func_name = src
                if src not in sources:
                    sources[func_name] = []
                sources[func_name].append((m.start(), m.group(0)))

        return sources

    def _find_dangerous_sinks(self) -> Dict[str, List[int]]:
        """Discover all dangerous sinks."""
        sinks: Dict[str, List[int]] = {}
        for sink in self.DANGEROUS_SINKS:
            matches = list(re.finditer(
                r'\b' + re.escape(sink) + r'\b', self._disasm, re.IGNORECASE
            ))
            if matches:
                sinks[sink] = [m.start() for m in matches]
        return sinks

    def _is_sql_input_reaching_sink(self, source_pos: int,
                                      sink_pos: int) -> bool:
        distance = abs(sink_pos - source_pos)
        if distance > 50000:
            return False
        context = self._disasm[
            min(source_pos, sink_pos):max(source_pos, sink_pos)
        ]
        return_count = len(re.findall(r'\bret\b', context, re.IGNORECASE))
        return return_count <= 5

    def trace_sql_inputs(self) -> List[SQLInjectionPoint]:
        points = []
        if not self._disasm:
            self._load_analysis_data()
        if not self._disasm:
            return points

        sources = self._find_taint_sources()
        sinks = self._find_dangerous_sinks()

        if not sources:
            logger.info("No database extension taint sources found (may not be a DB extension)")
            return points

        for src_name, src_positions in sources.items():
            for src_pos, src_text in src_positions:
                for sink_name, sink_positions in sinks.items():
                    for sink_pos in sink_positions:
                        if self._is_sql_input_reaching_sink(src_pos, sink_pos):
                            points.append(SQLInjectionPoint(
                                function_name=src_name,
                                sql_input_pos=src_pos,
                                is_vulnerable=True,
                                sink_function=sink_name,
                                severity=(
                                    "CRITICAL" if sink_name in [
                                        "system", "popen", "exec", "dlopen"
                                    ] else "HIGH"
                                ),
                            ))

        dangerous_imports = [
            imp for imp in self._imports
            if any(sink in imp.lower() for sink in self.DANGEROUS_SINKS)
        ]
        for imp in dangerous_imports:
            if sources and not any(
                    p.sink_function == imp for p in points
            ):
                points.append(SQLInjectionPoint(
                    function_name="import",
                    sql_input_pos=0,
                    is_vulnerable=True,
                    sink_function=imp,
                    severity="MEDIUM",
                ))

        return points

    def run(self) -> DBResult:
        logger.info("Analyzing database extension: %s", self.binary_path)
        self._load_analysis_data()

        if not self._is_db_extension():
            logger.info("Target is not a database extension module, continuing analysis anyway")
            self._imports = self._imports or []
            return DBResult(
                success=True,
                injection_points=[],
                extensions_scanned=[
                    os.path.basename(self.binary_path)
                ],
            )

        points = self.trace_sql_inputs()
        sources = self._find_taint_sources()
        sinks = self._find_dangerous_sinks()

        critical_count = sum(1 for p in points if p.severity == "CRITICAL")
        logger.info(
            "DB extension analysis complete: %d taint sources, "
            "%d dangerous sinks, %d vuln paths, "
            "%d critical",
            len(sources), len(sinks), len(points), critical_count
        )
        return DBResult(
            success=True,
            injection_points=points,
            total_taint_sources=len(sources),
            total_sinks=len(sinks),
            extensions_scanned=[os.path.basename(self.binary_path)],
        )


def create_database_extension_analyzer(binary_path: str) -> DatabaseExtensionAnalyzer:
    return DatabaseExtensionAnalyzer(binary_path)
