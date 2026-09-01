from dataclasses import dataclass
import logging
import os
import re
import json
import time
import hashlib
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

class SourceLanguage:
    # 源码语言
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    MIXED = "mixed"


class FindingKind:
    # 发现种类
    DANGEROUS_API = "dangerous_api"
    UNCHECKED_RETURN = "unchecked_return"
    FORMAT_STRING = "format_string"
    BUFFER_OVERFLOW_RISK = "buffer_overflow_risk"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    MEMORY_LEAK = "memory_leak"
    RACE_CONDITION = "race_condition"
    CUSTOM = "custom"


class CompileStatus:
    """compilestatus"""
    _val = None

    def __init__(self, value):
        self._val = value

    @property
    def valueBh(self):
        return self._val

    def __str__(self):
        return self._val

CompileStatus.SUCCESS = CompileStatus("success")
CompileStatus.FAILED = CompileStatus("failed")
CompileStatus.TIMEOUT = CompileStatus("timeout")
CompileStatus.SKIPPED = CompileStatus("skipped")
CompileStatus.NOT_ATTEMPTED = CompileStatus("not_attempted")

class SourceFinding:
    __slots__ = ('kind', 'file_path', 'line', 'column', 'function', 'code_snippet', 'message', 'cwe', 'severity', 'confirmed_in_binary', 'binary_addr',)

    def __init__(self, kind, file_path, line, column=0, function="", code_snippet="", message="", cwe="", severity="medium", confirmed_in_binary=False, binary_addr=0):
        self.kind = kind
        self.file_path = file_path
        self.line = line
        self.column = column
        self.function = function
        self.code_snippet = code_snippet
        self.message = message
        self.cwe = cwe
        self.severity = severity
        self.confirmed_in_binary = confirmed_in_binary
        self.binary_addr = binary_addr


class CompileResult:
    __slots__ = ('status', 'binary_path', 'stdout', 'stderr', 'exit_code', 'elapsed', 'error',)

    def __init__(self, status, binary_path="", stdout="", stderr="", exit_code=0, elapsed=0.0, error=""):
        self.status = status
        self.binary_path = binary_path
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed = elapsed
        self.error = error


class SourceBinaryMapping:
    __slots__ = ('file_path', 'line', 'function', 'binary_addr', 'binary_size', 'binary_name',)

    def __init__(self, file_path, line, function, binary_addr, binary_size, binary_name=""):
        self.file_path = file_path
        self.line = line
        self.function = function
        self.binary_addr = binary_addr
        self.binary_size = binary_size
        self.binary_name = binary_name


class HybridAnalysisResult:
    __slots__ = ('source_path', 'language', 'source_findings', 'compile_result', 'mappings', 'confirmed_findings', 'timestamp', 'notes',)

    def __init__(self, source_path, language, source_findings=None, compile_result=None, mappings=None, confirmed_findings=None, timestamp=0.0, notes=""):
        self.source_path = source_path
        self.language = language
        self.source_findings = source_findings if source_findings is not None else []
        self.compile_result = compile_result
        self.mappings = mappings if mappings is not None else []
        self.confirmed_findings = confirmed_findings if confirmed_findings is not None else []
        self.timestamp = timestamp
        self.notes = notes

class SourceScanner:

    DANGEROUS_APIS = {
        "strcpy": FindingKind.BUFFER_OVERFLOW_RISK,
        "strcat": FindingKind.BUFFER_OVERFLOW_RISK,
        "sprintf": FindingKind.FORMAT_STRING,
        "gets": FindingKind.BUFFER_OVERFLOW_RISK,
        "scanf": FindingKind.BUFFER_OVERFLOW_RISK,
        "memcpy": FindingKind.BUFFER_OVERFLOW_RISK,
        "memmove": FindingKind.BUFFER_OVERFLOW_RISK,
        "system": FindingKind.COMMAND_INJECTION,
        "execve": FindingKind.COMMAND_INJECTION,
        "popen": FindingKind.COMMAND_INJECTION,
        "fopen": FindingKind.PATH_TRAVERSAL,
        "sscanf": FindingKind.FORMAT_STRING,
        "snprintf": FindingKind.FORMAT_STRING,
        "vsprintf": FindingKind.FORMAT_STRING,
        "alloca": FindingKind.BUFFER_OVERFLOW_RISK,
        "realloc": FindingKind.USE_AFTER_FREE,
        "free": FindingKind.USE_AFTER_FREE,
    }

    CWE_MAPPING = {
        FindingKind.BUFFER_OVERFLOW_RISK: "CWE-120",
        FindingKind.FORMAT_STRING: "CWE-134",
        FindingKind.COMMAND_INJECTION: "CWE-78",
        FindingKind.PATH_TRAVERSAL: "CWE-22",
        FindingKind.USE_AFTER_FREE: "CWE-416",
        FindingKind.INTEGER_OVERFLOW: "CWE-190",
        FindingKind.MEMORY_LEAK: "CWE-401",
        FindingKind.RACE_CONDITION: "CWE-362",
        FindingKind.UNCHECKED_RETURN: "CWE-252",
    }

    SEVERITY = {
        FindingKind.BUFFER_OVERFLOW_RISK: "high",
        FindingKind.FORMAT_STRING: "high",
        FindingKind.COMMAND_INJECTION: "critical",
        FindingKind.PATH_TRAVERSAL: "high",
        FindingKind.USE_AFTER_FREE: "high",
        FindingKind.INTEGER_OVERFLOW: "medium",
        FindingKind.MEMORY_LEAK: "low",
        FindingKind.RACE_CONDITION: "medium",
        FindingKind.UNCHECKED_RETURN: "medium",
    }

    def __init__(self, language=None):
        if language is None:
            language = SourceLanguage.C
        self.m_language = language
        self.m_lock = threading.Lock()

    def scan_fileBh(self, file_path):
        if file_path is None:
            logger.warning("scan_file: file_path is None")
            return []
        szFindings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                szContent = f.read()
        except (OSError, IOError) as e:
            logger.warning(f"无法读取 {file_path}: {e}")
            return szFindings
        return self.scan_textBh(szContent, file_path)

    def scan_textBh(self, content, file_path="<memory>"):
        if content is None:
            logger.warning("scan_text: content is None")
            return []
        szFindings = []
        with self.m_lock:
            szCurrentFunc = ""
            vLines = content.split("\n")
            nLineNo = 1
            nTotal = len(vLines)
            while nLineNo <= nTotal:
                szLine = vLines[nLineNo - 1]
                # 跟踪当前函数
                m = re.match(r"\s*(?:[\w\*\s]+)\s+(\w+)\s*\([^)]*\)\s*\{?", szLine)
                if m:
                    szCurrentFunc = m.group(1)

                # 检测危险 API
                oApiKeys = list(self.DANGEROUS_APIS.keys())
                iApi = 0
                nApis = len(oApiKeys)
                while iApi < nApis:
                    szApi = oApiKeys[iApi]
                    szKind = self.DANGEROUS_APIS[szApi]
                    szPattern = r"\b" + re.escape(szApi) + r"\s*\("
                    if re.search(szPattern, szLine):
                        oCol = re.search(szPattern, szLine)
                        nCol = oCol.start() if oCol else 0
                        szFindings.append(SourceFinding(
                            kind=szKind,
                            file_path=file_path,
                            line=nLineNo,
                            column=nCol,
                            function=szCurrentFunc,
                            code_snippet=szLine.strip()[:200],
                            message=f"使用了危险 API: {szApi}",
                            cwe=self.CWE_MAPPING.get(szKind, ""),
                            severity=self.SEVERITY.get(szKind, "medium"),))
                    iApi += 1

                # 检测 unchecked return (malloc/alloc)
                oAllocMatch = re.search(r"\b(malloc|calloc|realloc|new)\s*\(", szLine)
                if oAllocMatch:
                    szAssignPart = szLine.split("=")[0] if "=" in szLine else ""
                    if "if" not in szLine and "(" not in szAssignPart:
                        szFindings.append(SourceFinding(
                            kind=FindingKind.UNCHECKED_RETURN,
                            file_path=file_path,
                            line=nLineNo,
                            column=oAllocMatch.start(),
                            function=szCurrentFunc,
                            code_snippet=szLine.strip()[:200],
                            message="alloc返回值未检查",
                            cwe=self.CWE_MAPPING.get(FindingKind.UNCHECKED_RETURN, ""),
                            severity=self.SEVERITY.get(FindingKind.UNCHECKED_RETURN, "medium"),))

                # 检测 SQL 注入
                if re.search(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\+", szLine, re.IGNORECASE):
                    szFindings.append(SourceFinding(
                        kind=FindingKind.SQL_INJECTION,
                        file_path=file_path,
                        line=nLineNo,
                        function=szCurrentFunc,
                        code_snippet=szLine.strip()[:200],
                        message="detected可能的 SQL inject",
                        cwe="CWE-89",
                        severity="critical",))
                nLineNo += 1
        return szFindings

class BuildCoordinator:

    _DEFAULT_TIMEOUT = 60.0

    def __init__(self, compiler="gcc", extra_args=None, timeout=60.0):
        if compiler is None:
            compiler = "gcc"
        self.m_compiler = compiler
        self.m_extra_args = extra_args if extra_args is not None else ["-O0", "-g"]
        self.m_timeout = timeout
        self.m_lock = threading.Lock()

    def compile_cBh(self, source_path, output_path):
        if source_path is None:
            logger.warning("compile_c: source_path is None")
            return CompileResult(status=CompileStatus.FAILED, error="source_path is None")
        if output_path is None:
            logger.warning("compile_c: output_path is None")
            return CompileResult(status=CompileStatus.FAILED, error="output_path is None")
        fStart = time.time()
        with self.m_lock:
            try:
                cmd = [self.m_compiler] + self.m_extra_args + ["-o", output_path, source_path]
                oProc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.m_timeout,)
                fElapsed = time.time() - fStart
                if oProc.returncode == 0 and os.path.exists(output_path):
                    return CompileResult(
                        status=CompileStatus.SUCCESS,
                        binary_path=output_path,
                        stdout=oProc.stdout,
                        stderr=oProc.stderr,
                        exit_code=oProc.returncode,
                        elapsed=fElapsed,)
                return CompileResult(
                    status=CompileStatus.FAILED,
                    stdout=oProc.stdout,
                    stderr=oProc.stderr,
                    exit_code=oProc.returncode,
                    elapsed=fElapsed,
                    error=oProc.stderr[:500] if oProc.stderr else "compilefailed",)
            except subprocess.TimeoutExpired:
                return CompileResult(
                    status=CompileStatus.TIMEOUT,
                    elapsed=time.time() - fStart,
                    error=f"compiletimeout ({self.m_timeout}s)",)
            except (OSError, FileNotFoundError) as e:
                return CompileResult(
                    status=CompileStatus.FAILED,
                    elapsed=time.time() - fStart,
                    error=f"compile器unavailable: {e}",)

    def compile_with_debug_infoBh(
        self,
        source_path,
        output_path
    ):
        """带debuginfocompile"""
        if source_path is None or output_path is None:
            return CompileResult(status=CompileStatus.FAILED, error="null source or output path")
        vOldArgs = list(self.m_extra_args)
        self.m_extra_args = ["-O0", "-g3", "-gdwarf-4"]
        oResult = self.compile_cBh(source_path, output_path)
        self.m_extra_args = vOldArgs
        return oResult

class SourceBinaryMapper:

    def __init__(self):
        self.m_lock = threading.Lock()

    def build_mappingsBh(self, symbols, debug_info=None):
        if symbols is None:
            symbols = []
        vMappings = []
        with self.m_lock:
            iSym = 0
            nSyms = len(symbols)
            while iSym < nSyms:
                oSym = symbols[iSym]
                if oSym.get("type") not in ("FUNC", "func"):
                    iSym += 1
                    continue
                szFilePath = oSym.get("file", "")
                nLine = int(oSym.get("line", 0))
                nAddr = int(oSym.get("addr", 0))
                nSize = int(oSym.get("size", 0))
                if not (szFilePath and nLine and nAddr):
                    iSym += 1
                    continue
                vMappings.append(SourceBinaryMapping(
                    file_path=szFilePath,
                    line=nLine,
                    function=oSym.get("name", ""),
                    binary_addr=nAddr,
                    binary_size=nSize,
                    binary_name=oSym.get("name", ""),))
                iSym += 1

            if debug_info:
                vLineTable = debug_info.get("line_table", [])
                iEntry = 0
                nEntries = len(vLineTable)
                while iEntry < nEntries:
                    oEntry = vLineTable[iEntry]
                    vMappings.append(SourceBinaryMapping(
                        file_path=oEntry.get("file", ""),
                        line=int(oEntry.get("line", 0)),
                        function=oEntry.get("func", ""),
                        binary_addr=int(oEntry.get("addr", 0)),
                        binary_size=0,))
                    iEntry += 1
        return vMappings

    def find_binary_addrBh(self, mappings, file_path, line):
        if mappings is None:
            return None
        if file_path is None:
            return None
        vCandidates = []
        iM = 0
        nMappings = len(mappings)
        while iM < nMappings:
            oM = mappings[iM]
            if oM.file_path == file_path and oM.line <= line < oM.line + 50:
                vCandidates.append(oM)
            iM += 1
        if not vCandidates:
            return None
        vCandidates.sort(key=lambda m: line - m.line)
        return vCandidates[0].binary_addr

class HybridAnalysisPipeline:
    """混合分析管道"""

    def __init__(self, compiler="gcc"):
        if compiler is None:
            compiler = "gcc"
        self.m_scanner = SourceScanner()
        self.m_compiler = compiler
        self.m_builder = BuildCoordinator(compiler=compiler)
        self.m_mapper = SourceBinaryMapper()
        self.m_lock = threading.Lock()

    def analyzeBh(
        self,
        source_path,
        output_binary=None,
        auto_compile=True,
        binary_symbols=None,
        debug_info=None,
        language=None
    ):
        """分析源码 (可compile对比)"""
        if source_path is None:
            logger.error("analyze: source_path is None")
            return HybridAnalysisResult(source_path="", language=SourceLanguage.C, notes="source_path is None")
        if language is None:
            language = SourceLanguage.C
        with self.m_lock:
            oResult = HybridAnalysisResult(
                source_path=source_path,
                language=language,)
            self.m_scanner.m_language = language

            # 源码扫描
            if os.path.isfile(source_path):
                oResult.source_findings = self.m_scanner.scan_fileBh(source_path)
            elif os.path.isdir(source_path):
                for root, _, files in os.walk(source_path):
                    iFile = 0
                    nFiles = len(files)
                    while iFile < nFiles:
                        szFname = files[iFile]
                        if szFname.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
                            fp = os.path.join(root, szFname)
                            oResult.source_findings.extend(self.m_scanner.scan_fileBh(fp))
                        iFile += 1

            # 自动compile
            if auto_compile and os.path.isfile(source_path):
                if not output_binary:
                    szBase = os.path.basename(source_path)
                    szName = os.path.splitext(szBase)[0]
                    output_binary = os.path.join("/tmp", szName + "_hybrid")
                oResult.compile_result = self.m_builder.compile_with_debug_infoBh(source_path, output_binary)

            # 构建映射
            if binary_symbols or debug_info:
                oResult.mappings = self.m_mapper.build_mappingsBh(binary_symbols if binary_symbols is not None else [], debug_info)

            # 交叉validate
            iFinding = 0
            nFindings = len(oResult.source_findings)
            while iFinding < nFindings:
                oFinding = oResult.source_findings[iFinding]
                if not oResult.mappings:
                    iFinding += 1
                    continue
                nAddr = self.m_mapper.find_binary_addrBh(oResult.mappings, oFinding.file_path, oFinding.line)
                if nAddr and nAddr > 0:
                    oFinding.confirmed_in_binary = True
                    oFinding.binary_addr = nAddr
                    oResult.confirmed_findings.append(oFinding)
                iFinding += 1

            oResult.timestamp = time.time()
            oResult.notes = f"源码发现 {len(oResult.source_findings)}, 已确认 {len(oResult.confirmed_findings)}"
            return oResult

    def set_compilerBh(self, compiler):
        if compiler is None:
            return
        self.m_compiler = compiler
        self.m_builder.m_compiler = compiler

def analyze_source(
    source_path,
    compiler="gcc",
    auto_compile=True,
    language="c"
):
    if source_path is None:
        logger.warning("analyze_source: source_path is None")
        return None
    oPipeline = HybridAnalysisPipeline(compiler=compiler)
    try:
        if language in (SourceLanguage.C, SourceLanguage.CPP, SourceLanguage.RUST, SourceLanguage.GO, SourceLanguage.MIXED):
            lang = language
        else:
            lang = SourceLanguage.C
    except:
        lang = SourceLanguage.C
    return oPipeline.analyzeBh(source_path, auto_compile=auto_compile, language=lang)
