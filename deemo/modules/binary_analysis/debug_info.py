import os
import logging
import subprocess
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class DebugInfoType(str, Enum):
    PDB = 'pdb'
    DWARF = 'dwarf'
    STABS = 'stabs'
    UNKNOWN = 'unknown'


class SymbolType(str, Enum):
    FUNCTION = 'function'
    DATA = 'data'
    TYPE = 'type'
    STRUCT = 'struct'
    UNION = 'union'
    ENUM = 'enum'
    CLASS = 'class'
    UNKNOWN = 'unknown'


@dataclass
class DebugSymbol:
    name: str
    address: int
    size: int = 0
    symbol_type: SymbolType = SymbolType.UNKNOWN
    demangled_name: str = ''
    source_file: str = ''
    source_line: int = 0
    type_info: str = ''


@dataclass
class TypeDefinition:
    name: str
    type_kind: str
    fields: List[Dict] = field(default_factory=list)
    size: int = 0
    alignment: int = 4


@dataclass
class DebugInfoResult:
    debug_type: DebugInfoType
    symbols: List[DebugSymbol]
    types: List[TypeDefinition]
    source_files: List[str]
    pdb_path: str = ''
    has_debug_info: bool = False
    enhanced_functions: int = 0
    enhanced_variables: int = 0


class DebugInfoParser:

    def __init__(self, binary_path: str = None):
        self.binary_path = binary_path
        self.symbols: List[DebugSymbol] = []
        self.types: List[TypeDefinition] = []
        self.source_files: List[str] = []
        self.debug_type = DebugInfoType.UNKNOWN

        try:
            from elftools.dwarf import DWARFInfo
            self.pyelftools_available = True
        except ImportError:
            self.pyelftools_available = False
            logger.info("pyelftools not installed, DWARF parsing limited")

    def _detect_binary_type(self) -> str:
        if not self.binary_path or not os.path.exists(self.binary_path):
            return 'unknown'

        with open(self.binary_path, 'rb') as f:
            magic = f.read(4)

        if magic[:2] == b'MZ':
            return 'pe'
        elif magic == b'\x7fELF':
            return 'elf'
        elif magic[:4] == b'\xca\xfe\xba\xbe':
            return 'mach-o'
        return 'unknown'

    def _find_pdb_file(self) -> Optional[str]:
        if not self.binary_path:
            return None

        binary_dir = os.path.dirname(self.binary_path)
        binary_name = os.path.basename(self.binary_path)
        pdb_name = os.path.splitext(binary_name)[0] + '.pdb'
        pdb_path = os.path.join(binary_dir, pdb_name)

        if os.path.exists(pdb_path):
            return pdb_path

        for subdir in ['pdb', 'symbols', 'debug']:
            pdb_path = os.path.join(binary_dir, subdir, pdb_name)
            if os.path.exists(pdb_path):
                return pdb_path

        return None

    def _parse_pdb_with_pdbparse(self, pdb_path: str) -> Tuple[List[DebugSymbol], List[TypeDefinition]]:
        symbols = []
        types = []

        try:
            import pdbparse
            pdb = pdbparse.parse(pdb_path)

            for symbol in pdb.STREAM_SYMBOLS:
                if hasattr(symbol, 'name') and hasattr(symbol, 'offset'):
                    sym = DebugSymbol(
                        name=str(symbol.name),
                        address=symbol.offset,
                        symbol_type=SymbolType.FUNCTION if 'func' in str(symbol.name).lower() else SymbolType.DATA
                    )
                    symbols.append(sym)

            logger.info("Extracted %d symbols from PDB", len(symbols))
        except ImportError:
            logger.warning("pdbparse not installed, cannot parse PDB")
        except Exception as e:
            logger.error("PDB parse failed: %s", e)

        return symbols, types

    def _parse_pdb_fallback(self, pdb_path: str) -> Tuple[List[DebugSymbol], List[TypeDefinition]]:
        symbols = []
        types = []

        try:
            result = subprocess.run(['dumpbin', '/symbols', pdb_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'UNDEF' in line or 'SECT' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                address = int(parts[0], 16)
                                name = ' '.join(parts[3:])
                                symbols.append(DebugSymbol(
                                    name=name,
                                    address=address,
                                    symbol_type=SymbolType.FUNCTION
                                ))
                            except ValueError:
                                pass
        except Exception as e:
            logger.debug("dumpbin unavailable: %s", e)

        return symbols, types

    def _parse_dwarf(self, elf_path: str) -> Tuple[List[DebugSymbol], List[TypeDefinition]]:
        symbols = []
        types = []

        if not self.pyelftools_available:
            return symbols, types

        try:
            from elftools.elf.elffile import ELFFile
            from elftools.dwarf.descriptions import describe_form_class

            with open(elf_path, 'rb') as f:
                elf = ELFFile(f)

                if not elf.has_dwarf_info():
                    return symbols, types

                dwarfinfo = elf.get_dwarf_info()

                for CU in dwarfinfo.iter_CUs():
                    for DIE in CU.iter_DIEs():
                        try:
                            if DIE.tag == 'DW_TAG_subprogram':
                                name = DIE.attributes.get('DW_AT_name')
                                addr = DIE.attributes.get('DW_AT_low_pc')
                                if name and addr:
                                    symbols.append(DebugSymbol(
                                        name=name.value.decode('utf-8'),
                                        address=addr.value,
                                        symbol_type=SymbolType.FUNCTION
                                    ))
                            elif DIE.tag == 'DW_TAG_variable':
                                name = DIE.attributes.get('DW_AT_name')
                                if name:
                                    symbols.append(DebugSymbol(
                                        name=name.value.decode('utf-8'),
                                        address=0,
                                        symbol_type=SymbolType.DATA
                                    ))
                            elif DIE.tag == 'DW_TAG_structure_type':
                                name = DIE.attributes.get('DW_AT_name')
                                if name:
                                    types.append(TypeDefinition(
                                        name=name.value.decode('utf-8'),
                                        type_kind='struct'
                                    ))
                        except Exception as e:
                            continue

                logger.info("Extracted %d symbols from DWARF", len(symbols))

        except Exception as e:
            logger.error("DWARF parse failed: %s", e)

        return symbols, types

    def _download_pdb_from_symbol_server(self) -> Optional[str]:
        logger.info("Attempting to download PDB from symbol server...")
        return None

    def _extract_source_files(self) -> List[str]:
        files = []

        if not self.binary_path:
            return files

        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()

            extensions = [b'.c\x00', b'.cpp\x00', b'.h\x00', b'.hpp\x00']
            for ext in extensions:
                offset = 0
                while True:
                    pos = data.find(ext, offset)
                    if pos == -1:
                        break
                    start = max(0, pos - 200)
                    path_data = data[start:pos + 4]
                    try:
                        path_str = path_data.decode('utf-8').strip()
                        if '\\' in path_str or '/' in path_str:
                            files.append(path_str)
                    except Exception:
                        logger.debug("suppressed", exc_info=True)
                    offset = pos + 4

            files = list(set(files))
        except Exception as e:
            logger.debug("Source file extraction failed: %s", e)

        return files

    def parse(self, pdb_path: str = None) -> DebugInfoResult:
        if not self.binary_path:
            return DebugInfoResult(
                debug_type=DebugInfoType.UNKNOWN,
                symbols=[],
                types=[],
                source_files=[],
                has_debug_info=False
            )

        binary_type = self._detect_binary_type()
        pdb_file = pdb_path or self._find_pdb_file()

        if binary_type == 'pe':
            self.debug_type = DebugInfoType.PDB

            if pdb_file:
                logger.info("Found PDB file: %s", pdb_file)
                symbols, types = self._parse_pdb_with_pdbparse(pdb_file)

                if not symbols:
                    symbols, types = self._parse_pdb_fallback(pdb_file)

                self.symbols = symbols
                self.types = types
            else:
                downloaded_pdb = self._download_pdb_from_symbol_server()
                if downloaded_pdb:
                    symbols, types = self._parse_pdb_with_pdbparse(downloaded_pdb)
                    self.symbols = symbols
                    self.types = types

        elif binary_type == 'elf':
            self.debug_type = DebugInfoType.DWARF
            symbols, types = self._parse_dwarf(self.binary_path)
            self.symbols = symbols
            self.types = types

        self.source_files = self._extract_source_files()

        return DebugInfoResult(
            debug_type=self.debug_type,
            symbols=self.symbols,
            types=self.types,
            source_files=self.source_files,
            pdb_path=pdb_file or '',
            has_debug_info=len(self.symbols) > 0,
            enhanced_functions=len([s for s in self.symbols if s.symbol_type == SymbolType.FUNCTION]),
            enhanced_variables=len([s for s in self.symbols if s.symbol_type == SymbolType.DATA]))

    def get_symbol_by_address(self, address: int) -> Optional[DebugSymbol]:
        for symbol in self.symbols:
            if symbol.address <= address < symbol.address + symbol.size:
                return symbol
        return None

    def get_type_by_name(self, name: str) -> Optional[TypeDefinition]:
        for type_def in self.types:
            if type_def.name == name:
                return type_def
        return None

    def enhance_decompilation(self, decompiled_code: str) -> str:
        if not self.symbols:
            return decompiled_code

        enhanced_code = decompiled_code

        for symbol in self.symbols:
            if symbol.symbol_type == SymbolType.FUNCTION and symbol.name:
                old_pattern = f'sub_{symbol.address:08X}'
                enhanced_code = enhanced_code.replace(old_pattern, symbol.name)

        return enhanced_code

    def generate_header_file(self, output_path: str) -> bool:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('// Type definitions\n')
                f.write('// Recovered from debug information\n\n')

                for type_def in self.types:
                    if type_def.type_kind == 'struct':
                        f.write(f'typedef struct {type_def.name} {{\n')
                        for field in type_def.fields:
                            f.write(f'    {field.get("type", "void*")} {field.get("name", "field")};\n')
                        f.write(f'}} {type_def.name};\n\n')

                f.write('// Symbol declarations\n')
                for symbol in self.symbols:
                    if symbol.symbol_type == SymbolType.FUNCTION:
                        f.write(f'void {symbol.name}(void);\n')

            logger.info("Header file generated: %s", output_path)
            return True
        except Exception as e:
            logger.error("Header generation failed: %s", e)
            return False

    def get_analysis_summary(self) -> Dict[str, Any]:
        result = self.parse()

        return {
            'debug_type': result.debug_type.value,
            'has_debug_info': result.has_debug_info,
            'num_symbols': len(result.symbols),
            'num_types': len(result.types),
            'num_source_files': len(result.source_files),
            'pdb_path': result.pdb_path,
            'enhanced_functions': result.enhanced_functions,
            'enhanced_variables': result.enhanced_variables,
        }
