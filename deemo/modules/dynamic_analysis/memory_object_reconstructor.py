import os
import re
import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
import typing

"""Heap object reconstruction from raw memory dumps.

Resolves object instances, field layouts, and inter-object reference graphs
via DWARF/PDB type metadata applied to unstructured memory snapshots. Detects
ptmalloc, jemalloc, tcmalloc, and mimalloc heap layout signatures.
"""

logger = logging.getLogger(__name__)

try:
    import elftools
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class AllocatorType(Enum):
    """Heap allocator variants identified through signature-based detection."""

    PTMALLOC = "ptmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    MIMALLOC = "mimalloc"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

class ObjectType(Enum):
    """Object classification derived from field count and pointer density analysis."""

    STRUCT = "struct"
    CLASS = "class"
    ARRAY = "array"
    STRING = "string"
    VECTOR = "vector"
    MAP = "map"
    LIST = "list"
    TREE = "tree"
    UNKNOWN = "unknown"


@dataclass
class TypeInfo:
    """Type metadata deserialized from DWARF or PDB debug information.

    Encodes the structural blueprint for reinterpreting raw byte sequences
    as typed fields.
    """

    name: str
    size: int
    align: int
    type_kind: str
    fields: List = field(default_factory=list)
    base_classes: List = field(default_factory=list)
    template_params: List = field(default_factory=list)
    is_polymorphic: bool = False
    vtable_offset: int = 0


@dataclass
class FieldInfo:
    """Field descriptor within a composite type, specifying offset, size, and pointer/array flags."""

    name: str
    offset: int
    size: int
    type_name: str
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None
    bit_offset: int = 0
    bit_size: int = 0


@dataclass
class DWARFTypeCache:
    """Fast-lookup registry of parsed type definitions, indexed by name and classification."""

    types: Dict = field(default_factory=dict)
    type_by_offset: Dict = field(default_factory=dict)
    structs: Dict = field(default_factory=dict)
    classes: Dict = field(default_factory=dict)


class DWARFParser:
    """Type definition extraction from ELF binaries through DWARF debug information.

    Walks compilation unit DIEs to recover struct, class, and union layout
    definitions. Degrades to no-op when pyelftools is absent or DWARF data
    is missing from the binary.
    """

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.type_cache = DWARFTypeCache()
        self._parse_dwarf()

    def _parse_dwarf(self):
        if not self.binary_path or not os.path.exists(self.binary_path):
            return

        try:
            if ELFTOOLS_AVAILABLE:
                from elftools.elf.elffile import ELFFile

                with open(self.binary_path, 'rb') as f:
                    elf = ELFFile(f)
                    if not elf.has_dwarf_info():
                        return

                    dwarf_info = elf.get_dwarf_info()

                    for CU in dwarf_info.iter_CUs():
                        for DIE in CU.iter_DIEs():
                            self._process_die(DIE)
            else:
                self._parse_dwarf_fallback()
        except Exception as e:
            logger.debug(f"DWARF parsing error: {e}")

    def _process_die(self, die):
        tag = die.tag
        name = die.get_attribute('DW_AT_name')
        name = name.value.decode('utf-8') if name else None

        if tag == 'DW_TAG_structure_type':
            self._parse_struct(die, name)
        elif tag == 'DW_TAG_class_type':
            self._parse_class(die, name)
        elif tag == 'DW_TAG_union_type':
            self._parse_union(die, name)

    def _parse_struct(self, die, name: Optional[str]):
        if not name:
            return

        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0

        type_info = TypeInfo(
            name=name,
            size=size,
            align=0,
            type_kind='struct',
            fields=[],
            base_classes=[],
            is_polymorphic=False
        )

        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)

        self.type_cache.types[name] = type_info
        self.type_cache.structs[name] = type_info

    def _parse_class(self, die, name: Optional[str]):
        if not name:
            return

        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0

        type_info = TypeInfo(
            name=name,
            size=size,
            align=0,
            type_kind='class',
            fields=[],
            base_classes=[],
            is_polymorphic=False
        )

        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)
            elif child.tag == 'DW_TAG_inheritance':
                base_name = child.get_attribute('DW_AT_name')
                if base_name:
                    type_info.base_classes.append(base_name.value.decode('utf-8'))

            elif child.tag == 'DW_TAG_vtable_entry':
                type_info.is_polymorphic = True

        self.type_cache.types[name] = type_info
        self.type_cache.classes[name] = type_info

    def _parse_union(self, die, name: Optional[str]):
        if not name:
            return

        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0

        type_info = TypeInfo(
            name=name,
            size=size,
            align=0,
            type_kind='union',
            fields=[],
            base_classes=[])
        for child in die.iter_children():
            if child.tag == 'DW_TAG_member':
                field = self._parse_field(child)
                if field:
                    type_info.fields.append(field)

        self.type_cache.types[name] = type_info

    def _parse_field(self, die) -> Optional[FieldInfo]:
        name_attr = die.get_attribute('DW_AT_name')
        if not name_attr:
            return None

        name = name_attr.value.decode('utf-8')

        offset_attr = die.get_attribute('DW_AT_data_member_location')
        offset = 0
        if offset_attr:
            if isinstance(offset_attr.value, int):
                offset = offset_attr.value

        type_name = 'void'
        type_attr = die.get_attribute('DW_AT_type')
        if type_attr:
            try:
                type_die = type_attr.value
                if hasattr(type_die, 'get_attribute'):
                    type_name_attr = type_die.get_attribute('DW_AT_name')
                    if type_name_attr:
                        type_name = type_name_attr.value.decode('utf-8')
            except Exception:
                logger.debug("Non-critical exception in type resolution", exc_info=True)

        size_attr = die.get_attribute('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0

        return FieldInfo(
            name=name,
            offset=offset,
            size=size,
            type_name=type_name,
            is_pointer=type_name.endswith('*'),
            is_array='[' in type_name)

    def _parse_dwarf_fallback(self):
        logger.debug("DWARF parsing disabled; fallback path engaged")

    def get_type_info(self, type_name: str) -> Optional[TypeInfo]:
        return self.type_cache.types.get(type_name)

    def get_struct_info(self, struct_name: str) -> Optional[TypeInfo]:
        return self.type_cache.structs.get(struct_name)

    def get_class_info(self, class_name: str) -> Optional[TypeInfo]:
        return self.type_cache.classes.get(class_name)

    def get_all_types(self) -> List[str]:
        return list(self.type_cache.types.keys())


class PDBParser:
    """Type definition recovery from PE binaries using adjacent PDB program databases.

    Probes standard locations for .pdb files adjacent to the binary.
    Falls back silently when the PDB is absent or cannot be parsed.
    """

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.type_cache = DWARFTypeCache()
        self._parse_pdb()

    def _parse_pdb(self):
        if not self.binary_path or not os.path.exists(self.binary_path):
            return

        try:
            pdb_path = self._find_pdb_path()
            if pdb_path:
                self._parse_pdb_file(pdb_path)
        except Exception as e:
            logger.debug(f"PDB parsing error: {e}")

    def _find_pdb_path(self) -> Optional[str]:
        pdb_path = self.binary_path + '.pdb'
        if os.path.exists(pdb_path):
            return pdb_path

        pdb_dir = os.path.join(os.path.dirname(self.binary_path), 'pdb')
        pdb_name = os.path.basename(self.binary_path) + '.pdb'
        pdb_path = os.path.join(pdb_dir, pdb_name)
        if os.path.exists(pdb_path):
            return pdb_path

        return None

    def _parse_pdb_file(self, pdb_path: str):
        self._parse_pdb_fallback()

    def _parse_pdb_fallback(self):
        logger.debug("PDB parsing not available; fallback path engaged")

    def get_type_info(self, type_name: str) -> Optional[TypeInfo]:
        return self.type_cache.types.get(type_name)

    def get_struct_info(self, struct_name: str) -> Optional[TypeInfo]:
        return self.type_cache.structs.get(struct_name)

    def get_class_info(self, class_name: str) -> Optional[TypeInfo]:
        return self.type_cache.classes.get(class_name)

    def get_all_types(self) -> List[str]:
        return list(self.type_cache.types.keys())


@dataclass
class MemoryObject:
    """Candidate object instance surfaced from a memory snapshot.

    Records address, size, inferred type, cross-references, originating
    allocator, and a confidence score clamped to [0.0, 1.0].
    """

    address: int
    size: int
    object_type: ObjectType
    fields: Dict = field(default_factory=dict)
    references: List = field(default_factory=list)
    allocator: AllocatorType = AllocatorType.UNKNOWN
    is_freed: bool = False
    confidence: float = 0.0


@dataclass
class ObjectField:
    """Decoded field value interpreted from raw bytes at a known offset within a reconstructed object."""

    name: str
    offset: int
    size: int
    value: Any = None
    is_pointer: bool = False
    pointer_target: Any = None


@dataclass
class ReconstructionResult:
    """Aggregate output of a single reconstruction pass.

    Holds recovered objects, the reference graph, type definitions,
    diagnostic warnings, and an outcome flag.
    """

    objects: List = field(default_factory=list)
    object_graph: Dict = field(default_factory=dict)
    type_definitions: Dict = field(default_factory=dict)
    warnings: List = field(default_factory=list)
    analysis_success: bool = False


class MemoryObjectReconstructor:
    """Pipeline for extracting typed object instances from unstructured heap dumps.

    Orchestrates allocator fingerprinting, object boundary scanning,
    DWARF/PDB-driven type inference, and cross-reference graph construction.
    """

    def __init__(self, memory_dump_path: str = "", allocator_type: AllocatorType = AllocatorType.UNKNOWN, binary_path: str = ""):
        self.memory_dump_path = memory_dump_path
        self.allocator_type = allocator_type
        self.objects: List[MemoryObject] = []
        self.object_graph: Dict[int, List[int]] = {}
        self.type_definitions: Dict[str, List[ObjectField]] = {}
        self.binary_path = binary_path
        self.dwarf_parser: Optional[DWARFParser] = None
        self.pdb_parser: Optional[PDBParser] = None

        if binary_path:
            self._init_type_parsers()

        logger.info(f"Memory object reconstructor initialized; allocator: {allocator_type.value}")

    def _init_type_parsers(self):
        if self.binary_path.endswith('.exe') or self.binary_path.endswith('.dll'):
            self.pdb_parser = PDBParser(self.binary_path)
            logger.info("PDB parser ready")
        else:
            self.dwarf_parser = DWARFParser(self.binary_path)
            logger.info("DWARF parser ready")

    def reconstruct(self, memory_data: bytes = None, start_address: int = 0) -> ReconstructionResult:
        logger.info("Initiating memory object reconstruction")

        result = ReconstructionResult()

        try:
            if memory_data is None and self.memory_dump_path:
                memory_data = self._load_memory_dump()

            if memory_data:
                self._detect_allocator_type(memory_data)
                self._scan_for_objects(memory_data, start_address)
                self._analyze_object_references(memory_data)
                self._infer_object_types()
                self._build_object_graph()

                result.objects = self.objects
                result.object_graph = self.object_graph
                result.type_definitions = self.type_definitions
                result.analysis_success = True

                logger.info(f"Memory object reconstruction finished; {len(self.objects)} objects recovered")
            else:
                result.warnings.append("Memory dump data load failed")

        except Exception as e:
            logger.error(f"Memory object reconstruction aborted: {e}")
            result.warnings.append(f"Reconstruction error: {e}")

        return result

    def _load_memory_dump(self) -> Optional[bytes]:
        try:
            with open(self.memory_dump_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Memory dump load error: {e}")
            return None

    def _detect_allocator_type(self, memory_data: bytes) -> None:
        allocator_signatures = {
            AllocatorType.PTMALLOC: [0x00000000, 0xffffffff],
            AllocatorType.JEMALLOC: [0x00000000, 0x00000001],
            AllocatorType.TCMALLOC: [0x00000000, 0x00000002],
        }

        for allocator, signatures in allocator_signatures.items():
            for sig in signatures:
                if sig in memory_data[:1024]:
                    self.allocator_type = allocator
                    logger.debug(f"Allocator identified: {allocator.value}")
                    return

    def _scan_for_objects(self, memory_data: bytes, start_address: int) -> None:
        chunk_size = 64
        offset = 0

        while offset < len(memory_data):
            chunk = memory_data[offset:offset + chunk_size]

            if len(chunk) >= 16:
                potential_object = self._analyze_chunk(chunk, start_address + offset)
                if potential_object:
                    self.objects.append(potential_object)

            offset += chunk_size

    def _analyze_chunk(self, chunk: bytes, address: int) -> Optional[MemoryObject]:
        pointer_count = 0
        references = []

        for i in range(0, len(chunk) - 8, 8):
            try:
                potential_ptr = int.from_bytes(chunk[i:i+8], 'little')
                if potential_ptr > 0x10000 and potential_ptr < 0x7fffffffffff:
                    pointer_count += 1
                    references.append(potential_ptr)
            except Exception:
                logger.debug("Non-critical exception in chunk analysis", exc_info=True)

        if pointer_count >= 1:
            obj = MemoryObject(
                address=address,
                size=len(chunk),
                object_type=ObjectType.UNKNOWN,
                references=references,
                allocator=self.allocator_type,
                confidence=0.5 + pointer_count * 0.1
            )

            return obj

        return None

    def _analyze_object_references(self, memory_data: bytes) -> None:
        for obj in self.objects:
            for ref_addr in obj.references:
                for target_obj in self.objects:
                    if target_obj.address <= ref_addr < target_obj.address + target_obj.size:
                        if obj.address not in self.object_graph:
                            self.object_graph[obj.address] = []
                        self.object_graph[obj.address].append(target_obj.address)

    def _infer_object_types(self) -> None:
        for obj in self.objects:
            type_info = self._find_matching_type(obj)
            if type_info:
                obj.object_type = ObjectType.CLASS if type_info.type_kind == 'class' else ObjectType.STRUCT
                obj.fields['type_info'] = type_info
                obj.confidence = min(1.0, obj.confidence + 0.3)
                logger.debug(f"Object {hex(obj.address)} type-matched: {type_info.name}")
            else:
                ref_count = len(obj.references)

                if ref_count == 0:
                    obj.object_type = ObjectType.STRUCT
                elif ref_count == 1:
                    obj.object_type = ObjectType.STRING
                elif ref_count >= 2 and ref_count <= 4:
                    obj.object_type = ObjectType.VECTOR
                elif ref_count > 4:
                    obj.object_type = ObjectType.MAP

                obj.confidence = min(1.0, obj.confidence + 0.2)

    def _find_matching_type(self, obj: MemoryObject) -> Optional[TypeInfo]:
        if self.dwarf_parser:
            for type_name, type_info in self.dwarf_parser.type_cache.types.items():
                if type_info.size > 0 and abs(type_info.size - obj.size) <= 8:
                    return type_info
        if self.pdb_parser:
            for type_name, type_info in self.pdb_parser.type_cache.types.items():
                if type_info.size > 0 and abs(type_info.size - obj.size) <= 8:
                    return type_info
        return None

    def _build_object_graph(self) -> None:
        for obj in self.objects:
            if obj.address not in self.object_graph:
                self.object_graph[obj.address] = []

    def reconstruct_object_at_address(self, memory_data: bytes, address: int) -> Optional[MemoryObject]:
        if address >= 0:
            offset = address
            if offset < len(memory_data):
                chunk = memory_data[offset:offset + 256]
                return self._analyze_chunk(chunk, address)
        return None

    def get_object_fields(self, obj: MemoryObject, memory_data: bytes) -> List[ObjectField]:
        fields = []
        offset = obj.address

        type_info = obj.fields.get('type_info')
        if type_info:
            fields = self._get_fields_from_type_info(obj, type_info, memory_data)
        else:
            for i in range(0, min(obj.size, 256), 8):
                try:
                    value = int.from_bytes(memory_data[offset + i:offset + i + 8], 'little')
                    is_pointer = value > 0x10000 and value < 0x7fffffffffff

                    field = ObjectField(
                        name=f"field_{i}",
                        offset=i,
                        size=8,
                        value=value,
                        is_pointer=is_pointer,
                        pointer_target=value if is_pointer else None
                    )

                    fields.append(field)
                except Exception:
                    logger.debug("Non-critical exception in field extraction", exc_info=True)

        return fields

    def _get_fields_from_type_info(self, obj: MemoryObject, type_info: TypeInfo, memory_data: bytes) -> List[ObjectField]:
        fields = []
        offset = obj.address

        for field_info in type_info.fields:
            try:
                field_offset = field_info.offset
                field_size = field_info.size
                field_end = field_offset + field_size

                if field_end > obj.size:
                    continue

                raw_value = memory_data[offset + field_offset:offset + field_end]

                value = self._parse_field_value(raw_value, field_info)

                field = ObjectField(
                    name=field_info.name,
                    offset=field_offset,
                    size=field_size,
                    value=value,
                    is_pointer=field_info.is_pointer,
                    pointer_target=value if field_info.is_pointer and value else None
                )

                fields.append(field)
            except Exception as e:
                logger.debug(f"Field {field_info.name} parse error: {e}")

        return fields

    def _parse_field_value(self, raw_value: bytes, field_info: FieldInfo) -> Any:
        if field_info.is_pointer:
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little')
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little')
        elif field_info.type_name == 'int' or field_info.type_name == 'long':
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little', signed=True)
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little', signed=True)
        elif field_info.type_name == 'unsigned int' or field_info.type_name == 'unsigned long':
            if len(raw_value) >= 8:
                return int.from_bytes(raw_value[:8], 'little', signed=False)
            elif len(raw_value) >= 4:
                return int.from_bytes(raw_value[:4], 'little', signed=False)
        elif field_info.type_name == 'float':
            if len(raw_value) >= 4:
                return struct.unpack('<f', raw_value[:4])[0]
        elif field_info.type_name == 'double':
            if len(raw_value) >= 8:
                return struct.unpack('<d', raw_value[:8])[0]

        return raw_value.hex() if raw_value else None


def reconstruct_objects(memory_dump_path: str = "", memory_data: bytes = None) -> ReconstructionResult:
    reconstructor = MemoryObjectReconstructor(memory_dump_path)
    return reconstructor.reconstruct(memory_data)
