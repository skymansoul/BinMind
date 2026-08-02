# 2026-07-22
# 固件提取器 — SquashFS/JFFS2/CramFS/CPIO/UBIFS/YAFFS/Android Sparse
# 多渠道提取策略：binwalk → 手动 → 通用carving

import os, re, shutil, struct, subprocess, tempfile, time, math
from .core import FirmwareImage, ExtractionResult, detect_file_system, shannon_entropy


class YAFFSExtractor:
    CHUNK_SIZE = 2048; SPARE_SIZE = 64; OBJECT_HEADER = 1
    def __init__(self, data: bytes):
        self._data = data; self._size = len(data)

    def extract(self, output_dir: str) -> int:
        _files = 0; _file_map = {}
        total_chunks = self._size // (self.CHUNK_SIZE + self.SPARE_SIZE)
        for _chunk_id in range(total_chunks):
            _chunk_off = _chunk_id * (self.CHUNK_SIZE + self.SPARE_SIZE)
            if _chunk_off + self.CHUNK_SIZE > self._size:
                break
            _spare = self._data[_chunk_off + self.CHUNK_SIZE:_chunk_off + self.CHUNK_SIZE + self.SPARE_SIZE]
            if len(_spare) < self.SPARE_SIZE:
                break
            _obj_id = struct.unpack_from("<I", _spare, 0)[0]
            _chk_id = struct.unpack_from("<I", _spare, 4)[0]
            _nbytes = struct.unpack_from("<I", _spare, 12)[0] if len(_spare) >= 16 else self.CHUNK_SIZE
            if _obj_id in (0, 0xFFFFFFFF):
                continue
            _chunk_data = self._data[_chunk_off:_chunk_off + min(_nbytes, self.CHUNK_SIZE)]
            if _obj_id not in _file_map:
                _file_map[_obj_id] = ("unknown_%d" % _obj_id, [])
            _file_map[_obj_id][1].append((_chk_id, _chunk_data))
        for _oid, (_name, _chunks) in _file_map.items():
            _chunks.sort(key=lambda x: x[0])
            _fpath = os.path.join(output_dir, "yaffs_files", _name)
            os.makedirs(os.path.dirname(_fpath), exist_ok=True)
            with open(_fpath, "wb") as _f:
                for _, _c in _chunks:
                    _f.write(_c)
            _files += 1
        return _files


class AndroidSparseExtractor:
    SPARSE_HEADER_MAGIC = 0xED26FF3A
    CHUNK_TYPE_RAW = 0xCAC1; CHUNK_TYPE_FILL = 0xCAC2
    CHUNK_TYPE_DONT_CARE = 0xCAC3; CHUNK_TYPE_CRC32 = 0xCAC4
    def __init__(self, data: bytes):
        self._data = data

    def extract(self, output_path: str) -> bool:
        _magic = struct.unpack_from("<I", self._data, 0)[0]
        if _magic != self.SPARSE_HEADER_MAGIC:
            return False
        _blk_sz = struct.unpack_from("<I", self._data, 12)[0]
        _total_blks = struct.unpack_from("<I", self._data, 16)[0]
        _total_chunks = struct.unpack_from("<I", self._data, 20)[0]
        _raw = bytearray(_total_blks * _blk_sz); _offset = 28
        for _ in range(_total_chunks):
            if _offset + 12 > len(self._data):
                break
            _chunk_type = struct.unpack_from("<H", self._data, _offset)[0]
            _chunk_sz = struct.unpack_from("<I", self._data, _offset + 4)[0]
            _total_sz = struct.unpack_from("<I", self._data, _offset + 8)[0]
            _offset += 12
            if _chunk_type == self.CHUNK_TYPE_RAW:
                _dst = _chunk_sz * _blk_sz
                if _total_sz > 0:
                    _raw_len = min(_total_sz, _dst, len(self._data) - _offset)
                    _raw[_chunk_sz * _blk_sz:_chunk_sz * _blk_sz + _raw_len] = self._data[_offset:_offset + _raw_len]
                _offset += _total_sz
            elif _chunk_type == self.CHUNK_TYPE_FILL and _offset + 4 <= len(self._data):
                _fill_val = struct.unpack_from("<I", self._data, _offset)[0]
                _fill_bytes = struct.pack("<I", _fill_val) * (_blk_sz // 4)
                for _b in range(_chunk_sz):
                    _dst_off = (_chunk_sz + _b) * _blk_sz
                    if _dst_off + _blk_sz <= len(_raw):
                        _raw[_dst_off:_dst_off + _blk_sz] = _fill_bytes
                _offset += 4
            elif _chunk_type == self.CHUNK_TYPE_DONT_CARE:
                pass
            elif _chunk_type == self.CHUNK_TYPE_CRC32:
                _offset += 4
        with open(output_path, "wb") as _f:
            _f.write(_raw)
        return True


class FirmwareExtractor:
    def __init__(self, firm: FirmwareImage):
        self._firm = firm; self._data = firm.data

    def extract(self, output_dir: str) -> ExtractionResult:
        os.makedirs(output_dir, exist_ok=True); _start = time.time()
        _errs = []; _warns = []; _ok = False; _file_count = 0
        _ent = shannon_entropy(self._data[:262144])
        if _ent > 0.92:
            _warns.append(f"High entropy ({_ent:.2f}) — firmware may be encrypted or use unknown compression")
        _fmt = self._detect_format()
        _dispatch = {"squashfs": self._extract_squashfs, "jffs2": self._extract_jffs2,
                     "cramfs": self._extract_cramfs, "cpio": self._extract_cpio,
                     "ubifs": self._extract_ubifs, "yaffs": self._extract_yaffs,
                     "android_sparse": self._extract_android_sparse}
        _fn = _dispatch.get(_fmt)
        if _fn:
            try:
                _ok = _fn(output_dir)
            except Exception as e:
                _errs.append(f"{_fmt} extraction failed: {e}")
        else:
            _warns.append(f"Unknown format '{_fmt}', falling back to generic")
            try:
                _ok = self._extract_generic(output_dir)
            except Exception as e:
                _errs.append(f"Generic extraction failed: {e}")
        if _ok:
            _file_count = self._walk_and_collect(output_dir)
        _elapsed = time.time() - _start
        return ExtractionResult(success=_ok, files_extracted=_file_count, errors=_errs,
                                warnings=_warns, extraction_time=_elapsed, root_path=output_dir)

    def _detect_format(self) -> str:
        _h = self._data[:8]
        if _h[:4] in (b"hsqs", b"sqsh"):
            return "squashfs"
        if _h[:2] in (b"\x19\x85", b"\x85\x19"):
            return "jffs2"
        if _h[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
            return "cramfs"
        if _h[:4] in (b"\x31\x18\x10\x06", b"\x06\x10\x18\x31"):
            return "ubifs"
        if _h[:6] == b"\x30\x37\x30\x37\x30\x31":
            return "cpio"
        if b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff" in self._data[:512]:
            return "yaffs"
        if struct.unpack_from("<I", self._data, 0)[0] == AndroidSparseExtractor.SPARSE_HEADER_MAGIC:
            return "android_sparse"
        if _h[:2] == b"\x1f\x8b":
            return "gzip"
        if _h[:3] == b"BZh":
            return "bzip2"
        if _h[:6] == b"\xfd7zXZ\x00":
            return "xz"
        if _h[:5] == b"\x5d\x00\x00\x80\x00":
            return "lzma"
        return "unknown"

    def _extract_squashfs(self, output_dir: str) -> bool:
        if shutil.which("unsquashfs"):
            _tmp = tempfile.NamedTemporaryFile(suffix=".sqfs", delete=False)
            _tmp.write(self._data); _tmp.close()
            try:
                subprocess.run(["unsquashfs", "-d", output_dir, _tmp.name],
                               capture_output=True, check=True, timeout=120)
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            finally:
                os.unlink(_tmp.name)
        if len(self._data) < 96:
            return False
        _block_size = struct.unpack_from("<I", self._data, 12)[0]; _saved = 0; _off = 96
        while _off < len(self._data) and _saved < 10000:
            _end = min(_off + _block_size, len(self._data))
            _chunk = self._data[_off:_end]
            _opath = os.path.join(output_dir, f"sqfs_chunk_{_saved:06d}")
            with open(_opath, "wb") as _f:
                _f.write(_chunk)
            _saved += 1; _off += _block_size
        return _saved > 0

    def _extract_jffs2(self, output_dir: str) -> bool:
        if shutil.which("jefferson"):
            _tmp = tempfile.NamedTemporaryFile(suffix=".jffs2", delete=False)
            _tmp.write(self._data); _tmp.close()
            try:
                subprocess.run(["jefferson", "-d", output_dir, _tmp.name],
                               capture_output=True, check=True, timeout=120)
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            finally:
                os.unlink(_tmp.name)
        return self._extract_generic(output_dir)

    def _extract_cramfs(self, output_dir: str) -> bool:
        if len(self._data) < 76:
            return False
        _scount = 0; _fs_size = struct.unpack_from(">I", self._data, 4)[0]
        if _fs_size == 0 or _fs_size > len(self._data) * 2:
            _fs_size = len(self._data)
        for _off in range(0, min(_fs_size, len(self._data)), 4096):
            _cpath = os.path.join(output_dir, f"cramfs_block_{_scount:04d}")
            with open(_cpath, "wb") as _f:
                _f.write(self._data[_off:_off + 4096])
            _scount += 1
        return _scount > 0

    def _extract_cpio(self, output_dir: str) -> bool:
        if shutil.which("cpio"):
            _tmp = tempfile.NamedTemporaryFile(suffix=".cpio", delete=False)
            _tmp.write(self._data); _tmp.close()
            try:
                _prev = os.getcwd(); os.chdir(output_dir)
                with open(_tmp.name, "rb") as _f:
                    subprocess.run(["cpio", "-idm"], stdin=_f, capture_output=True, timeout=60)
                os.chdir(_prev); return True
            except Exception:
                pass
            finally:
                os.unlink(_tmp.name)
        return self._extract_generic(output_dir)

    def _extract_ubifs(self, output_dir: str) -> bool:
        if shutil.which("ubireader_extract_images"):
            _tmp = tempfile.NamedTemporaryFile(suffix=".ubi", delete=False)
            _tmp.write(self._data); _tmp.close()
            try:
                subprocess.run(["ubireader_extract_images", "-o", output_dir, _tmp.name],
                               capture_output=True, check=True, timeout=120)
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            finally:
                os.unlink(_tmp.name)
        return self._extract_generic(output_dir)

    def _extract_yaffs(self, output_dir: str) -> bool:
        return YAFFSExtractor(self._data).extract(output_dir) > 0

    def _extract_android_sparse(self, output_dir: str) -> bool:
        _raw_path = os.path.join(output_dir, "sparse_raw.img")
        if AndroidSparseExtractor(self._data).extract(_raw_path):
            with open(_raw_path, "rb") as _f:
                _raw_data = _f.read()
            _inner_fs = detect_file_system(_raw_data)
            if _inner_fs != "unknown":
                from .core import FirmwareImage as FI, FirmwareType
                _sub = FI(path=_raw_path, data=_raw_data, size=len(_raw_data),
                          ftype=FirmwareType.ANDROID, fs_type=_inner_fs)
                return FirmwareExtractor(_sub).extract(os.path.join(output_dir, "inner"))
            return True
        return False

    def _extract_generic(self, output_dir: str) -> bool:
        _saved = 0; _text_chunks = []; _chunk = bytearray()
        for _b in self._data[:1048576]:
            if 0x20 <= _b <= 0x7E or _b in (0x0A, 0x09):
                _chunk.append(_b)
            else:
                if len(_chunk) >= 8:
                    _text_chunks.append(bytes(_chunk))
                _chunk = bytearray()
        if len(_chunk) >= 8:
            _text_chunks.append(bytes(_chunk))
        _strings_path = os.path.join(output_dir, "strings_output.txt")
        with open(_strings_path, "w", encoding="ascii", errors="replace") as _f:
            for _t in _text_chunks:
                _f.write(_t.decode("ascii", errors="replace") + "\n")
        _saved += 1
        for _off in range(0, min(len(self._data), 10000000), 512):
            _bin_path = os.path.join(output_dir, f"carved_{_off:08x}.bin")
            with open(_bin_path, "wb") as _f:
                _f.write(self._data[_off:_off + 512])
            _saved += 1
            if _saved > 5000:
                break
        return _saved > 0

    def _walk_and_collect(self, root: str) -> int:
        return sum(len(_files) for _, _, _files in os.walk(root))
