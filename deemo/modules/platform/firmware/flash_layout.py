# 2026-07-24
# Flash分区布局解析器 — mtdparts/GPT/MBR + UBI volume table + QSPI NOR

import re
import struct


class FlashLayoutParser:
    GPT_SIGNATURE = b"EFI PART"
    MBR_SIGNATURE_OFFSET = 510; MBR_SIGNATURE = b"\x55\xaa"
    UBI_EC_HDR_MAGIC = b"\x55\x42\x49\x23"

    def parse_mtdparts(self, data: str) -> list[dict]:
        _partitions = []
        _m = re.search(r"mtdparts=([a-zA-Z0-9_-]+):(.+)", data)
        if not _m:
            return _partitions
        _controller = _m.group(1); _parts_str = _m.group(2)
        for _chip_spec in _parts_str.split(";"):
            if not _chip_spec.strip():
                continue
            _offset = 0
            for _part in _chip_spec.split(","):
                _part = _part.strip()
                if not _part:
                    continue
                _m2 = re.match(r"(\d+)[kKmM]?\((\w+)\)(?:@(\d+)[kKmM]?)?(ro)?", _part)
                if not _m2:
                    _m2 = re.match(r"(\d+)[kKmM]?@(\d+)[kKmM]?\((\w+)\)(ro)?", _part)
                    if _m2:
                        _sz = int(_m2.group(1)); _name = _m2.group(3)
                        _off = int(_m2.group(2)); _ro = bool(_m2.group(4))
                    else:
                        continue
                else:
                    _sz = int(_m2.group(1)); _name = _m2.group(2)
                    _off_str = _m2.group(3); _off = int(_off_str) if _off_str else _offset
                    _ro = bool(_m2.group(4))
                _unit = _part[_m2.end(1):_m2.start(2)].strip("(")
                _sz_kb = _sz * 1024 if "m" in _unit.lower() or "M" in _unit else _sz
                _partitions.append({"name": _name, "size_kb": _sz_kb, "offset_kb": _off,
                                    "controller": _controller, "readonly": _ro, "type": "mtd"})
                _offset = _off + _sz_kb
        return _partitions

    def parse_ubi_volumes(self, data: bytes, block_size: int = 131072) -> list[dict]:
        volumes = []; seen_vol_ids = set(); n = len(data)
        off = 0
        while off + block_size <= n:
            ec_hdr = data[off:off + 64]
            if ec_hdr[:4] != self.UBI_EC_HDR_MAGIC:
                off += block_size; continue
            vid_off = off + 64
            if vid_off + 64 > n:
                break
            vid_hdr = data[vid_off:vid_off + 64]
            vid_magic = struct.unpack_from(">I", vid_hdr, 0)[0] if len(vid_hdr) >= 4 else 0
            if vid_magic == 0x55424921:
                vol_id = struct.unpack_from(">I", vid_hdr, 20)[0]
                if vol_id not in seen_vol_ids:
                    seen_vol_ids.add(vol_id)
                    volumes.append({"volume_id": vol_id, "peb_offset": off,
                                    "first_lnum": struct.unpack_from(">I", vid_hdr, 24)[0], "type": "ubi_volume"})
            off += block_size
        return volumes

    def detect_qspi_layout(self, data: bytes) -> dict:
        regions = []; n = len(data)
        if n > 64 and (data[4:8] == b'\x27\x05\x19\x56' or (data[0:4] == b'\x00\x00\x00\x00' and struct.unpack_from('<I', data, 4)[0] != 0)):
            regions.append({"name": "u-boot_spl", "offset": 0, "size": min(131072, n), "type": "bootloader"})
        for candidate_off in [0x20000, 0x40000, 0x60000, 0x80000, 0x100000]:
            if candidate_off + 64 <= n and data[candidate_off:candidate_off + 4] == b'\x27\x05\x19\x56':
                regions.append({"name": "u-boot", "offset": candidate_off, "size": min(524288, n - candidate_off), "type": "bootloader"})
                break
        for env_off in [0x40000, 0x80000, 0xC0000, 0x100000, 0x140000, 0x180000]:
            if env_off + 5 > n:
                continue
            env_crc = struct.unpack_from('<I', data, env_off)[0]
            if env_crc != 0 and env_crc != 0xFFFFFFFF:
                env_body = data[env_off + 4:env_off + 16384]
                if b'=' in env_body[:256] and b'\x00' in env_body[:256]:
                    regions.append({"name": "u-boot_env", "offset": env_off, "size": 32768, "type": "environment"})
                    break
        for dtb_search in range(0, min(n, 2097152), 4096):
            if dtb_search + 40 <= n and data[dtb_search:dtb_search + 4] == b'\xd0\x0d\xfe\xed':
                dtb_total = struct.unpack_from('>I', data, dtb_search + 4)[0]
                regions.append({"name": "device_tree", "offset": dtb_search, "size": min(dtb_total, n - dtb_search), "type": "dtb"})
                break
        for kern_search in range(0, min(n, 4194304), 65536):
            if kern_search + 128 > n:
                break
            if data[kern_search:kern_search + 2] == b'\x1f\x8b' and b'Linux' in data[kern_search + 2:kern_search + 258]:
                regions.append({"name": "kernel", "offset": kern_search, "size": min(8388608, n - kern_search), "type": "kernel"})
                break
        return {"detected": len(regions) >= 2, "regions": regions, "flash_type": "qspi_nor", "total_size": n}

    def parse_partition_table(self, data: bytes) -> list[dict]:
        _parts = []
        if len(data) >= 1024 and data[512:520] == self.GPT_SIGNATURE:
            return self._parse_gpt(data)
        if len(data) >= 512 and data[self.MBR_SIGNATURE_OFFSET:self.MBR_SIGNATURE_OFFSET + 2] == self.MBR_SIGNATURE:
            return self._parse_mbr(data)
        return _parts

    def _parse_gpt(self, data: bytes) -> list[dict]:
        _parts = []
        if len(data) < 1024:
            return _parts
        _hdr = data[512:604]
        _num_parts = struct.unpack_from("<I", _hdr, 80)[0]
        _entry_size = struct.unpack_from("<I", _hdr, 84)[0]
        _entry_lba = struct.unpack_from("<Q", _hdr, 72)[0]
        _entries_off = _entry_lba * 512
        for _i in range(min(_num_parts, 128)):
            _eoff = _entries_off + _i * _entry_size
            if _eoff + _entry_size > len(data):
                break
            _entry = data[_eoff:_eoff + _entry_size]
            if _entry[:16] == b"\x00" * 16:
                continue
            _start_lba = struct.unpack_from("<Q", _entry, 32)[0]
            _end_lba = struct.unpack_from("<Q", _entry, 40)[0]
            _attr = struct.unpack_from("<Q", _entry, 48)[0]
            _name_raw = _entry[56:128]
            try:
                _name = _name_raw.decode("utf-16-le").rstrip("\x00")
            except UnicodeDecodeError:
                _name = _name_raw.decode("ascii", errors="replace").rstrip("\x00")
            _parts.append({"name": _name, "start_lba": _start_lba, "end_lba": _end_lba,
                           "size_bytes": (_end_lba - _start_lba + 1) * 512,
                           "offset_bytes": _start_lba * 512, "type": "gpt", "attributes": _attr})
        return _parts

    def _parse_mbr(self, data: bytes) -> list[dict]:
        _parts = []
        if len(data) < 512:
            return _parts
        for _i in range(4):
            _off = 446 + _i * 16; _entry = data[_off:_off + 16]
            _status = _entry[0]; _part_type = _entry[4]
            _start_lba = struct.unpack_from("<I", _entry, 8)[0]
            _num_sectors = struct.unpack_from("<I", _entry, 12)[0]
            if _part_type == 0x00:
                continue
            _type_names = {0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16B", 0x07: "NTFS/HPFS",
                           0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA", 0x83: "Linux",
                           0x82: "Linux swap", 0x8E: "Linux LVM", 0xEE: "GPT Protective",
                           0xEF: "EFI System", 0xDA: "Non-FS"}
            _parts.append({"name": f"mbr_part{_i + 1}",
                           "part_type": _type_names.get(_part_type, f"0x{_part_type:02X}"),
                           "part_type_code": _part_type, "start_lba": _start_lba,
                           "num_sectors": _num_sectors, "size_bytes": _num_sectors * 512,
                           "offset_bytes": _start_lba * 512, "type": "mbr",
                           "bootable": _status == 0x80})
        return _parts

    def validate_address_ranges(self, partitions: list[dict]) -> list[dict]:
        _issues = []
        if not partitions:
            return _issues
        _overlaps = self.detect_overlap(partitions)
        for _a, _b in _overlaps:
            _issues.append({"type": "overlap", "severity": "CRITICAL",
                           "partitions": [_a.get("name", "?"), _b.get("name", "?")],
                           "finding": f"分区重叠: {_a.get('name', '?')} 与 {_b.get('name', '?')}"})
        for _p in partitions:
            _off = self._get_offset(_p)
            if _off % 4096 != 0:
                _issues.append({"type": "alignment", "severity": "MEDIUM",
                               "partition": _p.get("name", "?"), "offset": _off,
                               "finding": f"分区 {_p.get('name', '?')} 偏移 {_off} 未 4K 对齐"})
        _sorted = sorted(partitions, key=self._get_offset)
        for _i in range(len(_sorted) - 1):
            _cur, _nxt = _sorted[_i], _sorted[_i + 1]
            _cur_end = self._get_offset(_cur) + self._get_size(_cur)
            _nxt_start = self._get_offset(_nxt)
            if _nxt_start > _cur_end:
                _gap = _nxt_start - _cur_end
                _issues.append({"type": "gap", "severity": "LOW", "gap_bytes": _gap,
                               "between": [_cur.get("name", "?"), _nxt.get("name", "?")],
                               "finding": f"分区间隙 {_gap} 字节"})
        for _p in partitions:
            _name = _p.get("name", ""); _size = self._get_size(_p)
            if "ubi" in _name.lower() and _size < 1048576:
                _issues.append({"type": "ubi_capacity", "severity": "LOW", "partition": _name,
                               "finding": f"UBI 分区 {_name} 小于 1MB ({_size} bytes)"})
        return _issues

    def detect_overlap(self, partitions: list[dict]) -> list[tuple]:
        _sorted = sorted(partitions, key=self._get_offset); _overlaps = []
        for _i in range(len(_sorted)):
            for _j in range(_i + 1, len(_sorted)):
                _a, _b = _sorted[_i], _sorted[_j]
                _a_start, _a_end = self._get_offset(_a), self._get_offset(_a) + self._get_size(_a)
                _b_start, _b_end = self._get_offset(_b), self._get_offset(_b) + self._get_size(_b)
                if _a_start < _b_end and _b_start < _a_end:
                    _overlaps.append((_a, _b))
        return _overlaps

    def flash_size_estimate(self, partitions: list[dict]) -> int:
        if not partitions:
            return 0
        _max_end = max(self._get_offset(_p) + self._get_size(_p) for _p in partitions)
        return int(_max_end * 1.10)

    @staticmethod
    def _get_offset(part: dict) -> int:
        if "offset_bytes" in part:
            return part["offset_bytes"]
        if "offset_kb" in part:
            return part["offset_kb"] * 1024
        if "start_lba" in part:
            return part["start_lba"] * 512
        return 0

    @staticmethod
    def _get_size(part: dict) -> int:
        if "size_bytes" in part:
            return part["size_bytes"]
        if "size_kb" in part:
            return part["size_kb"] * 1024
        if "num_sectors" in part:
            return part["num_sectors"] * 512
        if "end_lba" in part and "start_lba" in part:
            return (part["end_lba"] - part["start_lba"] + 1) * 512
        return 0
