"""mmap IO 子模块——顺序读取器（游标驱动）"""

from ._mmap_file import MemoryMappedFile


class MmapReader:

    def __init__(self, mmap_file: MemoryMappedFile):
        self._mmap_file = mmap_file
        self._pos = 0

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > self._mmap_file.get_file_size():
            raise ValueError(f"Invalid offset: {offset}")
        self._pos = offset

    def tell(self) -> int:
        return self._pos

    def read(self, length: int) -> bytes:
        blob = self._mmap_file.read(self._pos, length)
        self._pos += len(blob)
        return blob

    def read_byte(self) -> int:
        b = self._mmap_file.read_byte(self._pos)
        self._pos += 1
        return b

    def read_int32(self, little_endian: bool = True) -> int:
        val = self._mmap_file.read_int32(self._pos, little_endian)
        self._pos += 4
        return val

    def read_int64(self, little_endian: bool = True) -> int:
        val = self._mmap_file.read_int64(self._pos, little_endian)
        self._pos += 8
        return val

    def read_string(self, max_length: int = 1024) -> str:
        s = self._mmap_file.read_string(self._pos, max_length)
        self._pos += len(s) + 1
        return s

    def read_until(self, delimiter: bytes) -> bytes:
        result = b""
        fsize = self._mmap_file.get_file_size()
        while self._pos < fsize:
            b = self._mmap_file.read_byte(self._pos)
            self._pos += 1
            if b == delimiter[0]:
                if len(delimiter) == 1:
                    break
                ok = True
                tmp = self._pos
                for i in range(1, len(delimiter)):
                    if tmp + i >= fsize:
                        ok = False
                        break
                    if self._mmap_file.read_byte(tmp + i) != delimiter[i]:
                        ok = False
                        break
                if ok:
                    self._pos = tmp + len(delimiter)
                    break
            result += bytes([b])
        return result

    def remaining(self) -> int:
        return max(0, self._mmap_file.get_file_size() - self._pos)
