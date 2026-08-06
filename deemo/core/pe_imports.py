"""Fast PE import table parsing, in-memory, sub-millisecond."""
import struct

def resolve(path: str) -> dict:
    """Return {IAT thunk address: "malloc"/"memcpy"/...}."""
    try:
        with open(path, 'rb') as f: data = f.read()
        if data[:2] != b'MZ': return {}
        pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
        if data[pe_off:pe_off+4] != b'PE\x00\x00': return {}
        coh = data[pe_off+4:pe_off+24]
        nsects = struct.unpack('<H', coh[2:4])[0]
        optsz = struct.unpack('<H', coh[16:18])[0]
        sections = []
        for i in range(nsects):
            sh = data[pe_off+24+optsz+i*40:pe_off+24+optsz+i*40+40]
            sections.append((
                sh[0:8].rstrip(b'\x00').decode(errors='replace'),
                struct.unpack('<I', sh[12:16])[0],  # va
                struct.unpack('<I', sh[16:20])[0],  # vs
                struct.unpack('<I', sh[20:24])[0],  # raw
            ))
        return _parse_imports(data, sections)
    except: return {}


def _rva_to_off(rva: int, sections: list) -> int:
    for nm, va, vs, ra in sections:
        if va <= rva < va + vs: return ra + (rva - va)
    return -1


def _read_str(data: bytes, off: int, skip: int = 0) -> str:
    if off < 0 or off >= len(data): return '?'
    start = off + skip
    end = data.index(0, start) if 0 in data[start:start+512] else start+512
    return data[start:end].decode(errors='replace')


def _parse_imports(data: bytes, sections: list) -> dict:
    imap = {}
    idata_va = idata_ra = idata_vs = 0
    for nm, va, vs, ra in sections:
        if nm == '.idata': idata_va=va; idata_ra=ra; idata_vs=vs
    if not idata_ra: return {}
    # Iterate import directory entries (20 bytes each)
    idata_end = idata_ra + min(idata_vs, len(data)-idata_ra)
    pos = idata_ra
    while pos + 20 <= idata_end:
        entry = data[pos:pos+20]
        if all(b == 0 for b in entry): break
        iat_rva = struct.unpack('<I', entry[16:20])[0]
        name_rva = struct.unpack('<I', entry[12:16])[0]
        pos += 20
        if not iat_rva or not name_rva: continue
        dll_name = _read_str(data, _rva_to_off(name_rva, sections))
        # Iterate IAT (8 bytes per thunk)
        iat_off = _rva_to_off(iat_rva, sections)
        if iat_off < 0: continue
        while iat_off + 8 <= len(data):
            va = struct.unpack('<Q', data[iat_off:iat_off+8])[0]
            if va == 0: break
            if va & 0x8000000000000000:
                imap[va] = f'{dll_name}!ord_{va&0xFFFF}'
            else:
                fn = _read_str(data, _rva_to_off(va, sections), skip=2)
                imap[va] = fn
            iat_off += 8
    return imap
