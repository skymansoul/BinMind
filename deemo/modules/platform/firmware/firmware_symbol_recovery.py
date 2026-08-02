import logging, os, re, subprocess, json, math, struct
logger = logging.getLogger(__name__)

def _crc16_ccitt(buf, poly=0x1021):
    crc = 0xFFFF
    for b in buf:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def _normalize_prologue(blob, arch_hint="arm"):
    buf = bytearray(blob[:32])
    if len(buf) < 4: return buf
    if arch_hint in ("arm","thumb"):
        i = 0
        while i <= len(buf)-4:
            hw = struct.unpack_from('<H', buf, i)[0]
            if (hw & 0xF800) in (0xF000, 0xE800):
                if i+2 <= len(buf)-2: buf[i:i+4] = b'\x00\x00\x00\x00'
                i += 4; continue
            if i <= len(buf)-4 and (buf[i+3] & 0x0F) == 0x0E and buf[i+3] in (0xEA, 0xEB):
                buf[i:i+4] = b'\x00\x00\x00\x00'
            i += 2
    elif arch_hint == "x86":
        i = 0
        while i <= len(buf)-5:
            if buf[i] == 0xE8: buf[i+1:i+5] = b'\x00\x00\x00\x00'; i += 5; continue
            if i <= len(buf)-7 and buf[i:i+2] in (b'\x48\x8D', b'\x4C\x8D') and buf[i+2] in (0x05,0x0D):
                buf[i+3:i+7] = b'\x00\x00\x00\x00'
            i += 1
    return buf

class BSPFingerprint:
    _BSP_SIGNATURES = {
        "SystemInit": {"patterns":[b'\x00\xb5\x00\xf0',b'SystemCoreClock'],"arch":"ARM","description":"System clock init"},
        "SysTick_Handler": {"patterns":[b'SysTick',b'\x70\x47'],"arch":"ARM","description":"SysTick handler"},
        "UART_Init": {"patterns":[b'UART',b'USART',b'baud',b'BRR'],"arch":"ARM","description":"UART init"},
        "vTaskStartScheduler": {"patterns":[b'FreeRTOS',b'SysTick',b'PendSV'],"arch":"ARM","description":"FreeRTOS scheduler"},
        "xQueueCreate": {"patterns":[b'Queue',b'uxQueueNumber',b'pcQueueName'],"arch":"ARM","description":"FreeRTOS queue"},
        "HAL_Init": {"patterns":[b'HAL_Init',b'Error_Handler',b'HAL_IncTick'],"arch":"ARM","description":"STM32 HAL"},
        "HAL_GPIO_WritePin": {"patterns":[b'GPIO',b'BSRR',b'ODR'],"arch":"ARM","description":"GPIO write"},
        "Reset_Handler": {"patterns":[b'\x00\x00\x00\x20',b'Reset_Handler',b'__main'],"arch":"ARM","description":"Reset vector"},
        "memcpy": {"patterns":[b'\x03\xc4',b'\x40\xf8\x04'],"arch":"ARM/Thumb","description":"memcpy (Thumb)"},
        "memset": {"patterns":[b'\x00\x23',b'\xc0\xf8'],"arch":"ARM/Thumb","description":"memset (Thumb)"},
    }
    _HARDWARE_PATTERNS = {"WiFi_Init":[(b'WiFi',b'wifi_',b'WLAN')],"BLE_Init":[(b'BLE',b'ble_',b'GAP',b'GATT')],
                          "SPI_Transfer":[(b'SPI',b'spi_',b'MOSI')],"I2C_Master":[(b'I2C',b'i2c_',b'SCL')]}
    _flirt_index: dict[int, list[tuple[str,bytes]]] = {}

_STR_XREF_HINTS = [
    (re.compile(rb'(?:error|fail|invalid|bad|wrong)\s*[:%]?\s*'), 'err_', 3),
    (re.compile(rb'\w+\.c:\d+'), 'assert_', 5), (re.compile(rb'%[dsuxpfgc]'), 'fmt_', 2),
    (re.compile(rb'(?:GET|POST|PUT|DELETE)\s+/'), 'http_', 4),
    (re.compile(rb'/proc/|/sys/|/dev/'), 'sysfs_', 4), (re.compile(rb'AT[+%]?\w{2,}'), 'modem_', 3),
]

class FirmwareSymbolRecoverer:
    def __init__(self, firmware_path):
        self.firmware_path = os.path.abspath(firmware_path); self._data = b""
        self._func_list = []; self.recovered = {}; self._strings = []; self._flirt_sigs = {}

    def _load(self):
        try:
            with open(self.firmware_path,'rb') as f: self._data = f.read()
        except Exception: logger.debug("firmware data load failed", exc_info=True)
        try:
            result = subprocess.run(['r2','-q','-c','aflj; q',self.firmware_path],
                                    capture_output=True, text=True, timeout=120, encoding='utf-8', errors='replace')
            self._func_list = json.loads(result.stdout) if result.stdout.strip() else []
        except Exception: logger.debug("r2 invocation failed", exc_info=True)

    def _extract_strings(self, min_len=4):
        strings = []; data = self._data; n = len(data); i = 0
        while i < n:
            if 0x20 <= data[i] <= 0x7E:
                j = i
                while j < n and 0x20 <= data[j] <= 0x7E: j += 1
                if j - i >= min_len and (j >= n or data[j] == 0): strings.append((i, data[i:j])); i = j
                else: i += 1
            else: i += 1
        self._strings = strings

    def _resolve_plt_imports(self):
        imports = {}; data = self._data; n = len(data)
        arm_plt = re.compile(rb'\x00\xc0\x00\xf0.{0,8}\x60\x47')
        for m in arm_plt.finditer(data):
            off = m.start()
            if off + 12 <= n:
                imm = struct.unpack_from('<I', data, off)[0]; pc_val = off + 4
                imports[off] = f"plt_{((pc_val + (imm & 0xFFF)) & 0xFFFFFFFF):08x}"
        mips_got = re.compile(rb'\x8f\x99....\x03\x20\xf8\x09')
        for m in mips_got.finditer(data):
            off = m.start()
            got_off = struct.unpack_from('<H', data, max(0, off-2))[0] if off >= 2 else 0
            imports[off] = f"mips_got_{got_off:04x}"
        return imports

    def _recover_by_string_xref(self):
        recovered = {}
        if not self._strings: self._extract_strings()
        str_offsets = {off for off,_ in self._strings}
        for func in self._func_list:
            foff = func.get('offset',0)
            if foff <= 0 or foff + 64 > len(self._data): continue
            probe = self._data[foff:foff+64]
            for arm_off in range(0, len(probe)-3, 2):
                imm = struct.unpack_from('<I', probe, arm_off)[0] & 0xFFFFFFFF
                if imm in str_offsets:
                    if arm_off >= 4:
                        instr = struct.unpack_from('<H', probe, arm_off-2)[0]
                        if (instr & 0xF8FF) not in (0x4800,0x6800,0x9800): continue
                    self._classify_by_string(recovered, foff, imm); break
        return recovered

    def _classify_by_string(self, recovered, func_offset, str_offset):
        str_bytes = self._data[str_offset:str_offset+128]
        term = str_bytes.find(b'\x00')
        if term >= 0: str_bytes = str_bytes[:term]
        for pat, prefix, _ in _STR_XREF_HINTS:
            if pat.search(str_bytes):
                sanitized = re.sub(rb'[^a-zA-Z0-9_]', b'_', str_bytes[:20])
                name = prefix.decode() + sanitized.decode('ascii','replace').strip('_')
                recovered.setdefault(name, [])
                if func_offset not in recovered[name]: recovered[name].append(func_offset)
                return

    def _pattern_match(self, patterns):
        matches = []
        for pat in patterns:
            pos = 0
            while True:
                idx = self._data.find(pat, pos)
                if idx == -1: break
                matches.append(idx); pos = idx + 1
        return matches

    def _pattern_match_fuzzy(self, pattern, max_dist=1):
        results = []; plen = len(pattern)
        if plen == 0: return results
        if plen < 8: return self._pattern_match([pattern])
        pos = 0; n = len(self._data)
        while pos <= n - plen:
            dist = sum(1 for k in range(plen) if self._data[pos+k] != pattern[k])
            if dist <= max_dist: results.append(pos); pos += plen
            else: pos += 1
        return results

    def _build_flirt_index(self):
        for func_name, sig_info in BSPFingerprint._BSP_SIGNATURES.items():
            patterns = sig_info.get("patterns",[])
            if not patterns: continue
            norm = _normalize_prologue(patterns[0], arch_hint=sig_info.get("arch","arm"))
            crc = _crc16_ccitt(norm); self._flirt_sigs[func_name] = crc
            BSPFingerprint._flirt_index.setdefault(crc,[]).append((func_name, bytes(norm)))

    def _match_flirt_signatures(self):
        sig_matches = {}
        if not self._flirt_sigs: self._build_flirt_index()
        n = len(self._data); segments = self._entropy_code_segments()
        if not segments: segments = [(0,n)]
        for seg_start, seg_end in segments:
            for off in range(seg_start, seg_end-32, 2):
                probe = _normalize_prologue(self._data[off:off+32])
                crc = _crc16_ccitt(bytes(probe))
                for name, sig_crc in self._flirt_sigs.items():
                    if crc == sig_crc:
                        sig_matches.setdefault(name,[]).append(off)
        return sig_matches

    def _entropy_code_segments(self):
        data = self._data; n = len(data); window, step = 512, 256
        segments = []
        if n < window: return [(0,n)]
        in_code = False; seg_start = 0
        for off in range(0, n-window, step):
            chunk = data[off:off+window]; counts = [0]*256
            for b in chunk: counts[b] += 1
            inv_w = 1.0/window
            entropy = -sum((c*inv_w)*math.log2(c*inv_w) for c in counts if c > 0)
            if entropy < 5.0 and not in_code: in_code = True; seg_start = off
            elif entropy >= 5.0 and in_code:
                in_code = False
                if off - seg_start > 64: segments.append((seg_start, off))
                seg_start = off
        if in_code and n - seg_start > 64: segments.append((seg_start, n))
        return segments if segments else [(0,n)]

    def recover_bsp_symbols(self):
        self._load()
        for func_name, sig_info in BSPFingerprint._BSP_SIGNATURES.items():
            matches = self._pattern_match(sig_info["patterns"])
            if matches:
                func_addrs = []
                for mp in matches:
                    for func in self._func_list:
                        offset = func.get('offset',0)
                        if abs(mp - offset) < 64: func_addrs.append(offset); break
                if func_addrs:
                    dedup = []; [dedup.append(a) for a in func_addrs if a not in dedup]
                    self.recovered[func_name] = dedup
        str_recovered = self._recover_by_string_xref()
        for name, addrs in str_recovered.items():
            if name not in self.recovered: self.recovered[name] = addrs
            else:
                for a in addrs:
                    if a not in self.recovered[name]: self.recovered[name].append(a)
        flirt_matches = self._match_flirt_signatures()
        for name, addrs in flirt_matches.items():
            suffixed = f"flirt_{name}"
            if suffixed not in self.recovered: self.recovered[suffixed] = addrs
        self.recovered["_plt_imports"] = list(self._resolve_plt_imports().keys())
        return self.recovered

    def apply_to_r2(self, output_script=""):
        lines = ["#!/usr/bin/env r2", "# Symbol recovery script"]
        for sym, addrs in self.recovered.items():
            if sym.startswith("_"): continue
            limit = min(3, len(addrs))
            for i in range(limit):
                lines.append(f"afn {sym}_{hex(addrs[i])[2:]} @ {hex(addrs[i])}")
        script = "\n".join(lines)
        if output_script:
            with open(output_script,'w') as f: f.write(script)
            logger.info(f"r2 script exported: {output_script}")
        return script

    def run(self):
        symbols = self.recover_bsp_symbols()
        sym_count = sum(1 for k in symbols if not k.startswith("_"))
        success = sym_count > 0
        result_symbols = {}
        for sym, addrs in symbols.items():
            if not sym.startswith("_"): result_symbols[sym] = [hex(a) for a in addrs]
            else: result_symbols[sym] = addrs
        return {'success': success, 'recovered_symbols': result_symbols,
                'total_functions': len(self._func_list),
                'recovery_rate': round(sym_count / max(1, len(self._func_list)), 3)}

def recover_firmware_symbols(firmware_path):
    return FirmwareSymbolRecoverer(firmware_path).run()
