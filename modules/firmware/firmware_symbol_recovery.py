import logging
import os
import re
import subprocess
import json

logger = logging.getLogger(__name__)


class BSPFingerprint:
    _BSP_SIGNATURES = {
        # ARM CMSIS
        "SystemInit": {
            "patterns": [b'\x00\xb5\x00\xf0', b'SystemCoreClock'],
            "arch": "ARM",
            "description": "System clock initialization"
        },
        "SysTick_Handler": {
            "patterns": [b'SysTick', b'\x70\x47'],
            "arch": "ARM",
            "description": "System tick interrupt handler"
        },
        "UART_Init": {
            "patterns": [b'UART', b'USART', b'baud', b'BRR'],
            "arch": "ARM",
            "description": "UART initialization"
        },
        # FreeRTOS
        "vTaskStartScheduler": {
            "patterns": [b'FreeRTOS', b'SysTick', b'PendSV'],
            "arch": "ARM",
            "description": "FreeRTOS scheduler start"
        },
        "xQueueCreate": {
            "patterns": [b'Queue', b'uxQueueNumber', b'pcQueueName'],
            "arch": "ARM",
            "description": "FreeRTOS queue creation"
        },
        # STM32 HAL
        "HAL_Init": {
            "patterns": [b'HAL_Init', b'Error_Handler', b'HAL_IncTick'],
            "arch": "ARM",
            "description": "STM32 HAL library initialization"
        },
        "HAL_GPIO_WritePin": {
            "patterns": [b'GPIO', b'BSRR', b'ODR'],
            "arch": "ARM",
            "description": "GPIO pin write"
        },
        # Common startup code
        "Reset_Handler": {
            "patterns": [b'\x00\x00\x00\x20', b'Reset_Handler', b'__main'],
            "arch": "ARM",
            "description": "Reset vector handler"
        },
        "memcpy": {
            "patterns": [b'\x03\xc4', b'\x40\xf8\x04'],
            "arch": "ARM/Thumb",
            "description": "Memory copy (Thumb optimized)"
        },
        "memset": {
            "patterns": [b'\x00\x23', b'\xc0\xf8'],
            "arch": "ARM/Thumb",
            "description": "Memory set (Thumb optimized)"
        },
    }

    _HARDWARE_PATTERNS = {
        "WiFi_Init": [(b'WiFi', b'wifi_', b'WLAN')],
        "BLE_Init": [(b'BLE', b'ble_', b'GAP', b'GATT')],
        "SPI_Transfer": [(b'SPI', b'spi_', b'MOSI')],
        "I2C_Master": [(b'I2C', b'i2c_', b'SCL')],
    }


class FirmwareSymbolRecoverer:

    def __init__(self, firmware_path):
        self.firmware_path = os.path.abspath(firmware_path)
        self._data = b""
        self._func_list = []
        self.recovered = {}

    def _load(self):
        try:
            with open(self.firmware_path, 'rb') as f:
                self._data = f.read()
        except Exception:
            logger.debug("firmware data load failed", exc_info=True)

        try:
            result = subprocess.run(
                ['r2', '-q', '-c', 'aflj; q', self.firmware_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            if result.stdout.strip():
                self._func_list = json.loads(result.stdout)
            else:
                self._func_list = []
        except Exception:
            logger.debug("r2 invocation failed, continuing with empty function list", exc_info=True)

    def _pattern_match(self, patterns):
        matches = []
        for pat in patterns:
            pos = 0
            while True:
                idx = self._data.find(pat, pos)
                if idx == -1:
                    break
                matches.append(idx)
                pos = idx + 1
        return matches

    def recover_bsp_symbols(self):
        self._load()

        for func_name, sig_info in BSPFingerprint._BSP_SIGNATURES.items():
            matches = self._pattern_match(sig_info["patterns"])

            if matches:
                func_addrs = []
                for match_pos in matches:
                    for func in self._func_list:
                        offset = func.get('offset', 0)
                        if abs(match_pos - offset) < 64:
                            func_addrs.append(offset)
                            break

                if func_addrs:
                    dedup = []
                    for addr in func_addrs:
                        if addr not in dedup:
                            dedup.append(addr)

                    self.recovered[func_name] = dedup

        return self.recovered

    def apply_to_r2(self, output_script=""):
        """Generate r2 script to apply recovered symbols."""
        lines = [
            "#!/usr/bin/env r2",
            "# Symbol recovery script",
        ]

        for sym, addrs in self.recovered.items():
            limit = min(3, len(addrs))
            for i in range(limit):
                addr = addrs[i]
                lines.append(f"afn {sym}_{hex(addr)[2:]} @ {hex(addr)}")

        script = "\n".join(lines)

        if output_script:
            with open(output_script, 'w') as f:
                f.write(script)
            logger.info(f"r2 recovery script exported: {output_script}")

        return script

    def run(self):
        symbols = self.recover_bsp_symbols()

        sym_count = len(symbols)
        success = sym_count > 0

        result_symbols = {}
        for sym, addrs in symbols.items():
            hex_addrs = [hex(a) for a in addrs]
            result_symbols[sym] = hex_addrs

        func_len = len(self._func_list)
        denom = max(1, func_len)

        recovery_rate = round(sym_count / denom, 3)

        return {
            'success': success,
            'recovered_symbols': result_symbols,
            'total_functions': func_len,
            'recovery_rate': recovery_rate,
        }


def recover_firmware_symbols(firmware_path):
    return FirmwareSymbolRecoverer(firmware_path).run()
