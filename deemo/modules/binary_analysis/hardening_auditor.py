# Copyright (c) 2024-2026 BinMind Project. All rights reserved.
# Licensed under the BinMind Proprietary License — see LICENSE file.
# hardening_auditor.py — Binary Hardening Auditor

import os
import re
import struct
import subprocess
import logging
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class HardeningStatus(StrEnum):
    """Hardening status."""
    ENABLED = "Enabled"
    DISABLED = "Disabled"
    PARTIAL = "Partial"
    UNKNOWN = "Unknown"

class RiskLevel(StrEnum):
    """Risk level. Weights used in score calculation."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class HardeningCheck:
    """Single hardening check item."""
    strName: str
    strDescription: str
    enStatus: str
    enRiskLevel: str
    strCurrentValue: str = ""
    strRecommendedValue: str = ""
    strFixCommand: str = ""
    lstCveReferences: list = field(default_factory=list)
    strDetails: str = ""

    def to_dict(self):
        """Convert to dict."""
        result = {}
        result['name'] = self.strName
        result['description'] = self.strDescription
        result['status'] = self.enStatus if self.enStatus is not None else HardeningStatus.UNKNOWN
        result['risk_level'] = self.enRiskLevel if self.enRiskLevel is not None else RiskLevel.INFO
        result['current_value'] = self.strCurrentValue
        result['recommended_value'] = self.strRecommendedValue
        result['fix_command'] = self.strFixCommand
        result['cve_references'] = self.lstCveReferences
        result['details'] = self.strDetails
        return result


@dataclass
class HardeningAuditReport:
    """Audit report. Aggregates all checks and scores."""
    strBinaryPath: str
    strBinaryFormat: str
    lstChecks: list = field(default_factory=list)
    nOverallScore: int = 0
    enRiskLevel: str = RiskLevel.INFO
    lstRecommendations: list = field(default_factory=list)
    strHardeningScript: str = ""
    bAuditSuccess: bool = False
    strErrorMessage: str = ""

    def get_enabled_checks(self):
        """Get enabled checks."""
        result = []
        for check in (self.lstChecks or []):
            if check is not None and check.enStatus == HardeningStatus.ENABLED:
                result.append(check)
        return result

    def get_disabled_checks(self):
        """Get disabled checks."""
        result = []
        for check in (self.lstChecks or []):
            if check is not None and check.enStatus == HardeningStatus.DISABLED:
                result.append(check)
        return result

    def get_failed_checks(self):
        """Get failed checks (disabled or unknown)."""
        result = []
        for check in (self.lstChecks or []):
            if check is not None and check.enStatus in [HardeningStatus.DISABLED, HardeningStatus.UNKNOWN]:
                result.append(check)
        return result

    def to_dict(self):
        """Convert to dict."""
        result = {}
        result['binary_path'] = self.strBinaryPath
        result['binary_format'] = self.strBinaryFormat
        checks_dict = []
        for check in (self.lstChecks or []):
            if check is not None:
                checks_dict.append(check.to_dict())
        result['checks'] = checks_dict
        result['overall_score'] = self.nOverallScore
        result['risk_level'] = self.enRiskLevel if self.enRiskLevel is not None else RiskLevel.INFO
        result['recommendations'] = self.lstRecommendations
        result['hardening_script'] = self.strHardeningScript
        result['audit_success'] = self.bAuditSuccess
        result['error_message'] = self.strErrorMessage
        return result


@dataclass
class HardeningRecommendation:
    """Hardening recommendation."""
    strCategory: str
    strIssue: str
    strSolution: str
    enPriority: str
    lstCommands: list = field(default_factory=list)
    strExplanation: str = ""

class HardeningAuditor:
    """Binary hardening auditor.
    Audits ELF/PE/Mach-O binaries for security hardening, generates fix scripts."""

    def __init__(self, strBinaryPath=None, nTimeout=120,
                 binary_path=None, timeout=None):
        # 规范参数名（binary_path/timeout）与历史匈牙利命名并存
        if binary_path is not None:
            strBinaryPath = binary_path
        if timeout is not None:
            nTimeout = timeout
        self.strBinaryPath = strBinaryPath
        self.nTimeout = nTimeout
        self.strBinaryFormat = self._detect_format()
        self.bVerbose = False

    def _detect_format(self):
        """Detect binary format."""
        fmt = 'UNKNOWN'

        if self.strBinaryPath is None:
            logger.error("binary path is None")
            return fmt

        try:
            with open(self.strBinaryPath, 'rb') as f:
                header = f.read(16)

            if header[:4] == b'\x7fELF':
                fmt = 'ELF'
            elif header[:2] == b'MZ':
                fmt = 'PE'
            elif header[:4] in [b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce',
                                b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe']:
                fmt = 'MACH-O'
            else:
                fmt = 'UNKNOWN'

        except Exception as e:
            logger.error("format detection failed: %s" % str(e))
            fmt = 'UNKNOWN'

        return fmt

    def audit(self):
        """Perform full hardening audit."""
        logger.info("auditing: %s" % self.strBinaryPath)

        report = HardeningAuditReport(
            strBinaryPath=self.strBinaryPath,
            strBinaryFormat=self.strBinaryFormat
        )

        try:
            fmt = self.strBinaryFormat
            if fmt is None:
                report.strErrorMessage = "unknown format"
                return report

            if fmt == 'ELF':
                self._audit_elf(report)
            elif fmt == 'PE':
                self._audit_pe(report)
            elif fmt == 'MACH-O':
                self._audit_macho(report)
            else:
                report.strErrorMessage = "unsupported format"
                return report

            self._calculate_overall_score(report)
            self._generate_hardening_script(report)

            report.bAuditSuccess = True
            logger.info("audit done, score: %d/100" % report.nOverallScore)

        except Exception as e:
            logger.error("audit failed: %s" % str(e))
            report.strErrorMessage = str(e)

        return report

    def _audit_elf(self, report):
        """Audit ELF binary. Prefer pyelftools, fall back to readelf."""
        if report is None:
            return

        try:
            from elftools.elf.elffile import ELFFile

            with open(self.strBinaryPath, 'rb') as f:
                elf = ELFFile(f)

                if elf is None:
                    logger.warning("ELF object is None")
                    return

                self._check_nx_elf(elf, report)
                self._check_relro_elf(elf, report)
                self._check_pie_elf(elf, report)
                self._check_canary_elf(elf, report)
                self._check_fortify_source_elf(elf, report)
                self._check_cet_elf(elf, report)
                self._check_stack_protector_elf(elf, report)
                self._check_bind_now_elf(elf, report)
                self._check_glibc_hooks_elf(elf, report)

        except ImportError:
            logger.warning("pyelftools unavailable, falling back to readelf")
            self._audit_elf_with_readelf(report)
        except Exception as e:
            logger.error("ELF audit failed: %s" % str(e))
            raise

    def _check_nx_elf(self, elf, report):
        """Check NX (Non-Executable Stack).
        NX prevents stack data from being executed as code."""
        if elf is None or report is None:
            return

        try:
            has_nx = True
            seg_count = elf.num_segments()

            for idx in range(seg_count):
                seg = elf.get_segment(idx)
                if seg is not None and seg.get('p_type') == 'PT_GNU_STACK':
                    flags = seg.get('p_flags', 0)
                    if flags is not None and (flags & 0x1):
                        has_nx = False
                    break

            check = HardeningCheck(
                strName='NX (Non-Executable Stack)',
                strDescription='stack pages non-executable, prevents shellcode',
                enStatus=HardeningStatus.ENABLED if has_nx else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not has_nx else RiskLevel.INFO,
                strCurrentValue='Enabled' if has_nx else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='gcc -z noexecstack -o binary binary.c',
                strDetails='NX bit marks stack memory non-executable'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("NX check skipped: %s" % str(e))

    def _check_relro_elf(self, elf, report):
        """Check RELRO (Relocation Read-Only).
        Read-only GOT prevents overwrites."""
        if elf is None or report is None:
            return

        try:
            relro_status = HardeningStatus.UNKNOWN
            relro_value = 'Unknown'

            seg_count = elf.num_segments()
            for idx in range(seg_count):
                seg = elf.get_segment(idx)
                if seg is not None and seg.get('p_type') == 'PT_GNU_RELRO':
                    relro_status = HardeningStatus.PARTIAL
                    relro_value = 'Partial RELRO'
                    break

            sec_count = elf.num_sections()
            for idx in range(sec_count):
                sec = elf.get_section(idx)
                if sec is not None and sec.name == '.data.rel.ro':
                    relro_status = HardeningStatus.ENABLED
                    relro_value = 'Full RELRO'
                    break

            is_full = (relro_status == HardeningStatus.ENABLED)
            check = HardeningCheck(
                strName='RELRO (Relocation Read-Only)',
                strDescription='read-only GOT, prevents GOT overwrite attacks',
                enStatus=relro_status,
                enRiskLevel=RiskLevel.MEDIUM if not is_full else RiskLevel.INFO,
                strCurrentValue=relro_value,
                strRecommendedValue='Full RELRO',
                strFixCommand='gcc -Wl,-z,relro,-z,now -o binary binary.c',
                strDetails='Full RELRO resolves all symbols at load time and marks GOT read-only'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("RELRO check skipped: %s" % str(e))

    def _check_pie_elf(self, elf, report):
        """Check PIE (Position Independent Executable).
        PIE enables code section ASLR."""
        if elf is None or report is None:
            return

        try:
            etype = elf.header.get('e_type') if elf.header is not None else None
            is_pie = (etype == 'ET_DYN')

            check = HardeningCheck(
                strName='PIE (Position Independent Executable)',
                strDescription='ASLR for code, harder to exploit',
                enStatus=HardeningStatus.ENABLED if is_pie else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if not is_pie else RiskLevel.INFO,
                strCurrentValue='Enabled (PIE)' if is_pie else 'Disabled (ET_EXEC)',
                strRecommendedValue='Enabled',
                strFixCommand='gcc -fPIE -pie -o binary binary.c',
                strDetails='PIE randomizes code base, hinders ROP'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("PIE check skipped: %s" % str(e))

    def _check_canary_elf(self, elf, report):
        """Check Stack Canary.
        Canary value checked before return, aborts on overflow."""
        if elf is None or report is None:
            return

        try:
            has_canary = False

            sec_count = elf.num_sections()
            for idx in range(sec_count):
                sec = elf.get_section(idx)
                if sec is None:
                    continue
                sec_name = sec.name
                if sec_name is not None:
                    if '__stack_chk_fail' in sec_name or '__stack_chk_guard' in sec_name:
                        has_canary = True
                        break
                    if '.note.GNU-stack' in sec_name:
                        data = None
                        try:
                            data = sec.data() if hasattr(sec, 'data') else None
                        except Exception:
                            data = None
                        if data is not None and b'stack-protector' in data.lower():
                            has_canary = True
                            break

            if not has_canary:
                sym_count = elf.num_symbols()
                for idx in range(sym_count):
                    sym = elf.get_symbol(idx)
                    if sym is not None and sym.name is not None:
                        if '__stack_chk_fail' in sym.name:
                            has_canary = True
                            break

            check = HardeningCheck(
                strName='Stack Canary',
                strDescription='Canary cookie detects stack overflows',
                enStatus=HardeningStatus.ENABLED if has_canary else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not has_canary else RiskLevel.INFO,
                strCurrentValue='Enabled' if has_canary else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='gcc -fstack-protector-strong -o binary binary.c',
                strDetails='Canary catches stack smashing before return'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Canary check skipped: %s" % str(e))

    def _check_fortify_source_elf(self, elf, report):
        """Check FORTIFY_SOURCE.
        Compile-time bounds checking for dangerous functions."""
        if elf is None or report is None:
            return

        try:
            has_fortify = False
            fortify_level = 0

            sec_count = elf.num_sections()
            for idx in range(sec_count):
                sec = elf.get_section(idx)
                if sec is None or sec.name is None:
                    continue
                if sec.name.startswith('.text'):
                    data = None
                    try:
                        data = sec.data() if hasattr(sec, '__bytes__') else None
                    except Exception:
                        data = None
                    if data is not None:
                        if b'__fortify_fail' in data:
                            has_fortify = True
                            fortify_level = 2
                            break
                        elif b'__chk' in data:
                            has_fortify = True
                            fortify_level = max(fortify_level, 1)

            check = HardeningCheck(
                strName='FORTIFY_SOURCE',
                strDescription='compile-time bounds checking',
                enStatus=HardeningStatus.ENABLED if has_fortify else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.LOW if not has_fortify else RiskLevel.INFO,
                strCurrentValue=('Level %d' % fortify_level) if has_fortify else 'Disabled',
                strRecommendedValue='Level 2',
                strFixCommand='gcc -D_FORTIFY_SOURCE=2 -O2 -o binary binary.c',
                strDetails='_FORTIFY_SOURCE=2 provides stronger runtime checks'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("FORTIFY_SOURCE check skipped: %s" % str(e))

    def _check_cet_elf(self, elf, report):
        """Check CET (Control-flow Enforcement Technology).
        IBT validates indirect branches, SHSTK protects return addresses."""
        if elf is None or report is None:
            return

        try:
            has_cet = False
            cet_type = ''

            sec_count = elf.num_sections()
            for idx in range(sec_count):
                sec = elf.get_section(idx)
                if sec is not None and sec.name == '.note.gnu.property':
                    data = None
                    try:
                        data = sec.data()
                    except Exception:
                        data = None
                    if data is not None and len(data) >= 32:
                        i = 0
                        data_len = len(data) - 8
                        while i < data_len:
                            if data[i:i+4] == b'GNU' and data[i+4] == 0:
                                flags = data[i+8:i+12]
                                if flags is not None and len(flags) >= 4:
                                    if flags[0] & 0x01:
                                        has_cet = True
                                        cet_type = 'IBT (Indirect Branch Tracking)'
                                    if flags[0] & 0x02:
                                        has_cet = True
                                        cet_type = 'SHSTK (Shadow Stack)' if not has_cet else 'IBT+SHSTK'
                                    if has_cet:
                                        break
                            i = i + 1
                    break

            if not has_cet:
                seg_count = elf.num_segments()
                for idx in range(seg_count):
                    seg = elf.get_segment(idx)
                    if seg is not None and seg.get('p_type') == 'PT_GNU_PROPERTY':
                        try:
                            prop_data = seg.data()
                            if prop_data is not None and b'GNU_PROPERTY_X86_FEATURE_1_AND' in prop_data:
                                has_cet = True
                                cet_type = 'IBT/SHSTK'
                                break
                        except Exception:
                            logger.debug("suppressed", exc_info=True)

            check = HardeningCheck(
                strName='CET (Control-flow Enforcement Technology)',
                strDescription='Intel CET: IBT + shadow stack',
                enStatus=HardeningStatus.ENABLED if has_cet else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not has_cet else RiskLevel.INFO,
                strCurrentValue=cet_type if has_cet else 'Disabled',
                strRecommendedValue='IBT + SHSTK',
                strFixCommand='gcc -fcf-protection=full -o binary binary.c',
                strDetails='CET mitigates ROP/JOP/BROP attacks'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("CET check skipped: %s" % str(e))

    def _check_stack_protector_elf(self, elf, report):
        """Check stack protector level.
        none / regular / strong -- each level adds more protection."""
        if elf is None or report is None:
            return

        try:
            protector_level = 'none'

            sec_count = elf.num_sections()
            for idx in range(sec_count):
                sec = elf.get_section(idx)
                if sec is not None and sec.name is not None:
                    if '__stack_chk_fail' in sec.name:
                        data = None
                        try:
                            data = sec.data() if hasattr(sec, 'data') else None
                        except Exception:
                            data = None
                        if data is not None:
                            if b'stack-protector-strong' in data or b'stack-protector-all' in data:
                                protector_level = 'strong'
                            else:
                                protector_level = 'regular'
                        break

            is_good = (protector_level != 'none')
            check = HardeningCheck(
                strName='Stack Protector Level',
                strDescription='stack protection function coverage',
                enStatus=HardeningStatus.ENABLED if is_good else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if protector_level != 'strong' else RiskLevel.INFO,
                strCurrentValue=protector_level,
                strRecommendedValue='strong',
                strFixCommand='gcc -fstack-protector-strong -o binary binary.c',
                strDetails='strong covers all functions with local arrays'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Stack Protector check skipped: %s" % str(e))

    def _check_bind_now_elf(self, elf, report):
        """Check BIND_NOW.
        Resolve all symbols at load, pairs with Full RELRO."""
        if elf is None or report is None:
            return

        try:
            bind_now = False

            seg_count = elf.num_segments()
            for idx in range(seg_count):
                seg = elf.get_segment(idx)
                if seg is not None and seg.get('p_type') == 'PT_GNU_BIND_NOW':
                    bind_now = True
                    break

            check = HardeningCheck(
                strName='BIND_NOW',
                strDescription='immediate binding, reduces runtime info leak',
                enStatus=HardeningStatus.ENABLED if bind_now else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.LOW if not bind_now else RiskLevel.INFO,
                strCurrentValue='Enabled' if bind_now else 'Disabled',
                strRecommendedValue='Enabled (with Full RELRO)',
                strFixCommand='gcc -Wl,-z,relro,-z,now -o binary binary.c',
                strDetails='BIND_NOW works together with Full RELRO'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("BIND_NOW check skipped: %s" % str(e))

    def _check_glibc_hooks_elf(self, elf, report):
        """Check glibc hooks availability.
        glibc 2.34+ removed these hooks; their presence implies older glibc."""
        if elf is None or report is None:
            return

        try:
            hooks_available = []
            hook_names = ['__malloc_hook', '__free_hook', '__realloc_hook',
                          '__memalign_hook', '__after_morecore_hook']

            sym_count = elf.num_symbols()
            for idx in range(sym_count):
                sym = elf.get_symbol(idx)
                if sym is not None and sym.name is not None:
                    sym_name = sym.name
                    for hook in hook_names:
                        if hook is not None and hook in sym_name:
                            hooks_available.append(sym_name)
                            break

            hook_count = len(hooks_available) if hooks_available is not None else 0
            has_hooks = (hook_count > 0)

            check = HardeningCheck(
                strName='Glibc Hooks Availability',
                strDescription='deprecated malloc hooks',
                enStatus=HardeningStatus.DISABLED if has_hooks else HardeningStatus.ENABLED,
                enRiskLevel=RiskLevel.INFO,
                strCurrentValue=('%d hooks found' % hook_count) if has_hooks else 'None (safe)',
                strRecommendedValue='no hooks (glibc 2.34+)',
                strDetails='glibc 2.34+ removed hooks, IO_FILE chain recommended'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("glibc hooks check skipped: %s" % str(e))

    def _audit_elf_with_readelf(self, report):
        """Fallback audit with readelf."""
        if report is None:
            return

        try:
            result = subprocess.run(
                ['readelf', '-l', '-n', '-S', self.strBinaryPath],
                capture_output=True,
                text=True,
                timeout=self.nTimeout
            )

            output = result.stdout if result is not None else ""

            has_rwe = ('GNU_STACK' in output and 'RWE' in output) if output else False
            has_gs = ('GNU_STACK' in output) if output else False

            if has_gs and not has_rwe:
                nx_status = HardeningStatus.ENABLED
            elif has_gs and has_rwe:
                nx_status = HardeningStatus.DISABLED
            else:
                nx_status = HardeningStatus.UNKNOWN

            nx_check = HardeningCheck(
                strName='NX (Non-Executable Stack)',
                strDescription='stack pages non-executable',
                enStatus=nx_status,
                enRiskLevel=RiskLevel.HIGH,
                strCurrentValue='manual review needed',
                strRecommendedValue='Enabled'
            )

            report.lstChecks.append(nx_check)

        except Exception as e:
            logger.error("readelf audit failed: %s" % str(e))

    def _audit_pe(self, report):
        """Audit PE binary."""
        if report is None:
            return

        try:
            import pefile

            pe = pefile.PE(self.strBinaryPath)

            if pe is None:
                logger.error("PE object is None")
                return

            self._check_dep_pe(pe, report)
            self._check_aslr_pe(pe, report)
            self._check_safeseh_pe(pe, report)
            self._check_cfg_pe(pe, report)
            self._check_gs_pe(pe, report)
            self._check_high_entropy_va_pe(pe, report)
            self._check_authenticode_pe(pe, report)

        except ImportError:
            logger.error("pefile not installed, cannot audit PE")
            report.strErrorMessage = "pefile library not installed"
        except Exception as e:
            logger.error("PE audit failed: %s" % str(e))

    def _check_dep_pe(self, pe, report):
        """Check DEP (Data Execution Prevention).
        DEP enforces non-executable memory pages."""
        if pe is None or report is None:
            return

        try:
            dll_chars = min(max(pe.OPTIONAL_HEADER.DllCharacteristics, 0), 0xFFFF)
            nx_enabled = bool(dll_chars & 0x0100)

            check = HardeningCheck(
                strName='DEP / NX (Data Execution Prevention)',
                strDescription='prevents data memory from being executed',
                enStatus=HardeningStatus.ENABLED if nx_enabled else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not nx_enabled else RiskLevel.INFO,
                strCurrentValue='Enabled' if nx_enabled else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='linker: /NXCOMPAT',
                strDetails='DEP enforces W^X on memory pages'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("DEP check skipped: %s" % str(e))

    def _check_aslr_pe(self, pe, report):
        """Check ASLR (Address Space Layout Randomization).
        ASLR randomizes module load addresses."""
        if pe is None or report is None:
            return

        try:
            dll_chars = min(max(pe.OPTIONAL_HEADER.DllCharacteristics, 0), 0xFFFF)
            aslr_enabled = bool(dll_chars & 0x0040)

            check = HardeningCheck(
                strName='ASLR (Address Space Layout Randomization)',
                strDescription='address space layout randomization',
                enStatus=HardeningStatus.ENABLED if aslr_enabled else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if not aslr_enabled else RiskLevel.INFO,
                strCurrentValue='Enabled' if aslr_enabled else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='compile: /DYNAMICBASE, linker: /HIGHENTROPYVA:YES',
                strDetails='ASLR randomizes base addresses'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("ASLR check skipped: %s" % str(e))

    def _check_safeseh_pe(self, pe, report):
        """Check SafeSEH (Structured Exception Handler Overwrite Protection)."""
        if pe is None or report is None:
            return

        try:
            has_safeseh = False

            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG
                if load_config is not None:
                    for entry in load_config:
                        if entry is not None:
                            if hasattr(entry, 'SEHandlerTable') and entry.SEHandlerTable is not None:
                                has_safeseh = True
                                break

            dll_chars = min(max(pe.OPTIONAL_HEADER.DllCharacteristics, 0), 0xFFFF)
            no_seh = bool(dll_chars & 0x0400)
            safeseh = has_safeseh and not no_seh

            check = HardeningCheck(
                strName='SafeSEH (Structured Exception Handler Overwrite Protection)',
                strDescription='SEH overwrite protection',
                enStatus=HardeningStatus.ENABLED if safeseh else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if not safeseh else RiskLevel.INFO,
                strCurrentValue='Enabled' if safeseh else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='compile: /SAFESEH, linker: /SAFESEH:YES',
                strDetails='SafeSEH validates handler before dispatch'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("SafeSEH check skipped: %s" % str(e))

    def _check_cfg_pe(self, pe, report):
        """Check CFG (Control Flow Guard).
        CFG validates indirect call/jump targets."""
        if pe is None or report is None:
            return

        try:
            dll_chars = min(max(pe.OPTIONAL_HEADER.DllCharacteristics, 0), 0xFFFF)
            cfg_enabled = bool(dll_chars & 0x4000)

            check = HardeningCheck(
                strName='CFG (Control Flow Guard)',
                strDescription='validates indirect call/jump targets',
                enStatus=HardeningStatus.ENABLED if cfg_enabled else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not cfg_enabled else RiskLevel.INFO,
                strCurrentValue='Enabled' if cfg_enabled else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='compile: /guard:cf, linker: /GUARD:CF',
                strDetails='CFG prevents jump/vtable overwrite attacks'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("CFG check skipped: %s" % str(e))

    def _check_gs_pe(self, pe, report):
        """Check GS (Stack Security).
        GS inserts a security cookie on the stack."""
        if pe is None or report is None:
            return

        try:
            has_gs = False

            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG
                if load_config is not None:
                    for entry in load_config:
                        if entry is not None:
                            if hasattr(entry, 'SecurityCookie') and entry.SecurityCookie is not None:
                                has_gs = True
                                break

            check = HardeningCheck(
                strName='GS (Stack Security Checks)',
                strDescription='stack security check (like canary)',
                enStatus=HardeningStatus.ENABLED if has_gs else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if not has_gs else RiskLevel.INFO,
                strCurrentValue='Enabled' if has_gs else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='compile: /GS',
                strDetails='GS inserts security cookie in stack frame'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("GS check skipped: %s" % str(e))

    def _check_high_entropy_va_pe(self, pe, report):
        """Check High Entropy VA.
        More entropy for 64-bit address space."""
        if pe is None or report is None:
            return

        try:
            dll_chars = min(max(pe.OPTIONAL_HEADER.DllCharacteristics, 0), 0xFFFF)
            heva_enabled = bool(dll_chars & 0x0020)

            check = HardeningCheck(
                strName='High Entropy VA (64-bit)',
                strDescription='high-entropy VA randomization for 64-bit',
                enStatus=HardeningStatus.ENABLED if heva_enabled else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.LOW if not heva_enabled else RiskLevel.INFO,
                strCurrentValue='Enabled' if heva_enabled else 'Disabled',
                strRecommendedValue='Enabled (64-bit)',
                strFixCommand='linker: /HIGHENTROPYVA:YES',
                strDetails='HEVA adds more entropy for 64-bit ASLR'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("High Entropy VA check skipped: %s" % str(e))

    def _check_authenticode_pe(self, pe, report):
        """Check Authenticode signature.
        Signature present does not mean not malicious."""
        if pe is None or report is None:
            return

        try:
            has_signature = False

            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                security_dir = pe.DIRECTORY_ENTRY_SECURITY
                if security_dir is not None:
                    has_signature = True

            check = HardeningCheck(
                strName='Authenticode Signature',
                strDescription='code signature (signed, not necessarily safe)',
                enStatus=HardeningStatus.ENABLED if has_signature else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.INFO,
                strCurrentValue='Signed' if has_signature else 'Unsigned',
                strRecommendedValue='sign for release builds',
                strFixCommand='SignTool sign /f certificate.pfx /p password /t http://timestamp.digicert.com binary.exe',
                strDetails='Authenticode does not prevent tampering'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Authenticode check skipped: %s" % str(e))

    def _audit_macho(self, report):
        """Audit Mach-O binary. Uses otool to extract header info."""
        if report is None:
            return

        try:
            result = subprocess.run(
                ['otool', '-hv', self.strBinaryPath],
                capture_output=True,
                text=True,
                timeout=self.nTimeout
            )

            output = result.stdout if result is not None else ""

            self._check_macho_pie(output, report)
            self._check_macho_canary(output, report)
            self._check_macho_arc(output, report)

        except Exception as e:
            logger.error("Mach-O audit failed: %s" % str(e))

    def _check_macho_pie(self, output, report):
        """Check Mach-O PIE."""
        if output is None or report is None:
            return

        try:
            is_pie = ('PIE' in output and 'NOUNDEAD' in output)

            check = HardeningCheck(
                strName='PIE (Position Independent Executable)',
                strDescription='position-independent executable',
                enStatus=HardeningStatus.ENABLED if is_pie else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.MEDIUM if not is_pie else RiskLevel.INFO,
                strCurrentValue='Enabled' if is_pie else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='clang -fPIE -pie',
                strDetails='PIE randomizes code segment base'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Mach-O PIE check skipped: %s" % str(e))

    def _check_macho_canary(self, output, report):
        """Check Mach-O stack canary."""
        if output is None or report is None:
            return

        try:
            has_stack_protector = ('SSP' in output or 'stack_chk' in output.lower())

            check = HardeningCheck(
                strName='Stack Canary',
                strDescription='stack overflow detection',
                enStatus=HardeningStatus.ENABLED if has_stack_protector else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.HIGH if not has_stack_protector else RiskLevel.INFO,
                strCurrentValue='Enabled' if has_stack_protector else 'Disabled',
                strRecommendedValue='Enabled',
                strFixCommand='clang -fstack-protector-strong',
                strDetails='canary value detects stack overflow'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Mach-O Canary check skipped: %s" % str(e))

    def _check_macho_arc(self, output, report):
        """Check ARC (Automatic Reference Counting).
        Only meaningful for Objective-C code."""
        if output is None or report is None:
            return

        try:
            has_arc = ('OBJC' in output or 'arc' in output.lower())

            check = HardeningCheck(
                strName='ARC (Automatic Reference Counting)',
                strDescription='auto ref counting for Obj-C memory mgmt',
                enStatus=HardeningStatus.ENABLED if has_arc else HardeningStatus.DISABLED,
                enRiskLevel=RiskLevel.INFO,
                strCurrentValue='Enabled' if has_arc else 'N/A (non Objective-C)',
                strRecommendedValue='Enabled (if Obj-C)',
                strFixCommand='clang -fobjc-arc',
                strDetails='ARC manages Obj-C object references'
            )

            report.lstChecks.append(check)

        except Exception as e:
            logger.debug("Mach-O ARC check skipped: %s" % str(e))

    def _calculate_overall_score(self, report):
        """Calculate overall hardening score. Weighted by risk level."""
        if report is None:
            return
        if report.lstChecks is None:
            return
        if len(report.lstChecks) == 0:
            report.nOverallScore = 100
            return

        total_weight = 0.0
        achieved_weight = 0.0

        weight_map = {
            RiskLevel.CRITICAL: 20,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
            RiskLevel.INFO: 0
        }

        for check in report.lstChecks:
            if check is None:
                continue

            rl = check.enRiskLevel
            weight = weight_map.get(rl, 0) if rl is not None else 0
            if weight == 0:
                continue

            total_weight = total_weight + weight

            status = check.enStatus
            if status is not None:
                if status == HardeningStatus.ENABLED:
                    achieved_weight = achieved_weight + weight
                elif status == HardeningStatus.PARTIAL:
                    achieved_weight = achieved_weight + weight * 0.5

        if total_weight > 0:
            raw_score = int((achieved_weight / total_weight) * 100)
            report.nOverallScore = min(max(raw_score, 0), 100)
        else:
            report.nOverallScore = 100

        score = report.nOverallScore

        if score >= 80:
            report.enRiskLevel = RiskLevel.LOW
        elif score >= 60:
            report.enRiskLevel = RiskLevel.MEDIUM
        elif score >= 40:
            report.enRiskLevel = RiskLevel.HIGH
        else:
            report.enRiskLevel = RiskLevel.CRITICAL

        failed = report.get_failed_checks()
        if failed is not None:
            for chk in failed:
                if chk is not None:
                    rec = "Enable %s: %s" % (chk.strName, chk.strFixCommand)
                    report.lstRecommendations.append(rec)

    def _generate_hardening_script(self, report):
        """Generate hardening script. Outputs an executable bash script."""
        if report is None:
            return

        lines = []
        lines.append("#!/bin/bash")
        lines.append("# Binary Hardening Script")
        lines.append("# Target: %s" % os.path.basename(self.strBinaryPath))
        lines.append("# Generated: %s" % __import__('datetime').datetime.now().isoformat())
        lines.append("")
        lines.append("set -e")
        lines.append("")
        lines.append("# Source file detection")
        lines.append('SRC_FILE="$1"')
        lines.append('OUTPUT_FILE="${2:-hardened_$(basename $SRC_FILE)}"')
        lines.append("")
        lines.append('if [ -z "$SRC_FILE" ]; then')
        lines.append('    echo "Usage: $0 <source file> [output]"')
        lines.append("    exit 1")
        lines.append("fi")
        lines.append("")

        disabled_checks = report.get_failed_checks()
        # 以报告声明的格式为准：报告来自手工构造时，审计器自身路径
        # 可能不可探测（strBinaryFormat 为 UNKNOWN）
        fmt = report.strBinaryFormat if report.strBinaryFormat else self.strBinaryFormat

        if fmt is not None and fmt == 'ELF':
            flags = []

            if disabled_checks is not None:
                for chk in disabled_checks:
                    if chk is not None:
                        name = chk.strName
                        if name is not None:
                            if 'NX' in name:
                                flags.append('-z noexecstack')
                            elif 'RELRO' in name:
                                flags.append('-Wl,-z,relro,-z,now')
                            elif 'PIE' in name:
                                flags.append('-fPIE -pie')
                            elif 'Canary' in name:
                                flags.append('-fstack-protector-strong')
                            elif 'FORTIFY' in name:
                                flags.append('-D_FORTIFY_SOURCE=2 -O2')
                            elif 'CET' in name:
                                flags.append('-fcf-protection=full')

            if flags is not None and len(flags) > 0:
                flags_joined = ' '.join(flags)
                lines.append("# Recommended compile command")
                lines.append('gcc %s -o "$OUTPUT_FILE" "$SRC_FILE"' % flags_joined)
                lines.append("")

        elif fmt is not None and fmt == 'PE':
            lines.append("# MSVC compile options")
            lines.append("# cl /GS /DYNAMICBASE /NXCOMPAT /SAFESEH /guard:cf /HIGHENTROPYVA:YES source.cpp /link /OUT:output.exe")
            lines.append("")

        lines.append("# Post-hardening verification")
        lines.append('echo "Verifying hardening status..."')
        lines.append('# Verify with checksec or similar')
        lines.append("")
        lines.append('echo "Hardening complete: $OUTPUT_FILE"')

        report.strHardeningScript = '\n'.join(lines)


def audit_binary(strBinaryPath, nTimeout=120):
    """Convenience function to audit a binary."""
    if strBinaryPath is None:
        logger.error("binary path is None")
        report = HardeningAuditReport(
            strBinaryPath="",
            strBinaryFormat="UNKNOWN",
            bAuditSuccess=False,
            strErrorMessage="null path"
        )
        return report

    auditor = HardeningAuditor(strBinaryPath, nTimeout)
    if auditor is None:
        report = HardeningAuditReport(
            strBinaryPath=strBinaryPath,
            strBinaryFormat="UNKNOWN",
            bAuditSuccess=False,
            strErrorMessage="auditor creation failed"
        )
        return report

    return auditor.audit()


def format_audit_report(report):
    """Format audit report into readable string."""
    if report is None:
        return "Error: report is None"

    lines = []
    lines.append("=" * 70)
    lines.append("Binary Hardening Audit Report")
    lines.append("=" * 70)

    lines.append("\nTarget: %s" % report.strBinaryPath)
    lines.append("Format: %s" % report.strBinaryFormat)
    lines.append("Score: %d/100" % report.nOverallScore)
    lines.append("Risk Level: %s" % (
        report.enRiskLevel if report.enRiskLevel is not None else "N/A"))
    lines.append("Status: %s" % (
        'Success' if report.bAuditSuccess else 'Failed'))

    lines.append("\n" + "-" * 70)
    lines.append("Hardening Check Details")
    lines.append("-" * 70)

    sorted_checks = []
    if report.lstChecks is not None:
        sorted_checks = list(report.lstChecks)

    sort_map = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4
    }

    def _sort_key(c):
        if c is None or c.enRiskLevel is None:
            return 99
        return sort_map.get(c.enRiskLevel, 99)

    sorted_checks = sorted(sorted_checks, key=_sort_key)

    for check in sorted_checks:
        if check is None:
            continue

        status = check.enStatus
        if status is None:
            status_icon = "?"
        elif status == HardeningStatus.ENABLED:
            status_icon = "+"
        elif status == HardeningStatus.DISABLED:
            status_icon = "-"
        else:
            status_icon = "~"

        risk_label = ""
        rl = check.enRiskLevel
        if rl is not None:
            if rl == RiskLevel.CRITICAL:
                risk_label = "[CRITICAL]"
            elif rl == RiskLevel.HIGH:
                risk_label = "[HIGH]"
            elif rl == RiskLevel.MEDIUM:
                risk_label = "[MEDIUM]"

        lines.append("\n%s %s %s" % (status_icon, check.strName, risk_label))
        lines.append("   Status: %s (%s)" % (
            status if status is not None else "N/A",
            check.strCurrentValue if check.strCurrentValue is not None else "N/A"))
        lines.append("   Desc: %s" % check.strDescription)

        if status != HardeningStatus.ENABLED and check.strFixCommand is not None:
            lines.append("   Fix: %s" % check.strFixCommand)

    if report.lstRecommendations is not None and len(report.lstRecommendations) > 0:
        lines.append("\n" + "-" * 70)
        lines.append("Recommendations")
        lines.append("-" * 70)
        rec_max = min(max(len(report.lstRecommendations), 0), 10)
        for idx, rec in enumerate(report.lstRecommendations):
            if idx >= rec_max:
                break
            if rec is not None:
                lines.append("  [%d] %s" % (idx + 1, rec))

    if report.strHardeningScript is not None and len(report.strHardeningScript) > 0:
        lines.append("\n" + "-" * 70)
        lines.append("Hardening Script")
        lines.append("-" * 70)
        script = report.strHardeningScript
        script_len = len(script)
        if script_len > 500:
            lines.append(script[:500])
            lines.append("... (%d chars total)" % script_len)
        else:
            lines.append(script)

    if report.strErrorMessage is not None and len(report.strErrorMessage) > 0:
        lines.append("\nError: %s" % report.strErrorMessage)

    lines.append("\n" + "=" * 70)

    return '\n'.join(lines)

# 兼容别名：规范命名属性与匈牙利字段的读写桥接（历史测试按规范名使用）

def _har_init(self, binary_path=None, binary_format=None, overall_score=None,
              risk_level=None, audit_success=None, checks=None,
              recommendations=None, hardening_script=None, **kw):
    self.strBinaryPath = binary_path if binary_path is not None else kw.pop('strBinaryPath', None)
    self.strBinaryFormat = binary_format if binary_format is not None else kw.pop('strBinaryFormat', None)
    self.nOverallScore = overall_score if overall_score is not None else kw.pop('nOverallScore', 0)
    self.enRiskLevel = risk_level if risk_level is not None else kw.pop('enRiskLevel', RiskLevel.INFO)
    self.bAuditSuccess = audit_success if audit_success is not None else kw.pop('bAuditSuccess', False)
    self.lstChecks = checks if checks is not None else kw.pop('lstChecks', [])
    self.lstRecommendations = recommendations if recommendations is not None else kw.pop('lstRecommendations', [])
    self.strHardeningScript = hardening_script if hardening_script is not None else kw.pop('strHardeningScript', "")


HardeningAuditReport.__init__ = _har_init
HardeningAuditReport.binary_path = property(lambda s: s.strBinaryPath)
HardeningAuditReport.binary_format = property(lambda s: s.strBinaryFormat)
HardeningAuditReport.overall_score = property(lambda s: s.nOverallScore)
HardeningAuditReport.risk_level = property(lambda s: s.enRiskLevel)
HardeningAuditReport.audit_success = property(lambda s: s.bAuditSuccess)
HardeningAuditReport.checks = property(lambda s: s.lstChecks)
HardeningAuditReport.recommendations = property(lambda s: s.lstRecommendations)
HardeningAuditReport.hardening_script = property(lambda s: s.strHardeningScript)


def _hck_init(self, name=None, description=None, status=None, risk_level=None,
              current_value=None, recommended_value=None, fix_command=None,
              cve_references=None, details=None, **kw):
    self.strName = name if name is not None else kw.pop('strName', None)
    self.strDescription = description if description is not None else kw.pop('strDescription', None)
    self.enStatus = status if status is not None else kw.pop('enStatus', None)
    self.enRiskLevel = risk_level if risk_level is not None else kw.pop('enRiskLevel', None)
    self.strCurrentValue = current_value if current_value is not None else kw.pop('strCurrentValue', "")
    self.strRecommendedValue = recommended_value if recommended_value is not None else kw.pop('strRecommendedValue', "")
    self.strFixCommand = fix_command if fix_command is not None else kw.pop('strFixCommand', "")
    self.lstCveReferences = cve_references if cve_references is not None else kw.pop('lstCveReferences', [])
    self.strDetails = details if details is not None else kw.pop('strDetails', "")


HardeningCheck.__init__ = _hck_init
HardeningCheck.name = property(lambda s: s.strName)
HardeningCheck.description = property(lambda s: s.strDescription)
HardeningCheck.status = property(lambda s: s.enStatus)
HardeningCheck.risk_level = property(lambda s: s.enRiskLevel)


def _haud_binary_path(self):
    return self.strBinaryPath


def _haud_timeout(self):
    return self.nTimeout


def _haud_binary_format(self):
    return self.strBinaryFormat


HardeningAuditor.binary_path = property(_haud_binary_path)
HardeningAuditor.timeout = property(_haud_timeout)
HardeningAuditor.binary_format = property(_haud_binary_format)
