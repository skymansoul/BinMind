#!/usr/bin/env python3
"""
ARM64e增强安全分析——Apple Silicon PAC/BTI深度审计。

分析维度：
  1. PAC指令检测——全量指针认证指令识别
  2. PAC签名gadget——签名神谕与绕过路径扫描
  3. PAC绕过路径——指针替换与重放攻击可行性评估
  4. BTI着陆点校验——间接跳转目标BTI覆盖率与违规报告
  5. JOP/COP gadget检测——PAC上下文下的抗JOP评估
  6. 密钥多样性——IA/IB/DA/DB密钥域使用统计与隔离分析
  7. 签名剥离检测——JIT代码页签名剥离识别
  8. 跨库PAC绕过链——dyld共享缓存跨边界PAC认证转发

技术基础：
  - ARMv8.3-A/ARMv8.6-A指令集静态反汇编模式匹配
  - PAC签名多样性启发式 + BTI覆盖率CFG间接跳转统计
  - JOP候选：间接跳转前N条指令组成的gadget链构造
  - 密钥域隔离：跨库PAC密钥不一致导致的签名/认证错配检测
"""

import logging
import os
import re
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PACKey(str, Enum):
    IA = "IA"
    IB = "IB"
    DA = "DA"
    DB = "DB"
    GA = "GA"
    UNKNOWN = "UNKNOWN"

class PACInstructionType(str, Enum):
    PACIASP = "paciasp"
    PACIBSP = "pacibsp"
    PACIAB = "paciab"
    PACIBAB = "pacibab"
    AUTIASP = "autiasp"
    AUTIBSP = "autibsp"
    AUTIAB = "autiab"
    AUTIBAB = "autibab"
    PACIA = "pacia"
    PACIB = "pacib"
    PACDA = "pacda"
    PACDB = "pacdb"
    PACGA = "pacga"
    AUTIA = "autia"
    AUTIB = "autib"
    AUTDA = "autda"
    AUTDB = "autdb"
    XPACI = "xpaci"
    XPACD = "xpacd"
    RETAB = "retab"
    BRAA = "braa"
    BRAB = "brab"
    BLRAA = "blraa"
    BLRAB = "blrab"
    ERETAA = "eretaa"
    ERETAB = "eretab"
    UNKNOWN = "unknown"

    @property
    def key(self) -> PACKey:
        _m = {
            "paciasp": PACKey.IA, "paciab": PACKey.IA, "pacia": PACKey.IA,
            "autiasp": PACKey.IA, "autiab": PACKey.IA, "autia": PACKey.IA,
            "braa": PACKey.IA, "blraa": PACKey.IA, "eretaa": PACKey.IA,
            "pacibsp": PACKey.IB, "pacibab": PACKey.IB, "pacib": PACKey.IB,
            "autibsp": PACKey.IB, "autibab": PACKey.IB, "autib": PACKey.IB,
            "brab": PACKey.IB, "blrab": PACKey.IB, "eretab": PACKey.IB, "retab": PACKey.IB,
            "pacda": PACKey.DA, "autda": PACKey.DA, "pacdb": PACKey.DB, "autdb": PACKey.DB,
            "pacga": PACKey.GA,
        }
        return _m.get(self.value, PACKey.UNKNOWN)

    @property
    def is_sign(self) -> bool:
        return self.value.startswith("pac")

    @property
    def is_auth(self) -> bool:
        return self.value.startswith("aut") or self.value == "retab"

    @property
    def is_branch(self) -> bool:
        return self.value in ("braa", "brab", "blraa", "blrab", "eretaa", "eretab", "retab")

    @property
    def is_strip(self) -> bool:
        return self.value.startswith("xpac")


class BTIInstructionType(str, Enum):
    BTI_C = "bti c"
    BTI_J = "bti j"
    BTI_JC = "bti jc"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 32, "HIGH": 16, "MEDIUM": 8, "LOW": 4, "INFO": 1}[self.value]


@dataclass
class PACInstruction:
    address: int
    mnemonic: str
    insn_type: PACInstructionType
    key: PACKey
    function_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"addr": f"0x{self.address:X}", "mnemonic": self.mnemonic,
                "type": self.insn_type.value, "key": self.key.value, "func": self.function_name}


@dataclass
class BTIInstruction:
    address: int
    insn_type: BTIInstructionType
    function_name: str = ""
    is_function_entry: bool = False
    missing_preceding: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"addr": f"0x{self.address:X}", "type": self.insn_type.value,
                "func": self.function_name, "entry": self.is_function_entry,
                "missing": self.missing_preceding}


@dataclass
class PACSigningGadget:
    address: int
    sign_insn: str
    source_reg: str
    modifier_reg: str
    key: PACKey
    context: str
    is_oracle: bool
    controllable_modifier: bool
    severity: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {"addr": f"0x{self.address:X}", "sign": self.sign_insn,
                "src": self.source_reg, "mod": self.modifier_reg, "key": self.key.value,
                "oracle": self.is_oracle, "ctrl": self.controllable_modifier, "severity": self.severity.value}


@dataclass
class PACBypassPath:
    source_addr: int
    target_addr: int
    auth_insn: str
    bypass_type: str
    authenticated_ptr: str
    replaceable_with: str
    key: PACKey
    difficulty: str
    severity: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {"src": f"0x{self.source_addr:X}", "tgt": f"0x{self.target_addr:X}",
                "auth": self.auth_insn, "type": self.bypass_type, "key": self.key.value,
                "diff": self.difficulty, "severity": self.severity.value}


@dataclass
class JOPGadget:
    address: int
    gadget_type: str
    sequence: list
    dst_reg: str = "x16"
    pac_protected: bool = False
    pac_key: PACKey = PACKey.UNKNOWN
    bti_landing: bool = False
    usefulness: str = "unknown"
    severity: Severity = Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        return {"addr": f"0x{self.address:X}", "type": self.gadget_type, "seq": self.sequence,
                "pac": self.pac_protected, "pkey": self.pac_key.value, "bti": self.bti_landing,
                "use": self.usefulness, "severity": self.severity.value}


@dataclass
class StripSignatureRegion:
    addr_range: tuple
    strip_count: int
    resign_count: int
    likely_jit: bool
    jit_calls: int
    risk: str

    def to_dict(self) -> Dict[str, Any]:
        return {"range": [f"0x{self.addr_range[0]:X}", f"0x{self.addr_range[1]:X}"],
                "strips": self.strip_count, "resigns": self.resign_count,
                "jit": self.likely_jit, "jit_calls": self.jit_calls, "risk": self.risk}


@dataclass
class CrossLibraryPACChain:
    caller_lib: str
    caller_func: str
    callee_lib: str
    callee_func: str
    caller_key: PACKey
    callee_key: PACKey
    key_mismatch: bool
    auth_forwarded: bool
    ga_used: bool
    risk_level: Severity

    def to_dict(self) -> Dict[str, Any]:
        return {"clib": self.caller_lib, "cfunc": self.caller_func,
                "dlib": self.callee_lib, "dfunc": self.callee_func,
                "ckey": self.caller_key.value, "dkey": self.callee_key.value,
                "mismatch": self.key_mismatch, "ga": self.ga_used, "risk": self.risk_level.value}


class Arm64eEnhancedAnalyzer:
    """ARM64e增强安全分析器——PAC/BTI深度审计。"""

    ALL_PAC = set(t.value for t in PACInstructionType if t != PACInstructionType.UNKNOWN)
    BRANCH_RE = re.compile(r"\b(br|blr|ret)\b\s+x\d+", re.IGNORECASE)
    SIGN_RE = re.compile(r"0x([0-9a-fA-F]+)\s+(pac[ia][a-z0-9]*)\s+(\w+),\s*(\w+)", re.IGNORECASE)
    JIT_SYMS = {"pthread_jit_write_protect_np", "sys_icache_invalidate",
                "vm_protect", "mach_vm_remap", "mmap"}
    LIB_PFX = {"dyld_": "dyld", "objc_": "libobjc", "_objc": "libobjc",
               "dispatch_": "libdispatch", "pthread_": "libsystem_pthread",
               "mach_": "libsystem_kernel", "xpc_": "libxpc", "os_": "libsystem"}

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self._funcs: List[Dict] = []
        self._imports: List[Dict] = []
        self._arch = "arm64e"
        self._dc: Dict[int, str] = {}

    def _r2(self, c: str, t: int = 60) -> str:
        try:
            r = subprocess.run(["r2", "-q", "-c", f"{c}; q", self.binary_path],
                capture_output=True, text=True, timeout=t, encoding="utf-8", errors="replace")
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def _load(self) -> bool:
        try:
            self._arch = self._r2("e asm.arch", 15).strip() or "arm64e"
            raw = self._r2("aaaa; aflj", 120)
            if raw:
                j = json.loads(raw)
                self._funcs = j if isinstance(j, list) else []
            raw2 = self._r2("aaa; iij", 60)
            if raw2:
                j2 = json.loads(raw2)
                self._imports = j2 if isinstance(j2, list) else []
            return True
        except Exception as e:
            logger.warning("Load failed: %s", e)
            return False

    def _disasm(self, addr: int) -> str:
        if addr not in self._dc:
            self._dc[addr] = self._r2(f"s 0x{addr:X}; pdb", 30)
        return self._dc[addr]

    def _func_for(self, addr: int) -> str:
        return next((f.get("name", "") for f in self._funcs
                     if f.get("offset", 0) <= addr < f.get("offset", 0) + f.get("size", 0)), "")

    def _func_addr(self, name: str) -> Optional[int]:
        return next((f.get("offset") for f in self._funcs if f.get("name") == name), None)

    def _exported(self, name: str) -> bool:
        return any(f.get("name") == name and f.get("type", "") in ("sym", "FUNC") for f in self._funcs)

    def _key_from(self, m: str) -> PACKey:
        ml = m.lower()
        if "ga" in ml:
            return PACKey.GA
        if "ia" in ml:
            return PACKey.IA
        if "ib" in ml:
            return PACKey.IB
        if "da" in ml:
            return PACKey.DA
        if "db" in ml:
            return PACKey.DB
        return PACKey.UNKNOWN

    # ---- 1. PAC指令检测 ----
    def _detect_pac(self) -> List[PACInstruction]:
        res = []
        seen = set()
        for mn in sorted(self.ALL_PAC):
            for line in self._r2(f"aaaa; /ad/ {mn}", 60).split("\n"):
                m = re.match(r"\s*(0x[0-9a-fA-F]+)\s+(\S+)", line)
                if not m:
                    continue
                a, ins = int(m.group(1), 16), m.group(2).lower()
                if a in seen:
                    continue
                seen.add(a)
                it = next((t for t in PACInstructionType if t.value == ins), PACInstructionType.UNKNOWN)
                res.append(PACInstruction(address=a, mnemonic=ins, insn_type=it, key=it.key,
                                          function_name=self._func_for(a)))
        return sorted(res, key=lambda x: x.address)

    # ---- 2. PAC签名gadget识别 ----
    def _signing_gadgets(self, pac: List[PACInstruction]) -> List[PACSigningGadget]:
        gs = []
        seen = set()
        for i in pac:
            if not i.insn_type.is_sign or not i.function_name or i.function_name in seen:
                continue
            seen.add(i.function_name)
            fa = self._func_addr(i.function_name)
            if not fa:
                continue
            dis = self._disasm(fa)
            for mm in self.SIGN_RE.finditer(dis):
                a = int(mm.group(1), 16)
                si = mm.group(2).lower()
                src = mm.group(3)
                modr = mm.group(4)
                ctrl = modr.lower() not in ("sp", "x31", "wsp", "wzr")
                oracle = ctrl and self._exported(i.function_name)
                k = self._key_from(si)
                gs.append(PACSigningGadget(address=a, sign_insn=si, source_reg=src,
                    modifier_reg=modr, key=k, context=i.function_name, is_oracle=oracle,
                    controllable_modifier=ctrl,
                    severity=Severity.CRITICAL if oracle else (Severity.HIGH if ctrl else Severity.MEDIUM)))
        return gs

    # ---- 3. PAC绕过路径分析 ----
    def _bypass_paths(self, pac: List[PACInstruction], _g: List[PACSigningGadget]) -> List[PACBypassPath]:
        paths = []
        auths = [i for i in pac if i.insn_type.is_auth and not i.insn_type.is_strip]
        for auth in auths[:30]:
            fa = self._func_addr(auth.function_name) if auth.function_name else None
            if not fa:
                continue
            lines = self._disasm(fa).split("\n")
            dr = None
            ai = -1
            for idx, line in enumerate(lines):
                am = re.match(rf"\s*0x{auth.address:X}\s+(aut\w+)\s+(\w+)", line, re.IGNORECASE)
                if am:
                    dr = am.group(2)
                    ai = idx
                    break
            if not dr or ai < 0:
                continue
            for j in range(ai + 1, min(ai + 15, len(lines))):
                if re.search(r"\b(br|blr)\s+" + re.escape(dr) + r"\s*$", lines[j], re.IGNORECASE):
                    ta = auth.address + (j - ai) * 4
                    seg = "\n".join(lines[ai:j + 1])
                    if re.search(r"xpac[di]", seg, re.IGNORECASE):
                        bt = "strip_resign"
                    elif re.search(r"(str|stp)\s", seg, re.IGNORECASE):
                        bt = "replay"
                    else:
                        bt = "substitution"
                    df = "trivial" if bt == "strip_resign" else ("moderate" if bt == "substitution" else "hard")
                    paths.append(PACBypassPath(source_addr=auth.address, target_addr=ta,
                        auth_insn=auth.mnemonic, bypass_type=bt, authenticated_ptr=dr,
                        replaceable_with=f"attacker_{dr}", key=auth.key, difficulty=df,
                        severity=Severity.HIGH if bt in ("substitution", "strip_resign") else Severity.MEDIUM))
                    break
        # 跨库PAC绕过检测
        for i in pac:
            if i.insn_type not in (PACInstructionType.BLRAA, PACInstructionType.BLRAB):
                continue
            if not i.function_name:
                continue
            fa = self._func_addr(i.function_name)
            if not fa:
                continue
            if re.search(rf"0x{i.address:X}\s+blra[a-z].*@plt", self._disasm(fa), re.IGNORECASE):
                paths.append(PACBypassPath(source_addr=i.address, target_addr=0,
                    auth_insn=i.mnemonic, bypass_type="cross_library", authenticated_ptr="lr",
                    replaceable_with="plt_stub_redirect", key=i.key,
                    difficulty="moderate", severity=Severity.HIGH))
        return paths

    # ---- 4. BTI着陆点校验 ----
    def _verify_bti(self) -> Tuple[List[BTIInstruction], float]:
        bis = []
        ba = {}
        for line in self._r2("aaaa; /ad/ bti", 60).split("\n"):
            m = re.match(r"\s*(0x[0-9a-fA-F]+)\s+(bti\s*\S*)", line)
            if m:
                a = int(m.group(1), 16)
                ba[a] = m.group(2).strip().lower()
        for a, bs in ba.items():
            if "bti j" in bs and "jc" not in bs:
                bt = BTIInstructionType.BTI_J
            elif "bti c" in bs:
                bt = BTIInstructionType.BTI_C
            else:
                bt = BTIInstructionType.BTI_JC
            ie = any(f.get("offset") == a for f in self._funcs)
            bis.append(BTIInstruction(address=a, insn_type=bt, function_name=self._func_for(a),
                                       is_function_entry=ie, missing_preceding=ie))
        ind = sum(len(self.BRANCH_RE.findall(self._disasm(f.get("offset", 0))))
                for f in self._funcs[:50])
        return bis, round(min(1.0, len(bis) / max(1, ind)), 3)

    # ---- 5. JOP/COP gadget检测 ----
    def _detect_jop(self, pac: List[PACInstruction]) -> List[JOPGadget]:
        gs = []
        pl = {i.address for i in pac}
        bp = re.compile(r"0x([0-9a-fA-F]+)\s+(br|blr|ret)\s+x?(\w+)", re.IGNORECASE)
        for f in self._funcs[:80]:
            fa = f.get("offset", 0)
            if not fa:
                continue
            lines = self._disasm(fa).split("\n")
            for ix, line in enumerate(lines):
                bm = bp.search(line)
                if not bm:
                    continue
                ba, bi, br = int(bm.group(1), 16), bm.group(2).lower(), bm.group(3)
                seq = []
                for j in range(max(0, ix - 4), ix + 1):
                    im = re.match(r".*0x[0-9a-fA-F]+\s+(\w+)", lines[j])
                    if im:
                        seq.append(im.group(1))
                gt = "jop_dispatch" if bi in ("br", "ret") else "cop_dispatch"
                prot = ba in pl
                pk = PACKey.UNKNOWN
                if prot:
                    for pi in pac:
                        if pi.address == ba:
                            pk = pi.key
                            break
                bti = bool(re.search(r"bti\s", self._disasm(ba)[:200], re.IGNORECASE))
                s = " ".join(seq).lower()
                if re.search(r"ldp.*ldr", s):
                    use = "dispatcher"
                elif re.search(r"add.*(?:br|blr|ret)", s):
                    use = "loader"
                elif len(seq) <= 2:
                    use = "terminator"
                elif re.search(r"mov\s+x\d+,\s*x\d+\s*(?:br|blr|ret)", s):
                    use = "nop-like"
                else:
                    use = "unknown"
                sev = Severity.LOW if prot else (Severity.HIGH if use == "dispatcher" else Severity.MEDIUM)
                gs.append(JOPGadget(address=ba, gadget_type=gt, sequence=seq, dst_reg=br,
                    pac_protected=prot, pac_key=pk, bti_landing=bti, usefulness=use, severity=sev))
                if len(gs) >= 25:
                    break
            if len(gs) >= 25:
                break
        return gs

    # ---- 6. 密钥多样性分析 ----
    def _key_dist(self, pac: List[PACInstruction]) -> Dict[str, int]:
        d = {"IA": 0, "IB": 0, "DA": 0, "DB": 0, "GA": 0, "UNKNOWN": 0, "_total": len(pac)}
        for i in pac:
            d[i.key.value] = d.get(i.key.value, 0) + 1
        d["_ia_ib"] = round(d["IA"] / max(1, d["IB"]), 2)
        d["_da_db"] = round(d["DA"] / max(1, d["DB"]), 2)
        d["_diversity"] = sum(1 for k in ("IA", "IB", "DA", "DB", "GA") if d[k] > 0)
        return d

    # ---- 7. 签名剥离检测 ----
    def _strip_regions(self, pac: List[PACInstruction]) -> List[StripSignatureRegion]:
        strips = sorted([i for i in pac if i.insn_type.is_strip], key=lambda x: x.address)
        if not strips:
            return []
        grps = []
        cur = [strips[0]]
        for s in strips[1:]:
            if s.address - cur[-1].address < 0x10000:
                cur.append(s)
            else:
                grps.append(cur)
                cur = [s]
        grps.append(cur)
        jc = sum(1 for imp in self._imports if any(s in imp.get("name", "") for s in self.JIT_SYMS))
        rs = []
        for g in grps:
            rg = (min(x.address for x in g), max(x.address for x in g))
            rc = sum(1 for i in pac if rg[0] <= i.address <= rg[1] and i.insn_type.is_sign)
            lj = jc > 0 and len(g) >= 2 and rc >= 1
            risk = "HIGH" if not lj and rc == 0 else ("MEDIUM" if lj else "LOW")
            rs.append(StripSignatureRegion(addr_range=rg, strip_count=len(g),
                resign_count=rc, likely_jit=lj, jit_calls=jc, risk=risk))
        return rs

    # ---- 8. 跨库PAC链分析 ----
    def _cross_lib(self, pac: List[PACInstruction]) -> List[CrossLibraryPACChain]:
        cs = []
        for i in pac:
            if i.insn_type not in (PACInstructionType.BLRAA, PACInstructionType.BLRAB):
                continue
            if not i.function_name:
                continue
            fa = self._func_addr(i.function_name)
            if not fa:
                continue
            if not re.search(rf"0x{i.address:X}\s+blra[a-z].*@plt", self._disasm(fa), re.IGNORECASE):
                continue
            cl = next((v for k, v in self.LIB_PFX.items() if i.function_name.startswith(k)), "main_binary")
            dl = "unknown_lib"
            for imp in self._imports:
                if imp.get("plt") == i.address:
                    dl = imp.get("uname", "unknown_lib").split(".")[0]
                    break
            mism = i.key != PACKey.IA
            ga = any(x.insn_type == PACInstructionType.PACGA
                   for x in pac if 0 < abs(x.address - i.address) < 0x100)
            risk = Severity.HIGH if mism and not ga else (Severity.MEDIUM if mism else Severity.LOW)
            cs.append(CrossLibraryPACChain(caller_lib=cl, caller_func=i.function_name,
                callee_lib=dl, callee_func="", caller_key=i.key, callee_key=PACKey.IA,
                key_mismatch=mism, auth_forwarded=ga, ga_used=ga, risk_level=risk))
        return cs

    # ---- 综合风险评估 ----
    @staticmethod
    def _pac_str(pac: List[PACInstruction]) -> str:
        t = len(pac)
        s = sum(1 for i in pac if i.insn_type.is_sign)
        a = sum(1 for i in pac if i.insn_type.is_auth)
        if t == 0:
            return "UNPROTECTED"
        if s > 30 and a > 20:
            return "STRONG"
        if s > 10 and a > 5:
            return "MODERATE"
        return "WEAK"

    @staticmethod
    def _risk(sg: List[PACSigningGadget], bp: List[PACBypassPath],
              jg: List[JOPGadget], bc: float) -> Severity:
        sc = sum(1 for g in sg if g.is_oracle) * 32
        sc += sum(p.severity.weight for p in bp)
        sc += sum(j.severity.weight for j in jg)
        if bc < 0.5:
            sc += 32
        elif bc < 0.8:
            sc += 8
        if sc >= 100:
            return Severity.CRITICAL
        if sc >= 50:
            return Severity.HIGH
        if sc >= 20:
            return Severity.MEDIUM
        if sc >= 5:
            return Severity.LOW
        return Severity.INFO

    # ---- 主分析入口 ----
    def analyze(self) -> Dict[str, Any]:
        """执行ARM64e增强安全分析全流程，返回结构化结果字典。"""
        logger.info("ARM64e enhanced analysis: %s", self.binary_path)
        if not self._load():
            return {"success": False, "error": "Binary load failed", "binary": self.binary_path}

        pac = self._detect_pac()
        sig = self._signing_gadgets(pac)
        byp = self._bypass_paths(pac, sig)
        bti, bc = self._verify_bti()
        jop = self._detect_jop(pac)
        kd = self._key_dist(pac)
        reg = self._strip_regions(pac)
        chn = self._cross_lib(pac)
        ps = self._pac_str(pac)
        overall = self._risk(sig, byp, jop, bc)

        sc = lambda items, cond: sum(1 for i in items if cond(i))
        return {"success": True, "binary": self.binary_path, "arch": self._arch,
            "pac": {"total": len(pac), "sign": sc(pac, lambda i: i.insn_type.is_sign),
                    "auth": sc(pac, lambda i: i.insn_type.is_auth),
                    "strip": sc(pac, lambda i: i.insn_type.is_strip),
                    "branch": sc(pac, lambda i: i.insn_type.is_branch),
                    "items": [i.to_dict() for i in pac[:50]]},
            "bti": {"total": len(bti), "c": sc(bti, lambda b: b.insn_type == BTIInstructionType.BTI_C),
                    "j": sc(bti, lambda b: b.insn_type == BTIInstructionType.BTI_J),
                    "jc": sc(bti, lambda b: b.insn_type == BTIInstructionType.BTI_JC),
                    "items": [b.to_dict() for b in bti[:30]]},
            "signing": {"total": len(sig), "oracles": sc(sig, lambda g: g.is_oracle),
                        "items": [g.to_dict() for g in sig[:20]]},
            "bypass": {"total": len(byp),
                       "substitution": sc(byp, lambda p: p.bypass_type == "substitution"),
                       "replay": sc(byp, lambda p: p.bypass_type == "replay"),
                       "strip_resign": sc(byp, lambda p: p.bypass_type == "strip_resign"),
                       "cross_lib": sc(byp, lambda p: p.bypass_type == "cross_library"),
                       "items": [p.to_dict() for p in byp[:20]]},
            "jop": {"total": len(jop), "dispatchers": sc(jop, lambda j: j.usefulness == "dispatcher"),
                    "pac_protected": sc(jop, lambda j: j.pac_protected),
                    "items": [j.to_dict() for j in jop[:15]]},
            "strip_regions": {"total": len(reg), "jit": sc(reg, lambda r: r.likely_jit),
                              "items": [r.to_dict() for r in reg]},
            "cross_lib_chains": {"total": len(chn), "key_mismatch": sc(chn, lambda c: c.key_mismatch),
                                 "items": [c.to_dict() for c in chn[:15]]},
            "key_distribution": kd, "pac_strength": ps, "bti_coverage": bc,
            "overall_risk": overall.value,
            "metadata": {"version": "2.0.0", "funcs": len(self._funcs), "imports": len(self._imports)}}


def analyze_arm64e_enhanced(binary_path: str) -> Dict[str, Any]:
    """模块级便捷入口——执行ARM64e增强分析并返回结果字典。"""
    return Arm64eEnhancedAnalyzer(binary_path).analyze()
