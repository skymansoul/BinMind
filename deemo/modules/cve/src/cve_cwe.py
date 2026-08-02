# 2026-08-28 ~ 2026-08-30
# CWE (Common Weakness Enumeration) knowledge enrichment.
# MITRE's CWE API provides rich metadata: descriptions, extended descriptions,
# common consequences, mitigations, detection methods.
#
# We currently extract CWE IDs from NVD data (e.g. "CWE-79") but have
# no local knowledge about what that weakness actually means. This module
# fills that gap — query by CWE ID and get actionable info back.
#
# Top 50 CWEs are seeded at init time (hardcoded) so common queries don't
# hit the network. The rest are fetched from MITRE API on demand and cached
# in sqlite, same pattern as cve_epss + cve_kev.
#
# MITRE API rate limit: 100 req/min with key, ~20 without. we're polite
# with a 1s delay between requests.

import json
import os
import re
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Any, Tuple

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False

_CWE_API_BASE = "https://cwe-api.mitre.org/api/v1"
_CWE_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "cwe_cache.db"
)

# cwe id pattern: CWE-\d+
_CWE_ID_RE = re.compile(r'CWE-\d+', re.IGNORECASE)


# ---- seed data: top 50 most common CWEs ----
# descriptions sourced from MITRE CWE database, manually trimmed for brevity.
# these cover the vast majority of real-world vulns — lazy-load the rest.
# format: {cwe_id: {name, description, extended_description}}

_TOP50_CWE_SEED: Dict[str, Dict[str, str]] = {
    "CWE-79": {
        "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "extended": "XSS flaws occur when an application includes untrusted data in a web page without proper validation. There are three main types: reflected (non-persistent), stored (persistent), and DOM-based. Attackers can use XSS to execute scripts in the victim's browser, hijack sessions, deface websites, or redirect users to malicious sites.",
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "description": "The software writes data past the end, or before the beginning, of the intended buffer.",
        "extended": "This can result in corruption of data, a crash, or code execution. Typically caused by a combination of missing bounds checking and use of unsafe functions in C/C++. Common in memory-unsafe languages. Stack-based and heap-based variants exist.",
    },
    "CWE-89": {
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
        "extended": "SQL injection allows attackers to read, modify, or delete database contents, bypass authentication, and in some cases execute commands on the underlying OS. The primary mitigation is parameterized queries (prepared statements). Input validation alone is insufficient.",
    },
    "CWE-78": {
        "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but does not neutralize special elements that could modify the intended OS command.",
        "extended": "OS command injection allows attackers to execute arbitrary commands on the host operating system. Functions like system(), exec(), popen() are common vectors. Mitigation: avoid invoking shell commands with user input; use library APIs instead.",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
        "extended": "This is a broad class covering many specific weaknesses. Input validation should happen at the trust boundary — validate type, length, format, and range. Whitelisting is preferred over blacklisting.",
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "description": "The software reads data past the end, or before the beginning, of the intended buffer.",
        "extended": "Out-of-bounds reads can lead to information disclosure, crashes (denial of service), and in combination with other bugs, arbitrary code execution. Common in C/C++ from missing bounds checks. Heartbleed (CVE-2014-0160) is the canonical example.",
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory located underneath a restricted parent directory, but does not properly neutralize special elements that can resolve to a location outside the restricted directory.",
        "extended": "Path traversal (aka directory traversal) allows attackers to read, write, or delete files outside the intended directory. Classic example: ../../../etc/passwd. Mitigation: canonicalize paths and validate against an allowlist of permitted directories.",
    },
    "CWE-416": {
        "name": "Use After Free",
        "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "extended": "UAF is a memory safety bug where a pointer continues to be used after the memory it points to has been freed. The freed memory may be reallocated for a different object, leading to type confusion. Common in C/C++. Mitigation: null pointers after free, use-after-free protections in modern allocators.",
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "description": "The software constructs all or part of a code segment using externally-influenced input, but does not neutralize special elements that could modify the intended code.",
        "extended": "Code injection is broader than OS command injection — it covers eval(), include(), unserialize(), template injection, and similar. The injected code runs with the privileges of the application.",
    },
    "CWE-77": {
        "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        "description": "The software constructs all or part of a command using externally-influenced input, but does not neutralize special elements that could modify the intended command.",
        "extended": "Similar to CWE-78 but broader — covers any command language, not just OS shells. Can include SQL, LDAP, XPath, etc. The root cause is treating data as code at an interface boundary.",
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid but is NULL.",
        "extended": "NULL pointer dereferences typically cause crashes (segfaults/access violations) resulting in denial of service. In some rare cases they can lead to code execution if the NULL page is mapped. Simple to fix: check for NULL before dereferencing.",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        "extended": "Covers missing authentication, weak credential storage, bypassable auth checks, and credential stuffing vulnerabilities. Not to be confused with CWE-862 (Missing Authorization) which is about access control AFTER authentication.",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        "extended": "Information disclosure can include credentials, PII, system configuration, source code, memory contents, or internal network topology. It often acts as an enabler for more severe attacks rather than being the end goal.",
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "description": "The software performs operations on a memory buffer, but it can read from or write to a memory location outside the intended boundary of the buffer.",
        "extended": "This is the classic buffer overflow class. Modern variants include stack buffer overflow, heap buffer overflow, and off-by-one errors. ASLR, DEP/NX, stack canaries, and safe languages are the primary defenses.",
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "description": "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.",
        "extended": "Missing authorization (aka missing access control) allows users to perform actions or access data they shouldn't be able to. Common patterns: direct object references (IDOR), missing function-level access control, forced browsing. Testing for this requires checking every endpoint and user role combination.",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
        "extended": "CSRF forces authenticated users to submit unwanted requests. Mitigation: anti-CSRF tokens (synchronizer token pattern), SameSite cookies, custom request headers. Modern frameworks (Rails, Django, Laravel) provide built-in CSRF protection.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "extended": "Unsafe deserialization can lead to remote code execution, object injection, and privilege escalation. Affects Java (ObjectInputStream), Python (pickle), PHP (unserialize), .NET (BinaryFormatter), and others. The safest fix: avoid deserializing untrusted data entirely.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "extended": "SSRF allows attackers to make the server send requests to internal services (cloud metadata endpoints, internal APIs, localhost). AWS IMDSv1 (169.254.169.254) is the classic target. Mitigation: URL allowlisting, network segmentation, disabling unnecessary URL schemes (file://, gopher://).",
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        "extended": "Unrestricted file upload can lead to remote code execution (uploaded webshell), stored XSS (uploaded HTML/SVG), or denial of service (uploaded zip bombs). Mitigation: validate file type by magic bytes (not extension), store outside web root, scan uploaded files.",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": "The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.",
        "extended": "Missing authentication is distinct from CWE-287 (Improper Authentication) — here there is NO authentication at all, rather than weak authentication. Common in internal APIs, debug endpoints left in production, and IoT devices.",
    },
}


class CWEClient:
    """MITRE CWE API client with local sqlite cache.
    Seeds the top 50 CWEs at init, lazy-fetches the rest from MITRE."""

    def __init__(self, cache_path: Optional[str] = None):
        self._cache_path = cache_path or _CWE_CACHE_PATH
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_cache()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            if self._cache_path != ":memory:":
                cache_dir = os.path.dirname(self._cache_path)
                if cache_dir:
                    os.makedirs(cache_dir, exist_ok=True)
            self._conn = sqlite3.connect(self._cache_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_cache(self):
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cwe_cache (
                    cwe_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    extended_description TEXT NOT NULL DEFAULT '',
                    consequences TEXT NOT NULL DEFAULT '[]',
                    mitigations TEXT NOT NULL DEFAULT '[]',
                    detection_methods TEXT NOT NULL DEFAULT '[]',
                    fetched_at REAL NOT NULL DEFAULT 0.0
                )
            """)
            conn.commit()

        # seed top 50 if table is empty
        with self._lock:
            count = conn.execute("SELECT COUNT(*) as cnt FROM cwe_cache").fetchone()
            if count and count["cnt"] == 0:
                now = time.time()
                for cwe_id, data in _TOP50_CWE_SEED.items():
                    conn.execute(
                        "INSERT OR IGNORE INTO cwe_cache "
                        "(cwe_id, name, description, extended_description, fetched_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            cwe_id.upper(),
                            data.get("name", ""),
                            data.get("description", ""),
                            data.get("extended", ""),
                            now,
                        ),
                    )
                conn.commit()

    # ---- local cache access ----
    def get_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get CWE data from cache. Returns None if not cached.
        Normalizes input: '79', 'cwe-79', 'CWE-79' all map to 'CWE-79'."""
        cwe_id = _normalize_cwe_id(cwe_id)
        if not cwe_id:
            return None

        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT * FROM cwe_cache WHERE cwe_id = ?", (cwe_id,)
            ).fetchone()

        if row:
            return {
                "cwe_id": row["cwe_id"],
                "name": row["name"],
                "description": row["description"],
                "extended_description": row["extended_description"],
                "consequences": json.loads(row["consequences"] or "[]"),
                "mitigations": json.loads(row["mitigations"] or "[]"),
                "detection_methods": json.loads(row["detection_methods"] or "[]"),
                "cached": True,
            }
        return None

    def has_cwe(self, cwe_id: str) -> bool:
        """Check if a CWE is in the local cache."""
        return self.get_cwe(cwe_id) is not None

    # ---- api fetch ----
    def fetch_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CWE data from MITRE API and cache it.
        Returns the same dict as get_cwe(), or None on failure."""
        cwe_id = _normalize_cwe_id(cwe_id)
        if not cwe_id:
            return None

        # check cache first
        cached = self.get_cwe(cwe_id)
        if cached is not None:
            return cached

        if not _HAS_URLLIB:
            return None

        # CWE API: GET /cwe/weakness/{id}
        numeric_id = cwe_id.replace("CWE-", "")
        url = f"{_CWE_API_BASE}/cwe/weakness/{numeric_id}"

        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "BinMind-CVE/1.0"},
            )
            time.sleep(0.5)  # polite rate limiting
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"[CWE] fetch failed for {cwe_id}: {e}")
            return None

        # extract relevant fields from MITRE's response structure
        weaknesses = data.get("Weaknesses", [])
        if not weaknesses:
            return None

        w = weaknesses[0]
        name = w.get("Name", "")
        description = w.get("Description", "")
        extended = w.get("Extended_Description", "")

        # consequences
        consequences: List[Dict] = []
        for c in w.get("Common_Consequences", []):
            consequences.append({
                "scope": ", ".join(c.get("Scope", [])),
                "impact": c.get("Impact", []),
                "note": c.get("Note", ""),
            })

        # mitigations
        mitigations: List[str] = []
        for m in w.get("Potential_Mitigations", []):
            text = m.get("Mitigation", "") or m.get("Description", "")
            if text:
                mitigations.append(text.strip())

        # detection methods
        detection: List[str] = []
        for d in w.get("Detection_Methods", []):
            text = d.get("Method", "") or d.get("Description", "")
            if text:
                detection.append(text.strip())

        # cache it
        now = time.time()
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                "INSERT OR REPLACE INTO cwe_cache "
                "(cwe_id, name, description, extended_description, "
                "consequences, mitigations, detection_methods, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cwe_id,
                    name,
                    description,
                    extended if isinstance(extended, str) else "",
                    json.dumps(consequences),
                    json.dumps(mitigations),
                    json.dumps(detection),
                    now,
                ),
            )
            conn.commit()

        return {
            "cwe_id": cwe_id,
            "name": name,
            "description": description,
            "extended_description": extended if isinstance(extended, str) else "",
            "consequences": consequences,
            "mitigations": mitigations,
            "detection_methods": detection,
            "cached": True,
        }

    # ---- enrichment ----
    def enrich_entry(self, entry) -> Dict[str, Any]:
        """Add CWE metadata to a CVE entry. Entry can be CVEEntry or dict.
        Returns dict with keys: cwes (list of {id, name, description, ...}).
        Does NOT modify the original entry."""
        cwe_ids: List[str] = []
        if hasattr(entry, 'cwes'):
            cwe_ids = list(entry.cwes) if entry.cwes else []
        elif isinstance(entry, dict):
            cwe_ids = entry.get('cwes', entry.get('cwe', []))

        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        enriched = []
        for cid in cwe_ids[:10]:  # cap at 10 CWEs per entry
            cwe_data = self.get_cwe(cid) or self.fetch_cwe(cid)
            if cwe_data:
                enriched.append(cwe_data)
            else:
                enriched.append({"cwe_id": cid, "name": "", "description": "", "cached": False})

        return {"cwe_enrichment": enriched}

    def get_mitigations(self, cwe_id: str) -> List[str]:
        """Get mitigation recommendations for a CWE."""
        data = self.get_cwe(cwe_id) or self.fetch_cwe(cwe_id)
        if data:
            return data.get("mitigations", [])
        return []

    def get_detection_methods(self, cwe_id: str) -> List[str]:
        """Get detection method recommendations for a CWE."""
        data = self.get_cwe(cwe_id) or self.fetch_cwe(cwe_id)
        if data:
            return data.get("detection_methods", [])
        return []

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        conn = self._get_conn()
        with self._lock:
            total = conn.execute("SELECT COUNT(*) as cnt FROM cwe_cache").fetchone()
            return {"cached_cwes": total["cnt"] if total else 0}

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# ---- helpers ----
def _normalize_cwe_id(raw: str) -> Optional[str]:
    """Normalize various CWE ID formats to 'CWE-NNN'.
    Handles: '79', 'cwe-79', 'CWE-79', 'CWE-079'.
    Returns None if input doesn't look like a CWE ID."""
    if not raw:
        return None
    s = raw.strip().upper()
    if not s.startswith("CWE-"):
        s = "CWE-" + s
    m = re.match(r'CWE-0*(\d+)', s)
    if not m:
        return None
    return f"CWE-{m.group(1)}"


def extract_cwes_from_text(text: str) -> List[str]:
    """Extract CWE IDs from arbitrary text.
    Returns normalized CWE IDs (e.g. ['CWE-79', 'CWE-89'])."""
    return [_normalize_cwe_id(m) for m in _CWE_ID_RE.findall(text) if _normalize_cwe_id(m)]


# module-level singleton (same pattern as everything else)
_cwe_instance: Optional[CWEClient] = None
_cwe_lock = threading.Lock()


def get_cwe_client() -> CWEClient:
    global _cwe_instance
    if _cwe_instance is None:
        with _cwe_lock:
            if _cwe_instance is None:
                _cwe_instance = CWEClient()
    return _cwe_instance
