# 2026-07-30 ~ 2026-09-12
# Main CVE analyzer — ties everything together.
# The double-KB architecture is acknowledged tech debt: CVEKnowledgeBase from
# cve_kb.py is SQLite-backed; there's also a CVEKB JSON-file version floating
# around. Analyzer lazy-loads whichever is available. Long-term these should
# consolidate into a single KB implementation.
#
# semantic_search() creates a fresh CVESearchEngine each call — fine for a few
# queries but slow for bulk use. Cache the engine on the instance if you need
# to do repeated searches. Noted as future optimization, not a bug.
#
# prioritize() try/except chains each module separately — if one fails (e.g.
# epss not installed), the others still work. Better than a single broad except.

import os
from typing import List, Dict, Optional, Any, Union

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase, get_kb


class CVEAnalyzer:
    """Main entry point for CVE analysis — file/binary/SBOM dispatch."""

    def __init__(self, kb: Optional[CVEKnowledgeBase] = None):
        """Initialize analyzer.
        kb: optional injection point. If None, uses the module-level singleton.
        Supports the double-KB pattern — pass a CVEKB JSON instance if needed."""
        self._kb = kb if kb is not None else get_kb()

    # ---- main dispatch ----
    def analyze(self, target: str) -> Dict[str, Any]:
        """Main entry point. Accepts file path, binary path, or SBOM path.
        Dispatches based on target type.
        Returns a dict with results from the analysis pipeline."""
        if not os.path.exists(target):
            return {"error": f"Target not found: {target}", "target": target}

        result: Dict[str, Any] = {
            "target": target,
            "type": self._detect_type(target),
        }

        target_type = result["type"]

        if target_type == "file":
            result["findings"] = self._analyze_file(target)
        elif target_type == "binary":
            result["findings"] = self._analyze_binary(target)
        elif target_type == "sbom":
            result["findings"] = self._analyze_sbom(target)
        else:
            result["error"] = f"Unknown target type: {target_type}"

        return result

    def _detect_type(self, target: str) -> str:
        """Guess target type from path/extension."""
        target_lower = target.lower()
        if target_lower.endswith((".json", ".xml")) and any(
            kw in os.path.basename(target_lower) for kw in ["sbom", "cyclonedx", "spdx", "bom"]
        ):
            return "sbom"
        if target_lower.endswith((".exe", ".dll", ".so", ".elf", ".bin", ".app", ".sys", ".ko", ".o")):
            return "binary"
        return "file"

    # ---- compat methods ----
    def analyze_strings(self, strings: List[str]) -> List[CVEEntry]:
        """Compat method — searches KB for CVEs mentioned in extracted strings.
        Parses CVE IDs (CVE-YYYY-NNNNN format) from the string list."""
        import re

        found: Dict[str, CVEEntry] = {}
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

        for s in strings:
            for match in cve_pattern.finditer(s):
                cve_id = match.group(0).upper()
                if cve_id not in found:
                    entry = self._kb.get(cve_id)
                    if entry:
                        found[cve_id] = entry

        return list(found.values())

    # ---- KB access ----
    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch a single CVE from the knowledge base."""
        return self._kb.get(cve_id)

    def search_cves(self, query: str, limit: int = 50) -> List[CVEEntry]:
        """Keyword search via the KB's built-in search."""
        entries, _ = self._kb.search(query=query, limit=limit)
        return entries

    # ---- semantic search ----
    def semantic_search(self, query: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
        """BM25 semantic search over CVE descriptions.
        Creates a NEW CVESearchEngine each call — engine NOT cached.
        Fine for a few queries, slow for bulk. Future optimization: cache on instance."""
        from .cve_search import CVESearchEngine

        engine = CVESearchEngine(self._kb)
        engine.build()
        return engine.search(query, top_n=top_n)

    # ---- enrichment ----
    def enrich_with_epss(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Batch EPSS enrichment. Returns dict of cve_id -> {score, percentile}."""
        try:
            from .cve_epss import EPSSClient
            client = EPSSClient()
            return client.fetch_scores(cve_ids)
        except ImportError:
            # cve_epss not available — return empty enrichment
            return {cve_id: {"epss_score": None, "epss_percentile": None} for cve_id in cve_ids}

    # ---- prioritization ----
    def prioritize(self, entries: List[CVEEntry]) -> List[CVEEntry]:
        """Sort entries by severity + EPSS score + SSVC decision.
        Each scoring module is try/except'd separately — one failure doesn't
        break the whole pipeline."""
        enriched = list(entries)

        # collect cve_ids for batch enrichment
        cve_ids = [e.cve_id for e in enriched]

        # EPSS scoring
        try:
            from .cve_epss import EPSSClient
            client = EPSSClient()
            epss_data = client.fetch_scores(cve_ids)
            for entry in enriched:
                data = epss_data.get(entry.cve_id, {})
                if data.get("epss_score") is not None:
                    entry.epss_score = data["epss_score"]
                if data.get("epss_percentile") is not None:
                    entry.epss_percentile = data["epss_percentile"]
        except ImportError:
            pass  # epss module not available

        # SSVC scoring (try import, skip if missing)
        try:
            from .cve_ssvc import evaluate_ssvc
            for entry in enriched:
                try:
                    decision = evaluate_ssvc(entry)
                    # stash decision on the entry (hacky — should be a field)
                    entry.__dict__["_ssvc_decision"] = decision
                except Exception:
                    pass
        except ImportError:
            pass

        # sort: CRITICAL > HIGH > MEDIUM > LOW > NONE > UNKNOWN, then by epss percentile desc
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

        def sort_key(e: CVEEntry) -> Tuple[int, float]:
            sev = severity_order.get(e.severity, 99)
            epss = -(e.epss_percentile or 0.0)  # negate so higher percentile = lower key
            return (sev, epss)

        enriched.sort(key=sort_key)
        return enriched

    # ---- internal analyzers ----
    def _analyze_file(self, path: str) -> Dict[str, Any]:
        """Analyze a text file — read contents, search KB."""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            findings["error"] = f"Failed to read file: {e}"
            return findings

        # extract CVE IDs using regex
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        cve_ids = list(set(m.group(0).upper() for m in cve_pattern.finditer(content)))

        entries = []
        for cve_id in cve_ids[:100]:  # cap at 100 to avoid ridiculous lookups
            entry = self._kb.get(cve_id)
            if entry:
                entries.append(entry)

        findings["cves"] = [e.to_dict() for e in entries]
        findings["cve_count"] = len(entries)
        return findings

    def _analyze_binary(self, path: str) -> Dict[str, Any]:
        """Analyze a binary — extract strings, search KB for CVEs."""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        # simple binary string extraction (no pefile/elf dependencies)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            findings["error"] = f"Failed to read binary: {e}"
            return findings

        # extract printable ASCII strings >= 4 chars
        strings = self._extract_strings(data)

        entries = self.analyze_strings(strings)
        findings["cves"] = [e.to_dict() for e in entries]
        findings["cve_count"] = len(entries)
        findings["strings_extracted"] = len(strings)
        return findings

    def _analyze_sbom(self, path: str) -> Dict[str, Any]:
        """Analyze an SBOM file — parse, match packages to known CVEs."""
        findings: Dict[str, Any] = {"path": path, "cves": []}

        try:
            # try sbom matcher if available
            from .cve_sbom_matcher import match_sbom
            result = match_sbom(path, self._kb)
            findings.update(result)
        except ImportError:
            # fallback: just read the file and look for CVE IDs
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                import re
                cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
                cve_ids = list(set(m.group(0).upper() for m in cve_pattern.finditer(content)))

                entries = []
                for cve_id in cve_ids[:100]:
                    entry = self._kb.get(cve_id)
                    if entry:
                        entries.append(entry)
                findings["cves"] = [e.to_dict() for e in entries]
                findings["cve_count"] = len(entries)
            except Exception as e:
                findings["error"] = f"SBOM analysis failed: {e}"

        return findings

    @staticmethod
    def _extract_strings(data: bytes, min_len: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data.
        Static method — doesn't need instance state."""
        strings: List[str] = []
        current: List[int] = []

        for byte in data:
            if 32 <= byte <= 126:  # printable ASCII
                current.append(byte)
            else:
                if len(current) >= min_len:
                    strings.append(bytes(current).decode("ascii", errors="replace"))
                current = []

        # don't forget the last one
        if len(current) >= min_len:
            strings.append(bytes(current).decode("ascii", errors="replace"))

        return strings
