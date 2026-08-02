# 2026-07-05: preserved; minor optimizations applied.
#!/usr/bin/env python3
# Knowledge graph for vulnerability analysis — entity/relation management, Cypher-style query,
# D3.js export, Graphviz visualization, and JSON/pickle/gexf serialization.
# 2026-07-13: added Cypher-style query parser; D3 export with color/size maps; GEXF support.
# 2026-07-25: 新增图中心性分析、差异比对、孤立引用清理 — 漏洞知识图谱枢纽节点识别与版本跟踪

import logging as _logging
import json as _json
import pickle as _pickle
import os as _os
from collections import defaultdict as _defaultdict
from typing import Dict, List, Optional, Any, Tuple, Set, Union

__dbg = _logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity and relation type enums (string‑based for extensibility)
# ---------------------------------------------------------------------------

ENTITY_TYPES = [
    "BINARY",
    "FUNCTION",
    "BASIC_BLOCK",
    "INSTRUCTION",
    "VULNERABILITY",
    "CVE",
    "EXPLOIT",
    "LIBRARY",
    "PROTOCOL",
    "STRING",
    "IMPORT",
    "EXPORT",
    "REGISTER",
    "MEMORY_REGION",
    "STACK_VARIABLE",
    "HEAP_OBJECT",
    "SYSCALL",
    "NETWORK_ENDPOINT",
    "FILE_PATH",
    "USER",
    "CERTIFICATE",
    "KEY",
    "PASSWORD",
    "TOKEN",
    "SESSION",
    "PATCH",
    "COMMIT",
    "AUTHOR",
    "TAG",
    "UNKNOWN",
]

RELATION_TYPES = [
    "CALLS",
    "REFERENCES",
    "CONTAINS",
    "DEPENDS_ON",
    "IMPLEMENTS",
    "INHERITS",
    "EXPLOITS",
    "PATCHES",
    "AFFECTS",
    "MITIGATES",
    "AUTHENTICATES",
    "ENCRYPTS",
    "SIGNED_BY",
    "COMPILED_FROM",
    "LINKS_TO",
    "IMPORTS",
    "EXPORTS",
    "BRANCHES_TO",
    "FALLS_THROUGH",
    "JUMPS_TO",
    "RETURNS_TO",
    "READS",
    "WRITES",
    "ALLOCATES",
    "FREES",
    "MAPS_TO",
    "TRANSLATES",
    "PROTECTS",
    "BYPASSES",
    "TRIGGERS",
    "DATA_FLOW",
    "CONTROL_FLOW",
    "TAINTED_BY",
    "SANITIZED_BY",
    "HAS_TYPE",
    "ANNOTATED_WITH",
    "SIMILAR_TO",
    "DUPLICATE_OF",
    "PREVIOUS_VERSION",
    "NEXT_VERSION",
    "BELONGS_TO",
    "OWNS",
    "HAS_PERMISSION",
    "VIOLATES",
    "COMPLIES_WITH",
    "GENERATED_BY",
    "ANALYZED_BY",
    "ALIAS_OF",
    "PARAMETER_OF",
    "RETURN_VALUE_OF",
]


class KnowledgeGraphEntity:
    """A node in the knowledge graph with typed properties."""

    __slots__ = ('m_id', 'm_type', 'm_props', 'm_labels', 'm_created', 'm_updated')

    def __init__(self, entity_id, entity_type, properties=None, labels=None):
        self.m_id = entity_id
        self.m_type = entity_type if entity_type in ENTITY_TYPES else "UNKNOWN"
        self.m_props = dict(properties) if properties else {}
        self.m_labels = list(labels) if labels else []
        import time as _time
        ts = _time.time()
        self.m_created = ts
        self.m_updated = ts

    def set_property(self, key, value):
        import time as _time
        self.m_props[key] = value
        self.m_updated = _time.time()

    def get_property(self, key, default=None):
        return self.m_props.get(key, default)

    def has_property(self, key):
        return key in self.m_props

    def add_label(self, label):
        if label not in self.m_labels:
            self.m_labels.append(label)

    def remove_label(self, label):
        if label in self.m_labels:
            self.m_labels.remove(label)

    def to_dict(self):
        return {
            "id": self.m_id,
            "type": self.m_type,
            "properties": dict(self.m_props),
            "labels": list(self.m_labels),
            "created": self.m_created,
            "updated": self.m_updated,
        }

    @classmethod
    def from_dict(cls, d):
        ent = cls(d["id"], d.get("type", "UNKNOWN"), d.get("properties"), d.get("labels"))
        ent.m_created = d.get("created", 0)
        ent.m_updated = d.get("updated", 0)
        return ent

    def __repr__(self):
        return f"<KnowledgeGraphEntity id={self.m_id} type={self.m_type}>"

    def __hash__(self):
        return hash(self.m_id)

    def __eq__(self, other):
        if not isinstance(other, KnowledgeGraphEntity):
            return False
        return self.m_id == other.m_id


class KnowledgeGraphRelation:
    """A directed edge connecting two entities."""

    __slots__ = ('m_id', 'm_src', 'm_dst', 'm_type', 'm_props', 'm_weight', 'm_created')

    def __init__(self, rel_id, source_id, dest_id, rel_type, properties=None, weight=1.0):
        self.m_id = rel_id
        self.m_src = source_id
        self.m_dst = dest_id
        self.m_type = rel_type if rel_type in RELATION_TYPES else "LINKS_TO"
        self.m_props = dict(properties) if properties else {}
        self.m_weight = float(weight) if weight is not None else 1.0
        import time as _time
        self.m_created = _time.time()

    def set_property(self, key, value):
        self.m_props[key] = value

    def get_property(self, key, default=None):
        return self.m_props.get(key, default)

    def to_dict(self):
        return {
            "id": self.m_id,
            "source": self.m_src,
            "target": self.m_dst,
            "type": self.m_type,
            "properties": dict(self.m_props),
            "weight": self.m_weight,
            "created": self.m_created,
        }

    @classmethod
    def from_dict(cls, d):
        rel = cls(
            d["id"], d["source"], d["target"], d.get("type", "LINKS_TO"),
            d.get("properties"), d.get("weight", 1.0),
        )
        rel.m_created = d.get("created", 0)
        return rel

    def __repr__(self):
        return f"<KnowledgeGraphRelation {self.m_src} -[{self.m_type}]-> {self.m_dst}>"

    def __hash__(self):
        return hash(self.m_id)

    def __eq__(self, other):
        if not isinstance(other, KnowledgeGraphRelation):
            return False
        return self.m_id == other.m_id


class CypherQuery:
    """Minimal Cypher‑style query parser for MATCH/WHERE/RETURN patterns."""

    __slots__ = ('m_raw', 'm_match_clause', 'm_where_clause', 'm_return_clause',
                 'm_limit', 'm_skip', 'm_order_by')

    def __init__(self, query_string):
        self.m_raw = query_string
        self.m_match_clause = None
        self.m_where_clause = None
        self.m_return_clause = None
        self.m_limit = None
        self.m_skip = 0
        self.m_order_by = None
        self._parse_cq(query_string)

    def _parse_cq(self, qs):
        qs_upper = qs.upper().strip()
        tokens = qs.split()
        n = len(tokens)
        i = 0

        while i < n:
            tok = tokens[i].upper()
            if tok == "MATCH":
                i += 1
                buf = []
                while i < n and tokens[i].upper() not in ("WHERE", "RETURN", "ORDER", "LIMIT", "SKIP"):
                    buf.append(tokens[i])
                    i += 1
                self.m_match_clause = " ".join(buf).strip()
            elif tok == "WHERE":
                i += 1
                buf = []
                while i < n and tokens[i].upper() not in ("RETURN", "ORDER", "LIMIT", "SKIP"):
                    buf.append(tokens[i])
                    i += 1
                self.m_where_clause = " ".join(buf).strip()
            elif tok == "RETURN":
                i += 1
                buf = []
                while i < n and tokens[i].upper() not in ("ORDER", "LIMIT", "SKIP"):
                    buf.append(tokens[i])
                    i += 1
                self.m_return_clause = " ".join(buf).strip()
            elif tok == "ORDER":
                i += 1
                if i < n and tokens[i].upper() == "BY":
                    i += 1
                buf = []
                while i < n and tokens[i].upper() not in ("LIMIT", "SKIP"):
                    buf.append(tokens[i])
                    i += 1
                self.m_order_by = " ".join(buf).strip()
            elif tok == "LIMIT":
                i += 1
                if i < n:
                    try:
                        self.m_limit = int(tokens[i])
                    except ValueError:
                        self.m_limit = None
                    i += 1
                else:
                    i += 1
            elif tok == "SKIP":
                i += 1
                if i < n:
                    try:
                        self.m_skip = int(tokens[i])
                    except ValueError:
                        self.m_skip = 0
                    i += 1
                else:
                    i += 1
            else:
                i += 1

    def __repr__(self):
        return f"<CypherQuery MATCH={self.m_match_clause} RETURN={self.m_return_clause}>"


class VulnKnowledgeGraph:
    """Full vulnerability knowledge graph with entity/relation CRUD, query, export, and stats."""

    __slots__ = ('m_name', 'm_entities', 'm_relations',
                 'm_entity_index', 'm_relation_index',
                 'm_adj_out', 'm_adj_in')

    def __init__(self, name="vuln_kg"):
        self.m_name = name
        self.m_entities: Dict[str, KnowledgeGraphEntity] = {}
        self.m_relations: Dict[str, KnowledgeGraphRelation] = {}
        self.m_entity_index: Dict[str, List[str]] = _defaultdict(list)
        self.m_relation_index: Dict[str, List[str]] = _defaultdict(list)
        self.m_adj_out: Dict[str, List[str]] = _defaultdict(list)
        self.m_adj_in: Dict[str, List[str]] = _defaultdict(list)

    # ---- Entity CRUD ----

    def add_entity(self, entity: KnowledgeGraphEntity) -> str:
        eid = entity.m_id
        self.m_entities[eid] = entity
        self.m_entity_index[entity.m_type].append(eid)
        return eid

    def create_entity(self, entity_id, entity_type, properties=None, labels=None) -> KnowledgeGraphEntity:
        ent = KnowledgeGraphEntity(entity_id, entity_type, properties, labels)
        self.add_entity(ent)
        return ent

    def get_entity(self, entity_id) -> Optional[KnowledgeGraphEntity]:
        return self.m_entities.get(entity_id)

    def get_entities_by_type(self, entity_type) -> List[KnowledgeGraphEntity]:
        eids = self.m_entity_index.get(entity_type, [])
        return [self.m_entities[eid] for eid in eids if eid in self.m_entities]

    def get_entities_by_label(self, label) -> List[KnowledgeGraphEntity]:
        result = []
        idx = 0
        ents = list(self.m_entities.values())
        while idx < len(ents):
            if label in ents[idx].m_labels:
                result.append(ents[idx])
            idx += 1
        return result

    def get_entities_by_property(self, key, value) -> List[KnowledgeGraphEntity]:
        result = []
        idx = 0
        ents = list(self.m_entities.values())
        while idx < len(ents):
            if ents[idx].get_property(key) == value:
                result.append(ents[idx])
            idx += 1
        return result

    def update_entity(self, entity_id, properties=None, labels=None) -> bool:
        ent = self.m_entities.get(entity_id)
        if ent is None:
            return False
        if properties:
            for k, v in properties.items():
                ent.set_property(k, v)
        if labels is not None:
            ent.m_labels = list(labels)
        return True

    def delete_entity(self, entity_id) -> bool:
        if entity_id not in self.m_entities:
            return False
        ent = self.m_entities.pop(entity_id)
        self.m_entity_index[ent.m_type].remove(entity_id)
        # Cascade: remove all relations connected to this entity
        to_remove = []
        ridx = 0
        rel_ids = list(self.m_relations.keys())
        while ridx < len(rel_ids):
            rel = self.m_relations[rel_ids[ridx]]
            if rel.m_src == entity_id or rel.m_dst == entity_id:
                to_remove.append(rel_ids[ridx])
            ridx += 1
        rj = 0
        while rj < len(to_remove):
            self.delete_relation(to_remove[rj])
            rj += 1
        return True

    def get_all_entities(self) -> List[KnowledgeGraphEntity]:
        return list(self.m_entities.values())

    def entity_count(self) -> int:
        return len(self.m_entities)

    # ---- Relation CRUD ----

    def add_relation(self, relation: KnowledgeGraphRelation) -> str:
        rid = relation.m_id
        self.m_relations[rid] = relation
        self.m_relation_index[relation.m_type].append(rid)
        self.m_adj_out[relation.m_src].append(rid)
        self.m_adj_in[relation.m_dst].append(rid)
        return rid

    def create_relation(self, rel_id, source_id, dest_id, rel_type,
                        properties=None, weight=1.0) -> KnowledgeGraphRelation:
        rel = KnowledgeGraphRelation(rel_id, source_id, dest_id, rel_type, properties, weight)
        self.add_relation(rel)
        return rel

    def get_relation(self, rel_id) -> Optional[KnowledgeGraphRelation]:
        return self.m_relations.get(rel_id)

    def get_relations_by_type(self, rel_type) -> List[KnowledgeGraphRelation]:
        rids = self.m_relation_index.get(rel_type, [])
        return [self.m_relations[rid] for rid in rids if rid in self.m_relations]

    def get_outgoing_relations(self, entity_id) -> List[KnowledgeGraphRelation]:
        rids = self.m_adj_out.get(entity_id, [])
        return [self.m_relations[rid] for rid in rids if rid in self.m_relations]

    def get_incoming_relations(self, entity_id) -> List[KnowledgeGraphRelation]:
        rids = self.m_adj_in.get(entity_id, [])
        return [self.m_relations[rid] for rid in rids if rid in self.m_relations]

    def get_neighbors(self, entity_id, direction="both") -> List[KnowledgeGraphEntity]:
        neighbors = set()
        if direction in ("out", "both"):
            out_rels = self.get_outgoing_relations(entity_id)
            ri = 0
            while ri < len(out_rels):
                nid = out_rels[ri].m_dst
                if nid in self.m_entities:
                    neighbors.add(nid)
                ri += 1
        if direction in ("in", "both"):
            in_rels = self.get_incoming_relations(entity_id)
            ri = 0
            while ri < len(in_rels):
                nid = in_rels[ri].m_src
                if nid in self.m_entities:
                    neighbors.add(nid)
                ri += 1
        return [self.m_entities[nid] for nid in neighbors]

    def update_relation(self, rel_id, properties=None, weight=None) -> bool:
        rel = self.m_relations.get(rel_id)
        if rel is None:
            return False
        if properties:
            for k, v in properties.items():
                rel.set_property(k, v)
        if weight is not None:
            rel.m_weight = float(weight)
        return True

    def delete_relation(self, rel_id) -> bool:
        if rel_id not in self.m_relations:
            return False
        rel = self.m_relations.pop(rel_id)
        self.m_relation_index[rel.m_type].remove(rel_id)
        if rel_id in self.m_adj_out.get(rel.m_src, []):
            self.m_adj_out[rel.m_src].remove(rel_id)
        if rel_id in self.m_adj_in.get(rel.m_dst, []):
            self.m_adj_in[rel.m_dst].remove(rel_id)
        return True

    def get_all_relations(self) -> List[KnowledgeGraphRelation]:
        return list(self.m_relations.values())

    def relation_count(self) -> int:
        return len(self.m_relations)

    # ---- Query ----

    def query(self, cypher: Union[str, CypherQuery]) -> List[Dict[str, Any]]:
        if isinstance(cypher, str):
            cq = CypherQuery(cypher)
        else:
            cq = cypher

        results: List[Dict[str, Any]] = []
        match_clause = cq.m_match_clause
        if match_clause is None:
            __dbg.warning("Query has no MATCH clause")
            return results

        # Parse MATCH pattern: (a:TYPE) -[r:REL_TYPE]-> (b:TYPE)
        match_upper = match_clause.upper().strip()
        if "<-" in match_upper and "->" in match_upper:
            __dbg.warning("Bidirectional patterns not supported yet")
            return results

        is_outgoing = "->" in match_clause
        is_incoming = "<-" in match_clause
        # Determine entity type filters from MATCH
        entity_type_filter = None
        rel_type_filter = None

        import re as _re

        # Extract entity type from (a:TYPE)
        ent_pat = _re.findall(r'\((\w+)(?::(\w+))?\)', match_clause)
        rel_pat = _re.findall(r'\[(\w+)(?::(\w+))?\]', match_clause)

        # Find which entities to match
        src_type = None
        dst_type = None
        if len(ent_pat) >= 2:
            src_var = ent_pat[0][0]
            src_type = ent_pat[0][1] if ent_pat[0][1] else None
            dst_var = ent_pat[1][0]
            dst_type = ent_pat[1][1] if ent_pat[1][1] else None

        if len(rel_pat) >= 1:
            rel_type_filter = rel_pat[0][1] if rel_pat[0][1] else None

        # Collect candidate relations
        candidates: List[KnowledgeGraphRelation] = []
        if rel_type_filter:
            candidates = self.get_relations_by_type(rel_type_filter)
        else:
            candidates = list(self.m_relations.values())

        # Filter by source/destination entity types
        filtered = []
        ri = 0
        while ri < len(candidates):
            rel = candidates[ri]
            src_ok = True
            dst_ok = True
            if src_type:
                src_ent = self.m_entities.get(rel.m_src)
                src_ok = src_ent is not None and src_ent.m_type == src_type
            if dst_type:
                dst_ent = self.m_entities.get(rel.m_dst)
                dst_ok = dst_ent is not None and dst_ent.m_type == dst_type
            if src_ok and dst_ok:
                filtered.append(rel)
            ri += 1

        # Apply WHERE clause
        if cq.m_where_clause:
            where_upper = cq.m_where_clause.upper()
            where_filtered = []
            rj = 0
            while rj < len(filtered):
                rel = filtered[rj]
                src_ent = self.m_entities.get(rel.m_src)
                dst_ent = self.m_entities.get(rel.m_dst)
                # Simple property equality: a.name = "foo"
                match_ok = True
                # Check for property conditions (simplified)
                cond_parts = where_upper.replace(" AND ", " and ").split(" and ")
                ck = 0
                while ck < len(cond_parts):
                    cond = cond_parts[ck].strip()
                    if "=" in cond and ">=" not in cond and "<=" not in cond and "!=" not in cond:
                        parts = cond.split("=")
                        lhs = parts[0].strip().lower()
                        rhs = parts[1].strip().strip("'").strip('"')
                        if lhs.startswith("a.") and src_ent:
                            prop_name = lhs[2:]
                            if str(src_ent.get_property(prop_name, "")) != rhs:
                                match_ok = False
                                break
                        elif lhs.startswith("b.") and dst_ent:
                            prop_name = lhs[2:]
                            if str(dst_ent.get_property(prop_name, "")) != rhs:
                                match_ok = False
                                break
                    ck += 1
                if match_ok:
                    where_filtered.append(rel)
                rj += 1
            filtered = where_filtered

        # Build result rows
        rk = 0
        while rk < len(filtered):
            rel = filtered[rk]
            row = {}
            src_ent = self.m_entities.get(rel.m_src)
            dst_ent = self.m_entities.get(rel.m_dst)
            if src_ent:
                row["a"] = src_ent.to_dict()
            if dst_ent:
                row["b"] = dst_ent.to_dict()
            row["r"] = rel.to_dict()
            results.append(row)
            rk += 1

        # LIMIT / SKIP
        if cq.m_skip:
            results = results[cq.m_skip:]
        if cq.m_limit is not None:
            results = results[:cq.m_limit]

        return results

    # ---- Path queries ----

    def find_paths(self, src_id, dst_id, max_depth=5) -> List[List[str]]:
        """BFS to find all paths between two entities (returns lists of relation IDs)."""
        paths: List[List[str]] = []
        queue: List[Tuple[str, List[str]]] = [(src_id, [])]
        visited_paths: Set[Tuple[str, ...]] = set()

        while len(queue) > 0:
            current, path = queue.pop(0)
            if len(path) >= max_depth:
                continue
            out_rels = self.get_outgoing_relations(current)
            ri = 0
            while ri < len(out_rels):
                rel = out_rels[ri]
                next_node = rel.m_dst
                new_path = path + [rel.m_id]
                path_tuple = tuple(new_path)
                if path_tuple in visited_paths:
                    ri += 1
                    continue
                visited_paths.add(path_tuple)
                if next_node == dst_id:
                    paths.append(new_path)
                else:
                    queue.append((next_node, new_path))
                ri += 1

        return paths

    def shortest_path(self, src_id, dst_id, max_depth=10) -> Optional[List[str]]:
        paths = self.find_paths(src_id, dst_id, max_depth)
        if not paths:
            return None
        shortest = paths[0]
        pi = 1
        while pi < len(paths):
            if len(paths[pi]) < len(shortest):
                shortest = paths[pi]
            pi += 1
        return shortest

    # ---- Subgraph extraction ----

    def subgraph(self, entity_ids: List[str], depth: int = 1) -> 'VulnKnowledgeGraph':
        """Extract a subgraph centered on the given entity IDs."""
        sg = VulnKnowledgeGraph(f"{self.m_name}_subgraph")
        visited: Set[str] = set()
        queue = [(eid, 0) for eid in entity_ids if eid in self.m_entities]
        qi = 0
        while qi < len(queue):
            eid, d = queue[qi]
            qi += 1
            if eid in visited or d > depth:
                continue
            visited.add(eid)
            ent = self.m_entities.get(eid)
            if ent:
                sg.add_entity(KnowledgeGraphEntity(
                    ent.m_id, ent.m_type,
                    dict(ent.m_props), list(ent.m_labels),
                ))
                # Add neighbors
                neighbors = self.get_neighbors(eid, "both")
                ni = 0
                while ni < len(neighbors):
                    nid = neighbors[ni].m_id
                    if nid not in visited:
                        queue.append((nid, d + 1))
                    ni += 1
                # Add relations between visited entities
                out_rels = self.get_outgoing_relations(eid)
                ri = 0
                while ri < len(out_rels):
                    rel = out_rels[ri]
                    if rel.m_dst in visited:
                        sg.add_relation(KnowledgeGraphRelation(
                            rel.m_id, rel.m_src, rel.m_dst, rel.m_type,
                            dict(rel.m_props), rel.m_weight,
                        ))
                    ri += 1
                in_rels = self.get_incoming_relations(eid)
                rj = 0
                while rj < len(in_rels):
                    rel = in_rels[rj]
                    if rel.m_src in visited:
                        sg.add_relation(KnowledgeGraphRelation(
                            rel.m_id, rel.m_src, rel.m_dst, rel.m_type,
                            dict(rel.m_props), rel.m_weight,
                        ))
                    rj += 1

        return sg

    # ---- Statistics ----

    def statistics(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "name": self.m_name,
            "entity_count": len(self.m_entities),
            "relation_count": len(self.m_relations),
            "entity_types": {},
            "relation_types": {},
            "density": 0.0,
            "avg_degree": 0.0,
            "max_out_degree": 0,
            "max_in_degree": 0,
            "isolated_nodes": 0,
        }

        # Entity type distribution
        etypes = list(self.m_entity_index.keys())
        ei = 0
        while ei < len(etypes):
            stats["entity_types"][etypes[ei]] = len(self.m_entity_index[etypes[ei]])
            ei += 1

        # Relation type distribution
        rtypes = list(self.m_relation_index.keys())
        ri = 0
        while ri < len(rtypes):
            stats["relation_types"][rtypes[ri]] = len(self.m_relation_index[rtypes[ri]])
            ri += 1

        # Degree statistics
        total_degree = 0
        max_out = 0
        max_in = 0
        isolated = 0
        eids = list(self.m_entities.keys())
        ei = 0
        while ei < len(eids):
            eid = eids[ei]
            out_d = len(self.m_adj_out.get(eid, []))
            in_d = len(self.m_adj_in.get(eid, []))
            total_degree += out_d + in_d
            if out_d > max_out:
                max_out = out_d
            if in_d > max_in:
                max_in = in_d
            if out_d == 0 and in_d == 0:
                isolated += 1
            ei += 1

        n = max(len(self.m_entities), 1)
        m = len(self.m_relations)
        stats["max_out_degree"] = max_out
        stats["max_in_degree"] = max_in
        stats["isolated_nodes"] = isolated
        stats["avg_degree"] = total_degree / n if n > 0 else 0
        stats["density"] = (2 * m) / (n * (n - 1)) if n > 1 else 0

        return stats

    # 2026-07-25: 图中心性分析 — 识别漏洞知识图谱中最关键的枢纽节点
    # 度中心性（Degree Centrality）: 直接连接的边数 / (N-1)，衡量节点局部影响力
    # 介数中心性（Betweenness Centrality）: 节点位于多少最短路径上，衡量信息桥接能力
    # 对于CVE/漏洞图谱，高中心性的节点通常是关键漏洞、核心二进制或广泛依赖的库

    def find_central_nodes(self, top_n: int = 10, centrality: str = "degree") -> List[Dict[str, Any]]:
        """Compute centrality scores and return the top-N most central nodes.

        centrality modes:
          - "degree": degree centrality (normalized by N-1)
          - "betweenness": betweenness centrality (Brandes algorithm, unweighted)
          - "all": both degree and betweenness scores
        """
        n = max(len(self.m_entities), 1)
        entities = list(self.m_entities.values())

        # ---- 度中心性: C_D(v) = deg(v) / (n-1) ----
        if centrality in ("degree", "all"):
            degree_scores: Dict[str, float] = {}
            ei = 0
            while ei < len(entities):
                eid = entities[ei].m_id
                out_d = len(self.m_adj_out.get(eid, []))
                in_d = len(self.m_adj_in.get(eid, []))
                degree_scores[eid] = (out_d + in_d) / (n - 1) if n > 1 else 0.0
                ei += 1

        # ---- 介数中心性: Brandes算法，针对所有节点对做BFS ----
        if centrality in ("betweenness", "all"):
            # 小心：O(V*(V+E)) 对大图较重；加一个节点数上限的警告
            betweenness: Dict[str, float] = {e.m_id: 0.0 for e in entities}
            if n > 5000:
                __dbg.warning("Betweenness centrality may be slow for graphs with >5000 nodes (%d nodes)", n)

            # 构建快速邻接表 (src -> [dst_ids])
            fwd_adj: Dict[str, List[str]] = _defaultdict(list)
            rels = list(self.m_relations.values())
            ri = 0
            while ri < len(rels):
                r = rels[ri]
                fwd_adj[r.m_src].append(r.m_dst)
                ri += 1

            eids_list = list(self.m_entities.keys())
            si = 0
            while si < len(eids_list):
                s = eids_list[si]
                # BFS from s
                stack: List[str] = []
                pred: Dict[str, List[str]] = {v: [] for v in eids_list}
                sigma: Dict[str, float] = {v: 0.0 for v in eids_list}
                dist: Dict[str, int] = {v: -1 for v in eids_list}

                sigma[s] = 1.0
                dist[s] = 0
                q: List[str] = [s]
                qi = 0
                while qi < len(q):
                    v = q[qi]
                    qi += 1
                    stack.append(v)
                    nbrs = fwd_adj.get(v, [])
                    wj = 0
                    while wj < len(nbrs):
                        w = nbrs[wj]
                        if dist[w] < 0:
                            dist[w] = dist[v] + 1
                            q.append(w)
                        if dist[w] == dist[v] + 1:
                            sigma[w] += sigma[v]
                            pred[w].append(v)
                        wj += 1

                delta: Dict[str, float] = {v: 0.0 for v in eids_list}
                # 逆序处理栈
                sk = len(stack) - 1
                while sk >= 0:
                    w = stack[sk]
                    sk -= 1
                    pj = 0
                    pw_list = pred[w]
                    while pj < len(pw_list):
                        v = pw_list[pj]
                        frac = (sigma[v] / sigma[w]) if sigma[w] > 0 else 0.0
                        delta[v] += frac * (1.0 + delta[w])
                        pj += 1
                    if w != s:
                        betweenness[w] += delta[w]
                si += 1

            # 有向图标准归一化：除以 (n-1)*(n-2)
            norm_factor = (n - 1) * (n - 2) if n > 2 else 1.0
            if norm_factor > 0:
                bi = 0
                bkeys = list(betweenness.keys())
                while bi < len(bkeys):
                    betweenness[bkeys[bi]] /= norm_factor
                    bi += 1

        # ---- 组装结果 ----
        result: List[Dict[str, Any]] = []
        ei = 0
        while ei < len(entities):
            ent = entities[ei]
            entry: Dict[str, Any] = {
                "id": ent.m_id,
                "type": ent.m_type,
                "label": ent.get_property("name", ent.m_id),
            }
            if centrality in ("degree", "all"):
                entry["degree_centrality"] = round(degree_scores[ent.m_id], 6)
            if centrality in ("betweenness", "all"):
                entry["betweenness_centrality"] = round(betweenness[ent.m_id], 6)
            result.append(entry)
            ei += 1

        # 按度中心性排序（默认），若为betweenness则按介数排序
        if centrality == "betweenness":
            result.sort(key=lambda x: x.get("betweenness_centrality", 0), reverse=True)
        elif centrality == "all":
            result.sort(key=lambda x: x.get("degree_centrality", 0), reverse=True)
        else:
            result.sort(key=lambda x: x.get("degree_centrality", 0), reverse=True)

        return result[:top_n]

    # 2026-07-25: 知识图谱差异比对 — 用于漏洞数据版本跟踪
    # 返回 added/removed/modified 三类变更，便于审计和回归检测

    def diff(self, other: 'VulnKnowledgeGraph') -> Dict[str, Any]:
        """Compare this graph (considered 'old' / baseline) with another graph ('new').

        Returns a dict with keys: added_entities, removed_entities, modified_entities,
        added_relations, removed_relations, modified_relations.
        An entity is 'modified' if its type, properties, or labels changed.
        A relation is 'modified' if its type, weight, source, target, or properties changed.
        """
        changes: Dict[str, Any] = {
            "added_entities": [],
            "removed_entities": [],
            "modified_entities": [],
            "added_relations": [],
            "removed_relations": [],
            "modified_relations": [],
        }

        # ---- 实体比对 ----
        my_eids = set(self.m_entities.keys())
        other_eids = set(other.m_entities.keys())

        # 新增实体 (在other中存在，在我中不存在)
        add_eids = other_eids - my_eids
        aid = 0
        add_list = sorted(add_eids)
        while aid < len(add_list):
            changes["added_entities"].append(other.m_entities[add_list[aid]].to_dict())
            aid += 1

        # 删除实体 (在我中存在，在other中不存在)
        del_eids = my_eids - other_eids
        didx = 0
        del_list = sorted(del_eids)
        while didx < len(del_list):
            changes["removed_entities"].append(self.m_entities[del_list[didx]].to_dict())
            didx += 1

        # 修改实体 (两边都存在但内容不同)
        common_eids = my_eids & other_eids
        eids_sorted = sorted(common_eids)
        ei = 0
        while ei < len(eids_sorted):
            eid = eids_sorted[ei]
            my_ent = self.m_entities[eid]
            other_ent = other.m_entities[eid]
            mod_entry: Dict[str, Any] = {"id": eid, "changes": []}
            if my_ent.m_type != other_ent.m_type:
                mod_entry["changes"].append({
                    "field": "type",
                    "old": my_ent.m_type,
                    "new": other_ent.m_type,
                })
            if my_ent.m_props != other_ent.m_props:
                # 列出具体的属性变更
                all_prop_keys = set(my_ent.m_props.keys()) | set(other_ent.m_props.keys())
                pk = 0
                pk_list = sorted(all_prop_keys)
                while pk < len(pk_list):
                    key = pk_list[pk]
                    ov = my_ent.m_props.get(key)
                    nv = other_ent.m_props.get(key)
                    if ov != nv:
                        mod_entry["changes"].append({
                            "field": f"property.{key}",
                            "old": ov,
                            "new": nv,
                        })
                    pk += 1
            if sorted(my_ent.m_labels) != sorted(other_ent.m_labels):
                mod_entry["changes"].append({
                    "field": "labels",
                    "old": list(my_ent.m_labels),
                    "new": list(other_ent.m_labels),
                })
            if mod_entry["changes"]:
                changes["modified_entities"].append(mod_entry)
            ei += 1

        # ---- 关系比对 ----
        my_rids = set(self.m_relations.keys())
        other_rids = set(other.m_relations.keys())

        add_rids = other_rids - my_rids
        ai = 0
        add_rids_sorted = sorted(add_rids)
        while ai < len(add_rids_sorted):
            changes["added_relations"].append(other.m_relations[add_rids_sorted[ai]].to_dict())
            ai += 1

        del_rids = my_rids - other_rids
        di = 0
        del_rids_sorted = sorted(del_rids)
        while di < len(del_rids_sorted):
            changes["removed_relations"].append(self.m_relations[del_rids_sorted[di]].to_dict())
            di += 1

        common_rids = my_rids & other_rids
        rids_sorted = sorted(common_rids)
        ri = 0
        while ri < len(rids_sorted):
            rid = rids_sorted[ri]
            my_rel = self.m_relations[rid]
            other_rel = other.m_relations[rid]
            mod_rel: Dict[str, Any] = {"id": rid, "changes": []}
            if my_rel.m_type != other_rel.m_type:
                mod_rel["changes"].append({
                    "field": "type",
                    "old": my_rel.m_type,
                    "new": other_rel.m_type,
                })
            if my_rel.m_src != other_rel.m_src:
                mod_rel["changes"].append({
                    "field": "source",
                    "old": my_rel.m_src,
                    "new": other_rel.m_src,
                })
            if my_rel.m_dst != other_rel.m_dst:
                mod_rel["changes"].append({
                    "field": "target",
                    "old": my_rel.m_dst,
                    "new": other_rel.m_dst,
                })
            if abs(my_rel.m_weight - other_rel.m_weight) > 1e-9:
                mod_rel["changes"].append({
                    "field": "weight",
                    "old": my_rel.m_weight,
                    "new": other_rel.m_weight,
                })
            if my_rel.m_props != other_rel.m_props:
                all_rpk = set(my_rel.m_props.keys()) | set(other_rel.m_props.keys())
                rpk = 0
                rpk_list = sorted(all_rpk)
                while rpk < len(rpk_list):
                    key = rpk_list[rpk]
                    ov = my_rel.m_props.get(key)
                    nv = other_rel.m_props.get(key)
                    if ov != nv:
                        mod_rel["changes"].append({
                            "field": f"property.{key}",
                            "old": ov,
                            "new": nv,
                        })
                    rpk += 1
            if mod_rel["changes"]:
                changes["modified_relations"].append(mod_rel)
            ri += 1

        __dbg.info(
            "Diff complete: +%d/-%d/~%d entities, +%d/-%d/~%d relations",
            len(changes["added_entities"]), len(changes["removed_entities"]),
            len(changes["modified_entities"]),
            len(changes["added_relations"]), len(changes["removed_relations"]),
            len(changes["modified_relations"]),
        )
        return changes

    # 2026-07-25: 孤立引用清理 — 删除entity后邻接表可能残留对已删除relation的引用
    # 以及relation指向的entity可能已被删除。此方法做一次全局自检并修复。

    def cleanup_orphan_references(self) -> Dict[str, int]:
        """Validate and clean stale references in adjacency indices and relation/entity indexes.

        Removes:
          - Adjacency entries referencing deleted relations
          - Adjacency entries for entities that no longer exist
          - Entity type index entries for deleted entities
          - Relation type index entries for deleted relations

        Returns a dict with counts of cleaned items per category.
        """
        clean_counts: Dict[str, int] = {
            "adj_out_stale_rels": 0,
            "adj_in_stale_rels": 0,
            "adj_out_stale_entities": 0,
            "adj_in_stale_entities": 0,
            "entity_index_stale": 0,
            "relation_index_stale": 0,
            "relation_dangling_src": 0,
            "relation_dangling_dst": 0,
            "dangling_relations_removed": 0,
        }

        # 1. 清理邻接表中指向已删除relation的引用
        out_keys = list(self.m_adj_out.keys())
        oi = 0
        while oi < len(out_keys):
            node = out_keys[oi]
            valid = [rid for rid in self.m_adj_out[node] if rid in self.m_relations]
            removed_count = len(self.m_adj_out[node]) - len(valid)
            clean_counts["adj_out_stale_rels"] += removed_count
            if valid:
                self.m_adj_out[node] = valid
            elif node not in self.m_entities:
                del self.m_adj_out[node]
            else:
                self.m_adj_out[node] = []
            oi += 1

        in_keys = list(self.m_adj_in.keys())
        ii = 0
        while ii < len(in_keys):
            node = in_keys[ii]
            valid = [rid for rid in self.m_adj_in[node] if rid in self.m_relations]
            removed_count = len(self.m_adj_in[node]) - len(valid)
            clean_counts["adj_in_stale_rels"] += removed_count
            if valid:
                self.m_adj_in[node] = valid
            elif node not in self.m_entities:
                del self.m_adj_in[node]
            else:
                self.m_adj_in[node] = []
            ii += 1

        # 2. 清理实体类型索引中不再存在的实体
        etype_keys = list(self.m_entity_index.keys())
        ei = 0
        while ei < len(etype_keys):
            etype = etype_keys[ei]
            valid_eids = [eid for eid in self.m_entity_index[etype] if eid in self.m_entities]
            clean_counts["entity_index_stale"] += len(self.m_entity_index[etype]) - len(valid_eids)
            if valid_eids:
                self.m_entity_index[etype] = valid_eids
            else:
                del self.m_entity_index[etype]
            ei += 1

        # 3. 清理关系类型索引中不再存在的关系
        rtype_keys = list(self.m_relation_index.keys())
        ri = 0
        while ri < len(rtype_keys):
            rtype = rtype_keys[ri]
            valid_rids = [rid for rid in self.m_relation_index[rtype] if rid in self.m_relations]
            clean_counts["relation_index_stale"] += len(self.m_relation_index[rtype]) - len(valid_rids)
            if valid_rids:
                self.m_relation_index[rtype] = valid_rids
            else:
                del self.m_relation_index[rtype]
            ri += 1

        # 4. 检查relation指向的实体是否存在 — 若悬空则移除相应的relation
        rel_ids = list(self.m_relations.keys())
        rj = 0
        while rj < len(rel_ids):
            r = self.m_relations[rel_ids[rj]]
            should_remove = False
            if r.m_src not in self.m_entities:
                clean_counts["relation_dangling_src"] += 1
                should_remove = True
            if r.m_dst not in self.m_entities:
                clean_counts["relation_dangling_dst"] += 1
                should_remove = True
            if should_remove:
                # 记录ID后再删，避免迭代中modify dict
                self.m_relations.pop(rel_ids[rj])
                # 同步清理关联索引
                if rel_ids[rj] in self.m_adj_out.get(r.m_src, []):
                    self.m_adj_out[r.m_src].remove(rel_ids[rj])
                if rel_ids[rj] in self.m_adj_in.get(r.m_dst, []):
                    self.m_adj_in[r.m_dst].remove(rel_ids[rj])
                rtype_list = self.m_relation_index.get(r.m_type, [])
                if rel_ids[rj] in rtype_list:
                    rtype_list.remove(rel_ids[rj])
                clean_counts["dangling_relations_removed"] += 1
            rj += 1

        total_cleaned = sum(clean_counts.values())
        if total_cleaned > 0:
            __dbg.info("Orphan cleanup: %d stale references removed across %d categories",
                       total_cleaned, sum(1 for v in clean_counts.values() if v > 0))
        return clean_counts

    # ---- D3.js export ----

    def _type_color_map(self):
        """Color mapping for entity types (D3-friendly palette)."""
        cmap = {
            "VULNERABILITY": "#e74c3c",
            "CVE": "#c0392b",
            "EXPLOIT": "#e67e22",
            "FUNCTION": "#3498db",
            "BASIC_BLOCK": "#2980b9",
            "BINARY": "#2ecc71",
            "LIBRARY": "#27ae60",
            "STRING": "#9b59b6",
            "IMPORT": "#8e44ad",
            "PASSWORD": "#f1c40f",
            "KEY": "#f39c12",
            "CERTIFICATE": "#1abc9c",
            "PATCH": "#16a085",
            "COMMIT": "#7f8c8d",
            "AUTHOR": "#95a5a6",
            "SYSCALL": "#d35400",
            "NETWORK_ENDPOINT": "#e91e63",
        }
        return cmap

    def _type_size_map(self):
        """Size mapping for entity types in D3 visualization."""
        smap = {
            "VULNERABILITY": 12,
            "CVE": 14,
            "EXPLOIT": 13,
            "FUNCTION": 8,
            "BASIC_BLOCK": 6,
            "BINARY": 16,
            "LIBRARY": 10,
            "PASSWORD": 7,
            "KEY": 7,
            "PATCH": 9,
            "DEFAULT": 7,
        }
        return smap

    def to_d3_json(self, output_path=None) -> str:
        """Export graph to D3.js force-directed layout JSON format."""
        cmap = self._type_color_map()
        smap = self._type_size_map()

        nodes: List[Dict] = []
        edges: List[Dict] = []

        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            node = {
                "id": ent.m_id,
                "type": ent.m_type,
                "label": ent.get_property("name", ent.m_id),
                "color": cmap.get(ent.m_type, "#bdc3c7"),
                "size": smap.get(ent.m_type, smap["DEFAULT"]),
                "properties": dict(ent.m_props),
                "labels": list(ent.m_labels),
            }
            nodes.append(node)
            ei += 1

        rel_list = list(self.m_relations.values())
        ri = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            edge = {
                "id": rel.m_id,
                "source": rel.m_src,
                "target": rel.m_dst,
                "type": rel.m_type,
                "weight": rel.m_weight,
                "properties": dict(rel.m_props),
            }
            edges.append(edge)
            ri += 1

        d3_data = {
            "graph": {
                "name": self.m_name,
                "nodes": nodes,
                "edges": edges,
                "stats": self.statistics(),
            }
        }

        result = _json.dumps(d3_data, indent=2, ensure_ascii=False, default=str)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(result)
            __dbg.info("D3 JSON exported to %s (%d nodes, %d edges)", output_path, len(nodes), len(edges))

        return result

    def to_d3_html(self, output_path=None) -> str:
        """Generate a self-contained D3.js visualization HTML page."""
        d3_json = self.to_d3_json()

        html = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Knowledge Graph — """ + self.m_name + r"""</title>
<style>
body { margin: 0; overflow: hidden; background: #1a1a2e; font-family: 'Segoe UI', sans-serif; }
.links line { stroke: #555; stroke-opacity: 0.6; stroke-width: 1px; }
.nodes circle { stroke: #fff; stroke-width: 1.5px; cursor: pointer; }
.nodes text { fill: #ccc; font-size: 10px; pointer-events: none; }
.tooltip { position: absolute; background: #2c3e50; color: #ecf0f1; padding: 8px 12px;
    border-radius: 4px; font-size: 12px; pointer-events: none; opacity: 0;
    transition: opacity 0.2s; max-width: 300px; word-wrap: break-word; }
.legend { position: absolute; top: 10px; right: 10px; background: rgba(44,62,80,0.9);
    padding: 10px; border-radius: 4px; color: #ecf0f1; font-size: 11px; }
</style>
</head>
<body>
<div class="tooltip" id="tooltip"></div>
<div class="legend" id="legend"></div>
<svg width="100%" height="100%"></svg>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const graphData = """ + d3_json + r""";
const width = window.innerWidth;
const height = window.innerHeight;

const svg = d3.select("svg"),
    g = svg.append("g");

const zoom = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (event) => {
    g.attr("transform", event.transform);
});
svg.call(zoom);

const simulation = d3.forceSimulation(graphData.graph.nodes)
    .force("link", d3.forceLink(graphData.graph.edges).id(d => d.id).distance(100))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide(30));

const link = g.append("g").attr("class", "links").selectAll("line")
    .data(graphData.graph.edges).enter().append("line")
    .attr("stroke-width", d => Math.max(1, Math.min(d.weight * 3, 6)));

const node = g.append("g").attr("class", "nodes").selectAll("g")
    .data(graphData.graph.nodes).enter().append("g")
    .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

node.append("circle").attr("r", d => d.size).attr("fill", d => d.color);

node.append("text").text(d => d.label.substring(0, 20))
    .attr("dx", d => d.size + 4).attr("dy", 3);

node.on("mouseover", (event, d) => {
    d3.select("#tooltip").style("opacity", 1)
        .html("<b>" + d.label + "</b><br>Type: " + d.type + "<br>" +
              JSON.stringify(d.properties).substring(0, 200));
}).on("mousemove", (event) => {
    d3.select("#tooltip").style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY - 10) + "px");
}).on("mouseout", () => {
    d3.select("#tooltip").style("opacity", 0);
});

simulation.on("tick", () => {
    link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
});

function dragstarted(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
function dragended(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }

// Legend
const types = [...new Set(graphData.graph.nodes.map(n => n.type))];
const legendHtml = types.map(t => {
    const node = graphData.graph.nodes.find(n => n.type === t);
    const color = node ? node.color : "#bdc3c7";
    return `<div><span style="display:inline-block;width:12px;height:12px;
        background:${color};border-radius:50%;margin-right:6px;"></span>${t}</div>`;
}).join("");
d3.select("#legend").html("<b>Legend</b><br>" + legendHtml);
</script>
</body>
</html>"""

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(html)
            __dbg.info("D3 HTML exported to %s", output_path)

        return html

    # ---- Graphviz export ----

    def to_dot(self, output_path=None) -> str:
        """Export graph to Graphviz DOT format."""
        lines: List[str] = []
        lines.append(f"digraph {self.m_name} {{")
        lines.append('    rankdir=LR;')
        lines.append('    node [fontname="Courier New", fontsize=10];')
        lines.append('    edge [fontname="Courier New", fontsize=8];')
        lines.append('')

        cmap = self._type_color_map()

        # Nodes
        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            eid_safe = ent.m_id.replace('"', '\\"').replace('\n', '\\n')
            color = cmap.get(ent.m_type, "#bdc3c7")
            label = ent.get_property("name", ent.m_id)[:40]
            lines.append(f'    "{eid_safe}" [label="{label}", fillcolor="{color}", style=filled, shape=box];')
            ei += 1

        lines.append('')

        # Edges
        rel_list = list(self.m_relations.values())
        ri = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            src_safe = rel.m_src.replace('"', '\\"').replace('\n', '\\n')
            dst_safe = rel.m_dst.replace('"', '\\"').replace('\n', '\\n')
            lines.append(f'    "{src_safe}" -> "{dst_safe}" [label="{rel.m_type}" weight={rel.m_weight}];')
            ri += 1

        lines.append('}')

        dot_content = '\n'.join(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(dot_content)
            __dbg.info("DOT exported to %s", output_path)

        return dot_content

    # ---- Import / Export ----

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.m_name,
            "entities": [e.to_dict() for e in self.m_entities.values()],
            "relations": [r.to_dict() for r in self.m_relations.values()],
        }

    @classmethod
    def from_dict(cls, d) -> 'VulnKnowledgeGraph':
        kg = cls(d.get("name", "imported_kg"))
        entities = d.get("entities", [])
        ei = 0
        while ei < len(entities):
            ent = KnowledgeGraphEntity.from_dict(entities[ei])
            kg.add_entity(ent)
            ei += 1
        relations = d.get("relations", [])
        ri = 0
        while ri < len(relations):
            rel = KnowledgeGraphRelation.from_dict(relations[ri])
            kg.add_relation(rel)
            ri += 1
        return kg

    def save_json(self, filepath: str):
        with open(filepath, 'w', encoding='utf-8') as fh:
            _json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False, default=str)
        __dbg.info("Knowledge graph saved to %s (JSON)", filepath)

    @classmethod
    def load_json(cls, filepath: str) -> 'VulnKnowledgeGraph':
        with open(filepath, 'r', encoding='utf-8') as fh:
            data = _json.load(fh)
        return cls.from_dict(data)

    def save_pickle(self, filepath: str):
        with open(filepath, 'wb') as fh:
            _pickle.dump(self, fh, protocol=_pickle.HIGHEST_PROTOCOL)
        __dbg.info("Knowledge graph saved to %s (pickle)", filepath)

    @classmethod
    def load_pickle(cls, filepath: str) -> 'VulnKnowledgeGraph':
        with open(filepath, 'rb') as fh:
            return _pickle.load(fh)

    def save_gexf(self, filepath: str):
        """Export to GEXF (Graph Exchange XML Format), compatible with Gephi."""
        import xml.etree.ElementTree as _ET
        root = _ET.Element("gexf", xmlns="http://gexf.net/1.3", version="1.3")
        graph_elem = _ET.SubElement(root, "graph", mode="static", defaultedgetype="directed")

        # Attributes
        attrs_node = _ET.SubElement(graph_elem, "attributes", {"class": "node", "mode": "static"})
        _ET.SubElement(attrs_node, "attribute", {"id": "type", "title": "Type", "type": "string"})
        _ET.SubElement(attrs_node, "attribute", {"id": "labels", "title": "Labels", "type": "string"})

        attrs_edge = _ET.SubElement(graph_elem, "attributes", {"class": "edge", "mode": "static"})
        _ET.SubElement(attrs_edge, "attribute", {"id": "reltype", "title": "RelationType", "type": "string"})
        _ET.SubElement(attrs_edge, "attribute", {"id": "weight", "title": "Weight", "type": "float"})

        # Nodes
        nodes_elem = _ET.SubElement(graph_elem, "nodes")
        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            node_elem = _ET.SubElement(nodes_elem, "node", {"id": str(ent.m_id), "label": ent.get_property("name", ent.m_id)})
            attvals = _ET.SubElement(node_elem, "attvalues")
            _ET.SubElement(attvals, "attvalue", {"for": "type", "value": ent.m_type})
            _ET.SubElement(attvals, "attvalue", {"for": "labels", "value": ",".join(ent.m_labels)})
            ei += 1

        # Edges
        edges_elem = _ET.SubElement(graph_elem, "edges")
        rel_list = list(self.m_relations.values())
        ri = 0
        ridx = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            edge_elem = _ET.SubElement(edges_elem, "edge", {
                "id": str(ridx),
                "source": str(rel.m_src),
                "target": str(rel.m_dst),
                "type": "directed",
            })
            attvals_e = _ET.SubElement(edge_elem, "attvalues")
            _ET.SubElement(attvals_e, "attvalue", {"for": "reltype", "value": rel.m_type})
            _ET.SubElement(attvals_e, "attvalue", {"for": "weight", "value": str(rel.m_weight)})
            ri += 1
            ridx += 1

        tree = _ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        __dbg.info("GEXF exported to %s", filepath)

    # ---- Merge ----

    def merge(self, other: 'VulnKnowledgeGraph', conflict_strategy="keep_first"):
        """Merge another knowledge graph into this one."""
        other_ents = other.get_all_entities()
        oi = 0
        while oi < len(other_ents):
            ent = other_ents[oi]
            if ent.m_id not in self.m_entities:
                self.add_entity(KnowledgeGraphEntity(
                    ent.m_id, ent.m_type,
                    dict(ent.m_props), list(ent.m_labels),
                ))
            elif conflict_strategy == "update":
                self.update_entity(ent.m_id, dict(ent.m_props), list(ent.m_labels))
            oi += 1

        other_rels = other.get_all_relations()
        oj = 0
        while oj < len(other_rels):
            rel = other_rels[oj]
            if rel.m_id not in self.m_relations:
                self.add_relation(KnowledgeGraphRelation(
                    rel.m_id, rel.m_src, rel.m_dst, rel.m_type,
                    dict(rel.m_props), rel.m_weight,
                ))
            elif conflict_strategy == "update":
                self.update_relation(rel.m_id, dict(rel.m_props), rel.m_weight)
            oj += 1

        __dbg.info("Merged %d entities and %d relations", len(other_ents), len(other_rels))

    # ---- Clear ----

    def clear(self):
        self.m_entities.clear()
        self.m_relations.clear()
        self.m_entity_index.clear()
        self.m_relation_index.clear()
        self.m_adj_out.clear()
        self.m_adj_in.clear()

    def __repr__(self):
        return f"<VulnKnowledgeGraph name={self.m_name} entities={len(self.m_entities)} relations={len(self.m_relations)}>"

    def __len__(self):
        return len(self.m_entities)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_knowledge_graph(name="vuln_kg") -> VulnKnowledgeGraph:
    return VulnKnowledgeGraph(name)


def load_knowledge_graph(filepath: str) -> Optional[VulnKnowledgeGraph]:
    ext = _os.path.splitext(filepath)[1].lower()
    if ext == ".json":
        return VulnKnowledgeGraph.load_json(filepath)
    elif ext in (".pkl", ".pickle"):
        return VulnKnowledgeGraph.load_pickle(filepath)
    else:
        __dbg.error("Unsupported file format: %s", ext)
        return None
