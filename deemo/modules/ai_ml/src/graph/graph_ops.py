# Extracted from knowledge_graph.py — low-level 图 DB operations layer.
# Provides entity/relation CRUD, traversal, Cypher-style 查询 execution,
# path finding, subgraph extraction, statistical metrics, orphan cleanup,
# and 序列化 (dict/JSON/pickle). Analogous to Neo4j driver / networkx backend.

from collections import OrderedDict
import logging as _logging
import json as _json
import pickle as _pickle
import os as _os
from collections import defaultdict as _defaultdict
from typing import Dict, List, Optional, Any, Tuple, Set, Union

_STALE_LIMIT = 256

_dbg = _logging.getLogger(__name__)

# Entity and relation type enums (string-based for extensibility)

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
    """Minimal Cypher-style query parser for MATCH/WHERE/RETURN patterns."""

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


class BaseGraphOps:
    """Low-level graph database operations.

    Provides CRUD for entities and relations, adjacency-based traversal,
    Cypher-style query execution, BFS path finding, subgraph extraction,
    statistical metrics, orphan reference cleanup, and serialization.

    Serves as the backend layer for VulnKnowledgeGraph and other
    domain-specific graph structures.
    """

    __slots__ = ('m_name', 'm_entities', 'm_relations',
                 'm_entity_index', 'm_relation_index',
                 'm_adj_out', 'm_adj_in')

    def __init__(self, name: str = ""):
        self.m_name = name
        self.m_entities: Dict[str, KnowledgeGraphEntity] = {}
        self.m_relations: Dict[str, KnowledgeGraphRelation] = {}
        self.m_entity_index: Dict[str, List[str]] = _defaultdict(list)
        self.m_relation_index: Dict[str, List[str]] = _defaultdict(list)
        self.m_adj_out: Dict[str, List[str]] = _defaultdict(list)
        self.m_adj_in: Dict[str, List[str]] = _defaultdict(list)

# Entity CRUD

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

# Relation CRUD

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

# Query

    def query(self, cypher: Union[str, CypherQuery]) -> List[Dict[str, Any]]:
        if isinstance(cypher, str):
            cq = CypherQuery(cypher)
        else:
            cq = cypher

        results: List[Dict[str, Any]] = []
        match_clause = cq.m_match_clause
        if match_clause is None:
            _dbg.warning("Query has no MATCH clause")
            return results

        # Parse MATCH pattern: (a:TYPE) -[r:REL_TYPE]-> (b:TYPE)
        match_upper = match_clause.upper().strip()
        if "<-" in match_upper and "->" in match_upper:
            _dbg.warning("Bidirectional patterns not supported yet")
            return results

        # Determine entity type filters from MATCH
        import re as _re

        # Extract entity type from (a:TYPE)
        ent_pat = _re.findall(r'\((\w+)(?::(\w+))?\)', match_clause)
        rel_pat = _re.findall(r'\[(\w+)(?::(\w+))?\]', match_clause)

        # Find which entities to match
        src_type = None
        dst_type = None
        if len(ent_pat) >= 2:
            src_type = ent_pat[0][1] if ent_pat[0][1] else None
            dst_type = ent_pat[1][1] if ent_pat[1][1] else None

        if len(rel_pat) >= 1:
            rel_type_filter = rel_pat[0][1] if rel_pat[0][1] else None
        else:
            rel_type_filter = None

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

# Path queries

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

# Subgraph extraction

    def subgraph(self, entity_ids: List[str], depth: int = 1) -> 'BaseGraphOps':
        """Extract a subgraph centered on the given entity IDs.

        Uses ``self.__class__`` for construction so that subclasses
        (e.g. VulnKnowledgeGraph) produce instances of their own type.
        """
        sg = self.__class__(f"{self.m_name}_subgraph")
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

# Statistics

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

# Orphan cleanup
    # Validates and repairs stale references in adjacency indices and relation/entity
    # indexes after deletions. Ensures 图 consistency.

    def cleanup_orphan_references(self) -> Dict[str, int]:
        """Validate and clean stale references in adjacency indices and relation/entity indexes.

        Removes:
          - Adjacency entries referencing deleted relations
          - Adjacency entries for entities that no longer exist
          - Entity type index entries for deleted entities
          - Relation type index entries for deleted relations
          - Relations whose source or destination entity no longer exists

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

        # 1. Clean adjacency entries pointing to deleted relations
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

        # 2. Clean entity type index entries for removed entities
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

        # 3. Clean relation type index entries for removed relations
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

        # 4. Remove relations whose source/destination entity is missing
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
                self.m_relations.pop(rel_ids[rj])
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
            _dbg.info("Orphan cleanup: %d stale references removed across %d categories",
                       total_cleaned, sum(1 for v in clean_counts.values() if v > 0))
        return clean_counts

# Serialization

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.m_name,
            "entities": [e.to_dict() for e in self.m_entities.values()],
            "relations": [r.to_dict() for r in self.m_relations.values()],
        }

    @classmethod
    def from_dict(cls, d) -> 'BaseGraphOps':
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
        _dbg.info("Knowledge graph saved to %s (JSON)", filepath)

    @classmethod
    def load_json(cls, filepath: str) -> 'BaseGraphOps':
        with open(filepath, 'r', encoding='utf-8') as fh:
            data = _json.load(fh)
        return cls.from_dict(data)

    def save_pickle(self, filepath: str):
        with open(filepath, 'wb') as fh:
            _pickle.dump(self, fh, protocol=_pickle.HIGHEST_PROTOCOL)
        _dbg.info("Knowledge graph saved to %s (pickle)", filepath)

    @classmethod
    def load_pickle(cls, filepath: str) -> 'BaseGraphOps':
        with open(filepath, 'rb') as fh:
            return _pickle.load(fh)

# Maintenance

    def clear(self):
        self.m_entities.clear()
        self.m_relations.clear()
        self.m_entity_index.clear()
        self.m_relation_index.clear()
        self.m_adj_out.clear()
        self.m_adj_in.clear()

    def __repr__(self):
        return f"<{self.__class__.__name__} name={self.m_name} entities={len(self.m_entities)} relations={len(self.m_relations)}>"

    def __len__(self):
        return len(self.m_entities)
