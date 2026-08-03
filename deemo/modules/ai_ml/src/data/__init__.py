# data/__init__.py -- 数据层统一导出

from .preprocessing import (
    normalize_instruction,
    normalize_opcode_seq,
    tokenize_instruction,
    clean_assembly_line,
    normalize_function,
)

from .graph_builder import (
    build_cfg_graph,
    build_cpg_graph,
    adjacency_from_edges,
    get_register_set,
)

from .dataset import (
    BinaryFuncDataset,
    TripletMiningDataset,
    collate_fn,
)
