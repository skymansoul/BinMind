"""
实验元数据表 schema 定义。

扩展 vuln_db 的 analysis_runs，四维评估指标对应申报书 §5.3 第四条。
参考: Klees et al., 2018, CCS; Bohme et al., 2021, IEEE S&P.
"""

# 实验元数据表（扩展 vuln_db 的 analysis_runs）
_EXPERIMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_name TEXT NOT NULL,
    sample_id TEXT,
    sample_path TEXT,
    binary_format TEXT,
    arch TEXT,
    bits INTEGER,
    checksec_json TEXT,
    pipeline_config TEXT,
    started_at TEXT,
    finished_at TEXT,
    elapsed_sec REAL,
    status TEXT DEFAULT 'running',
    -- 产出物
    report_md_path TEXT,
    report_json_path TEXT,
    exploit_script_path TEXT,
    -- 质量指标
    total_vulns INTEGER DEFAULT 0,
    critical_vulns INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    llm_contributions INTEGER DEFAULT 0,
    -- 四维评估数据
    discovery_efficiency REAL DEFAULT 0.0,
    result_quality_score REAL DEFAULT 0.0,
    llm_assistance_score REAL DEFAULT 0.0,
    applicability_score REAL DEFAULT 0.0,
    -- 元数据
    tags TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_experiments_name ON experiments(experiment_name);
CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status);
CREATE INDEX IF NOT EXISTS idx_experiments_created ON experiments(created_at);
"""
