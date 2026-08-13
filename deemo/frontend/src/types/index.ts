// Shared type definitions for API responses and domain models

export interface BinaryInfo {
  format: string
  arch: string
  bits: number
  language?: string
  size: number
  sha256?: string
}

export interface VulnerabilityItem {
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  function_name?: string
  description: string
  exploitation?: string
  cwe?: string
  attack_techniques?: string[]
}

export type AnalysisResult = {
  analysis_id: string
  binary_info: BinaryInfo
  vulnerabilities: VulnerabilityItem[]
  pseudocode?: string
  fuzzer_harness?: string
  report_paths?: {
    markdown?: string
    json?: string
    html?: string
  }
  created_at: string
}

export interface ProjectItem {
  id: string
  name: string
  binary_path: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  current_step: string
  created_at: string
  updated_at: string
}

export interface FuzzSession {
  session_id: string
  fuzzer_type: string
  binary_path: string
  status: 'running' | 'stopped' | 'finished'
  started_at: string
  coverage?: number
  crashes?: number
}

export interface KnowledgeGraphData {
  nodes: Array<{ id: string; name: string; type: string; properties?: any }>
  links: Array<{ source: string; target: string; type: string; properties?: any }>
}
