// 集中式 API 客户端（与 FastAPI 后端通信）
import axios, { AxiosInstance } from 'axios'

const baseURL = (import.meta as any).env.VITE_API_BASE || '/api'

export const http: AxiosInstance = axios.create({
  baseURL,
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' }
})

// 通用响应封装
export interface APIResponse<T = any> {
  success: boolean
  message?: string
  data?: T
}

// 分析
export const analyzeBinary = (params: {
  binary_path: string
  functions?: string[]
  use_ai?: boolean
  enable_symbolic_execution?: boolean
}) => http.post<APIResponse>('/analyze', params).then(r => r.data)

export const getAnalysisResult = (analysisId: string) =>
  http.get<APIResponse>(`/analyze/${analysisId}`).then(r => r.data)

// 模糊测试
export const startFuzzing = (params: {
  binary_path: string
  fuzzer_type: string
  duration?: number
}) => http.post<APIResponse>('/fuzz/start', params).then(r => r.data)

export const getFuzzStatus = (sessionId: string) =>
  http.get<APIResponse>(`/fuzz/status/${sessionId}`).then(r => r.data)

export const stopFuzzing = (sessionId: string) =>
  http.post<APIResponse>(`/fuzz/stop/${sessionId}`).then(r => r.data)

// 漏洞数据库
export const searchVulnerabilities = (params: {
  query: string
  limit?: number
}) => http.post<APIResponse>('/vuln/search', params).then(r => r.data)

// 项目管理
export const listProjects = () =>
  http.get<APIResponse>('/projects').then(r => r.data)

export const createProject = (params: { name: string; binary_path: string }) =>
  http.post<APIResponse>('/projects', params).then(r => r.data)

// 知识图谱
export const getKnowledgeGraph = (params: { project_id?: string }) =>
  http.get<APIResponse>('/knowledge/graph', { params }).then(r => r.data)

// 报告
export const getReports = (analysisId: string) =>
  http.get<APIResponse>(`/reports/${analysisId}`).then(r => r.data)

export default http
