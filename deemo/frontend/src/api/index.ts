import axios, { AxiosInstance, AxiosError } from 'axios'

const _baseURL = (import.meta as any).env.VITE_API_BASE || '/api'
const _maxRetry = 3
const _retry_delay_base = 1000

export const http: AxiosInstance = axios.create({
  baseURL: _baseURL,
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' }
})

export interface APIResponse<T = any> {
  success: boolean
  message?: string
  data?: T
}

async function _doRetryRequest<T>(
  executorFn: () => Promise<T>,
  retries_left: number
): Promise<T> {
  let last_error: any = null

  let attempt_idx = 0
  while (attempt_idx <= retries_left) {
    try {
      const result = await executorFn()
      return result
    } catch (err: any) {
      last_error = err
      attempt_idx = attempt_idx + 1
      if (attempt_idx > retries_left) {
        break
      }
      // exponential backoff capped at 8s
      let delay = _retry_delay_base * Math.pow(2, attempt_idx - 1)
      if (delay > 8000) { delay = 8000 }
      console.warn('[api-retry] 第' + attempt_idx + '次重试, 等' + delay + 'ms, 错误:', err.message || err)
      await new Promise(function(resolve) {
        setTimeout(resolve, delay)
      })
    }
  }
  throw last_error
}

function _shouldRetryError(err: any): boolean {
  if (err && err.code === 'ECONNABORTED') { return true }
  if (err && err.response) {
    const statusCode = err.response.status
    if (statusCode === 502 || statusCode === 503 || statusCode === 504 || statusCode === 429) {
      return true
    }
  }
  if (err && err.message && (err.message.indexOf('Network Error') >= 0 || err.message.indexOf('timeout') >= 0)) {
    return true
  }
  return false
}

// normalize axios response — handles both JSON and HTML error pages
function _parseResponseData(rawResponse: any): any {
  if (!rawResponse) {
    console.error('[api-parse] 响应体为空，检查后端/nginx配置')
    return null
  }

  const resp_data = rawResponse.data
  if (typeof resp_data === 'string') {
    try {
      const parsed = JSON.parse(resp_data)
      return parsed
    } catch (e) {
      console.warn('[api-parse] 响应不是JSON:', (resp_data as string).substring(0, 100))
      return { success: false, message: 'Server returned non-JSON response', data: resp_data }
    }
  }

  return resp_data
}

export const analyzeBinary = (params: {
  binary_path: string
  functions?: string[]
  use_ai?: boolean
  enable_symbolic_execution?: boolean
}): Promise<APIResponse> => {
  // 后端 AnalysisRequest 契约: binary_name 必填, function_names/enable_symbolic
  const payload: any = {
    binary_name: params.binary_path,
    enable_symbolic: params.enable_symbolic_execution === true
  }
  if (Array.isArray(params.functions) && params.functions.length > 0) {
    payload['function_names'] = params.functions
  }
  return _doRetryRequest(function() {
    return http.post('/analyze', payload).then(function(r) {
      return _parseResponseData(r)
    })
  }, _maxRetry)
}

export const getAnalysisResult = (analysisId: string): Promise<APIResponse> => {
  return http.get('/analyze/' + analysisId).then(function(r) {
    return _parseResponseData(r)
  })
}

export const startFuzzing = (params: {
  binary_path: string
  fuzzer_type: string
  duration?: number
}): Promise<APIResponse> => {
  return _doRetryRequest(function() {
    return http.post('/fuzz/start', params).then(function(r) {
      return _parseResponseData(r)
    })
  }, 2)
}

export const getFuzzStatus = (sessionId: string): Promise<APIResponse> => {
  return http.get('/fuzz/status/' + sessionId).then(function(r) {
    return _parseResponseData(r)
  })
}

export const stopFuzzing = (sessionId: string): Promise<APIResponse> => {
  return http.post('/fuzz/stop/' + sessionId).then(function(r) {
    return _parseResponseData(r)
  })
}

export const searchVulnerabilities = (params: {
  query: string
  limit?: number
}): Promise<APIResponse> => {
  return _doRetryRequest(function() {
    return http.post('/vuln/search', params).then(function(r) {
      return _parseResponseData(r)
    })
  }, _maxRetry)
}

export const listProjects = (): Promise<APIResponse> => {
  return http.get('/projects').then(function(r) {
    return _parseResponseData(r)
  })
}

export const createProject = (params: { name: string; binary_path: string }): Promise<APIResponse> => {
  return _doRetryRequest(function() {
    return http.post('/projects', params).then(function(r) {
      return _parseResponseData(r)
    })
  }, _maxRetry)
}

export const getKnowledgeGraph = (params: { project_id?: string }): Promise<APIResponse> => {
  return http.get('/knowledge/graph', { params: params }).then(function(r) {
    return _parseResponseData(r)
  })
}

export const getReports = (analysisId: string): Promise<APIResponse> => {
  return http.get('/reports/' + analysisId).then(function(r) {
    return _parseResponseData(r)
  })
}

export default http
