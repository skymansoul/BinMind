<template>
  <el-card>
    <template #header>
      <span>二进制漏洞分析</span>
    </template>
    <el-form :model="form" label-width="120px">
      <el-form-item label="二进制路径">
        <el-input v-model="form.binary_path" placeholder="/path/to/binary" />
      </el-form-item>
      <el-form-item label="目标函数">
        <el-input v-model="functionsInput" placeholder="main, vuln, win (留空使用默认)" />
      </el-form-item>
      <el-form-item label="启用选项">
        <el-checkbox v-model="form.use_ai">使用 AI 分析</el-checkbox>
        <el-checkbox v-model="form.enable_symbolic_execution">符号执行</el-checkbox>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="analyzing" @click="onAnalyze">
          {{ analyzing ? '分析中...' : '开始分析' }}
        </el-button>
      </el-form-item>
    </el-form>

    <el-alert
      v-if="progressMessage"
      :title="progressMessage"
      type="info"
      :closable="false"
      style="margin-bottom: 12px"
    />

    <el-divider v-if="result" />

    <div v-if="result">
      <h3>分析结果</h3>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="格式">{{ result.binary_info?.format }}</el-descriptions-item>
        <el-descriptions-item label="架构">{{ result.binary_info?.arch }}</el-descriptions-item>
        <el-descriptions-item label="位数">{{ result.binary_info?.bits }}</el-descriptions-item>
        <el-descriptions-item label="语言">{{ result.binary_info?.language }}</el-descriptions-item>
      </el-descriptions>

      <h3 style="margin-top:20px">导出报告</h3>
      <el-space wrap>
        <el-button
          v-if="hasReport('markdown')"
          type="primary"
          plain
          @click="openReport('markdown')"
        >
          查看 Markdown
        </el-button>
        <el-button
          v-if="hasReport('json')"
          type="primary"
          plain
          @click="openReport('json')"
        >
          下载 JSON
        </el-button>
        <el-button
          v-if="hasReport('html')"
          type="primary"
          plain
          @click="openReport('html')"
        >
          查看 HTML
        </el-button>
      </el-space>
      <el-alert
        v-if="!hasAnyReport"
        title="后端未返回可下载报告"
        type="warning"
        :closable="false"
        style="margin-top: 12px"
      />

      <h3 style="margin-top:20px">发现的漏洞 ({{ result.vulnerabilities?.length || 0 }})</h3>
      <el-table :data="result.vulnerabilities || []" border>
        <el-table-column prop="severity" label="严重性" width="100">
          <template #default="{ row }">
            <el-tag :type="severityTag(row.severity)">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="200" />
        <el-table-column prop="function_name" label="函数" width="180" />
        <el-table-column prop="description" label="描述" />
      </el-table>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, reactive, ref, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { analyzeBinary, getAnalysisResult, getReportDownloadUrl } from '@/api'
import type { AnalysisResult } from '@/types'

const form = reactive({
  binary_path: '',
  use_ai: true,
  enable_symbolic_execution: false
})
const functionsInput = ref('')
const analyzing = ref(false)
const result = ref<AnalysisResult | null>(null)
const progressMessage = ref('')

// 轮询控制: 间隔与超时上限
const POLL_INTERVAL_MS = 2000
const POLL_TIMEOUT_MS = 300000
let pollTimer: ReturnType<typeof setTimeout> | null = null

const stopPolling = () => {
  if (pollTimer !== null) {
    clearTimeout(pollTimer)
    pollTimer = null
  }
}

onUnmounted(() => {
  stopPolling()
})

const pollResult = (taskId: string, startedAt: number) => {
  const doPoll = async () => {
    try {
      const resp = await getAnalysisResult(taskId)
      const payload: any = resp?.data

      if (!resp?.success || payload == null) {
        throw new Error(resp?.message || '查询分析状态失败')
      }

      if (payload.status === 'completed') {
        result.value = payload as AnalysisResult
        progressMessage.value = ''
        analyzing.value = false
        ElMessage.success('分析完成')
        return
      }

      if (payload.status === 'failed') {
        analyzing.value = false
        progressMessage.value = ''
        ElMessage.error(payload.message || '分析失败')
        return
      }

      // pending/running → 继续轮询
      const progress_hint = payload.progress != null
        ? ' (进度 ' + payload.progress + '%)'
        : ''
      progressMessage.value = (payload.message || '分析进行中') + progress_hint

      if (Date.now() - startedAt > POLL_TIMEOUT_MS) {
        analyzing.value = false
        progressMessage.value = ''
        ElMessage.error('分析超时，请稍后在任务列表中查看')
        return
      }

      pollTimer = setTimeout(doPoll, POLL_INTERVAL_MS)
    } catch (err: any) {
      analyzing.value = false
      progressMessage.value = ''
      ElMessage.error(err?.message || '轮询分析结果失败')
    }
  }

  pollTimer = setTimeout(doPoll, POLL_INTERVAL_MS)
}

const onAnalyze = async () => {
  if (!form.binary_path) {
    ElMessage.warning('请先填写二进制路径')
    return
  }

  stopPolling()
  analyzing.value = true
  result.value = null
  progressMessage.value = '任务提交中...'

  try {
    let func_list: string[] | undefined = undefined

    const raw_input = functionsInput.value
    if (raw_input) {
      const raw_parts = raw_input.split(',')
      const temp_parts: string[] = []

      for (let i = 0; i < raw_parts.length; i++) {
        const trimmed = raw_parts[i].trim()
        if (trimmed) {
          temp_parts.push(trimmed)
        }
      }

      if (temp_parts.length > 0) {
        func_list = temp_parts
      }
    }

    const request_body: any = {
      binary_path: form.binary_path,
      use_ai: form.use_ai,
      enable_symbolic_execution: form.enable_symbolic_execution
    }
    if (Array.isArray(func_list)) {
      request_body['functions'] = func_list
    }

    const resp = await analyzeBinary(request_body)
    if (resp?.success) {
      const submit_data: any = resp.data
      // 后端异步契约: 返回 task_id 后进入轮询
      if (submit_data && typeof submit_data.task_id === 'string') {
        progressMessage.value = '任务已提交，等待分析结果...'
        pollResult(submit_data.task_id, Date.now())
      } else if (submit_data && submit_data.status === 'completed') {
        // 兼容同步返回结果的后端
        result.value = submit_data as AnalysisResult
        analyzing.value = false
        progressMessage.value = ''
      } else {
        analyzing.value = false
        progressMessage.value = ''
        ElMessage.warning(resp?.message || '提交成功但未返回任务 ID')
      }
    } else {
      analyzing.value = false
      progressMessage.value = ''
      ElMessage.error(resp?.message || '提交分析任务失败')
    }
  } catch (err: any) {
    analyzing.value = false
    progressMessage.value = ''
    ElMessage.error(err?.message || '提交分析任务失败')
  }
}

const reportPaths = computed(() => result.value?.report_paths || {})

const hasReport = (format: 'markdown' | 'json' | 'html') => {
  return Boolean(reportPaths.value?.[format])
}

const hasAnyReport = computed(() => {
  return hasReport('markdown') || hasReport('json') || hasReport('html')
})

const openReport = (format: 'markdown' | 'json' | 'html') => {
  if (!result.value?.analysis_id) {
    ElMessage.warning('分析 ID 不存在，无法打开报告')
    return
  }
  window.open(getReportDownloadUrl(result.value.analysis_id, format), '_blank')
}

const severityTag = (s: string) => {
  if (!s) {
    return 'info'
  }

  if (s === 'Critical') {
    return 'danger'
  }
  if (s === 'High') {
    return 'warning'
  }
  if (s === 'Medium') {
    return 'info'
  }
  if (s === 'Low') {
    return ''
  }

  return 'info'
}
</script>
