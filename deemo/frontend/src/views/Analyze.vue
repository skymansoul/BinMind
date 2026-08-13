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

    <el-divider v-if="result" />

    <div v-if="result">
      <h3>分析结果</h3>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="格式">{{ result.binary_info?.format }}</el-descriptions-item>
        <el-descriptions-item label="架构">{{ result.binary_info?.arch }}</el-descriptions-item>
        <el-descriptions-item label="位数">{{ result.binary_info?.bits }}</el-descriptions-item>
        <el-descriptions-item label="语言">{{ result.binary_info?.language }}</el-descriptions-item>
      </el-descriptions>

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
import { reactive, ref } from 'vue'
import { analyzeBinary } from '@/api'
import type { AnalysisResult } from '@/types'

const form = reactive({
  binary_path: '',
  use_ai: true,
  enable_symbolic_execution: false
})
const functionsInput = ref('')
const analyzing = ref(false)
const result = ref<AnalysisResult | null>(null)

const onAnalyze = async () => {
  if (!form.binary_path) {
    return
  }

  analyzing.value = true

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
      result.value = resp.data as AnalysisResult
    }
  } finally {
    analyzing.value = false
  }
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
