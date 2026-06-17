<template>
  <el-card>
    <template #header>模糊测试控制台</template>
    <el-form :model="form" label-width="120px">
      <el-form-item label="二进制路径">
        <el-input v-model="form.binary_path" />
      </el-form-item>
      <el-form-item label="Fuzzer 类型">
        <el-select v-model="form.fuzzer_type">
          <el-option label="LibFuzzer" value="libfuzzer" />
          <el-option label="AFL" value="afl" />
          <el-option label="AFL++" value="afl++" />
        </el-select>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="running" @click="onStart">启动</el-button>
        <el-button :disabled="!sessionId" @click="onStop">停止</el-button>
      </el-form-item>
    </el-form>

    <el-divider v-if="status" />

    <div v-if="status">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="会话">{{ status.session_id }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag>{{ status.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="崩溃数">{{ status.crashes || 0 }}</el-descriptions-item>
      </el-descriptions>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { startFuzzing, getFuzzStatus, stopFuzzing } from '@/api'
import type { FuzzSession } from '@/types'

const form = reactive({ binary_path: '', fuzzer_type: 'libfuzzer' })
const running = ref(false)
const sessionId = ref('')
const status = ref<FuzzSession | null>(null)

const onStart = async () => {
  running.value = true
  try {
    const r = await startFuzzing(form)
    if (r.success && r.data) {
      sessionId.value = (r.data as FuzzSession).session_id
      status.value = r.data as FuzzSession
    }
  } finally {
    running.value = false
  }
}

const onStop = async () => {
  await stopFuzzing(sessionId.value)
  if (sessionId.value) {
    const r = await getFuzzStatus(sessionId.value)
    if (r.success) status.value = r.data as FuzzSession
  }
}
</script>
