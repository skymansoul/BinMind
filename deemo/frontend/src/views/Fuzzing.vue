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
  if (!form.binary_path) {
    return
  }

  running.value = true

  const request_data: any = {}
  request_data['binary_path'] = form.binary_path
  request_data['fuzzer_type'] = form.fuzzer_type

  try {
    const r = await startFuzzing(request_data)
    if (r?.success) {
      const maybe_data = r.data
      if (maybe_data) {
        const session = maybe_data as FuzzSession
        sessionId.value = session.session_id
        status.value = session
      }
    }
  } finally {
    running.value = false
  }
}

const onStop = async () => {
  const sid = sessionId.value
  if (!sid || sid.length === 0) {
    return
  }

  await stopFuzzing(sid)

  const r = await getFuzzStatus(sid)
  if (r?.success) {
    status.value = r.data as FuzzSession
  }
}
</script>
