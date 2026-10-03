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
import { ref, reactive, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { startFuzzing, getFuzzStatus, stopFuzzing } from '@/api'
import type { FuzzSession } from '@/types'

const form = reactive({ binary_path: '', fuzzer_type: 'libfuzzer' })
const running = ref(false)
const sessionId = ref('')
const status = ref<FuzzSession | null>(null)

// 运行中会话的状态轮询
const STATUS_POLL_MS = 3000
let statusTimer: ReturnType<typeof setTimeout> | null = null

const stopStatusPolling = () => {
  if (statusTimer !== null) {
    clearTimeout(statusTimer)
    statusTimer = null
  }
}

onUnmounted(() => {
  stopStatusPolling()
})

const scheduleStatusPoll = (sid: string) => {
  stopStatusPolling()
  const doPoll = async () => {
    try {
      const r = await getFuzzStatus(sid)
      if (r?.success && r.data != null) {
        status.value = r.data as FuzzSession
        // 会话已结束则停止轮询
        if (status.value.status !== 'running') {
          stopStatusPolling()
          return
        }
      }
    } catch {
      // 网络抖动时继续下一轮
    }
    statusTimer = setTimeout(doPoll, STATUS_POLL_MS)
  }
  statusTimer = setTimeout(doPoll, STATUS_POLL_MS)
}

const onStart = async () => {
  if (!form.binary_path) {
    ElMessage.warning('请先填写二进制路径')
    return
  }

  running.value = true
  stopStatusPolling()

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
        ElMessage.success('模糊测试已启动')
        if (session.status === 'running') {
          scheduleStatusPoll(session.session_id)
        }
      }
    } else {
      ElMessage.error(r?.message || '启动失败')
    }
  } catch (err: any) {
    const detail = err?.response?.data?.detail
    ElMessage.error(typeof detail === 'string' ? detail : (err?.message || '启动失败'))
  } finally {
    running.value = false
  }
}

const onStop = async () => {
  const sid = sessionId.value
  if (!sid || sid.length === 0) {
    return
  }

  stopStatusPolling()

  try {
    const stop_resp = await stopFuzzing(sid)
    if (!stop_resp?.success) {
      ElMessage.warning(stop_resp?.message || '停止请求未成功')
    }
  } catch (err: any) {
    const detail = err?.response?.data?.detail
    ElMessage.error(typeof detail === 'string' ? detail : (err?.message || '停止失败'))
  }

  try {
    const r = await getFuzzStatus(sid)
    if (r?.success) {
      status.value = r.data as FuzzSession
    }
  } catch {
    // 停止后的状态查询失败不阻断
  }
}
</script>
