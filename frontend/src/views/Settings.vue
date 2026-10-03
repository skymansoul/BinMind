<template>
  <el-card>
    <template #header>系统设置</template>
    <el-form label-width="140px">
      <el-form-item label="API 基础地址">
        <el-input v-model="apiBase" placeholder="http://127.0.0.1:8000/api" />
      </el-form-item>
      <el-form-item label="本地模型路径">
        <el-input v-model="localModel" placeholder="/path/to/local/llama.cpp/model.gguf" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="onSave">保存</el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'

const apiBase = ref('')
const localModel = ref('')

const LS_KEY_API = 'binmind_api_base'
const LS_KEY_MODEL = 'binmind_local_model'

const loadSettings = () => {
  const saved_api = localStorage.getItem(LS_KEY_API)

  if (saved_api) {
    apiBase.value = saved_api
  } else {
    apiBase.value = 'http://127.0.0.1:8000/api'
  }

  const saved_model = localStorage.getItem(LS_KEY_MODEL)
  if (saved_model !== null) {
    localModel.value = saved_model
  } else {
    localModel.value = ''
  }
}

onMounted(() => {
  loadSettings()
})

const onSave = () => {
  const api_value = apiBase.value
  const model_value = localModel.value

  if (api_value) {
    let trimmed_api = api_value
    while (trimmed_api.length > 0 && trimmed_api[trimmed_api.length - 1] === '/') {
      trimmed_api = trimmed_api.substring(0, trimmed_api.length - 1)
    }
    localStorage.setItem(LS_KEY_API, trimmed_api)
  } else {
    localStorage.setItem(LS_KEY_API, '')
  }

  if (typeof model_value === 'string') {
    localStorage.setItem(LS_KEY_MODEL, model_value)
  } else {
    localStorage.setItem(LS_KEY_MODEL, '')
  }

  ElMessage.success('已保存设置')
}
</script>
