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

onMounted(() => {
  apiBase.value = localStorage.getItem('deemo_api_base') || 'http://127.0.0.1:8000/api'
  localModel.value = localStorage.getItem('deemo_local_model') || ''
})

const onSave = () => {
  localStorage.setItem('deemo_api_base', apiBase.value)
  localStorage.setItem('deemo_local_model', localModel.value)
  ElMessage.success('已保存设置')
}
</script>
