<template>
  <el-container class="layout-container">
    <el-aside width="220px" class="sidebar">
      <div class="logo">
        <h2>🛡️ BinMind</h2>
        <p class="version">v1.4.0</p>
      </div>
      <el-menu
        :default-active="route.path"
        router
        background-color="#001529"
        text-color="#ffffff"
        active-text-color="#409EFF"
      >
        <el-menu-item index="/">
          <el-icon><HomeFilled /></el-icon>
          <span>工作台</span>
        </el-menu-item>
        <el-menu-item index="/analyze">
          <el-icon><Document /></el-icon>
          <span>二进制分析</span>
        </el-menu-item>
        <el-menu-item index="/projects">
          <el-icon><Folder /></el-icon>
          <span>项目管理</span>
        </el-menu-item>
        <el-menu-item index="/fuzzing">
          <el-icon><Loading /></el-icon>
          <span>模糊测试</span>
        </el-menu-item>
        <el-menu-item index="/knowledge">
          <el-icon><Share /></el-icon>
          <span>知识图谱</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-title">{{ getPageTitle() }}</div>
        <div class="header-status">
          <el-tag :type="backendStatus.type" size="small">{{ backendStatus.text }}</el-tag>
        </div>
      </el-header>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import http from '@/api'

const route = useRoute()
const backendStatus = ref({ type: 'info' as 'success' | 'info' | 'danger', text: '检测中...' })

onMounted(async () => {
  await checkBackendHealth()
})

const checkBackendHealth = async () => {
  try {
    const resp = await http.get('/health')
    if (resp && resp.data !== undefined) {
      backendStatus.value = { type: 'success', text: '后端已连接' }
    } else {
      backendStatus.value = { type: 'success', text: '后端已连接' }
    }
  } catch {
    backendStatus.value = { type: 'danger', text: '后端离线' }
  }
}

const getPageTitle = () => {
  const meta = route.meta
  if (!meta) {
    return 'BinMind'
  }
  const title = meta.title
  if (title == null || title === '') {
    return 'BinMind'
  }
  return title
}
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.sidebar {
  background: #001529;
  color: white;
}

.logo {
  padding: 20px;
  text-align: center;
  border-bottom: 1px solid #1f2d3d;
}

.logo h2 {
  margin: 0;
  color: #fff;
  font-size: 22px;
}

.logo .version {
  margin: 4px 0 0;
  font-size: 12px;
  color: #8c9bab;
}

.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: #fff;
  border-bottom: 1px solid #e6e6e6;
}

.header-title {
  font-size: 18px;
  font-weight: 600;
}

.main-content {
  background: #f5f7fa;
  padding: 20px;
}
</style>
