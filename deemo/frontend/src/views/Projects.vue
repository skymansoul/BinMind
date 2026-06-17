<template>
  <el-card>
    <template #header>
      <div style="display:flex; justify-content:space-between; align-items:center">
        <span>项目管理</span>
        <el-button type="primary" size="small" @click="showCreate = true">新建项目</el-button>
      </div>
    </template>
    <el-table :data="projects" border>
      <el-table-column prop="id" label="ID" width="120" />
      <el-table-column prop="name" label="名称" />
      <el-table-column prop="status" label="状态" width="120">
        <template #default="{ row }">
          <el-tag :type="statusTag(row.status)">{{ row.status }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="current_step" label="当前步骤" width="160" />
      <el-table-column prop="created_at" label="创建时间" width="200" />
    </el-table>

    <el-dialog v-model="showCreate" title="新建项目" width="500px">
      <el-form :model="newProject" label-width="100px">
        <el-form-item label="项目名称">
          <el-input v-model="newProject.name" />
        </el-form-item>
        <el-form-item label="二进制路径">
          <el-input v-model="newProject.binary_path" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showCreate = false">取消</el-button>
        <el-button type="primary" @click="onCreate">创建</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue'
import { listProjects, createProject } from '@/api'
import type { ProjectItem } from '@/types'

const projects = ref<ProjectItem[]>([])
const showCreate = ref(false)
const newProject = reactive({ name: '', binary_path: '' })

const loadProjects = async () => {
  const r = await listProjects()
  if (r.success) projects.value = (r.data as ProjectItem[]) || []
}

const onCreate = async () => {
  if (!newProject.name) return
  await createProject(newProject)
  showCreate.value = false
  await loadProjects()
}

const statusTag = (s: string) => {
  if (s === 'completed') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'running') return 'warning'
  return 'info'
}

onMounted(loadProjects)
</script>
