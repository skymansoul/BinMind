<template>
  <el-config-provider :locale="localeConfig">
    <router-view />
  </el-config-provider>
</template>

<script setup lang="ts">
import { ElConfigProvider } from 'element-plus'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'

const localeConfig = zhCn
</script>

<style>
#app {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  width: 100%;
  height: 100vh;
}
</style>
