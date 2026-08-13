import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import App from './App.vue'
import router from './router'
import './styles/main.css'

// HMR guard
let _initDone = false

function _bootstrapApp() {
  if (_initDone) {
    console.warn('[bootstrap] 已经初始化过了，跳过重复创建')
    return
  }
  _initDone = true

  const app_instance = createApp(App)

  const pinia_instance = createPinia()
  app_instance.use(pinia_instance)

  app_instance.use(router)

  app_instance.use(ElementPlus)

  app_instance.config.errorHandler = function(err: any, instance: any, info: string) {
    console.error('[vue-error] 组件错误: ' + info)
    console.error('[vue-error] 错误详情:', err)
    if (instance) {
      try {
        const compName = instance.$options && instance.$options.name ? instance.$options.name : '(anonymous)'
        console.error('[vue-error] 出问题的组件: ' + compName)
      } catch (_e) {
        console.error('[vue-error] 无法获取组件名')
      }
    }
  }

  const mount_target = document.getElementById('app')
  if (mount_target === null) {
    console.error('[bootstrap] 挂载点#app不存在! 检查index.html')
    return
  }
  app_instance.mount('#app')
}

// 启动!
_bootstrapApp()
