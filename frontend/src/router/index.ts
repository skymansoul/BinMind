import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'home',
    component: () => import('@/views/Dashboard.vue'),
    meta: { title: '工作台' }
  },
  {
    path: '/analyze',
    name: 'analyze',
    component: () => import('@/views/Analyze.vue'),
    meta: { title: '二进制分析' }
  },
  {
    path: '/projects',
    name: 'projects',
    component: () => import('@/views/Projects.vue'),
    meta: { title: '项目管理' }
  },
  {
    path: '/fuzzing',
    name: 'fuzzing',
    component: () => import('@/views/Fuzzing.vue'),
    meta: { title: '模糊测试' }
  },
  {
    path: '/knowledge',
    name: 'knowledge',
    component: () => import('@/views/KnowledgeGraph.vue'),
    meta: { title: '知识图谱' }
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('@/views/Settings.vue'),
    meta: { title: '设置' }
  }
]

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

router.afterEach((to: any) => {
  const pageTitle = to.meta?.title || 'BinMind'
  document.title = pageTitle + ' - 二进制漏洞分析平台'
})

export default router

export function getRouterInstance() {
  return router
}
