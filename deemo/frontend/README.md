# Deemo 前端

基于 **Vue 3 + Vite + TypeScript + Element Plus** 的图形化界面，支持：
- **Web 模式**（浏览器访问 FastAPI 后端）
- **Electron 桌面模式**（打包为独立桌面应用）

## 启动方式

### Web 模式
```bash
cd frontend
npm install
npm run dev
# 默认监听 http://127.0.0.1:5173
```

### Electron 模式
```bash
cd frontend
npm install
npm run electron:dev
```

### 打包
```bash
npm run build               # 仅构建 Web 资源
npm run electron:build      # 构建并打包为桌面应用
```

## 与后端通信
通过 `vite.config.ts` 的 `proxy` 配置：
- Web：`/api` 代理到 `http://127.0.0.1:8000`
- Electron：通过 `electron/main.cjs` 直接与本地后端进程通信

## 目录结构
```
frontend/
├── electron/           # Electron 主进程
├── src/
│   ├── api/            # REST API 客户端
│   ├── components/     # 通用组件
│   ├── router/         # Vue Router
│   ├── styles/         # 全局样式
│   ├── types/          # TypeScript 类型
│   ├── views/          # 页面视图
│   ├── App.vue
│   └── main.ts
├── index.html
├── package.json
├── tsconfig.json
└── vite.config.ts
```
