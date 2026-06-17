// Deemo Electron 预加载脚本
// 通过 contextBridge 暴露安全的 IPC 接口给渲染进程
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('deemoAPI', {
  selectBinary: () => ipcRenderer.invoke('select-binary'),
  startBackend: () => ipcRenderer.invoke('start-backend'),
  platform: process.platform
})
