// Deemo Electron 主进程入口
// 负责启动 Vite 开发服务器并加载前端页面
const { app, BrowserWindow, ipcMain, dialog } = require('electron')
const path = require('path')
const isDev = !app.isPackaged

let mainWindow = null

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'Deemo - 二进制漏洞分析平台',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.cjs')
    }
  })

  if (isDev) {
    mainWindow.loadURL('http://127.0.0.1:5173')
    mainWindow.webContents.openDevTools()
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  }
}

// IPC：让前端选择本地二进制文件
ipcMain.handle('select-binary', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'Binary', extensions: ['bin', 'elf', 'exe', 'so', 'dll', 'dylib', 'macho', ''] },
      { name: 'All Files', extensions: ['*'] }
    ]
  })
  if (result.canceled || result.filePaths.length === 0) return null
  return result.filePaths[0]
})

// IPC：暴露 Python 后端进程
ipcMain.handle('start-backend', async () => {
  return { status: 'started', port: 8000 }
})

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})
