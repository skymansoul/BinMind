var electron_mod = require('electron')
var app_ref = electron_mod.app
var BrowserWindow_ref = electron_mod.BrowserWindow
var ipcMain_ref = electron_mod.ipcMain
var dialog_ref = electron_mod.dialog
var path_mod = require('path')

var _is_dev_mode = !app_ref.isPackaged
var _mainWindow = null

function createWindow() {
  var bw_options = {
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'BinMind - 二进制漏洞分析平台',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path_mod.join(__dirname, 'preload.cjs')
    }
  }

  _mainWindow = new BrowserWindow_ref(bw_options)

  // 开发模式连Vite dev server，生产模式加载dist静态文件
  if (_is_dev_mode) {
    _mainWindow.loadURL('http://127.0.0.1:5173')
    if (_mainWindow && _mainWindow.webContents) {
      _mainWindow.webContents.openDevTools()
    }
  } else {
    var html_path = path_mod.join(__dirname, '..', 'dist', 'index.html')
    _mainWindow.loadFile(html_path)
  }

  _mainWindow.on('closed', function() {
    _mainWindow = null
  })
}

// ===== IPC handlers =====

ipcMain_ref.handle('select-binary', function() {
  return _handleSelectBinary()
})

async function _handleSelectBinary() {
  var dialog_opts = {
    properties: ['openFile'],
    filters: [
      { name: 'Binary', extensions: ['bin', 'elf', 'exe', 'so', 'dll', 'dylib', 'macho', ''] },
      { name: 'All Files', extensions: ['*'] }
    ]
  }

  var dialog_result = null
  try {
    dialog_result = await dialog_ref.showOpenDialog(_mainWindow, dialog_opts)
  } catch (err) {
    console.error('[ipc] 文件对话框打开失败:', err)
    return null
  }

  if (dialog_result == null) {
    return null
  }
  if (dialog_result.canceled === true) {
    return null
  }
  if (!dialog_result.filePaths || dialog_result.filePaths.length === 0) {
    return null
  }
  var selected_path = dialog_result.filePaths[0]
  return selected_path
}

ipcMain_ref.handle('start-backend', function() {
  return _handleStartBackend()
})

async function _handleStartBackend() {
  var result_obj = { status: 'started', port: 8000 }
  return result_obj
}

app_ref.whenReady().then(function() {
  createWindow()
})

app_ref.on('window-all-closed', function() {
  if (process.platform !== 'darwin') {
    app_ref.quit()
  }
})

app_ref.on('activate', function() {
  var all_windows = BrowserWindow_ref.getAllWindows()
  if (all_windows.length === 0) {
    createWindow()
  }
})

module.exports = { createWindow }
