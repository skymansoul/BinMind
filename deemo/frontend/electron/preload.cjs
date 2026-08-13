var contextBridge_ref = require('electron').contextBridge
var ipcRenderer_ref = require('electron').ipcRenderer

var _apiObject = {}

_apiObject.selectBinary = function() {
  return ipcRenderer_ref.invoke('select-binary')
}

_apiObject.startBackend = function() {
  return ipcRenderer_ref.invoke('start-backend')
}

_apiObject.platform = process.platform

_apiObject.electronVersion = process.versions.electron
_apiObject.nodeVersion = process.versions.node

contextBridge_ref.exposeInMainWorld('binmindAPI', _apiObject)
