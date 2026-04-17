const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

  // System info
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),

  // Window controls
  minimize: () => ipcRenderer.invoke('minimize-window'),
  maximize: () => ipcRenderer.invoke('maximize-window'),
  close: () => ipcRenderer.invoke('close-window'),

  // Events
  onSettingsOpen: (callback) => ipcRenderer.on('open-settings', callback),

  // Remove listeners
  removeAllListeners: (event) => ipcRenderer.removeAllListeners(event)
});