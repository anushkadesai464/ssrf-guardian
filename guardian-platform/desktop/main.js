const { app, BrowserWindow, ipcMain, shell } = require('electron')
const path = require('path')

let mainWindow

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 780,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    backgroundColor: '#080b12',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    titleBarStyle: 'hidden',
    show: false,
  })

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'login.html'))
  mainWindow.once('ready-to-show', () => mainWindow.show())
}

app.whenReady().then(createWindow)
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() })

ipcMain.on('minimize', () => mainWindow.minimize())
ipcMain.on('maximize', () => {
  if (mainWindow.isMaximized()) mainWindow.unmaximize()
  else mainWindow.maximize()
})
ipcMain.on('close', () => mainWindow.close())
ipcMain.on('navigate', (_, page) => {
  mainWindow.loadFile(path.join(__dirname, 'renderer', page))
})