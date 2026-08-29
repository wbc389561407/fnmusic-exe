// preload: 通过 contextBridge 向渲染层暴露受控的 IPC 接口
// setup.html 用 serverBridge.submit 提交服务器地址
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('serverBridge', {
  // 提交服务器地址（含可选用户名密码），返回 Promise<{ ok: boolean, error?: string }>
  submit: (payload) => ipcRenderer.invoke('submit-server', payload),
  // 获取应用版本号（主进程 app.getVersion()，sandbox 下不能用 require 读 package.json）
  getVersion: () => ipcRenderer.invoke('get-app-version'),
  // 检查更新，返回 Promise<{ hasUpdate, latestVersion, releaseUrl, ... }>
  checkUpdate: () => ipcRenderer.invoke('check-update'),
  // 最小化到托盘（叉叉按钮调用）
  minimizeToTray: () => ipcRenderer.invoke('minimize-to-tray'),
  // 窗口最小化（任务栏）
  minimizeWindow: () => ipcRenderer.invoke('window-minimize'),
  // 最大化 / 还原切换
  toggleMaximize: () => ipcRenderer.invoke('toggle-maximize'),
  // 置顶切换
  togglePin: () => ipcRenderer.invoke('toggle-pin'),
  // 监听最大化状态变化（切换图标）
  onMaximizedChanged: (cb) => ipcRenderer.on('maximized-changed', (_e, m) => cb(m)),
  // 监听置顶状态变化（页面加载后同步状态）
  onPinChanged: (cb) => ipcRenderer.on('pin-changed', (_e, p) => cb(p)),
  // 读取已保存的服务器地址与用户名（用于设置页预填）
  getSavedInput: () => ipcRenderer.invoke('get-saved-input'),
  // 登录接口返回错误时，渲染层通知主进程跳回设置页
  notifyLoginFail: () => ipcRenderer.invoke('login-fail'),
  // 设置页读取并清空待展示的登录错误提示
  getLoginError: () => ipcRenderer.invoke('get-login-error'),
  // 渲染层上报侧边栏歌单列表（MutationObserver 检测到变化时调用）
  reportPlaylists: (names) => ipcRenderer.send('playlists-updated', names)
});

// 阻止页面默认拖拽打开文件的行为
window.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', (e) => e.preventDefault());
});
