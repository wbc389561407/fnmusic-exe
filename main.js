const { app, BrowserWindow, shell, session, Menu, ipcMain, Tray, nativeImage, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');

// 项目仓库地址（版本更新检查与首页展示统一使用）
const REPO_URL = 'https://github.com/wbc389561407/fnmusic-exe';
// 用 tags 接口而非 releases/latest：后者会跳过 prerelease / draft，导致取到的不是最新 tag
const REPO_TAGS_API = 'https://api.github.com/repos/wbc389561407/fnmusic-exe/tags';

// 伪装成普通 Chrome 浏览器的 User-Agent，避免被站点拦截
const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// 持久化分区：cookies / localStorage 都落盘到 userData，重启后保留登录态
const PARTITION = 'persist:feiniu';

// 获取持久化 session
function getSession() {
  return session.fromPartition(PARTITION);
}

// 让会话 cookie（无过期时间）也持久化保存，避免重启后需要重新登录
function setupCookiePersistence() {
  const ses = getSession();

  // 注意：不要在此处设置 setCertificateVerifyProc。
  // 之前对非 fnos.net 域名返回 callback(-2) 会直接拒绝 SSL 握手（net_error -2 ERR_FAILED），
  // 导致普通 https 站点（如 your-domain.com）无法加载。
  // fnid 中转 *.fnos.net 的证书问题改由窗口级 certificate-error 事件处理。
  ses.cookies.on('changed', (_e, cookie, _cause, removed) => {
    if (removed) return;
    // 仅处理「会话型」cookie（没有 expirationDate）
    if (!cookie.session && cookie.expirationDate) return;
    try {
      const host = (cookie.domain || '').replace(/^\./, '');
      const url = (cookie.secure ? 'https://' : 'http://') + host + (cookie.path || '/');
      const detail = {
        url,
        name: cookie.name,
        value: cookie.value,
        path: cookie.path || '/',
        secure: cookie.secure,
        httpOnly: cookie.httpOnly,
        sameSite: cookie.sameSite || 'unspecified',
        expirationDate: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365 // 1 年
      };
      if (!cookie.hostOnly) detail.domain = cookie.domain;
      ses.cookies.set(detail).catch(() => {});
    } catch {}
  });
}

// 配置文件路径（userData 目录下的 config.json）
function getConfigPath() {
  return path.join(app.getPath('userData'), 'config.json');
}

// 读取已保存的服务器地址
function readConfig() {
  try {
    const raw = fs.readFileSync(getConfigPath(), 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// 写入配置
function writeConfig(cfg) {
  fs.writeFileSync(getConfigPath(), JSON.stringify(cfg, null, 2), 'utf-8');
}

// 规范化地址：
// - 不带协议的纯 IP / 主机名 → 默认补 http:// 与 :5666 端口（飞牛 NAS 默认端口）
// - 带协议 / 带端口 → 完全尊重用户输入，不覆盖
// - 去首尾空格
function normalizeUrl(input) {
  let url = (input || '').trim();
  if (!url) return null;
  const hasProto = /^https?:\/\//i.test(url);
  if (!hasProto) url = 'http://' + url;
  try {
    const u = new URL(url);
    // 仅「不带协议」场景补默认端口 5666；带协议的地址不干预端口
    if (!hasProto && !u.port) {
      u.port = '5666';
    }
    return u.href;
  } catch {
    return null;
  }
}

// ===== fnid 解析（通过 fnos.net 远程访问 API 获取真实服务器地址）=====
// 逆向自 fnos.net 前端 JS，API 需同时携带两套签名
// 候选地址优先级：局域网 http（最快，无证书问题）> fnos.net 中继 https（兜底）
// 不考虑公网 IP 直连（家庭网络绝大多数无公网 IP，且公网 IP 直连意义不大）
const FNOS_PREFIX = 'NDzZTVxnRKP8Z0jXg1VAMonaG8akvh';
const FNOS_API_KEY = 'zIGtkc3dqZnJpd29qZXJqa2w7c';
const FNOS_API_PATH = '/api/v1/fn/con';
const FNOS_API_URL = 'https://fnos.net' + FNOS_API_PATH;

// 判断输入是否为 fnid：不含 . / : 且不带协议的短字符串
function isFnid(input) {
  const s = (input || '').trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return false; // 带协议的是网址
  if (/[.\/:]/.test(s)) return false;        // 含 . / : 视为网址/IP
  return /^[a-zA-Z0-9_-]+$/.test(s);          // 仅字母数字下划线短横
}

// 通过 fnid 调用 fnos.net API 解析真实服务器地址
// 返回候选地址列表（按优先级排序）：局域网 http > fnos.net 中继 https 兜底
// API 返回数据示例：
//   { ipv4: ["192.168.x.x"], publicIpv4: ["x.x.x.x"], fn: ["your-fnid.fnos.net:443"],
//     port: { httpPort: 40710, httpsPort: 40711 } }
async function resolveFnid(fnid) {
  const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
  const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

  // fn-sign：基于 fnid + 当前时间戳的 sha256
  const tsFn = Date.now();
  const fnSign = sha256(`trim_connect\`${fnid}\`${tsFn}\`anna`);

  // authx：基于 PREFIX + url + nonce + ts + md5(body) + apiKey 的 md5
  const body = JSON.stringify({ fnId: fnid });
  const nonce = (Math.floor(Math.random() * 9e5) + 1e5).toString().padStart(6, '0');
  const tsAx = Date.now();
  const authxSign = md5([FNOS_PREFIX, FNOS_API_PATH, nonce, tsAx, md5(body), FNOS_API_KEY].join('_'));
  const authx = `nonce=${nonce}&timestamp=${tsAx}&sign=${authxSign}`;

  // 用 Promise.race 加超时，防止网络挂起导致前端永远卡在"连接中"
  const withTimeout = (p, ms) =>
    Promise.race([
      p,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
    ]);

  try {
    const resp = await withTimeout(fetch(FNOS_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'fn-sign': fnSign,
        'authx': authx,
        'User-Agent': UA
      },
      body
    }), 10000);
    const json = await withTimeout(resp.json(), 5000);
    console.log('[resolveFnid] api response code:', json && json.code);
    if (!json || json.code !== 0 || !json.data) return null;

    const d = json.data;
    const httpPort = d.port && d.port.httpPort;
    const candidates = [];

    // 1. 局域网 http（优先级最高，局域网内最快，无证书问题）
    if (httpPort) {
      (d.ipv4 || []).forEach((ip) => {
        candidates.push(`http://${ip}:${httpPort}`);
      });
    }

    // 2. fnos.net 中继 https（兜底，跨网段时使用）
    (d.fn || []).forEach((fn) => {
      const m = fn.match(/^([^:]+):(\d+)$/);
      if (m) {
        const host = m[1];
        const port = parseInt(m[2], 10);
        candidates.push(port === 443 ? `https://${host}` : `https://${host}:${port}`);
      } else {
        candidates.push(`https://${fn}`);
      }
    });

    console.log('[resolveFnid] candidates:', candidates);
    return candidates.length > 0 ? candidates : null;
  } catch (e) {
    console.error('[resolveFnid] error:', e.message);
    return null;
  }
}

// 顺序探测候选地址：先逐个尝试局域网 http，通则用；全不通则用 https 中继兜底
// 注意：https 中继不做主动探测（证书可能过期，fetch 会失败），直接交由 BrowserWindow 加载
async function probeCandidates(candidates) {
  const withTimeout = (p, ms) =>
    Promise.race([
      p,
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms))
    ]);

  const httpCandidates = candidates.filter((u) => u.startsWith('http://'));
  const httpsFallback = candidates.find((u) => u.startsWith('https://'));

  // 顺序逐个探测局域网 http 候选，第一个可达即返回
  for (const url of httpCandidates) {
    try {
      // 任何 HTTP 响应（含 401/404/302）都说明地址可达
      await withTimeout(fetch(url, { method: 'GET', redirect: 'manual' }), 5000);
      console.log('[probeCandidates] lan reachable:', url);
      return url;
    } catch (e) {
      console.log('[probeCandidates] lan failed:', url, e.message);
    }
  }

  console.log('[probeCandidates] all lan failed, fallback to relay');
  return httpsFallback || null;
}

// 统一解析用户输入为可访问地址（异步：fnid 分支需要调用远程 API）
// - fnid：调 fnos.net API 获取候选 → 顺序探测局域网 → 不通再用中继
// - IP / 网址：规范化 + 补 /music/
// 返回 { url, error }，url 非空即可直接访问
async function resolveAccessUrl(input) {
  const s = (input || '').trim();
  if (!s) return { url: null, error: '请输入服务器地址' };

  if (isFnid(s)) {
    console.log('[resolveAccessUrl] fnid -> resolve via fnos.net API');
    const candidates = await resolveFnid(s);
    if (!candidates || candidates.length === 0) {
      return { url: null, error: 'fnid 解析失败，请检查或使用网址登录' };
    }
    const selected = await probeCandidates(candidates);
    if (!selected) {
      return { url: null, error: '所有候选地址均不可达，请检查网络或使用网址登录' };
    }
    const finalUrl = ensureMusicSuffix(selected);
    if (!finalUrl) {
      return { url: null, error: '解析到的地址格式无效' };
    }
    console.log('[resolveAccessUrl] fnid ->', finalUrl);
    return { url: finalUrl, error: null };
  }

  const url = normalizeUrl(s);
  if (!url) return { url: null, error: '地址无效，请检查后重试' };
  const finalUrl = ensureMusicSuffix(url);
  if (!finalUrl) return { url: null, error: '地址格式无效' };
  console.log('[resolveAccessUrl] address ->', finalUrl);
  return { url: finalUrl, error: null };
}

// 自动补 /music/ 后缀（带尾斜杠）
// 统一用 /music/ 避免服务器 301 重定向 /music → /music/ 导致 loadURL 出现 ERR_FAILED
function ensureMusicSuffix(url) {
  try {
    const u = new URL(url);
    if (/\/music\/?$/.test(u.pathname)) {
      u.pathname = u.pathname.replace(/\/+$/, '') + '/';
      return u.href;
    }
    const path = u.pathname.replace(/\/+$/, '');
    u.pathname = path + '/music/';
    return u.href;
  } catch {
    return null;
  }
}

// 验证目标地址是否为飞牛音乐服务
// 在 loadURL 之前做一次 HTTP 请求探测，避免直接加载 502 / 非飞牛音乐页面导致卡死
// 返回 { ok: true } 或 { ok: false, error: string }
// 使用原生 http/https 模块而不是 fetch，确保能控制 SSL 证书验证（fnos.net/局域网 IP 允许自签）
function verifyFnMusic(targetUrl) {
  return new Promise((resolve) => {
    const MAX_REDIRECTS = 10;
    const TIMEOUT_MS = 12000;

    // 递归实现重定向跟随
    function doRequest(currentUrl, redirectLeft) {
      let parsed;
      try {
        parsed = new URL(currentUrl);
      } catch {
        resolve({ ok: false, error: '地址格式无效' });
        return;
      }

      const isHttps = parsed.protocol === 'https:';
      const host = parsed.hostname;
      const isHttpsRelay = host.endsWith('.fnos.net');
      const isLanIp = /^\d+\.\d+\.\d+\.\d+$/.test(host);
      const mod = isHttps ? https : require('http');

      const options = {
        hostname: host,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': UA,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        timeout: TIMEOUT_MS
      };
      // fnos.net 中转与局域网 IP：与 certificate-error 事件保持一致，允许自签 / 过期证书
      if (isHttps && (isHttpsRelay || isLanIp)) {
        options.rejectUnauthorized = false;
      }

      const req = mod.request(options, (res) => {
        const status = res.statusCode || 0;

        // 处理重定向
        if (status >= 300 && status < 400 && res.headers.location && redirectLeft > 0) {
          let next;
          try {
            next = new URL(res.headers.location, currentUrl).href;
          } catch {
            // 重定向地址无效，直接使用当前状态判断
            next = null;
          }
          if (next) {
            // 消费掉当前响应避免内存泄漏
            res.resume();
            doRequest(next, redirectLeft - 1);
            return;
          }
        }

        // 按状态码快速分类错误
        if (status === 502) {
          res.resume();
          resolve({ ok: false, error: '飞牛 NAS 上未安装或未启动飞牛音乐，请先在 NAS 中安装飞牛音乐插件' });
          return;
        }
        if (status >= 500 && status < 600) {
          res.resume();
          resolve({ ok: false, error: '服务器错误（' + status + '），飞牛音乐服务异常，请稍后再试' });
          return;
        }
        if (status === 404 || status === 403) {
          res.resume();
          resolve({ ok: false, error: '未检测到飞牛音乐服务，请确认地址正确且飞牛 NAS 上已安装飞牛音乐' });
          return;
        }

        // 读取响应正文（限制大小为 2MB，防止下载大文件卡死）
        const MAX_BODY = 2 * 1024 * 1024;
        const chunks = [];
        let total = 0;
        res.on('data', (c) => {
          total += c.length;
          if (total > MAX_BODY) {
            // 超限：认为页面存在，不再继续校验（SPA 首屏通常 < 500KB）
            res.destroy();
            // 超限且状态码正常 → 认为是合法服务
            if (status >= 200 && status < 400) resolve({ ok: true });
            else resolve({ ok: false, error: '服务器响应过大，无法校验' });
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => {
          let bodyText;
          try {
            bodyText = Buffer.concat(chunks).toString('utf-8');
          } catch {
            bodyText = '';
          }
          console.log('[verifyFnMusic] status:', status, 'url:', currentUrl, 'bodyLen:', bodyText.length);

          const lower = bodyText.toLowerCase();
          const hasMusicMarkers =
            lower.indexOf('飞牛音乐') >= 0 ||
            lower.indexOf('fnmusic') >= 0 ||
            lower.indexOf('fnos-music') >= 0 ||
            lower.indexOf('music center') >= 0 ||
            lower.indexOf('音乐中心') >= 0 ||
            /\/music\/assets\//.test(lower) ||
            /\/music\/_nuxt\//.test(lower) ||
            /\/music\/static\//.test(lower) ||
            (lower.indexOf('login') >= 0 &&
              lower.indexOf('password') >= 0 &&
              (lower.indexOf('/music') >= 0 || lower.indexOf('音乐') >= 0));

          if (status >= 200 && status < 400 && !hasMusicMarkers) {
            resolve({ ok: false, error: '该地址不是飞牛音乐服务，请检查地址是否正确' });
            return;
          }
          resolve({ ok: true });
        });
        res.on('error', (e) => {
          console.log('[verifyFnMusic] response error:', e.message);
          resolve({ ok: false, error: '读取响应失败：' + (e.message || '未知错误') });
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('timeout'));
      });
      req.on('error', (e) => {
        console.log('[verifyFnMusic] request error:', e.message, 'url:', currentUrl);
        // 网络错误 / 超时 / 证书错误（非白名单域名）
        if (e.message && /certificate|ssl|tls/i.test(e.message)) {
          resolve({ ok: false, error: '服务器证书验证失败，无法安全连接' });
          return;
        }
        if (e.message === 'timeout') {
          resolve({ ok: false, error: '连接超时，请检查服务器地址或网络' });
          return;
        }
        resolve({ ok: false, error: '无法连接到服务器，请检查地址或网络' });
      });
      req.end();
    }

    doRequest(targetUrl, MAX_REDIRECTS);
  });
}

let mainWindow = null;
let tray = null;
// 从远程页面读取到的歌单名称列表（用户创建的自定义歌单）
let cachedPlaylists = [];
// 是否处于「真正退出」流程：托盘右键退出 / window-all-closed 时置 true，
// 用于拦截 close 事件，让叉叉走「最小化到托盘」而非退出
let isQuitting = false;
// 自动登录失败检测定时器：登录后若仍停留在 /login 则跳回设置页
let loginFailTimer = null;
// 待展示给设置页的登录错误提示（设置页读取后清空）
let pendingLoginError = '';

// 基准窗口高度（在该高度下页面竖直方向无滚动条）
const BASE_HEIGHT = 1150;
// 三档窗口尺寸预设
const WIN_PRESETS = {
  large: { width: 1855, height: 1143, label: '大窗口' },
  medium: { width: 1575, height: 927, label: '中窗口' },
  small: { width: 1280, height: 860, label: '小窗口' }
};

// 根据屏幕高度自动选择最合适的窗口档位（默认大窗口，超了用中窗口，还超用小窗口）
function pickDefaultPreset() {
  const { workArea } = require('electron').screen.getPrimaryDisplay();
  const h = workArea.height;
  if (h >= WIN_PRESETS.large.height) return 'large';
  if (h >= WIN_PRESETS.medium.height) return 'medium';
  return 'small';
}

// 读取持久化的窗口档位（large/medium/small），无配置则自动选择
function getSavedPreset() {
  const cfg = readConfig();
  if (cfg.windowPreset && WIN_PRESETS[cfg.windowPreset]) return cfg.windowPreset;
  return pickDefaultPreset();
}

// 计算指定档位的窗口尺寸与页面缩放比例
// - 缩放比例固定 100%，保证页面按原始尺寸显示
function calcWinSizeAndZoom(preset) {
  const p = WIN_PRESETS[preset] || WIN_PRESETS.small;
  return { winWidth: p.width, winHeight: p.height, zoom: 1.0 };
}

// 浏览器固定缩放档位（百分比），缩放只能取这些值保证字体清晰
const ZOOM_STEPS = [0.25, 0.33, 0.50, 0.67, 0.75, 0.80, 0.90, 1.00, 1.10, 1.25, 1.50, 1.75, 2.00];

// 将任意缩放比例吸附到最接近的固定档位
function snapToZoomStep(value) {
  let best = ZOOM_STEPS[0];
  let bestDiff = Math.abs(value - best);
  for (let i = 1; i < ZOOM_STEPS.length; i++) {
    const diff = Math.abs(value - ZOOM_STEPS[i]);
    if (diff < bestDiff) {
      best = ZOOM_STEPS[i];
      bestDiff = diff;
    }
  }
  return best;
}

// 切换窗口档位：持久化配置并立即应用尺寸与缩放
function applyWindowPreset(preset) {
  if (!WIN_PRESETS[preset]) return;
  const cfg = readConfig();
  cfg.windowPreset = preset;
  writeConfig(cfg);
  if (mainWindow && !mainWindow.isDestroyed()) {
    const { winWidth, winHeight, zoom } = calcWinSizeAndZoom(preset);
    mainWindow.setSize(winWidth, winHeight);
    mainWindow.webContents.setZoomFactor(zoom);
  }
  // 刷新托盘菜单勾选状态
  if (tray) tray.setContextMenu(buildTrayMenu());
}

// ===== 启动页配置 =====
// 登录成功进入主页后，自动点击侧边栏中匹配 navText 的导航项
// - 'home'：不点击任何项，保持站点默认进入的首页
// - 'playlist'：navText 取自 config.customPlaylist（用户在托盘菜单输入的歌单名称）
// 固定项的 navText 与飞牛音乐侧边栏文案对应；若实际文案不同，点击不会命中（保持默认）
const STARTUP_TARGETS = {
  home:      { label: '首页',       navText: '' },
  favorites: { label: '收藏',       navText: '收藏' },
  recent:    { label: '最近',       navText: '最近' },
  albums:    { label: '专辑',       navText: '专辑' },
  artists:   { label: '歌手',       navText: '歌手' },
  genres:    { label: '风格',       navText: '风格' },
  library:   { label: '音乐库',     navText: '音乐库' },
  playlist:  { label: '自定义歌单', navText: '' }
};
// 默认启动页：首页（不点击任何导航项，保持站点默认行为）
const DEFAULT_STARTUP_TARGET = 'home';

// 读取持久化的启动页 key，无配置或无效则返回默认值
function getSavedStartupTarget() {
  const cfg = readConfig();
  const k = cfg.startupTarget;
  return (k && STARTUP_TARGETS[k]) ? k : DEFAULT_STARTUP_TARGET;
}

// 设置启动页 key 并刷新托盘菜单
function setStartupTarget(key) {
  if (!STARTUP_TARGETS[key]) return;
  const cfg = readConfig();
  cfg.startupTarget = key;
  writeConfig(cfg);
  if (tray) tray.setContextMenu(buildTrayMenu());
}

// ===== 自动播放模式配置 =====
// - off：不自动播放
// - continue：点击底部播放按钮（恢复上次播放进度）
// - playAll：启动页为歌单时点击「播放全部」；为音乐库时点击「随机漫游」
// - random：启动页为歌单时点击「随机」；为音乐库时点击「随机漫游」
const AUTO_PLAY_MODES = {
  off:      { label: '关闭' },
  continue: { label: '继续播放' },
  playAll:  { label: '全部播放' },
  random:   { label: '随机播放' }
};
const DEFAULT_AUTO_PLAY_MODE = 'off';

// 读取自动播放模式，兼容旧版 autoPlay 布尔字段
function getSavedAutoPlayMode() {
  const cfg = readConfig();
  if (cfg.autoPlayMode && AUTO_PLAY_MODES[cfg.autoPlayMode]) return cfg.autoPlayMode;
  // 旧版 autoPlay: true 视为 continue
  if (cfg.autoPlay === true) return 'continue';
  return DEFAULT_AUTO_PLAY_MODE;
}

// 设置自动播放模式并刷新托盘菜单
function setAutoPlayMode(mode) {
  if (!AUTO_PLAY_MODES[mode]) return;
  const cfg = readConfig();
  cfg.autoPlayMode = mode;
  // 清理旧字段，避免歧义
  delete cfg.autoPlay;
  writeConfig(cfg);
  if (tray) tray.setContextMenu(buildTrayMenu());
}

// 注入登录失败检测：hook fetch / XHR，捕获登录接口的错误响应，命中后立即通知主进程跳回设置页
// 不依赖自动登录，手动在登录页提交失败也会触发
function injectLoginFailHook() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.executeJavaScript(`
    (function(){
      if (window.__fnLoginHookInstalled) return;
      window.__fnLoginHookInstalled = true;

      function notifyFail(){
        try {
          if (window.serverBridge && typeof window.serverBridge.notifyLoginFail === 'function') {
            window.serverBridge.notifyLoginFail();
          }
        } catch {}
      }

      function isLoginError(status, body){
        // HTTP 错误状态码
        if (status >= 400 && status < 600) return true;
        if (!body) return false;
        var s = String(body).toLowerCase();
        // 中文常见错误文案
        if (s.indexOf('密码') >= 0 && (s.indexOf('错误') >= 0 || s.indexOf('不正确') >= 0)) return true;
        if (s.indexOf('用户名') >= 0 && (s.indexOf('错误') >= 0 || s.indexOf('不存在') >= 0)) return true;
        if (s.indexOf('登录失败') >= 0 || s.indexOf('账号或密码') >= 0) return true;
        // 通用 JSON 错误结构
        try {
          var j = JSON.parse(body);
          if (j && j.success === false) return true;
          if (j && j.code !== undefined && j.code !== 0 && j.code !== 200 && j.code !== '0' && j.code !== '200' && (j.msg || j.message || j.error)) return true;
        } catch {}
        return false;
      }

      function isLoginUrl(url){
        return /login/i.test(url || '');
      }

      // hook fetch
      var origFetch = window.fetch;
      if (typeof origFetch === 'function') {
        window.fetch = function(){
          var args = arguments;
          var reqUrl = '';
          try { reqUrl = (typeof args[0] === 'string') ? args[0] : (args[0] && args[0].url) || ''; } catch {}
          return origFetch.apply(this, args).then(function(res){
            try {
              if (isLoginUrl(reqUrl) || isLoginUrl(res.url)) {
                res.clone().text().then(function(body){
                  if (isLoginError(res.status, body)) notifyFail();
                }).catch(function(){});
              }
            } catch {}
            return res;
          });
        };
      }

      // hook XHR
      var origOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url){
        this.__fnReqUrl = url;
        return origOpen.apply(this, arguments);
      };
      var origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function(){
        var self = this;
        this.addEventListener('load', function(){
          try {
            if (isLoginUrl(self.__fnReqUrl)) {
              var body = self.responseText || '';
              if (isLoginError(self.status, body)) notifyFail();
            }
          } catch {}
        });
        return origSend.apply(this, arguments);
      };
    })();
  `).catch(() => {});
}

// 自动登录：若当前在登录页且配置了用户名密码，自动填入 input 并点击 button
// 在 did-finish-load（整页加载）和 did-navigate-in-page（SPA 路由切换）时都会触发
// - 未保存密码：跳回设置页让用户重新输入
// - 已保存密码：自动登录，登录后若仍停留在 /login（cookie 未拿到/登录失败）则跳回设置页
function tryAutoLogin() {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  // 仅在远程页面的登录页处理
  let currentUrl = '';
  try { currentUrl = mainWindow.webContents.getURL(); } catch {}
  if (!/\/login/i.test(currentUrl)) return;

  // 安装登录失败 hook（自动/手动登录接口返回错误都会立即跳回设置页）
  injectLoginFailHook();

  const cfg = readConfig();
  // 没有保存的密码或用户名：回到设置页，可重新输入密码或全部重填
  if (!cfg.username || !cfg.password) {
    loadSetup();
    return;
  }

  const creds = JSON.stringify({ u: cfg.username, p: cfg.password });
  mainWindow.webContents.executeJavaScript(`
    (function(){
      var creds = ${creds};
      // 防重复
      if (window.__fnAutoLoginDone) return;
      window.__fnAutoLoginDone = true;

      var tries = 0;
      var timer = setInterval(function(){
        tries++;
        if (tries > 20) { clearInterval(timer); return; }

        // 登录表单：两个 input（用户名 + 密码）+ 一个 button
        var inputs = document.querySelectorAll('input');
        if (inputs.length < 2) return;
        var userEl = inputs[0];
        var passEl = inputs[1];
        // 确保第二个是密码框（登录表单的标志）
        if (passEl.type !== 'password') return;

        // 使用原生 setter 触发框架（React/Vue）的 onChange
        var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(userEl, creds.u);
        userEl.dispatchEvent(new Event('input', { bubbles: true }));
        userEl.dispatchEvent(new Event('change', { bubbles: true }));
        setter.call(passEl, creds.p);
        passEl.dispatchEvent(new Event('input', { bubbles: true }));
        passEl.dispatchEvent(new Event('change', { bubbles: true }));

        clearInterval(timer);

        // 点击登录按钮（type=submit 的那个，避免误点页面其他 button）
        var btn = document.querySelector('button[type="submit"]') || document.querySelector('button');
        if (btn) btn.click();
      }, 400);
    })();
  `).catch(() => {});

  // 登录失败检测：8 秒后若仍停留在登录页（未拿到 cookie / 登录失败），跳回设置页
  if (loginFailTimer) clearTimeout(loginFailTimer);
  loginFailTimer = setTimeout(() => {
    loginFailTimer = null;
    if (!mainWindow || mainWindow.isDestroyed()) return;
    try {
      const url = mainWindow.webContents.getURL();
      if (/\/login/i.test(url)) {
        loadSetup();
      }
    } catch {}
  }, 8000);
}

// 登录成功进入主页后，自动点击一次启动页配置对应的侧边栏导航项
// - 'home'：不点击任何项，保持站点默认首页
// - 其他：查找侧边栏中文案匹配的导航项并点击
// 仅在首次进入主页触发一次，避免后续干扰用户手动切换页面
function tryClickStartupNav() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  let currentUrl = '';
  try { currentUrl = mainWindow.webContents.getURL(); } catch {}
  // 仅在远程页面且非登录页处理
  if (!/^https?:/i.test(currentUrl)) return;
  if (/\/login/i.test(currentUrl)) return;

  const cfg = readConfig();
  const targetKey = cfg.startupTarget && STARTUP_TARGETS[cfg.startupTarget]
    ? cfg.startupTarget
    : DEFAULT_STARTUP_TARGET;
  const target = STARTUP_TARGETS[targetKey];

  // 计算需要匹配的导航文案
  let navText = target.navText;
  if (targetKey === 'playlist') {
    navText = (cfg.customPlaylist || '').trim();
  }
  // 空文案（首页 / 未配置自定义歌单）：不点击任何项
  if (!navText) return;

  const navTextJson = JSON.stringify(navText);
  mainWindow.webContents.executeJavaScript(`
    (function(){
      if (window.__fnClickStartupStarted) return;
      window.__fnClickStartupStarted = true;
      var NAV_TEXT = ${navTextJson};
      var tries = 0;
      var timer = setInterval(function(){
        tries++;
        if (tries > 30) { clearInterval(timer); return; } // 最多重试 15 秒
        if (window.__fnClickStartupDone) { clearInterval(timer); return; }
        // 查找文案匹配的侧边栏导航项
        // - 固定导航项：span 在带 svg 图标的容器内（div[class*="nav"] / li / a / [role="button"]）
        // - 自定义歌单：span 在 button 内（无 svg，靠封面图区分），closest 直接命中 button
        var spans = document.querySelectorAll('span');
        var target = null;
        for (var i = 0; i < spans.length; i++) {
          var s = spans[i];
          if (s.textContent.trim() !== NAV_TEXT) continue;
          // 优先匹配带 svg 的导航容器，其次匹配 button（歌单项）
          var box = s.closest('div[class*="nav"], li, a, [role="button"], button') || s.parentElement;
          if (!box) continue;
          // button 元素直接视为可点击项（歌单）；其余容器要求带 svg（固定导航项）
          if (box.tagName !== 'BUTTON' && !box.querySelector('svg')) continue;
          target = box;
          break;
        }
        if (!target) return; // 导航未渲染，下次继续
        window.__fnClickStartupDone = true;
        clearInterval(timer);
        target.click();
      }, 500);
    })();
  `).catch(() => {});
}

// 自动播放：按配置模式与启动页选择不同按钮点击
// - continue：点击底部「播放」按钮（恢复上次进度）
// - playAll：启动页为歌单时点击「播放全部」；为音乐库时点击「随机漫游」
// - random：启动页为歌单时点击「随机」；为音乐库时点击「随机漫游」
// - 其他启动页（首页/收藏等）：playAll / random 退化为点击底部「播放」按钮
// 播放按钮可能异步加载，多次重试；检测到「暂停」按钮出现说明已在播放
function tryAutoPlay() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const cfg = readConfig();
  const mode = getSavedAutoPlayMode();
  if (mode === 'off') return;

  const startupKey = cfg.startupTarget && STARTUP_TARGETS[cfg.startupTarget]
    ? cfg.startupTarget
    : DEFAULT_STARTUP_TARGET;

  // 计算需要点击的按钮 aria-label
  // - continue：固定点击底部「播放」
  // - playAll / random：根据启动页选择
  //   - 歌单：playAll→播放全部，random→随机
  //   - 音乐库：两者都点「随机漫游」
  //   - 其他页面：退化为「播放」
  let targetLabel = '播放';
  if (mode === 'continue') {
    targetLabel = '播放';
  } else if (mode === 'playAll') {
    if (startupKey === 'playlist') targetLabel = '播放全部';
    else if (startupKey === 'library') targetLabel = '随机漫游';
    else targetLabel = '播放';
  } else if (mode === 'random') {
    if (startupKey === 'playlist') targetLabel = '随机';
    else if (startupKey === 'library') targetLabel = '随机漫游';
    else targetLabel = '播放';
  }

  const labelJson = JSON.stringify(targetLabel);
  mainWindow.webContents.executeJavaScript(`
    (function(){
      if (window.__fnAutoPlayStarted) return;
      // 仅在主界面启动（登录页 pathname 含 /login）
      if (location.pathname.indexOf('/login') !== -1) return;
      window.__fnAutoPlayStarted = true;

      var TARGET_LABEL = ${labelJson};
      var tries = 0;
      var maxTries = 20;  // 最多重试 10 秒
      var timer = setInterval(function(){
        tries++;
        if (tries > maxTries) { clearInterval(timer); return; }
        // 检测到「暂停」按钮 = 已在播放，停止重试
        if (document.querySelector('button[aria-label="暂停"]')) {
          clearInterval(timer);
          return;
        }
        // 点击目标按钮（按钮可能异步加载，多次重试）
        var btn = document.querySelector('button[aria-label="' + TARGET_LABEL + '"]');
        if (btn) btn.click();
      }, 500);
    })();
  `).catch(() => {});
}

function createWindow() {
  const preset = getSavedPreset();
  const { winWidth, winHeight, zoom } = calcWinSizeAndZoom(preset);
  mainWindow = new BrowserWindow({
    width: winWidth,
    height: winHeight,
    minWidth: 1000,
    minHeight: 860,
    title: '飞牛音乐',
    backgroundColor: '#00000000',
    show: false,
    autoHideMenuBar: true,
    // 无边框客户端外观：隐藏标题栏，叉叉用自定义注入按钮（原生 overlay 无法控制 hover 底色）
    frame: false,
    // 仅保留关闭按钮（叉叉 = 最小化到托盘），隐藏最小化 / 最大化按钮
    minimizable: false,
    maximizable: false,
    titleBarStyle: 'hidden',
    icon: path.join(__dirname, 'build', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      plugins: true,
      partition: PARTITION,
      // 关闭后台节流：窗口最小化/失焦后，页面定时器与音频仍正常推进，
      // 站点「无感知」窗口被最小化，照常自动切换下一首
      backgroundThrottling: false
    }
  });

  // 每次启动强制使用计算出的窗口尺寸与页面缩放，避免系统记住上次调整后的大小
  mainWindow.once('ready-to-show', () => {
    mainWindow.setSize(winWidth, winHeight);
    mainWindow.webContents.setZoomFactor(zoom);
    mainWindow.show();
  });

  // 窗口尺寸变化时保持页面缩放 100%，不再按高度动态调整
  let resizeTimer = null;
  mainWindow.on('resize', () => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.setZoomFactor(1.0);
      }
    }, 150);
  });

  // 远程页面加载完成后，注入顶部可拖拽条（浮于页面之上，不占用布局空间，避免底部被裁）
  mainWindow.webContents.on('did-finish-load', () => {
    const currentUrl = mainWindow.webContents.getURL();
    if (!/^https?:/i.test(currentUrl)) return; // 仅对远程服务器页面注入
    mainWindow.webContents.insertCSS(`
      body { -webkit-app-region: no-drag; }
      .__fn-dragbar {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 36px !important;
        -webkit-app-region: drag !important;
        z-index: 2147483647 !important;
        background: rgba(15, 15, 23, 0.0) !important;
        pointer-events: auto !important;
      }
      .__fn-close-btn {
        position: fixed !important;
        top: 8px !important;
        right: 10px !important;
        width: 22px !important;
        height: 22px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        -webkit-app-region: no-drag !important;
        z-index: 2147483648 !important;
        cursor: pointer !important;
        color: #8a8a96 !important;
        background: transparent !important;
        border: none !important;
        border-radius: 4px !important;
        transition: color 0.15s !important;
        opacity: 0.7 !important;
      }
      .__fn-close-btn:hover {
        color: #e8e8f0 !important;
        background: transparent !important;
        opacity: 1 !important;
      }
      .__fn-close-btn svg {
        width: 11px !important;
        height: 11px !important;
        display: block !important;
      }
      /* 隐藏首页「最近添加」歌曲模块 */
      .__fn-hide-recent { display: none !important; }
    `).catch(() => {});
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (document.getElementById('__fn-dragbar')) return;
        var d = document.createElement('div');
        d.id = '__fn-dragbar';
        d.className = '__fn-dragbar';
        document.documentElement.appendChild(d);
        // 自定义关闭按钮（叉叉 = 最小化到托盘，由主进程 close 事件处理）
        var b = document.createElement('div');
        b.id = '__fn-close-btn';
        b.className = '__fn-close-btn';
        b.title = '关闭';
        b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/></svg>';
        b.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.minimizeToTray) {
            window.serverBridge.minimizeToTray();
          }
        });
        document.documentElement.appendChild(b);
      })();
    `).catch(() => {});
    // 隐藏首页「最近添加」歌曲模块（保留「最近添加」专辑模块）
    // 区分依据：歌曲模块标题为「最近添加歌曲」，专辑模块标题为「最近添加专辑」
    // SPA 异步渲染，用 MutationObserver 持续隐藏
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (window.__fnHideRecentStarted) return;
        window.__fnHideRecentStarted = true;
        var KEY = '最近添加歌曲';
        function hideRecent(){
          var titles = document.querySelectorAll('h1,h2,h3,h4,h5,h6,[class*="title"],[class*="Title"]');
          for (var i = 0; i < titles.length; i++) {
            var t = titles[i];
            if ((t.textContent || '').trim().indexOf(KEY) === -1) continue;
            var box = t.closest('section, article, [class*="card"], [class*="block"], [class*="section"], [class*="module"]');
            if (box && !box.classList.contains('__fn-hide-recent')) {
              box.classList.add('__fn-hide-recent');
            }
          }
        }
        hideRecent();
        new MutationObserver(hideRecent).observe(document.documentElement, {
          childList: true, subtree: true
        });
      })();
    `).catch(() => {});

    // 隐藏页面内「退出登录」按钮（避免误触退出，登录态由本应用托管）
    // 该按钮用 Tailwind 通用类无唯一标识，按文本内容匹配；SPA 异步渲染，用 MutationObserver 持续隐藏
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (window.__fnHideLogoutStarted) return;
        window.__fnHideLogoutStarted = true;
        function hideLogout(){
          var spans = document.querySelectorAll('span');
          for (var i = 0; i < spans.length; i++) {
            if (spans[i].textContent.trim() === '退出登录') {
              var el = spans[i].closest('button');
              if (el && el.parentElement) el.parentElement.style.display = 'none';
            }
          }
        }
        hideLogout();
        new MutationObserver(hideLogout).observe(document.documentElement, {
          childList: true, subtree: true
        });
      })();
    `).catch(() => {});

    // 持续读取侧边栏自定义歌单列表并上报主进程（供托盘菜单展示）
    // 歌单按钮特征：button 内含封面 img（src 带 coverId=playlist_）和名称 span
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (window.__fnPlaylistObserverStarted) return;
        window.__fnPlaylistObserverStarted = true;
        function readPlaylists(){
          var seen = {};
          var texts = [];
          // 歌单封面图 src 含 coverId=playlist_，由此定位歌单按钮
          var imgs = document.querySelectorAll('img[src*="coverId=playlist_"]');
          for (var i = 0; i < imgs.length; i++) {
            var btn = imgs[i].closest('button');
            if (!btn) continue;
            var span = btn.querySelector('span');
            if (!span) continue;
            var text = span.textContent.trim();
            if (!text || seen[text]) continue;
            seen[text] = true;
            texts.push(text);
          }
          return texts;
        }
        var lastReport = null;
        function report(){
          try {
            var texts = readPlaylists();
            var sig = texts.join('\\u0001');
            if (sig === lastReport) return;
            lastReport = sig;
            if (window.serverBridge && typeof window.serverBridge.reportPlaylists === 'function') {
              window.serverBridge.reportPlaylists(texts);
            }
          } catch {}
        }
        report();
        var timer = null;
        new MutationObserver(function(){
          if (timer) return;
          timer = setTimeout(function(){ timer = null; report(); }, 500);
        }).observe(document.documentElement, { childList: true, subtree: true });
      })();
    `).catch(() => {});

    // 切换到配置的启动页 + 自动播放 + 自动登录
    tryClickStartupNav();
    tryAutoPlay();
    tryAutoLogin();
  });

  // SPA 路由切换（如 cookie 失效跳到 /login，或自动登录后跳回主页）
  // did-finish-load 不会触发，需监听 did-navigate-in-page
  mainWindow.webContents.on('did-navigate-in-page', () => {
    tryClickStartupNav();
    tryAutoLogin();
    tryAutoPlay();
  });

  // 站内新窗口放行，站外用系统默认浏览器打开
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // 禁止任何 window.open 新建窗口（避免页面弹出的额外窗口）
    // 同源链接用系统浏览器打开，跨域链接也用系统浏览器打开
    if (url) shell.openExternal(url);
    return { action: 'deny' };
  });

  // 窗口级证书错误处理：放行 fnos.net 中转域名与 NAS 直连 IP 的证书
  // fnos.net 证书可能过期（ERR_CERT_DATE_INVALID），NAS 自签证书也会被拒绝
  // 注意：仅放行这两类，普通 https 站点走默认验证，避免引入安全风险
  mainWindow.webContents.on('certificate-error', (event, url, error, certificate, callback) => {
    let host = '';
    try { host = new URL(url).hostname; } catch {}
    if (host.endsWith('.fnos.net') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      event.preventDefault();
      callback(true); // 接受证书
    } else {
      callback(false); // 拒绝（走默认）
    }
  });

  // 仅允许停留在当前服务器站内
  // 跨域导航直接阻止，不调用 shell.openExternal：
  //  - 页面内部的重定向（如 fnos.net 中继 → NAS 局域网 IP）已由 isNavigationAllowed 放行
  //  - 其他跨域导航通常是页面 a 标签跳转，应交给 setWindowOpenHandler（target=_blank）走系统浏览器
  //  - 若此处也 openExternal，会发生"app 内被弹出到外部浏览器"的问题
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const allowed = getAllowedOrigin();
    console.log('[will-navigate] url:', url, 'allowed:', allowed);
    if (allowed && !isNavigationAllowed(url, allowed)) {
      console.log('[will-navigate] BLOCKED');
      event.preventDefault();
    }
  });

  // 诊断：页面加载失败时打印错误，便于定位白屏 / 跳转失败
  // 主页面加载失败（非静态资源）时作为兜底，跳回设置页并提示，避免卡死在错误页
  mainWindow.webContents.on('did-fail-load', (_e, errorCode, errorDescription, validatedURL, isMainFrame) => {
    console.log('[did-fail-load] code:', errorCode, 'desc:', errorDescription, 'url:', validatedURL, 'mainFrame:', isMainFrame);
    // 非主框架（子资源）失败不处理，或未设置过远程地址（本地 setup 页）不处理
    if (!isMainFrame || !lastServerUrl) return;
    // 仅在失败的 URL 与最近 applyServerUrl 的 URL 高度匹配时才跳回（避免子页面导航失败被误处理）
    let match = false;
    try { match = validatedURL && new URL(validatedURL).origin === new URL(lastServerUrl).origin; } catch {}
    if (!match) return;
    // -3 ERR_ABORTED 通常是用户主动导航 / 新的 loadURL 覆盖，不视为错误
    if (errorCode === -3) return;
    const errMsg =
      '页面加载失败（错误码 ' + errorCode + '），请确认飞牛音乐已安装且服务器可访问：' + (errorDescription || validatedURL);
    console.log('[did-fail-load] bounce to setup:', errMsg);
    pendingLoginError = errMsg;
    loadSetup();
  });

  // 诊断：导航开始时打印，确认 loadURL 是否触发
  mainWindow.webContents.on('did-start-navigation', (_e, url, isInPlace, isMainFrame) => {
    console.log('[did-start-navigation] url:', url, 'mainFrame:', isMainFrame);
  });

  // 媒体自动播放 / 全屏权限（使用持久化分区）
  getSession().setPermissionRequestHandler((wc, permission, callback) => {
    callback(permission === 'media' || permission === 'fullscreen');
  });

  // 启动分支：读取用户原始输入，每次启动走一次 resolveAccessUrl 确认本次访问地址
  // - 有 serverInput：异步解析为可访问地址并加载（fnid 需调 API + 探测）
  // - 没有：进入设置页
  const cfg = readConfig();
  if (cfg.serverInput) {
    resolveAccessUrl(cfg.serverInput).then(async ({ url, error }) => {
      if (!url) {
        console.log('[startup] resolve failed:', error);
        pendingLoginError = error || '服务器地址解析失败，请重新输入';
        loadSetup();
        return;
      }
      // 启动时同样验证是否为飞牛音乐，避免白屏 / 502 卡死
      const verified = await verifyFnMusic(url);
      if (!verified.ok) {
        console.log('[startup] verify failed:', verified.error);
        pendingLoginError = verified.error;
        loadSetup();
        return;
      }
      applyServerUrl(url);
    });
  } else {
    loadSetup();
  }

  // 叉叉 = 最小化到托盘；只有 isQuitting（托盘右键退出）才真正关闭
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.hide();
      }
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// 当前允许的站点前缀（origin），仅在进入服务器后生效
let allowedOrigin = null;
// 最近一次 applyServerUrl 的目标 URL（用于 did-fail-load 判断是否为主页面加载失败）
let lastServerUrl = null;
function getAllowedOrigin() {
  return allowedOrigin;
}

// 判断 IP 是否为私网地址（10.x / 172.16-31.x / 192.168.x / 127.x / 169.254.x）
function isPrivateIp(ip) {
  if (!ip) return false;
  return (
    ip === '127.0.0.1' ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  );
}

// 判断目标 url 是否允许在 app 内导航
// 1. 同 origin 直接放行
// 2. fnos.net 中继场景：放行整个 fnos.net 域内导航（子域名 ↔ 路径形式互转）
// 3. fnos.net 中继可能 302 重定向到 NAS 局域网 IP：放行私网 IP，避免重定向被丢到外部浏览器
// 4. 局域网 IP origin 场景：放行同 IP 不同端口（NAS 站内跳端口登录等）
function isNavigationAllowed(url, allowed) {
  if (!url || !allowed) return false;
  if (url.startsWith(allowed)) return true;
  try {
    const allowedHost = new URL(allowed).hostname;
    const navHost = new URL(url).hostname;
    // fnos.net 域内互转
    if ((allowedHost === 'fnos.net' || allowedHost.endsWith('.fnos.net')) &&
        (navHost === 'fnos.net' || navHost.endsWith('.fnos.net'))) {
      return true;
    }
    // fnos.net 中继 → 私网 IP 重定向放行
    if ((allowedHost === 'fnos.net' || allowedHost.endsWith('.fnos.net')) && isPrivateIp(navHost)) {
      return true;
    }
    // 局域网 IP origin：放行同 IP 不同端口
    if (isPrivateIp(allowedHost) && navHost === allowedHost) {
      return true;
    }
  } catch {}
  return false;
}

// 应用服务器地址：设置 allowedOrigin 并在窗口加载，不写配置
function applyServerUrl(rawUrl) {
  const url = normalizeUrl(rawUrl);
  if (!url) {
    loadSetup();
    return;
  }
  try {
    allowedOrigin = new URL(url).origin;
  } catch {
    allowedOrigin = null;
  }
  lastServerUrl = url;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.loadURL(url, { userAgent: UA }, (err) => {
      if (err) console.log('[applyServerUrl] loadURL error:', err.code, err.message);
    });
  }
}

// 加载本地服务器地址输入页
function loadSetup() {
  allowedOrigin = null;
  lastServerUrl = null;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.loadFile(path.join(__dirname, 'setup.html'));
  }
}

// 退出登录：清除 cookies（登录态）与已保存的密码，保留服务器地址等其它配置，回到设置页
function logoutAccount() {
  const cfg = readConfig();
  delete cfg.password;
  writeConfig(cfg);
  getSession().clearStorageData({ storages: ['cookies'] }).catch(() => {});
  allowedOrigin = null;
  loadSetup();
}

// 返回已保存的服务器地址与用户名，供设置页预填（退出登录后保留输入历史）
ipcMain.handle('get-saved-input', () => {
  const cfg = readConfig();
  return { url: cfg.serverInput || '', username: cfg.username || '' };
});

// 登录接口返回错误：渲染层 hook 检测到失败后通知主进程，立即跳回设置页并带错误提示
ipcMain.handle('login-fail', () => {
  if (loginFailTimer) { clearTimeout(loginFailTimer); loginFailTimer = null; }
  pendingLoginError = '用户名或密码错误';
  loadSetup();
  return true;
});

// 设置页读取并清空待展示的登录错误提示
ipcMain.handle('get-login-error', () => {
  const msg = pendingLoginError;
  pendingLoginError = '';
  return msg;
});

// 设置页提交服务器地址（含可选用户名密码）：统一走 resolveAccessUrl 解析，持久化用户原始输入
ipcMain.handle('submit-server', async (event, payload) => {
  // 兼容：payload 可能是字符串（旧调用）或对象 { url, username, password }
  const input = typeof payload === 'string'
    ? payload.trim()
    : (payload && payload.url ? payload.url : '').trim();
  const username = (payload && typeof payload === 'object' ? (payload.username || '').trim() : '');
  const password = (payload && typeof payload === 'object' ? (payload.password || '') : '');

  const { url, error } = await resolveAccessUrl(input);
  if (!url) {
    return { ok: false, error };
  }

  // 在 loadURL 之前先验证：避免直接加载 502 / 非飞牛音乐页面导致卡死
  const verified = await verifyFnMusic(url);
  if (!verified.ok) {
    console.log('[submit-server] verify failed:', verified.error);
    return { ok: false, error: verified.error };
  }

  // 持久化用户原始输入与登录凭据，下次启动重新解析
  const cfg = readConfig();
  cfg.serverInput = input;
  if (username) cfg.username = username;
  if (password) cfg.password = password;
  writeConfig(cfg);
  applyServerUrl(url);
  return { ok: true };
});

// 返回应用版本号（sandbox 渲染进程无法 require package.json，由主进程提供）
ipcMain.handle('get-app-version', () => app.getVersion());

// 比较版本号：返回 1 表示 latest > current，0 相等，-1 latest < current
function compareVersions(latest, current) {
  const pa = String(latest).replace(/^v/, '').split('.').map(Number);
  const pb = String(current).replace(/^v/, '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const da = pa[i] || 0;
    const db = pb[i] || 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

// 检查更新：调用 GitHub tags 接口获取最新 tag，与当前版本对比
async function checkForUpdate() {
  return new Promise((resolve) => {
    const req = https.get(REPO_TAGS_API, { headers: { 'User-Agent': 'fnmusic-exe-updater' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const list = JSON.parse(data);
          // tags 接口返回数组（按创建时间倒序），取第一个即最新 tag
          const latestTag = (Array.isArray(list) && list[0] && list[0].name) || '';
          if (!latestTag) {
            resolve({ hasUpdate: false, error: 'no_tag' });
            return;
          }
          const currentVer = app.getVersion();
          const hasUpdate = compareVersions(latestTag, currentVer) > 0;
          resolve({
            hasUpdate,
            currentVersion: currentVer,
            latestVersion: latestTag,
            releaseUrl: REPO_URL + '/releases/tag/' + latestTag
          });
        } catch {
          resolve({ hasUpdate: false, error: 'parse_failed' });
        }
      });
    });
    req.on('error', (e) => resolve({ hasUpdate: false, error: e.message }));
    req.setTimeout(8000, () => { req.destroy(); resolve({ hasUpdate: false, error: 'timeout' }); });
  });
}

ipcMain.handle('check-update', () => checkForUpdate());

// 最小化到托盘（叉叉按钮调用）
ipcMain.handle('minimize-to-tray', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.hide();
  }
  return true;
});

// 渲染层通过 MutationObserver 持续上报侧边栏歌单列表，主进程缓存并刷新托盘菜单
ipcMain.on('playlists-updated', (_event, names) => {
  const sorted = (Array.isArray(names) ? names : []).slice().sort();
  const cached = cachedPlaylists.slice().sort();
  cachedPlaylists = Array.isArray(names) ? names : [];
  // 仅在列表变化时重建托盘菜单，避免无谓刷新
  if (JSON.stringify(sorted) !== JSON.stringify(cached)) {
    if (tray) tray.setContextMenu(buildTrayMenu());
  }
});

// 创建托盘图标与右键菜单
function createTray() {
  const iconPath = path.join(__dirname, 'build', 'icon.ico');
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    if (trayIcon.isEmpty()) trayIcon = nativeImage.createEmpty();
  } catch {
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip('飞牛音乐');

  tray.setContextMenu(buildTrayMenu());

  // 单击托盘图标：显示/隐藏主窗口
  tray.on('click', () => showMainWindow());
}

// 构建「启动页」子菜单：固定项与自定义歌单平级，全部为 radio 互斥选择
function buildStartupTargetSubmenu() {
  const currentKey = getSavedStartupTarget();
  const cfg = readConfig();

  // 固定选项（不含自定义歌单）
  const fixed = Object.keys(STARTUP_TARGETS)
    .filter((k) => k !== 'playlist')
    .map((k) => ({
      label: STARTUP_TARGETS[k].label,
      type: 'radio',
      checked: currentKey === k,
      click: () => setStartupTarget(k)
    }));

  const items = [...fixed];

  // 自定义歌单：从页面读取的歌单列表，与固定项平级列出
  cachedPlaylists.forEach((name) => {
    items.push({
      label: name,
      type: 'radio',
      checked: currentKey === 'playlist' && cfg.customPlaylist === name,
      click: () => {
        const c = readConfig();
        c.customPlaylist = name;
        c.startupTarget = 'playlist';
        writeConfig(c);
        if (tray) tray.setContextMenu(buildTrayMenu());
      }
    });
  });

  return items;
}

// 构建「自动播放」子菜单：4 个模式 radio 互斥选择
function buildAutoPlaySubmenu() {
  const currentMode = getSavedAutoPlayMode();
  return Object.keys(AUTO_PLAY_MODES).map((k) => ({
    label: AUTO_PLAY_MODES[k].label,
    type: 'radio',
    checked: currentMode === k,
    click: () => setAutoPlayMode(k)
  }));
}

// 构建托盘右键菜单（每次构建都读取最新状态，确保勾选正确）
function buildTrayMenu() {
  return Menu.buildFromTemplate([
    {
      label: '显示主窗口',
      click: () => showMainWindow()
    },
    { type: 'separator' },
    {
      label: '开机自启',
      type: 'checkbox',
      checked: app.getLoginItemSettings().openAtLogin,
      click: (menuItem) => {
        // 切换开机自启状态
        app.setLoginItemSettings({ openAtLogin: menuItem.checked });
        // 重新构建菜单刷新勾选状态
        tray.setContextMenu(buildTrayMenu());
      }
    },
    {
      label: '自动播放',
      submenu: buildAutoPlaySubmenu()
    },
    { type: 'separator' },
    {
      label: '窗口大小',
      submenu: [
        {
          label: '大窗口 (1855×1143)',
          type: 'radio',
          checked: getSavedPreset() === 'large',
          click: () => applyWindowPreset('large')
        },
        {
          label: '中窗口 (1575×927)',
          type: 'radio',
          checked: getSavedPreset() === 'medium',
          click: () => applyWindowPreset('medium')
        },
        {
          label: '小窗口 (1280×860)',
          type: 'radio',
          checked: getSavedPreset() === 'small',
          click: () => applyWindowPreset('small')
        }
      ]
    },
    {
      label: '启动页',
      submenu: buildStartupTargetSubmenu()
    },
    { type: 'separator' },
    {
      label: '退出登录',
      click: () => {
        logoutAccount();
        showMainWindow();
      }
    },
    { type: 'separator' },
    {
      label: '关于',
      click: () => {
        const ver = app.getVersion();
        dialog.showMessageBox({
          type: 'info',
          title: '关于飞牛音乐',
          message: '飞牛音乐',
          detail: `版本：v${ver}\n\n基于 Electron 封装的飞牛音乐桌面客户端\n项目地址：https://github.com/wbc389561407/fnmusic-exe\n\n声明：个人自用项目，仅供学习交流。`,
          buttons: ['确定'],
          icon: path.join(__dirname, 'build', 'icon.ico')
        });
      }
    },
    { type: 'separator' },
    {
      label: '退出飞牛音乐',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);
}

// 显示并聚焦主窗口
function showMainWindow() {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  } else {
    createWindow();
  }
}

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: '文件',
      submenu: [isMac ? { role: 'close' } : { role: 'quit' }]
    },
    {
      label: '编辑',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: '视图',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: '设置',
      submenu: [
        {
          label: '切换服务器地址...',
          click: () => loadSetup()
        },
        {
          label: '清除已保存地址并重置',
          click: () => {
            try {
              fs.unlinkSync(getConfigPath());
            } catch {}
            loadSetup();
          }
        }
      ]
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ===== 启动时更新检测 =====
// 启动后调用 checkForUpdate（GitHub tags 接口），有更新则弹窗一次
// 注意：checkForUpdate 同时被 IPC 'check-update' 复用，供设置页显示更新链接（不弹窗）
// 启动弹窗与设置页链接互不干扰，避免重复弹窗
async function checkUpdateAndNotify() {
  try {
    const info = await checkForUpdate();
    if (!info || !info.hasUpdate) return;
    const result = await dialog.showMessageBox({
      type: 'info',
      title: '发现新版本',
      message: '发现新版本',
      detail: `当前版本：v${info.currentVersion}\n最新版本：${info.latestVersion}\n\n是否前往下载最新版本？`,
      buttons: ['前往下载', '稍后再说'],
      defaultId: 0,
      cancelId: 1
    });
    if (result.response === 0 && info.releaseUrl) {
      shell.openExternal(info.releaseUrl);
    }
  } catch (e) {
    console.log('[checkUpdateAndNotify] error:', e.message);
  }
}

// 单实例锁：防止重复启动多个程序实例
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  // 已有实例在运行，当前实例直接退出
  app.quit();
} else {
  app.on('second-instance', () => {
    // 用户再次双击图标尝试启动第二个实例：聚焦到已有窗口
    showMainWindow();
  });

  app.whenReady().then(() => {
    setupCookiePersistence();
    buildMenu();
    createTray();
    createWindow();
    // 启动后延迟 3 秒异步检测更新（不阻塞窗口显示），仅弹窗一次
    setTimeout(checkUpdateAndNotify, 3000);

    app.on('activate', () => {
      // macOS 点击 dock 图标时，若窗口被隐藏则重新显示
      showMainWindow();
    });
  });
}

// 退出前强制写入 cookie 存储，确保登录态落盘
let quitting = false;
app.on('will-quit', (event) => {
  if (quitting) return;
  quitting = true;
  event.preventDefault();
  let done = false;
  const finish = () => { if (!done) { done = true; app.exit(0); } };
  getSession().cookies.flushStore().finally(finish);
  // 兜底：最多等 1.5s 强制退出，避免 flushStore 卡住导致无法关闭
  setTimeout(finish, 1500);
});

// 窗口全部关闭后不退出应用，保留托盘（点击叉叉已 hide 到托盘，正常不会触发）
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // 不直接 quit，保持托盘运行；用户从托盘「退出」才真正结束
  }
});

// 真正退出时销毁托盘图标
app.on('before-quit', () => {
  isQuitting = true;
  if (tray) {
    tray.destroy();
    tray = null;
  }
});
