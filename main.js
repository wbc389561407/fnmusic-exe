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
// - 不带协议的纯 IP / 主机名 → 默认补 http://（端口探测在 resolveAccessUrl 中处理）
// - 带协议 / 带端口 → 完全尊重用户输入，不覆盖
// - 去首尾空格
function normalizeUrl(input) {
  let url = (input || '').trim();
  if (!url) return null;
  const hasProto = /^https?:\/\//i.test(url);
  if (!hasProto) url = 'http://' + url;
  try {
    return new URL(url).href;
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
// - 不带协议且不带端口的域名 / IP：先试 http 默认端口，不通再补 5666 端口（飞牛 NAS 默认端口）
// - 带协议 / 带端口：完全尊重用户输入，单地址验证
// - 验证时跟随重定向，重定向到新地址则用新地址访问
// 返回 { url, error, verified }，url 非空即可直接访问；verified 为内部已完成的验证结果（外层可复用，避免重复请求）
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

  const base = normalizeUrl(s);
  if (!base) return { url: null, error: '地址无效，请检查后重试' };

  // 构造候选地址列表（均补 /music/ 后缀）
  const first = ensureMusicSuffix(base);
  if (!first) return { url: null, error: '地址格式无效' };
  const candidates = [first];

  // 仅「不带协议且不带端口」的输入追加 5666 候选：先试默认端口，不通再补 5666
  const hasProto = /^https?:\/\//i.test(s);
  try {
    const u = new URL(base);
    if (!hasProto && !u.port) {
      const u2 = new URL(base);
      u2.port = '5666';
      const second = ensureMusicSuffix(u2.href);
      if (second && second !== first) candidates.push(second);
    }
  } catch {}

  // 顺序验证候选：第一个通过即用；验证跟随重定向，用重定向后的新地址
  let lastError = null;
  for (const cand of candidates) {
    console.log('[resolveAccessUrl] try ->', cand);
    const verified = await verifyFnMusic(cand);
    if (verified.ok) {
      const finalUrl = verified.finalUrl || cand;
      console.log('[resolveAccessUrl] address ->', finalUrl);
      return { url: finalUrl, error: null, verified };
    }
    lastError = verified.error;
    console.log('[resolveAccessUrl] failed:', cand, '-', verified.error);
  }
  return { url: null, error: lastError || '无法连接到服务器，请检查地址或网络' };
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
// 页面分类：gate=访问码门禁页，fnmusic=飞牛音乐服务页，other=其他
// 先判 gate：门禁页可能同时含服务名（如 <title>），必须优先命中
function classifyPage(bodyText) {
  const lower = (bodyText || '').toLowerCase();
  if (lower.indexOf('请输入访问码') >= 0 || lower.indexOf('请输入访问密码') >= 0) return 'gate';
  if (
    lower.indexOf('飞牛音乐') >= 0 ||
    lower.indexOf('fnmusic') >= 0 ||
    lower.indexOf('fnos-music') >= 0
  ) return 'fnmusic';
  return 'other';
}

// 在 loadURL 之前做一次 HTTP 请求探测，避免直接加载 502 / 非飞牛音乐页面导致卡死
// 返回：
// - 飞牛音乐页 → { ok: true, gate: false, finalUrl }（finalUrl 为重定向跟随后的最终地址）
// - 访问码门禁页 → { ok: true, gate: true, finalUrl }（过码由 passGateInBackground 后台完成）
// - 其他页面 → { ok: false, error }
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
            if (status >= 200 && status < 400) resolve({ ok: true, gate: false, finalUrl: currentUrl });
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

          // 只放行飞牛音乐页与访问码门禁页（门禁页由 passGateInBackground 后台过码）
          // finalUrl 为重定向跟随后的最终地址（重定向到新地址则用新地址访问）
          const kind = classifyPage(bodyText);
          if (kind === 'fnmusic') {
            resolve({ ok: true, gate: false, finalUrl: currentUrl });
            return;
          }
          if (kind === 'gate') {
            resolve({ ok: true, gate: true, finalUrl: currentUrl });
            return;
          }
          if (status >= 200 && status < 400) {
            resolve({ ok: false, error: '该地址不是飞牛音乐服务，请检查地址是否正确' });
          } else {
            resolve({ ok: false, error: '服务器响应异常（' + status + '），无法确认是飞牛音乐服务' });
          }
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

// 后台过访问码门禁：用隐藏 BrowserWindow 加载门禁页并自动填码提交
// - 与主窗口共用 PARTITION，过码 cookie 自动共享，主窗口 loadURL 直达音乐/登录页（门禁页不显示）
// - DOM 层模拟真实输入（input/change 事件 + 点击确定），兼容 form / fetch / XHR 各种提交实现
// 返回：'passed'（通过）/ 'wrong-code'（访问码错误或超时）/ 'no-code'（未配置访问码）
function passGateInBackground(url, accessCode) {
  return new Promise((resolve) => {
    const code = (typeof accessCode === 'string' && accessCode.trim())
      ? accessCode.trim()
      : (readConfig().accessCode || '').trim();
    if (!code) {
      resolve('no-code');
      return;
    }

    let settled = false;
    let pollTimer = null;
    let gateWin = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (pollTimer) clearInterval(pollTimer);
      if (gateWin && !gateWin.isDestroyed()) gateWin.destroy();
      console.log('[passGateInBackground] result:', result);
      resolve(result);
    };
    // 总超时 20 秒：提交后仍停留在门禁页 = 访问码错误
    setTimeout(() => finish('wrong-code'), 20000);

    gateWin = new BrowserWindow({
      show: false,
      webPreferences: {
        partition: PARTITION,
        contextIsolation: true,
        nodeIntegration: false,
        // 隐藏窗口不被后台节流，保证看门狗定时器正常跑
        backgroundThrottling: false
      }
    });

    // 页面状态检查：标题已渲染且不再是门禁 → 已通过
    function checkPassed() {
      if (settled || !gateWin || gateWin.isDestroyed()) return;
      gateWin.webContents.executeJavaScript(`
        (function(){
          var t = '';
          var h = document.querySelector('#page-title') || document.querySelector('h1');
          if (h) t = (h.textContent || '').trim();
          if (!t) t = (document.title || '').trim();
          if (!t) return { known: false };
          return { known: true, gate: t.indexOf('访问码') !== -1 || t.indexOf('访问密码') !== -1 };
        })();
      `).then((st) => {
        if (settled) return;
        if (st && st.known && !st.gate) finish('passed');
      }).catch(() => {});
    }

    // 看门狗：命中门禁页自动填码并点击「确定」（最多 2 次，间隔 4 秒）
    gateWin.webContents.on('dom-ready', () => {
      gateWin.webContents.executeJavaScript(`
        (function(){
          if (window.__fnGateWatchdog) return;
          window.__fnGateWatchdog = true;
          var CODE = ${JSON.stringify(code)};
          var submits = 0, lastAt = 0;
          function isGate(){
            var h = document.querySelector('#page-title') || document.querySelector('h1');
            if (!h) return false;
            var t = (h.textContent || '').trim();
            return t.indexOf('访问码') !== -1 || t.indexOf('访问密码') !== -1;
          }
          function submitGate(){
            var inputs = document.querySelectorAll('input');
            var input = null;
            for (var i = 0; i < inputs.length; i++) {
              var el = inputs[i];
              var ty = (el.type || 'text').toLowerCase();
              if (ty !== 'password' && ty !== 'text') continue;
              var r = el.getBoundingClientRect();
              if (r.width <= 0 && r.height <= 0) continue;
              input = el;
              if (ty === 'password') break;
            }
            if (!input) return false;
            var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
            setter.call(input, CODE);
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            setTimeout(function(){
              var btn = document.querySelector('button[type="submit"]') || document.querySelector('button');
              if (btn && !btn.disabled) btn.click();
            }, 350);
            return true;
          }
          setInterval(function(){
            if (!isGate()) return;
            if (submits >= 2) return;
            var now = Date.now();
            if (lastAt && now - lastAt < 4000) return;
            if (submitGate()) { submits++; lastAt = now; }
          }, 500);
        })();
      `).catch(() => {});
    });

    pollTimer = setInterval(checkPassed, 800);
    gateWin.loadURL(url, { userAgent: UA }).catch(() => finish('wrong-code'));
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
// 访问码看门狗注入计数：单次连接周期内累计上限 2 次，用尽仍见门禁页 = 访问码错误
// （防无限循环）；重新连接或到达正常页面时清零
let accessCodeSubmits = 0;

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

// 按当前窗口内容区宽度自适应页面缩放：以 1280 宽为 100%，吸附到浏览器固定缩放档位
// 窗口拉大 → 页面等比放大，窗口拉小 → 等比缩小
const ZOOM_BASE_WIDTH = 1280;
function applyAdaptiveZoom() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const [contentW] = mainWindow.getContentSize();
  mainWindow.webContents.setZoomFactor(snapToZoomStep(contentW / ZOOM_BASE_WIDTH));
}

// 切换窗口档位：持久化配置并立即应用尺寸与缩放
function applyWindowPreset(preset) {
  if (!WIN_PRESETS[preset]) return;
  const cfg = readConfig();
  cfg.windowPreset = preset;
  writeConfig(cfg);
  if (mainWindow && !mainWindow.isDestroyed()) {
    const { winWidth, winHeight } = calcWinSizeAndZoom(preset);
    mainWindow.setSize(winWidth, winHeight);
    applyAdaptiveZoom();
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

// 访问码自动填入：服务器开启访问码保护时，先加载到「请输入访问码」页面
// 注入常驻看门狗持续轮询（覆盖标题/表单晚渲染、SPA 路由切换），命中访问码页即填码并点击「确定」，
// 通过后服务器自动跳转到登录页/音乐页，后续自动登录、启动页、自动播放流程照常触发
// - 输入框：密码框优先，其次可见的文本类输入框（排除隐藏字段）
// - 填码后延迟 350ms 再点击（等框架同步状态、按钮解禁）；提交后 4s 未跳转自动重试
// - 单页面最多提交 2 次；整周期累计注入上限 4 次，防访问码错误时无限循环
function tryAutoAccessCode() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  let currentUrl = '';
  try { currentUrl = mainWindow.webContents.getURL(); } catch {}
  if (!/^https?:/i.test(currentUrl)) return; // 仅远程页面处理

  const cfg = readConfig();
  const code = (cfg.accessCode || '').trim();
  if (!code) return; // 未配置访问码则不处理

  const allowed = accessCodeSubmits < 2;
  const codeJson = JSON.stringify(code);
  mainWindow.webContents.executeJavaScript(`
    (function(){
      if (window.__fnAccessCodeWatchdog) return 'started';
      // 页面明确不是访问码页（标题已渲染且不匹配）：不装看门狗，并通知主进程清零计数
      var h0 = document.querySelector('#page-title') || document.querySelector('h1');
      if (h0) {
        var t0 = (h0.textContent || '').trim();
        if (t0 && t0.indexOf('访问码') === -1 && t0.indexOf('访问密码') === -1) return 'skip';
      }
      // 注入配额用尽（此前已提交多次仍未通过）：确认仍停留在门禁页 = 访问码错误
      if (!${allowed}) {
        (function confirmGate(tries){
          tries++;
          var h = document.querySelector('#page-title') || document.querySelector('h1');
          var t = h ? (h.textContent || '').trim() : '';
          if (!t) { if (tries < 16) setTimeout(function(){ confirmGate(tries); }, 300); return; }
          if (t.indexOf('访问码') !== -1 || t.indexOf('访问密码') !== -1) notifyFail();
        })(0);
        return 'blocked';
      }
      window.__fnAccessCodeWatchdog = true;
      var OPT = { code: ${codeJson} };
      var MAX_SUBMITS = 2;
      var RETRY_AFTER_MS = 4000;
      var submits = 0;
      var lastSubmitAt = 0;

      function isGatePage(){
        var h1 = document.querySelector('#page-title') || document.querySelector('h1');
        if (!h1) return false;
        var t = (h1.textContent || '').trim();
        return t.indexOf('访问码') !== -1 || t.indexOf('访问密码') !== -1;
      }
      // 访问码错误：通知主进程跳回设置页报错（同文档只通知一次）
      function notifyFail(){
        if (window.__fnAccessCodeFailed) return;
        window.__fnAccessCodeFailed = true;
        try {
          if (window.serverBridge && typeof window.serverBridge.notifyAccessCodeFail === 'function') {
            window.serverBridge.notifyAccessCodeFail();
          }
        } catch (e) {}
      }
      function findInput(){
        var inputs = document.querySelectorAll('input');
        var best = null;
        for (var i = 0; i < inputs.length; i++) {
          var el = inputs[i];
          var ty = (el.type || 'text').toLowerCase();
          if (ty === 'hidden' || ty === 'checkbox' || ty === 'radio' || ty === 'file' || ty === 'submit' || ty === 'button') continue;
          var rect = el.getBoundingClientRect();
          if (rect.width <= 0 && rect.height <= 0) continue; // 不可见（隐藏字段）跳过
          if (ty === 'password') return el;
          if (!best) best = el;
        }
        return best;
      }
      function findButton(){
        var btns = document.querySelectorAll('button, input[type="submit"]');
        var fallback = null;
        for (var i = 0; i < btns.length; i++) {
          var el = btns[i];
          if (el.disabled) continue;
          var rect = el.getBoundingClientRect();
          if (rect.width <= 0 && rect.height <= 0) continue;
          if (el.type === 'submit') return el;
          if (!fallback) fallback = el;
        }
        return fallback;
      }
      function submitGate(){
        var input = findInput();
        if (!input) return false;
        var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, OPT.code);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        // 延迟点击：等框架把输入同步进状态（按钮可能由禁用转为可用）
        setTimeout(function(){
          var b = findButton();
          if (b && !b.disabled) b.click();
          else if (input.form && input.form.requestSubmit) input.form.requestSubmit();
        }, 350);
        return true;
      }
      // 注入时立即先提交一次（dom-ready 阶段执行，门禁页几乎不可见）
      if (isGatePage() && submitGate()) {
        submits++;
        lastSubmitAt = Date.now();
      }
      var timer = setInterval(function(){
        if (submits >= MAX_SUBMITS) {
          // 提交次数用尽且等待超时仍停留在门禁页：访问码错误 → 跳回设置页报错
          if (isGatePage() && lastSubmitAt && Date.now() - lastSubmitAt >= RETRY_AFTER_MS) {
            clearInterval(timer);
            notifyFail();
          }
          return;
        }
        if (!isGatePage()) return;
        var now = Date.now();
        if (lastSubmitAt && now - lastSubmitAt < RETRY_AFTER_MS) return; // 等页面跳转
        if (submitGate()) {
          submits++;
          lastSubmitAt = Date.now();
        }
      }, 600);
      return 'watchdog';
    })();
  `).then((status) => {
    if (status === 'watchdog') accessCodeSubmits++;
    else if (status === 'skip') accessCodeSubmits = 0;
  }).catch(() => {});
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

  // 任务栏缩略图工具栏按钮（悬停任务栏图标时出现）：上一首 / 播放暂停 / 下一首
  // 手工编码 16x16 BGRA 位图（nativeImage 不支持 SVG dataURL），图形 10px 高、居中
  const TB_SHAPES = {
    // |◀ 上一首
    prev: ['................','................','................','...xx.......x...','...xx......xx...','...xx.....xxx...','...xx....xxxx...','...xx...xxxxx...','...xx...xxxxx...','...xx....xxxx...','...xx.....xxx...','...xx......xx...','...xx.......x...','................','................','................'],
    // ▶| 下一首
    next: ['................','................','................','...x.......xx...','...xx......xx...','...xxx.....xx...','...xxxx....xx...','...xxxxx...xx...','...xxxxx...xx...','...xxxx....xx...','...xxx.....xx...','...xx......xx...','...x.......xx...','................','................','................'],
    // ▶ 播放
    play: ['................','................','................','.....x..........','.....xx.........','.....xxx........','.....xxxx.......','.....xxxxx......','.....xxxxx......','.....xxxx.......','.....xxx........','.....xx.........','.....x..........','................','................','................'],
    // ⏸ 暂停
    pause: ['................','................','................','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','.....xx..xx.....','................','................','................'],
  };
  function makeTbIcon(kind) {
    const rows = TB_SHAPES[kind];
    const w = 16, h = rows.length;
    const buf = Buffer.alloc(w * h * 4, 0); // 全透明底
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < rows[y].length; x++) {
        if (rows[y][x] === 'x') {
          const i = (y * w + x) * 4;
          buf[i] = buf[i + 1] = buf[i + 2] = buf[i + 3] = 255; // 不透明白
        }
      }
    }
    return nativeImage.createFromBitmap(buf, { width: w, height: h });
  }
  const tbIconCache = {};
  function getTbIcon(kind) {
    if (!tbIconCache[kind]) tbIconCache[kind] = makeTbIcon(kind);
    return tbIconCache[kind];
  }
  function updateThumbar(playing) {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.setThumbarButtons([
      {
        tooltip: '上一首',
        icon: getTbIcon('prev'),
        click: () => clickPlayerBtn(['上一首', '上一步', '上一曲', 'prev', 'previous'])
      },
      {
        tooltip: playing ? '暂停' : '播放',
        icon: getTbIcon(playing ? 'pause' : 'play'),
        click: () => clickPlayerBtn(playing ? ['暂停', 'pause'] : ['播放', 'play'])
      },
      {
        tooltip: '下一首',
        icon: getTbIcon('next'),
        click: () => clickPlayerBtn(['下一首', '下一步', '下一曲', 'next'])
      }
    ]);
  }
  // 在页面里点击匹配 aria-label / title / class 的播放器按钮
  function clickPlayerBtn(labels) {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    const arr = JSON.stringify(labels);
    mainWindow.webContents.executeJavaScript(`
      (function(){
        var labels = ${arr};
        // 先按 aria-label / title 精确匹配
        for (var i = 0; i < labels.length; i++) {
          var b = document.querySelector('button[aria-label="' + labels[i] + '"], [role="button"][aria-label="' + labels[i] + '"]');
          if (b) { b.click(); return true; }
        }
        // 退而求其次：audio 元素直接控制（播放/暂停兜底）
        var a = document.querySelector('audio');
        if (a && labels.indexOf('暂停') !== -1 && !a.paused) { a.pause(); return true; }
        if (a && labels.indexOf('播放') !== -1 && a.paused) { a.play(); return true; }
        return false;
      })();
    `).catch(() => {});
  }
  // 轮询页面播放状态，同步任务栏缩略图按钮（播放/暂停图标切换）
  let lastPlaying = null;
  function pollPlayingState() {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (document.querySelector('button[aria-label="暂停"]')) return true;
        var a = document.querySelector('audio');
        return a ? !a.paused : false;
      })();
    `).then(playing => {
      if (playing !== lastPlaying) {
        lastPlaying = playing;
        updateThumbar(playing);
      }
    }).catch(() => {});
  }
  updateThumbar(false);
  setInterval(pollPlayingState, 1500);
  mainWindow = new BrowserWindow({  width: winWidth,
    height: winHeight,
    minWidth: 900,
    minHeight: 600,
    title: '飞牛音乐',
    backgroundColor: '#00000000',
    show: false,
    autoHideMenuBar: true,
    // 无边框客户端外观：隐藏标题栏，叉叉用自定义注入按钮（原生 overlay 无法控制 hover 底色）
    frame: false,
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
  // 窗口隐藏到托盘再恢复后 Windows 会清掉缩略图工具栏：重新显示时强制重设
  // （lastPlaying 不变时轮询不会触发重设）
  mainWindow.on('show', () => {
    lastPlaying = null;
    pollPlayingState();
  });
  mainWindow.on('restore', () => {
    lastPlaying = null;
    pollPlayingState();
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow.setSize(winWidth, winHeight);
    applyAdaptiveZoom();
    mainWindow.show();
  });

  // 窗口尺寸变化时按宽度自适应页面缩放（防抖，避免拖动过程频繁触发）
  let resizeTimer = null;
  mainWindow.on('resize', () => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(applyAdaptiveZoom, 150);
  });

  // 远程页面 DOM 就绪即注入（早于 did-finish-load 与 React 渲染，避免先显示再隐藏的闪烁）
  mainWindow.webContents.on('dom-ready', () => {
    const currentUrl = mainWindow.webContents.getURL();
    if (!/^https?:/i.test(currentUrl)) return; // 仅对远程服务器页面注入
    // 置顶状态持久：SPA 不整页刷新时注入脚本不重复执行（有 id 守卫），先同步状态
    mainWindow.webContents.send('pin-changed', mainWindow.isAlwaysOnTop());
    mainWindow.webContents.insertCSS(`
      body { -webkit-app-region: no-drag; }
      /* 隐藏页面自带的「设置/用户」悬浮胶囊（功能已移入标题栏）：
         纯 CSS :has() 渲染首帧即生效，无需等 JS/Observer，避免先显示后隐藏的闪烁 */
      div:has(> div > button[aria-label="设置"]):has(> * > button[aria-label="打开用户菜单"]) { visibility: hidden !important; }
      .__fn-dragbar {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 40px !important;
        -webkit-app-region: drag !important;
        z-index: 2147483647 !important;
        background: transparent !important;
        pointer-events: auto !important;
      }
      .__fn-close-btn, .__fn-min-btn, .__fn-max-btn, .__fn-pin-btn, .__fn-set-btn, .__fn-user-btn {
        position: fixed !important;
        top: 0 !important;
        width: 28px !important;
        height: 40px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        -webkit-app-region: no-drag !important;
        z-index: 2147483648 !important;
        cursor: pointer !important;
        color: #8a8a96 !important;
        background: transparent !important;
        border: none !important;
        border-radius: 6px !important;
        transition: color 0.15s !important;
        opacity: 0.75 !important;
      }
      .__fn-close-btn { right: 8px !important; }
      .__fn-min-btn { right: 72px !important; }
      .__fn-max-btn { right: 40px !important; }
      .__fn-pin-btn { right: 104px !important; }
      .__fn-set-btn { right: 168px !important; }
      .__fn-user-btn { right: 136px !important; }
      .__fn-close-btn:hover, .__fn-min-btn:hover, .__fn-max-btn:hover, .__fn-pin-btn:hover, .__fn-set-btn:hover, .__fn-user-btn:hover {
        color: #e8e8f0 !important;
        background: rgba(255, 255, 255, 0.08) !important;
        opacity: 1 !important;
      }
      .__fn-pin-btn.__fn-pinned { color: #6ab0ff !important; opacity: 1 !important; }
      .__fn-close-btn svg, .__fn-min-btn svg, .__fn-max-btn svg, .__fn-pin-btn svg, .__fn-set-btn svg, .__fn-user-btn svg {
        width: 13px !important;
        height: 13px !important;
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
        // 置顶按钮（右上角，关闭按钮左侧）
        var pin = document.createElement('div');
        pin.id = '__fn-pin-btn';
        pin.className = '__fn-pin-btn';
        pin.title = '置顶';
        pin.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l6 6-4 1v5l-2 2-2-2v-5l-4-1z"/></svg>';
        pin.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.togglePin) window.serverBridge.togglePin();
        });
        document.documentElement.appendChild(pin);
        if (window.serverBridge && window.serverBridge.onPinChanged) {
          window.serverBridge.onPinChanged(function(pinned){
            pin.classList.toggle('__fn-pinned', !!pinned);
          });
        }
        // 最大化/还原按钮
        var mx = document.createElement('div');
        mx.id = '__fn-max-btn';
        mx.className = '__fn-max-btn';
        mx.title = '最大化';
        var svgMax = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="5" y="5" width="14" height="14" rx="2"/></svg>';
        var svgRestore = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="8" width="13" height="13" rx="2"/><path d="M8 8V5a2 2 0 0 1 2-2h11v11a2 2 0 0 1-2 2h-3"/></svg>';
        mx.innerHTML = svgMax;
        mx.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.toggleMaximize) window.serverBridge.toggleMaximize();
        });
        document.documentElement.appendChild(mx);
        if (window.serverBridge && window.serverBridge.onMaximizedChanged) {
          window.serverBridge.onMaximizedChanged(function(m){
            mx.innerHTML = m ? svgRestore : svgMax;
            mx.title = m ? '还原' : '最大化';
          });
        }
        // 最小化按钮
        var mn = document.createElement('div');
        mn.id = '__fn-min-btn';
        mn.className = '__fn-min-btn';
        mn.title = '最小化';
        mn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>';
        mn.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.minimizeWindow) window.serverBridge.minimizeWindow();
        });
        document.documentElement.appendChild(mn);
        // 设置按钮（转点击页面原「设置」按钮，原悬浮胶囊已隐藏）
        var st = document.createElement('div');
        st.id = '__fn-set-btn';
        st.className = '__fn-set-btn';
        st.title = '设置';
        st.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M11.998 8.5a3.5 3.5 0 110 7 3.5 3.5 0 010-7zm0 2a1.5 1.5 0 10.001 3 1.5 1.5 0 000-3z"/><path fill-rule="evenodd" clip-rule="evenodd" d="M15.64 2.216c1.3 0 2.503.688 3.162 1.807L22.4 10.14a3.668 3.668 0 010 3.718l-3.598 6.117a3.668 3.668 0 01-3.161 1.807H8.359c-1.3 0-2.503-.688-3.161-1.807L1.6 13.858a3.668 3.668 0 010-3.718l3.598-6.117a3.669 3.669 0 013.16-1.807h7.283zm-7.281 2c-.59 0-1.137.312-1.437.821l-3.598 6.117a1.667 1.667 0 000 1.69l3.598 6.117c.3.509.846.821 1.437.821h7.282c.59 0 1.137-.312 1.436-.821l3.6-6.117a1.667 1.667 0 000-1.69l-3.6-6.117a1.667 1.667 0 00-1.436-.821H8.359z"/></svg>';
        st.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.clickPageButton) window.serverBridge.clickPageButton(['设置']);
        });
        document.documentElement.appendChild(st);
        // 用户菜单按钮（转点击页面原头像按钮）
        var ub = document.createElement('div');
        ub.id = '__fn-user-btn';
        ub.className = '__fn-user-btn';
        ub.title = '用户菜单';
        ub.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5"/></svg>';
        ub.addEventListener('click', function(){
          if (window.serverBridge && window.serverBridge.clickPageButton) window.serverBridge.clickPageButton(['打开用户菜单']);
        });
        document.documentElement.appendChild(ub);
        // 隐藏页面自带的「设置/用户」悬浮胶囊（功能已移入标题栏）
        // 用 visibility:hidden 保留坐标，点击标题栏按钮触发原按钮时弹出菜单位置不变
        function hideDock(){
          var s = document.querySelector('button[aria-label="设置"]');
          var u = document.querySelector('button[aria-label="打开用户菜单"]');
          if (!s || !u) return;
          var p = s.parentElement;
          while (p && !p.contains(u)) p = p.parentElement;
          if (p && p !== document.body && !p.__fnDockHidden) {
            p.__fnDockHidden = true;
            p.style.setProperty('visibility', 'hidden', 'important');
          }
        }
        hideDock();
        if (!window.__fnHideDockObs) {
          window.__fnHideDockObs = true;
          var ht = null;
          new MutationObserver(function(){
            if (ht) clearTimeout(ht);
            ht = setTimeout(hideDock, 300);
          }).observe(document.body, { childList: true, subtree: true });
        }
        // 歌曲列表最后几首会被底部悬浮播放栏遮住：找 data-index 最大的行注入 padding-bottom 100px
        function fixLayout(){
          // 给最后一首歌（data-index 最大）注入 padding-bottom，滑过播放栏
          var rows = document.querySelectorAll('[data-index]');
          var last = null, maxIdx = -1;
          for (var i = 0; i < rows.length; i++) {
            var idx = parseInt(rows[i].getAttribute('data-index'), 10);
            if (!isNaN(idx) && idx > maxIdx) { maxIdx = idx; last = rows[i]; }
          }
          if (last && !last.__fnPadded) {
            last.__fnPadded = true;
            last.style.setProperty('padding-bottom', '100px', 'important');
          }
        }
        fixLayout();
        if (!window.__fnShrinkObs) {
          window.__fnShrinkObs = true;
          var t = null;
          new MutationObserver(function(){
            if (t) clearTimeout(t);
            t = setTimeout(fixLayout, 300);
          }).observe(document.body, { childList: true, subtree: true });
        }
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

    // 底部播放栏贴底：测量播放栏底边与窗口底部的实际空隙，用 translateY 精确下移补齐
    // 关键：getBoundingClientRect() 含 transform，必须先减去上次注入的位移得到「原始底边」，
    // 否则目标值被自己的位移污染，窗口变化时会反复重算 → 与页面过渡动画互相撕扯（来回蹦跶）
    // FINE_TUNE_PX：手动微调，正数 = 在自动贴底基础上再往下压，负数 = 往上收
    mainWindow.webContents.executeJavaScript(`
      (function(){
        if (window.__fnPlayerBottomStarted) return;
        window.__fnPlayerBottomStarted = true;
        var FINE_TUNE_PX = 0;
        function stickBottom(){
          var p = document.querySelector('div.music-player-glass[data-music-queue-interaction="true"]');
          if (!p || !p.isConnected) return;
          var applied = p.__fnAppliedY || 0;
          var rawBottom = p.getBoundingClientRect().bottom - applied;
          var gap = window.innerHeight - rawBottom + FINE_TUNE_PX;
          gap = Math.round(gap * 10) / 10;
          // 目标没变不重写 style，避免反复触发页面布局过渡动画
          if (Math.abs(gap - applied) < 0.5) return;
          p.__fnAppliedY = gap;
          p.style.setProperty('transform', 'translateY(' + gap + 'px)', 'important');
        }
        stickBottom();
        setTimeout(stickBottom, 300);
        setTimeout(stickBottom, 1000);
        // 窗口缩放（含 zoom 自适应）后防抖校准：等页面重排/动画稳定再测，避开中间态
        var rt = null;
        window.addEventListener('resize', function(){
          if (rt) clearTimeout(rt);
          rt = setTimeout(stickBottom, 200);
        });
        // 兜底周期校准（幂等：目标不变时不会重写）
        setInterval(stickBottom, 1000);
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

    // 访问码自动填入（通过访问码门禁后才能进入登录/主页面）
    tryAutoAccessCode();
    // 切换到配置的启动页 + 自动播放 + 自动登录
    tryClickStartupNav();
    tryAutoPlay();
    tryAutoLogin();
  });

  // SPA 路由切换（如 cookie 失效跳到 /login，或自动登录后跳回主页）
  // did-finish-load 不会触发，需监听 did-navigate-in-page
  mainWindow.webContents.on('did-navigate-in-page', () => {
    tryAutoAccessCode();
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
    resolveAccessUrl(cfg.serverInput).then(async ({ url, error, verified }) => {
      if (!url) {
        console.log('[startup] resolve failed:', error);
        pendingLoginError = error || '服务器地址解析失败，请重新输入';
        loadSetup();
        return;
      }
      // 启动时同样验证是否为飞牛音乐，避免白屏 / 502 卡死（resolve 内已验证则复用结果）
      const v = verified || await verifyFnMusic(url);
      if (!v.ok) {
        console.log('[startup] verify failed:', v.error);
        pendingLoginError = v.error;
        loadSetup();
        return;
      }
      // 重定向到新地址则用新地址访问
      const finalUrl = v.finalUrl || url;
      // 访问码门禁：隐藏窗口后台过码，主窗口不显示门禁页
      if (v.gate) {
        const r = await passGateInBackground(finalUrl);
        if (r !== 'passed') {
          pendingLoginError = r === 'no-code'
            ? '服务器开启了访问码保护，请在访问密码栏填写后重试'
            : '访问码错误，请检查访问密码后重新连接';
          loadSetup();
          return;
        }
      }
      applyServerUrl(finalUrl);
    });
  } else {
    loadSetup();
  }

  // 叉叉 = 最小化到托盘；只有 isQuitting（托盘右键退出）才真正关闭
  // 最大化状态变化时通知渲染层切换按钮图标
  mainWindow.on('maximize', () => {
    if (!mainWindow.isDestroyed()) mainWindow.webContents.send('maximized-changed', true);
  });
  mainWindow.on('unmaximize', () => {
    if (!mainWindow.isDestroyed()) mainWindow.webContents.send('maximized-changed', false);
  });

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
  accessCodeSubmits = 0; // 新的连接周期：重置访问码提交计数
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
  return { url: cfg.serverInput || '', username: cfg.username || '', accessCode: cfg.accessCode || '' };
});

// 访问码错误（多次提交后仍停留在访问码页）：跳回设置页并在访问码输入框处报错
ipcMain.handle('access-code-fail', () => {
  pendingLoginError = '访问码错误，请检查访问密码后重新连接';
  loadSetup();
  return true;
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
  const accessCode = (payload && typeof payload === 'object' ? (payload.accessCode || '').trim() : '');

  const { url, error, verified } = await resolveAccessUrl(input);
  if (!url) {
    return { ok: false, error };
  }

  // 在 loadURL 之前先验证：避免直接加载 502 / 非飞牛音乐页面导致卡死（resolve 内已验证则复用结果）
  const v = verified || await verifyFnMusic(url);
  if (!v.ok) {
    console.log('[submit-server] verify failed:', v.error);
    return { ok: false, error: v.error };
  }
  // 重定向到新地址则用新地址访问
  const finalUrl = v.finalUrl || url;
  // 访问码门禁：隐藏窗口后台过码（访问码传用户刚输入的值，此时配置尚未持久化）
  if (v.gate) {
    const r = await passGateInBackground(finalUrl, accessCode);
    if (r !== 'passed') {
      return {
        ok: false,
        error: r === 'no-code'
          ? '服务器开启了访问码保护，请在访问密码栏填写后重试'
          : '访问码错误，请检查访问密码后重新连接'
      };
    }
  }

  // 持久化用户原始输入与登录凭据，下次启动重新解析
  const cfg = readConfig();
  cfg.serverInput = input;
  if (username) cfg.username = username;
  if (password) cfg.password = password;
  // 访问码选填：填了保存，清空则移除
  if (accessCode) cfg.accessCode = accessCode;
  else delete cfg.accessCode;
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

// 窗口最小化（任务栏）
ipcMain.handle('window-minimize', () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.minimize();
  return true;
});

// 最大化 / 还原切换
ipcMain.handle('toggle-maximize', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  else mainWindow.maximize();
  return mainWindow.isMaximized();
});

// 置顶切换
ipcMain.handle('toggle-pin', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  const pinned = !mainWindow.isAlwaysOnTop();
  mainWindow.setAlwaysOnTop(pinned);
  return pinned;
});

// 标题栏「设置/用户」按钮：转点击页面内对应按钮（原悬浮胶囊已隐藏）
ipcMain.handle('page-click', (_event, labels) => {
  if (!mainWindow || mainWindow.isDestroyed() || !Array.isArray(labels)) return false;
  const arr = JSON.stringify(labels);
  return mainWindow.webContents.executeJavaScript(`
    (function(){
      var labels = ${arr};
      for (var i = 0; i < labels.length; i++) {
        var b = document.querySelector('button[aria-label="' + labels[i] + '"], button[title="' + labels[i] + '"], [role="button"][aria-label="' + labels[i] + '"]');
        if (b) { b.click(); return true; }
      }
      return false;
    })();
  `).catch(() => false);
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
