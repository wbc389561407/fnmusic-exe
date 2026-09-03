// setup.html 的脚本：收集服务器地址并通过 preload 暴露的 serverBridge 提交给主进程
// 放在外部文件，避免被页面 CSP 当作内联脚本拦截
(function () {
  function init() {
    var form = document.getElementById('form');
    var input = document.getElementById('url');
    var userEl = document.getElementById('username');
    var passEl = document.getElementById('password');
    var codeEl = document.getElementById('accesscode');
    var btn = document.getElementById('btn');
    var msg = document.getElementById('msg');

    if (!form) return;

    function setMsg(text, isError) {
      msg.textContent = text || '';
      msg.style.color = isError ? '#ff8a8a' : '#8aff9d';
    }

    // 若 preload 未成功注入桥接对象，给出可见提示
    if (!window.serverBridge || typeof window.serverBridge.submit !== 'function') {
      setMsg('初始化失败：桥接对象不可用，请重启应用', true);
      btn.disabled = true;
      return;
    }

    // 显示应用版本号（异步从主进程获取）
    var versionEl = document.getElementById('app-version');
    if (versionEl && typeof window.serverBridge.getVersion === 'function') {
      window.serverBridge.getVersion().then(function (v) {
        if (v) versionEl.textContent = 'v' + v;
      });
    }

    // 预填已保存的服务器地址与用户名（退出登录后保留输入历史，密码不回填）
    if (typeof window.serverBridge.getSavedInput === 'function') {
      window.serverBridge.getSavedInput().then(function (saved) {
        if (saved && saved.url && input) input.value = saved.url;
        if (saved && saved.username && userEl) userEl.value = saved.username;
      });
    }

    // 读取并展示登录失败提示（由主进程 login-fail 流程写入，读取即清空）
    if (typeof window.serverBridge.getLoginError === 'function') {
      window.serverBridge.getLoginError().then(function (errMsg) {
        if (errMsg) {
          setMsg(errMsg, true);
          // 访问码错误聚焦访问码输入框，其余聚焦密码输入框
          if (errMsg.indexOf('访问码') >= 0 && codeEl) codeEl.focus();
          else if (passEl) passEl.focus();
        }
      });
    }

    // 检查更新：调用 GitHub API 对比最新 release 版本，有更新则显示提示
    var updateTip = document.getElementById('update-tip');
    var updateLink = document.getElementById('update-link');
    if (updateTip && updateLink && typeof window.serverBridge.checkUpdate === 'function') {
      window.serverBridge.checkUpdate().then(function (info) {
        if (info && info.hasUpdate && info.latestVersion) {
          updateLink.textContent = '发现新版本 ' + info.latestVersion + '，点击前往下载';
          updateLink.href = info.releaseUrl || 'https://github.com/wbc389561407/fnmusic-exe/releases/latest';
          updateTip.style.display = 'block';
        }
      });
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var url = input.value.trim();
      if (!url) {
        setMsg('请输入服务器地址', true);
        input.focus();
        return;
      }
      var username = userEl ? userEl.value.trim() : '';
      var password = passEl ? passEl.value : '';
      var accessCode = codeEl ? codeEl.value.trim() : '';
      if (!username) {
        setMsg('请输入用户名', true);
        userEl.focus();
        return;
      }
      if (!password) {
        setMsg('请输入密码', true);
        passEl.focus();
        return;
      }
      btn.disabled = true;
      btn.textContent = '连接中...';
      setMsg('');
      try {
        var res = await window.serverBridge.submit({ url: url, username: username, password: password, accessCode: accessCode });
        if (!res || !res.ok) {
          setMsg((res && res.error) || '连接失败，请检查地址', true);
          btn.disabled = false;
          btn.textContent = '连接';
        } else {
          // 成功：主进程会加载远程页面跳转。加 30 秒兜底（含后台过访问码门禁最多 20s），若页面仍未跳转则恢复按钮
          setTimeout(function () {
            if (document.getElementById('btn')) {
              btn.disabled = false;
              btn.textContent = '连接';
              setMsg('连接超时，请检查服务器是否在线', true);
            }
          }, 30000);
        }
      } catch (err) {
        setMsg('发生错误：' + (err.message || err), true);
        btn.disabled = false;
        btn.textContent = '连接';
      }
    });

    // 仓库链接点击：交给主进程 setWindowOpenHandler → shell.openExternal 用系统浏览器打开
    var repoLink = document.getElementById('repo-link');
    if (repoLink) {
      repoLink.addEventListener('click', function (e) {
        e.preventDefault();
        window.open(repoLink.href);
      });
    }

    // 更新链接点击：同样用系统浏览器打开 Release 页面
    var updateLink = document.getElementById('update-link');
    if (updateLink) {
      updateLink.addEventListener('click', function (e) {
        e.preventDefault();
        window.open(updateLink.href);
      });
    }

    // 自定义关闭按钮：调用 IPC 最小化到托盘
    var closeBtn = document.getElementById('close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', function () {
        if (window.serverBridge && window.serverBridge.minimizeToTray) {
          window.serverBridge.minimizeToTray();
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
