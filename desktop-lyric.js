// desktop-lyric.js: 桌面歌词窗口的脚本
// 通过 preload 暴露的 desktopLyricBridge 接收歌词更新、控制播放
(function () {
  var container = document.getElementById('container');
  var content = document.getElementById('lyric-content');
  var btnLock = document.getElementById('btn-lock');
  var btnClose = document.getElementById('btn-close');
  var btnPrev = document.getElementById('btn-prev');
  var btnPlay = document.getElementById('btn-play');
  var btnNext = document.getElementById('btn-next');

  var locked = false;

  function render(data) {
    // data: { current: string, prev: string, next: string, playing: bool }
    if (!data) return;
    var html = '';
    if (data.prev) {
      html += '<div class="lyric-line other">' + escapeHtml(data.prev) + '</div>';
    }
    if (data.current) {
      html += '<div class="lyric-line current">' + escapeHtml(data.current) + '</div>';
    } else {
      html += '<div class="lyric-line empty">暂无歌词</div>';
    }
    if (data.next) {
      html += '<div class="lyric-line other">' + escapeHtml(data.next) + '</div>';
    }
    if (!data.prev && !data.current && !data.next) {
      html = '<div class="lyric-line empty">暂无歌词</div>';
    }
    content.innerHTML = html;
    // 更新播放/暂停图标
    if (btnPlay) {
      if (data.playing) {
        btnPlay.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="5" width="4" height="14"/><rect x="14" y="5" width="4" height="14"/></svg>';
        btnPlay.title = '暂停';
      } else {
        btnPlay.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
        btnPlay.title = '播放';
      }
    }
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // 锁定/解锁拖动
  btnLock.addEventListener('click', function () {
    locked = !locked;
    container.classList.toggle('locked', locked);
    btnLock.style.color = locked ? '#6ab0ff' : '#ccc';
  });

  btnClose.addEventListener('click', function () {
    if (window.desktopLyricBridge && window.desktopLyricBridge.close) {
      window.desktopLyricBridge.close();
    }
  });

  btnPrev.addEventListener('click', function () {
    if (window.desktopLyricBridge && window.desktopLyricBridge.control) {
      window.desktopLyricBridge.control('prev');
    }
  });

  btnPlay.addEventListener('click', function () {
    if (window.desktopLyricBridge && window.desktopLyricBridge.control) {
      window.desktopLyricBridge.control('play-pause');
    }
  });

  btnNext.addEventListener('click', function () {
    if (window.desktopLyricBridge && window.desktopLyricBridge.control) {
      window.desktopLyricBridge.control('next');
    }
  });

  // 接收歌词更新
  if (window.desktopLyricBridge && window.desktopLyricBridge.onUpdate) {
    window.desktopLyricBridge.onUpdate(function (data) {
      render(data);
    });
  }

  // 请求一次初始歌词
  if (window.desktopLyricBridge && window.desktopLyricBridge.requestLyrics) {
    window.desktopLyricBridge.requestLyrics();
  }
})();
