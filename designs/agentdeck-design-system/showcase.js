/* AgentDeck 设计系统 · 展示页交互 */
(function () {
  var root = document.documentElement;
  var THEMES = ["codex", "terminal", "linear", "warm", "notion", "macos"];

  /* ---- 图标初始化 ---- */
  function drawIcons() {
    if (window.lucide && window.lucide.createIcons) {
      window.lucide.createIcons();
    }
  }

  /* ---- 主题切换 ---- */
  function setTheme(name) {
    if (THEMES.indexOf(name) === -1) name = "codex";
    root.setAttribute("data-theme", name);
    try { localStorage.setItem("agentdeck-ds-theme", name); } catch (e) {}
    document.querySelectorAll("[data-theme-btn]").forEach(function (b) {
      var active = b.getAttribute("data-theme-btn") === name;
      if (b.hasAttribute("aria-pressed")) b.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  document.querySelectorAll("[data-theme-btn]").forEach(function (b) {
    b.addEventListener("click", function () {
      setTheme(b.getAttribute("data-theme-btn"));
    });
  });

  // 优先级：URL ?t= 参数 > localStorage > 默认 codex（?t= 便于分享指定主题的链接）
  var param = null;
  try { param = new URLSearchParams(window.location.search).get("t"); } catch (e) {}
  var saved = null;
  try { saved = localStorage.getItem("agentdeck-ds-theme"); } catch (e) {}
  setTheme(param || saved || "codex");

  /* ---- 侧栏导航高亮（滚动同步 + 点击） ---- */
  var links = Array.prototype.slice.call(document.querySelectorAll(".sidenav a"));
  var sections = links
    .map(function (a) { return document.querySelector(a.getAttribute("href")); })
    .filter(Boolean);

  function onScroll() {
    var pos = window.scrollY + 120;
    var current = sections[0];
    sections.forEach(function (s) {
      if (s.offsetTop <= pos) current = s;
    });
    links.forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("href") === "#" + current.id);
    });
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  /* ---- 缩放切换（通用：每个 .wbscene 各自缩放其被预览元素）---- */
  document.querySelectorAll(".wbscene").forEach(function (scene) {
    var btns = scene.querySelectorAll(".wbscale-btn");
    var view = scene.querySelector(".wbscene__view");
    var target = view ? view.firstElementChild : null;
    btns.forEach(function (b) {
      b.addEventListener("click", function () {
        if (target) target.style.setProperty("--wb-zoom", b.getAttribute("data-scale"));
        btns.forEach(function (x) {
          x.setAttribute("aria-pressed", x === b ? "true" : "false");
        });
      });
    });
  });

  /* ---- 用量热力图填充（类 GitHub 提交热力）---- */
  document.querySelectorAll(".heatmap").forEach(function (hm) {
    var weeks = parseInt(hm.getAttribute("data-weeks") || "17", 10);
    var n = weeks * 7, s = "";
    for (var i = 0; i < n; i++) {
      // 确定性伪随机（避免依赖随机种子），让分布看起来自然
      var v = Math.sin((i + 1) * 12.9898) * 43758.5453;
      v = v - Math.floor(v);
      var lvl = v < 0.30 ? 0 : v < 0.52 ? 1 : v < 0.72 ? 2 : v < 0.88 ? 3 : 4;
      s += '<i class="hm hm-' + lvl + '"></i>';
    }
    hm.innerHTML = s;
  });

  drawIcons();
})();
