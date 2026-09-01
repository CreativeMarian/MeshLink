// M1-1 Release GUI 修复 —— JS 层错误契约自动测试（用户规格二/八/十二）。
//
// 直接加载真实 `apps/meshlink-ui/ui/app.js`（带最小 DOM / Tauri invoke 桩），
// 断言：
//  1. `formatError` 对所有拒绝形态（string / Error / {error} / {code} / {} / null / undefined）
//     都返回**非 undefined** 的可读文本，最终兜底 `ERROR_UNKNOWN`（用户规格二）；
//  2. `send()` 把 invoke 拒绝（字符串等）归一化为 {code,message}，message 永不为 undefined；
//  3. `showError` 在无 `.error-text` 子元素的空横幅上不抛错、不留下空红色区（用户规格八）；
//  4. `toast` 替代 window.alert（用户规格九）。
//
// 运行：`node apps/meshlink-ui/tests/ui_error_contract.test.js`
// 通过时输出 `UI ERROR CONTRACT TESTS PASS` 并以 exit 0 结束。

"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const APP_JS = path.join(__dirname, "..", "ui", "app.js");
const source = fs.readFileSync(APP_JS, "utf8");

/* ---------------- 最小 DOM 桩 ---------------- */

function makeClassList() {
  const set = new Set();
  return {
    add: (c) => set.add(c),
    remove: (c) => set.delete(c),
    toggle: (c, force) => { const on = force !== undefined ? force : !set.has(c); if (on) set.add(c); else set.delete(c); return on; },
    contains: (c) => set.has(c),
    _set: set,
  };
}

function makeEl(id) {
  return {
    id,
    classList: makeClassList(),
    dataset: {},
    style: {},
    value: "",
    textContent: "",
    innerHTML: "",
    children: [],
    // 默认无 .error-text 子节点（首页 home-error 的真实形态，用户规格八的回归点）。
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild: function (ch) { this.children.push(ch); return ch; },
    addEventListener: () => {},
    setAttribute: () => {},
    focus: () => {},
    select: () => {},
    remove: () => {},
  };
}

const els = {};
// 动态 invoke 持有器：app.js 在加载时解构捕获 `invoke`，因此初始 stub 必须委托到
// 可变实现，测试运行时替换 `__invokeImpl` 即可。
let __invokeImpl = async () => { throw new Error("invoke 未被桩"); };
const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  setInterval: () => 0,
  clearInterval: () => {},
  Date,
  Number,
  String,
  JSON,
  Promise,
  URL,
  Math,
  navigator: { clipboard: undefined },
  confirm: () => false,
  window: {
    isSecureContext: false,
    __MESHLINK_TEST__: {},
    __TAURI__: {
      core: { invoke: (cmd, args) => __invokeImpl(cmd, args) },
      event: { listen: async () => () => {} },
    },
  },
  document: {
    getElementById: (id) => (els[id] ||= makeEl(id)),
    createElement: (tag) => makeEl(tag),
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener: () => {},
    body: { appendChild: () => {} },
    documentElement: {},
  },
};
sandbox.window.document = sandbox.document;
sandbox.globalThis = sandbox;

vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: "app.js" });

const api = sandbox;

/* ---------------- 测试骨架 ---------------- */
let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra !== undefined ? "  → " + JSON.stringify(extra) : "")); }
}

/* ---------------- 1) formatError 契约 ---------------- */
console.log("[1] formatError：任何输入都不得返回 undefined / 空白");
check("undefined → ERROR_UNKNOWN", api.formatError(undefined) === "ERROR_UNKNOWN");
check("null → ERROR_UNKNOWN", api.formatError(null) === "ERROR_UNKNOWN");
check("空字符串 → ERROR_UNKNOWN", api.formatError("") === "ERROR_UNKNOWN");
check("字符串保留原样", api.formatError("命令非法：missing field id") === "命令非法：missing field id");
check("{message} → message", api.formatError({ message: "m" }) === "m");
check("{error} → error", api.formatError({ error: "e" }) === "e");
check("{code} → code", api.formatError({ code: "C" }) === "C");
// 用户规格二顺序：message 优先于 code（`{code,message}` 返回 message）。
check("{code,message} → message（规格顺序）", api.formatError({ code: "C", message: "m" }) === "m");
check("{} → JSON 兜底（非 undefined）", typeof api.formatError({}) === "string" && api.formatError({}) !== "");
check("非对象原语 → String 兜底", api.formatError(42) === "42");
check("任意返回都非 undefined", (() => { const v = api.formatError({ x: 1 }); return v !== undefined && v !== ""; })());
const zero = api.formatError(0);
check("0 → '0'（非 undefined）", zero === "0");

/* ---------------- 2) send() 归一化 ---------------- */
console.log("[2] send()：invoke 拒绝必须归一化为 {code,message}，message 永不为 undefined");
async function withInvoke(rejectValue) {
  __invokeImpl = async () => { throw rejectValue; };
  try { await api.send("GetStatus"); return { ok: true }; }
  catch (e) { return { ok: false, code: e.code, message: e.message }; }
}
(async () => {
  let r = await withInvoke("命令非法：missing field id");
  check("字符串拒绝 → message 非 undefined", r.ok === false && typeof r.message === "string" && r.message !== "", r);
  check("字符串拒绝 → code=INVOKE_FAILED", r.code === "INVOKE_FAILED", r);

  r = await withInvoke({ message: "m" });
  check("{message} 拒绝 → message='m'", r.message === "m", r);

  r = await withInvoke({});
  check("空对象拒绝 → message=ERROR_UNKNOWN", r.message === "ERROR_UNKNOWN", r);

  r = await withInvoke(undefined);
  check("undefined 拒绝 → message=ERROR_UNKNOWN", r.message === "ERROR_UNKNOWN", r);

  // ok:false + error 对象（agent 正常错误响应路径）。
  __invokeImpl = async () => ({ ok: false, error: { code: "INVITE_TTL_INVALID", message: "有效期必须是 permanent / 24h / 7d" } });
  try { await api.send("CreateFriendInvite", { ttl: "bogus" }); r = { ok: true }; }
  catch (e) { r = { ok: false, code: e.code, message: e.message }; }
  check("agent 错误响应 → code 透传", r.code === "INVITE_TTL_INVALID", r);
  check("agent 错误响应 → message 非空", typeof r.message === "string" && r.message !== "", r);

  // 成功路径：ok:true → 返回 data。
  __invokeImpl = async () => ({ ok: true, data: { devices: [] } });
  const d = await api.send("ListDevices");
  check("ok:true → 返回 data", d && Array.isArray(d.devices), d);

  /* ---------------- 3) showError 在空横幅上不抛错 ---------------- */
  console.log("[3] showError：无 .error-text 子元素也不抛错、不留下空红色区");
  const banner = makeEl("home-error");
  let threw = false;
  try { api.showError(banner, "X", "m"); } catch (e) { threw = true; }
  check("不抛错", !threw);
  check("横幅可见（hidden 移除）", !banner.classList.contains("hidden"));
  const child = banner.children.find((c) => c.className === "error-text");
  check("自动补 .error-text 子节点", !!child && child.textContent !== "");
  api.hideError(banner);
  check("hideError 后隐藏", banner.classList.contains("hidden"));

  /* ---------------- 4) toast 替代 alert ---------------- */
  console.log("[4] toast：代替 window.alert");
  api.toast("生成失败：真实错误", true);
  const t = els["toast"];
  check("toast 已创建且带文案", !!t && t.textContent === "生成失败：真实错误", t && t.textContent);
  check("toast 显示类已加", !!t && t.classList.contains("show") && t.classList.contains("toast-error"));
  api.toast("正常提示", false);
  check("非错误 toast 不带 error 类", els["toast"].classList.contains("toast-error") === false);

  /* ---------------- 5) isProdHttpRejected：RFC1918 私网 http 放行（与 Rust 对齐） ---------------- */
  console.log("[5] isProdHttpRejected：loopback/私网放行、公网 http 拒绝");
  check("https 放行", api.isProdHttpRejected("https://control.example.com/") === false);
  check("http://localhost 放行", api.isProdHttpRejected("http://localhost:18080") === false);
  check("http://127.0.0.1 放行", api.isProdHttpRejected("http://127.0.0.1:18080") === false);
  check("http://10.0.0.5 私网放行", api.isProdHttpRejected("http://10.0.0.5:18080") === false);
  check("http://172.16.0.8 私网放行", api.isProdHttpRejected("http://172.16.0.8:18080") === false);
  check("http://192.168.1.10 私网放行", api.isProdHttpRejected("http://192.168.1.10:18080") === false);
  check("公网 http 拒绝", api.isProdHttpRejected("http://control.example.com") === true);
  check("公网 IP http 拒绝", api.isProdHttpRejected("http://8.8.8.8:18080") === true);
  check("非法 URL 拒绝", api.isProdHttpRejected("garbage") === true);

  /* ---------------- 6) renderStatus：网络服务未连接明确提示 ---------------- */
  console.log("[6] renderStatus：服务未连时不显示模糊『连接失败』");
  const S = sandbox.window.__MESHLINK_TEST__.S;
  // renderStatus 内部经 getElementById 读写 els["status-pill"/"status-text"]，测试从 els 读回。
  const statusText = () => (els["status-text"] ||= makeEl("status-text")).textContent;
  // S.ctlErr 置位（CONTROLLER_UNREACHABLE 事件路径）→ 首页状态 = 网络服务未启动。
  S.ctlErr = true;
  api.renderStatus({ state: "FAILED", user_facing: "连接失败" });
  check("ctlErr → 显示『网络服务未启动』", statusText() === "网络服务未启动", statusText());
  // 有设备 ID + 非服务失败 → 保持『连接失败』（不误报服务）。
  S.ctlErr = false;
  api.renderStatus({ state: "FAILED", user_facing: "连接失败", device_id: "dev-x" });
  check("有设备 ID 的失败保持『连接失败』", statusText() === "连接失败", statusText());
  // 无设备 ID（首次启动未注册成功）→ 视为网络服务未启动。
  S.ctlErr = false;
  api.renderStatus({ state: "FAILED", user_facing: "连接失败" });
  check("无设备 ID 失败 → 网络服务未启动", statusText() === "网络服务未启动", statusText());
  // READY 正常。
  S.ctlErr = false;
  api.renderStatus({ state: "READY", user_facing: "已就绪", device_id: "dev-x" });
  check("READY 正常显示『已就绪』", statusText() === "已就绪", statusText());
  S.ctlErr = false;

  /* ---------------- 7) NOT_CONFIGURED：首次启动未配置网络服务 ---------------- */
  console.log("[7] renderStatus：未配置状态与首页提示");
  S.ctlErr = false;
  api.renderStatus({ state: "NOT_CONFIGURED", user_facing: "等待创建连接" });
  check("NOT_CONFIGURED → 显示『等待创建连接』", statusText() === "等待创建连接", statusText());
  const noconfig = els["home-noconfig"] || makeEl("home-noconfig");
  // renderStatus 内对 READY/CONNECTED 会隐藏，NOT_CONFIGURED 分支要显式显示。
  const noconfigAfter = els["home-noconfig"];
  check("首页未配置提示已显示", !!(noconfigAfter && !noconfigAfter.classList.contains("hidden")));
  // 连接后应隐藏未配置提示。
  api.renderStatus({ state: "READY", user_facing: "已就绪", device_id: "dev-x" });
  const nc2 = els["home-noconfig"];
  check("READY 后未配置提示隐藏", !!(nc2 && nc2.classList.contains("hidden")));

  /* ---------------- 8) 连接模式 UI：创建连接 / 加入连接（P1-3：不再显示局域网地址卡） ---------------- */
  console.log("[8] 连接模式：创建连接 / 加入连接切换（已移除「我的电脑地址」显示）");
  // 默认 remote 模式（未配置）。
  const modeLocal = els["mode-local"] || makeEl("mode-local");
  const modeRemote = els["mode-remote"] || makeEl("mode-remote");
  modeLocal.checked = false; modeRemote.checked = true;
  api.syncControllerModeUI();
  // sync 会经 getElementById 创建真实元素，需从 els 读回（勿缓存本地对象）。
  const urlRow2 = els["ctl-url-row"] || makeEl("ctl-url-row");
  check("加入连接模式显示地址输入框", urlRow2.style.display !== "none");
  // P1-3：两种模式都不再展示「我的电脑地址」局域网卡（元素不存在或隐藏）。
  const lanCard = els["ctl-lan-card"];
  check("不展示局域网地址卡（元素未创建）", lanCard === undefined);
  modeLocal.checked = true; modeRemote.checked = false;
  api.syncControllerModeUI();
  const urlRow3 = els["ctl-url-row"] || makeEl("ctl-url-row");
  check("创建连接模式也显示地址输入框", urlRow3.style.display !== "none");
  const hint = els["ctl-mode-hint"] || makeEl("ctl-mode-hint");
  check("创建连接模式提示含发起方说明", (hint.textContent || "").indexOf("发起方") !== -1);

  console.log("\nRESULT: " + pass + " passed, " + fail + " failed");
  if (fail > 0) process.exit(1);
  console.log("UI ERROR CONTRACT TESTS PASS");
})();
