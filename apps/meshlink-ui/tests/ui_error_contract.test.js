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

  console.log("\nRESULT: " + pass + " passed, " + fail + " failed");
  if (fail > 0) process.exit(1);
  console.log("UI ERROR CONTRACT TESTS PASS");
})();
