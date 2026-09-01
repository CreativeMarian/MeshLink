// 6 位连接码全链路 UI 契约测试（用户规格一/二/五/六/七/八/十）。
//
// 直接加载真实 `apps/meshlink-ui/ui/app.js`（最小 DOM / Tauri invoke 桩），断言：
//  1. CreateQuickSession 响应 code="482731" → UI 立即显示 482731（不依赖后续事件）；
//  2. code 为 number / 空 / 非 6 位 → 抛 QUICK_CODE_INVALID_RESPONSE，UI 不显示假码；
//  3. 前导零 "001234" 全链路保留；
//  4. 复制 clipboard 严格 = 纯 6 位数字（无前缀/无换行/无 JSON）；
//  5. paste 必须 preventDefault + getData("text") + normalize（带文本/带空格/超长都正确）；
//  6. join 前严格校验：长度≠6（含只粘贴出 "11" 的情况）不发请求；
//  7. 合法 join 发送完全相同的 6 位 string；
//  8. WaitingForPeer 事件 code 也走 schema 断言。
//
// 运行：`node apps/meshlink-ui/tests/quick_code_ui_contract.test.js`
// 通过时输出 `QUICK CODE UI CONTRACT TESTS PASS` 并以 exit 0 结束。

"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const APP_JS = path.join(__dirname, "..", "ui", "app.js");
const source = fs.readFileSync(APP_JS, "utf8");

/* ---------------- 最小 DOM 桩（带事件监听捕获） ---------------- */

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
  const el = {
    id,
    classList: makeClassList(),
    dataset: {},
    style: {},
    value: "",
    textContent: "",
    innerHTML: "",
    children: [],
    disabled: false,
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild: function (ch) { this.children.push(ch); return ch; },
    addEventListener: function (type, fn) { (this._listeners || (this._listeners = {}))[type] = fn; },
    dispatchEvent: function (ev) {
      if (!ev.target) ev.target = this;
      const fn = this._listeners && this._listeners[ev.type];
      if (fn) fn.call(this, ev);
      return true;
    },
    setAttribute: () => {},
    focus: () => {},
    select: () => {},
    remove: () => {},
    style: {},
  };
  return el;
}

const els = {};
let __invokeImpl = async () => { throw new Error("invoke 未被桩"); };
const invokeCalls = [];
let __copied = [];          // document.execCommand 复制捕获
let __lastCreated = null;   // 最近一次 createElement 的引用

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
  Event: class { constructor(type) { this.type = type; } },
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
    createElement: (tag) => { __lastCreated = makeEl(tag); return __lastCreated; },
    execCommand: (cmd) => { if (cmd === "copy" && __lastCreated) __copied.push(__lastCreated.value); return true; },
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
const S = sandbox.window.__MESHLINK_TEST__.S; // app.js 经测试钩子暴露的内部状态
const ERROR_TEXT = sandbox.window.__MESHLINK_TEST__.ERROR_TEXT;

/* ---------------- 测试骨架 ---------------- */
let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra !== undefined ? "  → " + JSON.stringify(extra) : "")); }
}

function resetState() {
  invokeCalls.length = 0;
  __copied.length = 0;
  // 复位 Agent 桩：默认失败，测试内按需设置。
  __invokeImpl = async () => { throw new Error("invoke 未被桩"); };
  api.resetSessionUi();
  S.view = "home";
  S.code = null;
}

async function main() {
  // 1) normalizeQuickCode 基础契约
  check("normalize '482731' → '482731'", api.normalizeQuickCode("482731") === "482731");
  check("normalize '001234' 保留前导零", api.normalizeQuickCode("001234") === "001234");
  check("normalize ' 482731 ' 去空格", api.normalizeQuickCode(" 482731 ") === "482731");
  check("normalize '连接码：482731' 去文本", api.normalizeQuickCode("连接码：482731") === "482731");
  check("normalize '123456789' 截断到 6", api.normalizeQuickCode("123456789") === "123456");
  check("normalize '' → ''", api.normalizeQuickCode("") === "");
  check("normalize null → ''", api.normalizeQuickCode(null) === "");
  check("normalize undefined → ''", api.normalizeQuickCode(undefined) === "");

  // 2) validateQuickCodeResponse schema 断言
  check("validate string 6 位 → 原样", api.validateQuickCodeResponse({ code: "482731" }) === "482731");
  let threw = false;
  try { api.validateQuickCodeResponse({ code: 482731 }); } catch (e) { threw = e.code === "QUICK_CODE_INVALID_RESPONSE"; }
  check("validate number 482731 → QUICK_CODE_INVALID_RESPONSE", threw);
  threw = false;
  try { api.validateQuickCodeResponse({ code: "48273" }); } catch (e) { threw = e.code === "QUICK_CODE_INVALID_RESPONSE"; }
  check("validate 5 位 → QUICK_CODE_INVALID_RESPONSE", threw);
  threw = false;
  try { api.validateQuickCodeResponse({}); } catch (e) { threw = e.code === "QUICK_CODE_INVALID_RESPONSE"; }
  check("validate 空响应 → QUICK_CODE_INVALID_RESPONSE", threw);

  // 3) Creator：响应即显示（用户规格三，不依赖 WaitingForPeer 事件）
  resetState();
  __invokeImpl = async (cmd, args) => {
    invokeCalls.push({ cmd, args });
    if (cmd === "agent_connect") return { ok: true, data: { state: "READY", device_id: "dev-x" } };
    if (cmd === "ipc_request" && args && args.cmd === "CreateQuickSession") {
      return { ok: true, data: { session_id: "s1", code: "482731", expires_at: "2026-09-01T10:00:00Z", status: "WAITING" } };
    }
    throw new Error("unexpected invoke: " + cmd);
  };
  await api.startCreate();
  check("Creator 显示 code=482731", els["create-code"].textContent === "482731");
  check("Creator S.code=482731", S.code === "482731");
  check("Creator 视图切到 create", S.view === "create");
  check("Creator 请求了 CreateQuickSession",
    invokeCalls.some((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "CreateQuickSession"));

  // 4) Creator 前导零：001234 全链路保留
  resetState();
  __invokeImpl = async (cmd, args) => {
    if (cmd === "agent_connect") return { ok: true, data: { state: "READY", device_id: "dev-x" } };
    if (cmd === "ipc_request" && args && args.cmd === "CreateQuickSession") {
      return { ok: true, data: { session_id: "s2", code: "001234", expires_at: null, status: "WAITING" } };
    }
    throw new Error("unexpected invoke");
  };
  await api.startCreate();
  check("Creator 前导零显示 001234（不是 1234）", els["create-code"].textContent === "001234");
  check("Creator S.code=001234", S.code === "001234");

  // 5) Creator：非法响应（number）→ 真实错误码，不显示假码
  resetState();
  __invokeImpl = async (cmd, args) => {
    if (cmd === "agent_connect") return { ok: true, data: { state: "READY" } };
    if (cmd === "ipc_request" && args && args.cmd === "CreateQuickSession") {
      return { ok: true, data: { session_id: "s3", code: 482731, status: "WAITING" } };
    }
    throw new Error("unexpected invoke");
  };
  await api.startCreate();
  const homeErr = els["home-error"];
  const homeErrText = homeErr.children.length ? homeErr.children[0].textContent : "";
  check("非法 number code → home-error 显示真实错误",
    homeErr.classList.contains("hidden") === false && homeErrText.length > 0);
  check("非法 number code → 不显示假码（仍是占位）", els["create-code"].textContent !== "482731");
  check("非法 number code → ERROR_TEXT 有 QUICK_CODE_INVALID_RESPONSE",
    !!ERROR_TEXT && typeof ERROR_TEXT.QUICK_CODE_INVALID_RESPONSE === "string");

  // 6) 复制：clipboard 严格 = 纯 6 位数字
  resetState();
  S.code = "482731";
  els["create-code"].textContent = "482731";
  await api.copyQuickCode();
  check("复制 clipboard == 482731（无前缀/无换行/无 JSON）", __copied.length === 1 && __copied[0] === "482731");
  check("复制 Toast == 连接码已复制：482731", els["toast"] && els["toast"].textContent === "连接码已复制：482731");
  // 复制前断言：S.code 非法时不复制
  resetState();
  S.code = null;
  els["create-code"].textContent = "------";
  __copied.length = 0;
  await api.copyQuickCode();
  check("复制断言：非法码不复制", __copied.length === 0);

  // 7) paste：preventDefault + getData("text") + normalize
  resetState();
  const joinInput = els["join-code"];
  const pasteEvt = (text) => ({
    preventDefault: () => { joinInput._prevented = true; },
    clipboardData: { getData: () => text },
    target: joinInput,
    type: "paste",
  });
  joinInput._prevented = false;
  joinInput.dispatchEvent(pasteEvt("482731"));
  check("paste '482731' → input=482731", joinInput.value === "482731");
  check("paste 调用了 preventDefault", joinInput._prevented === true);
  joinInput._prevented = false;
  joinInput.dispatchEvent(pasteEvt("001234"));
  check("paste '001234' 保留前导零", joinInput.value === "001234");
  joinInput.dispatchEvent(pasteEvt(" 482731 "));
  check("paste ' 482731 ' 去空格", joinInput.value === "482731");
  joinInput.dispatchEvent(pasteEvt("连接码：482731"));
  check("paste '连接码：482731' 去文本", joinInput.value === "482731");
  joinInput.dispatchEvent(pasteEvt("123456789"));
  check("paste '123456789' 截断到 6", joinInput.value === "123456");

  // 8) join 前严格校验：长度≠6（含"只显示 11"）不发请求
  resetState();
  joinInput.value = "11";
  let invokeCountBefore = invokeCalls.length;
  await api.startJoin();
  check("join '11' → 不发送请求", invokeCalls.length === invokeCountBefore);
  check("join '11' → 显示 SESSION_CODE_INVALID",
    els["join-error"].classList.contains("hidden") === false);
  // 空输入
  resetState();
  joinInput.value = "";
  invokeCountBefore = invokeCalls.length;
  await api.startJoin();
  check("join '' → 不发送请求", invokeCalls.length === invokeCountBefore);
  // 合法码 → 发送完全相同的 string
  resetState();
  __invokeImpl = async (cmd, args) => {
    invokeCalls.push({ cmd, args });
    if (cmd === "agent_connect") return { ok: true, data: { state: "READY" } };
    if (cmd === "ipc_request" && args && args.cmd === "JoinQuickSession") {
      return { ok: true, data: { status: "accepted" } };
    }
    throw new Error("unexpected invoke");
  };
  joinInput.value = "482731";
  await api.startJoin();
  const joinCall = invokeCalls.find((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "JoinQuickSession");
  check("join '482731' → 发送 JoinQuickSession {code:'482731'}",
    !!joinCall && joinCall.args.payload && joinCall.args.payload.code === "482731");
  // 前导零 join
  resetState();
  __invokeImpl = async (cmd, args) => {
    invokeCalls.push({ cmd, args });
    if (cmd === "agent_connect") return { ok: true, data: { state: "READY" } };
    if (cmd === "ipc_request" && args && args.cmd === "JoinQuickSession") return { ok: true, data: { status: "accepted" } };
    throw new Error("unexpected invoke");
  };
  joinInput.value = "001234";
  await api.startJoin();
  const joinCall2 = invokeCalls.find((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "JoinQuickSession");
  check("join '001234' 前导零完整发送", !!joinCall2 && joinCall2.args.payload.code === "001234");

  // 9) WaitingForPeer 事件：code 也走 schema 断言
  resetState();
  api.handleEvent({ event: "WaitingForPeer", code: "001234", expires_at: "2026-09-01T10:00:00Z" });
  check("WaitingForPeer 001234 显示", els["create-code"].textContent === "001234");
  api.resetSessionUi();
  api.handleEvent({ event: "WaitingForPeer", code: "12" });
  check("WaitingForPeer 非法 code → toast 报 QUICK_CODE_INVALID_RESPONSE",
    els["toast"] && els["toast"].textContent.includes("QUICK_CODE_INVALID_RESPONSE"));

  // 10) GetStatus active_session 恢复（用户规格四：页面切换不丢码）
  resetState();
  api.renderStatus({
    state: "WAITING_FOR_PEER",
    user_facing: "等待好友加入...",
    device_id: "dev-x",
    active_session: { session_id: "s9", code: "001234", status: "WAITING_FOR_PEER", expires_at: "2026-09-01T10:00:00Z" },
  });
  check("GetStatus active_session 恢复 001234 并回 create 视图",
    S.code === "001234" && els["create-code"].textContent === "001234" && S.view === "create");

  console.log(fail === 0 ? "\nQUICK CODE UI CONTRACT TESTS PASS" : "\nQUICK CODE UI CONTRACT TESTS FAILED");
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
