// M1-1.5 最近连接 UI 契约测试。
//
// 直接加载真实 `apps/meshlink-ui/ui/app.js`（最小 DOM / Tauri invoke 桩），断言：
//  1. ListRecentConnections 响应 → 首页渲染最近连接（名称/上次连接/路径/次数/好友标记）；
//  2. recentFriendStatus：ACCEPTED→"好友"、PENDING→"待接受"、无→null；
//  3. 好友标记存在时不渲染"添加好友"按钮；
//  4. recentConnect 好友 → 走 ConnectFriend（不发 CreateQuickSession）；
//  5. recentConnect 非好友 → 走 CreateQuickSession（重新创建临时 6 位码，不自动永久授权）；
//  6. deleteRecent → 发送 DeleteRecentConnection 并本地过滤 + Toast；
//  7. recentRelativeTime 相对时间换算。
//
// 运行：`node apps/meshlink-ui/tests/recent_ui_contract.test.js`
// 通过时输出 `RECENT UI CONTRACT TESTS PASS` 并以 exit 0 结束。

"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const APP_JS = path.join(__dirname, "..", "ui", "app.js");
const source = fs.readFileSync(APP_JS, "utf8");

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
let __copied = [];
let __lastCreated = null;
let __confirmResult = false;

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
  confirm: () => __confirmResult,
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
const S = sandbox.window.__MESHLINK_TEST__.S;
const ERROR_TEXT = sandbox.window.__MESHLINK_TEST__.ERROR_TEXT;

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra !== undefined ? "  → " + JSON.stringify(extra) : "")); }
}

function resetState() {
  invokeCalls.length = 0;
  __copied.length = 0;
  __confirmResult = false;
  __invokeImpl = async () => { throw new Error("invoke 未被桩"); };
  S.friends = [];
  S.recent = [];
  S.deviceId = "dev-self";
  S.view = "home";
}

const isoNow = () => new Date().toISOString();
const isoMinAgo = (m) => new Date(Date.now() - m * 60000).toISOString();
const isoHourAgo = (h) => new Date(Date.now() - h * 3600000).toISOString();

const stubInvoke = (handlers) => {
  __invokeImpl = async (cmd, args) => {
    invokeCalls.push({ cmd, args });
    const h = handlers[cmd];
    if (typeof h === "function") return h(args);
    if (cmd === "ipc_request" && args && handlers["ipc:" + args.cmd]) {
      return handlers["ipc:" + args.cmd](args);
    }
    throw new Error("unexpected invoke: " + cmd + " " + JSON.stringify(args || {}));
  };
};

async function main() {
  // 1) recentFriendStatus
  S.friends = [
    { device_id: "dev-f", status: "ACCEPTED", name: "好友A" },
    { device_id: "dev-p", status: "PENDING", name: "待A" },
  ];
  check("recentFriendStatus ACCEPTED → '好友'", api.recentFriendStatus("dev-f") === "好友");
  check("recentFriendStatus PENDING → '待接受'", api.recentFriendStatus("dev-p") === "待接受");
  check("recentFriendStatus 非好友 → null", api.recentFriendStatus("dev-x") === null);

  // 2) recentRelativeTime
  check("recentRelativeTime 刚刚", api.recentRelativeTime(isoNow()) === "刚刚");
  check("recentRelativeTime 10分钟前", api.recentRelativeTime(isoMinAgo(10)) === "10分钟前");
  check("recentRelativeTime 2小时前", api.recentRelativeTime(isoHourAgo(2)) === "2小时前");
  check("recentRelativeTime 非法 → 原样", api.recentRelativeTime("") === "--");

  // 3) refreshRecent 渲染首页（好友标记）
  resetState();
  S.friends = [{ device_id: "dev-b", status: "ACCEPTED", name: "Bob-PC" }];
  stubInvoke({
    "ipc:ListRecentConnections": () => ({
      ok: true, data: {
        recent_connections: [{
          id: 1,
          remote_device_id: "dev-b",
          remote_name: "Bob-PC",
          remote_fingerprint: "a".repeat(64),
          last_connected_at: isoMinAgo(10),
          last_overlay_ip: "10.88.0.2",
          last_path: "directlink",
          connection_count: 3,
        }],
      },
    }),
  });
  await api.refreshRecent();
  const html = els["home-recent"].innerHTML;
  check("首页渲染最近连接（含 Bob-PC）", html.includes("Bob-PC"));
  check("首页渲染好友标记", html.includes("好友"));
  check("好友标记时不渲染「添加好友」", !html.includes("添加好友"));
  check("首页渲染路径 DirectLink", html.includes("DirectLink"));
  check("首页渲染次数 3次", html.includes("3次"));
  check("好友标记渲染「连接」", html.includes(">连接<"));

  // 4) 非好友 → 渲染「添加好友」按钮
  resetState();
  S.friends = [];
  stubInvoke({
    "ipc:ListRecentConnections": () => ({
      ok: true, data: {
        recent_connections: [{
          id: 2,
          remote_device_id: "dev-stranger",
          remote_name: "",
          remote_fingerprint: "b".repeat(64),
          last_connected_at: isoHourAgo(1),
          last_overlay_ip: "10.88.0.9",
          last_path: "n2n",
          connection_count: 1,
        }],
      },
    }),
  });
  await api.refreshRecent();
  const html2 = els["home-recent"].innerHTML;
  check("非好友显示「添加好友」按钮", html2.includes("添加好友"));
  check("非好友显示「删除」按钮", html2.includes("删除"));
  check("非好友显示路径 N2N", html2.includes("N2N"));
  check("非好友远程名称缺失 → 用短 device_id", html2.includes("dev-stranger"));

  // 5) recentConnect 好友 → 走 ConnectFriend
  resetState();
  S.friends = [{ device_id: "dev-f", status: "ACCEPTED", name: "好友A" }];
  stubInvoke({
    "ipc:ConnectFriend": () => ({ ok: true, data: {} }),
  });
  await api.recentConnect("dev-f", "好友A");
  const connectCall = invokeCalls.find((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "ConnectFriend");
  check("好友 recentConnect → 发送 ConnectFriend",
    !!connectCall && connectCall.args.payload.device_id === "dev-f");
  check("好友 recentConnect → 不创建临时码",
    !invokeCalls.some((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "CreateQuickSession"));

  // 6) recentConnect 非好友 → 走 CreateQuickSession（重新创建临时 6 位码）
  resetState();
  S.friends = [];
  stubInvoke({
    "ipc:CreateQuickSession": () => ({
      ok: true, data: { session_id: "sx", code: "001234", expires_at: null, status: "WAITING" },
    }),
  });
  await api.recentConnect("dev-s", "张三电脑");
  const createCall = invokeCalls.find((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "CreateQuickSession");
  check("非好友 recentConnect → 创建临时码", !!createCall);
  check("非好友 recentConnect → 显示 001234", els["create-code"].textContent === "001234");
  check("非好友 recentConnect → toast 提示确认（不自动永久授权）",
    els["toast"] && els["toast"].textContent.includes("001234") && els["toast"].textContent.includes("确认"));

  // 7) deleteRecent → DeleteRecentConnection + 本地过滤 + Toast
  resetState();
  S.recent = [{ remote_device_id: "dev-del" }, { remote_device_id: "dev-keep" }];
  stubInvoke({
    "ipc:DeleteRecentConnection": () => ({ ok: true, data: { deleted: true } }),
  });
  __confirmResult = true;
  await api.deleteRecent("dev-del");
  const delCall = invokeCalls.find((c) => c.cmd === "ipc_request" && c.args && c.args.cmd === "DeleteRecentConnection");
  check("deleteRecent → 发送 DeleteRecentConnection",
    !!delCall && delCall.args.payload.remote_device_id === "dev-del");
  check("deleteRecent → 本地过滤", S.recent.length === 1 && S.recent[0].remote_device_id === "dev-keep");
  check("deleteRecent → Toast", els["toast"] && els["toast"].textContent.includes("已删除"));

  // 8) RecentConnectionsChanged 事件 → 触发 refreshRecent
  resetState();
  let called = false;
  const orig = api.refreshRecent;
  api.refreshRecent = async () => { called = true; };
  api.handleEvent({ event: "RecentConnectionsChanged" });
  check("RecentConnectionsChanged 事件 → refreshRecent", called === true);
  api.refreshRecent = orig;

  // 9) Connected 事件 → 触发 refreshRecent（连接成功即记录）
  resetState();
  called = false;
  api.refreshRecent = async () => { called = true; };
  api.handleEvent({ event: "Connected", peer_device_id: "dev-x", local_overlay_ip: "10.88.0.1", peer_overlay_ip: "10.88.0.2" });
  check("Connected 事件 → refreshRecent（记录 recent）", called === true);
  check("Connected 事件视图切到 connected", S.view === "connected");
  api.refreshRecent = orig;

  // 10) ERROR_TEXT 存在
  check("ERROR_TEXT 有 LIST_RECENT_FAILED", !!ERROR_TEXT && typeof ERROR_TEXT.LIST_RECENT_FAILED === "string");
  check("ERROR_TEXT 有 DELETE_RECENT_FAILED", typeof ERROR_TEXT.DELETE_RECENT_FAILED === "string");

  console.log(fail === 0 ? "\nRECENT UI CONTRACT TESTS PASS" : "\nRECENT UI CONTRACT TESTS FAILED");
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
