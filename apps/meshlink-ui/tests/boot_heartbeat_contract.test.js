// Boot 健壮性 + 心跳轮询契约测试。
// 验证两个核心修复（真实双机复现的 UI 冻结根因）：
//  1. boot() 里 startStatusPoll() 必须在 listen 之前、且 listen 抛异常不得中断心跳启动；
//     （修复前：startStatusPoll 在 await listen 之后，listen 抛异常 → boot 中断 →
//      heartbeat 永不启动 → UI 永久停在初始渲染「已就绪」，即使 agent 已 CONNECTED）
//  2. heartbeat() 能正确消费 GetStatus=CONNECTED（状态文字「已连接」+ 虚拟 IP + 路径）。
//
// 运行：`node apps/meshlink-ui/tests/boot_heartbeat_contract.test.js`
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
    id, classList: makeClassList(), dataset: {}, style: {}, value: "", textContent: "", innerHTML: "",
    children: [], disabled: false,
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild: function (ch) { this.children.push(ch); return ch; },
    addEventListener: function (type, fn) { (this._listeners || (this._listeners = {}))[type] = fn; },
    dispatchEvent: function (ev) { if (!ev.target) ev.target = this; const fn = this._listeners && this._listeners[ev.type]; if (fn) fn.call(this, ev); return true; },
    setAttribute: () => {}, focus: () => {}, select: () => {}, remove: () => {},
  };
  return el;
}

const els = {};
// 可配置：默认安全返回，测试内按需覆盖。
let __invokeImpl = async () => ({ ok: true, data: [] });
// 可配置：默认正常 listen，测试内模拟抛异常（真实双机 root cause）。
let __listenImpl = async () => () => {};

const sandbox = {
  console, setTimeout, clearTimeout,
  setInterval: () => 1,           // 返回 1（truthy），pollTimer 可判
  clearInterval: () => {},
  Date, Number, String, JSON, Promise, URL, Math,
  Event: class { constructor(type) { this.type = type; } },
  navigator: { clipboard: undefined },
  confirm: () => false,
  window: {
    isSecureContext: false,
    __MESHLINK_TEST__: {},
    __TAURI__: {
      core: { invoke: (cmd, args) => __invokeImpl(cmd, args) },
      event: { listen: (name, cb) => __listenImpl(name, cb) },
    },
  },
  document: {
    getElementById: (id) => (els[id] ||= makeEl(id)),
    createElement: (tag) => makeEl(tag),
    execCommand: () => true,
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
// 关键：加载前就设好「listen 抛异常」——模拟真实环境 boot 中断场景。
__listenImpl = async () => { throw new Error("simulated listen failure"); };
vm.runInContext(source, sandbox, { filename: "app.js" });

const api = sandbox;
const S = sandbox.window.__MESHLINK_TEST__.S;

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra !== undefined ? "  -> " + JSON.stringify(extra) : "")); }
}

async function main() {
  // 等 app.js 加载时的 boot() 完成（内部多个 await）。
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));

  // —— 场景 1：listen 抛异常时 boot 仍启动心跳轮询（修复核心） ——
  check("boot: listen 抛异常后 startStatusPoll 仍被调用 (pollTimer 已设置)",
    S.pollTimer !== null && S.pollTimer !== undefined, S.pollTimer);

  // —— 场景 2：heartbeat 正确消费 GetStatus=CONNECTED（GetStatus 是状态权威来源） ——
  __invokeImpl = async (cmd, args) => {
    if (cmd === "ipc_request" && args && args.cmd === "GetStatus") {
      return { ok: true, data: {
        state: "CONNECTED", user_facing: "已连接", device_id: "dev-x",
        controller: "https://controller.example", current_path: "directlink",
        active_session: null,
        session: { peers: [{ device_id: "dev-y", local_overlay_ip: "10.88.0.1", peer_overlay_ip: "10.88.0.2", connected: true }] },
      } };
    }
    return { ok: true, data: [] };
  };
  S.view = "home";
  await api.heartbeat();
  check("heartbeat GetStatus=CONNECTED -> 状态文字=已连接", els["status-text"].textContent === "已连接", els["status-text"].textContent);
  check("heartbeat CONNECTED -> home-overlay-ip=10.88.0.1", els["home-overlay-ip"].textContent === "10.88.0.1", els["home-overlay-ip"].textContent);
  check("heartbeat CONNECTED -> home-path=DirectLink", els["home-path"].textContent === "DirectLink", els["home-path"].textContent);
  // syncConnectedView 兜底：home 视图 CONNECTED -> 切到 connected 页
  check("heartbeat CONNECTED -> syncConnectedView 切到 connected 视图", S.view === "connected", S.view);
  check("heartbeat CONNECTED -> conn-peer-ip=10.88.0.2", els["conn-peer-ip"].textContent === "10.88.0.2", els["conn-peer-ip"].textContent);
  check("heartbeat CONNECTED -> conn-local-ip=10.88.0.1", els["conn-local-ip"].textContent === "10.88.0.1", els["conn-local-ip"].textContent);
  check("heartbeat CONNECTED -> conn-path=DirectLink", els["conn-path"].textContent === "DirectLink", els["conn-path"].textContent);

  console.log(fail === 0 ? "\nBOOT HEARTBEAT CONTRACT TESTS PASS" : "\nBOOT HEARTBEAT CONTRACT TESTS FAILED");
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
