/* MeshLink UI（M1-1 Friend & Device UX）：状态全部来自 Agent 事件与 GetStatus，
 * UI 不自行推断；普通 UI 不显示 Noise/srflx/Candidate/epoch/STUN/Wintun（规格十四）。 */
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

/* ---------------- 常量 ---------------- */

const STEP_FIND = 0, STEP_DIRECT = 1, STEP_SECURE = 2, STEP_OVERLAY = 3;

const ERROR_TEXT = {
  DIRECTLINK_FAILED: "无法建立直连。双方网络可能受限，请稍后重试。",
  SESSION_CODE_INVALID: "连接码无效：必须是 6 位数字。",
  SESSION_NOT_FOUND: "连接码不存在或已过期，请确认后重试。",
  SESSION_EXPIRED: "连接码已过期，请让对方重新创建。",
  SESSION_RATE_LIMITED: "尝试次数过多，请 1 分钟后再试。",
  SESSION_BUSY: "当前已有进行中的会话，请先取消。",
  DEVICE_KEY_MISMATCH: "设备身份验证失败：对方设备密钥与注册信息不符，连接已终止。",
  AGENT_TIMEOUT: "后台服务响应超时，请重试。",
  AGENT_STOPPED: "后台服务已停止。",
  CONTROLLER_UNREACHABLE: "无法连接服务，请检查网络。",
  INVITE_TTL_INVALID: "邀请有效期设置无效。",
  INVITE_REDEEM_FAILED: "邀请兑换失败，请确认邀请是否有效。",
  LIST_FRIENDS_FAILED: "好友列表加载失败。",
  LIST_DEVICES_FAILED: "设备列表加载失败。",
  FRIEND_CONNECT_FAILED: "无法发起连接：对方可能不是你的好友。",
  FRIEND_ACCEPT_FAILED: "接受好友请求失败。",
  FRIEND_REMOVE_FAILED: "删除好友失败。",
  ACCEPT_REQUEST_FAILED: "接受连接请求失败。",
  REJECT_REQUEST_FAILED: "拒绝连接请求失败。",
  CONTROLLER_URL_INVALID: "生产 Controller 必须使用 HTTPS。",
  REQUEST_REJECTED: "对方拒绝了连接请求。",
  QUICK_CODE_INVALID_RESPONSE: "连接码响应无效：Controller 未返回有效的 6 位码。",
  LIST_RECENT_FAILED: "最近连接加载失败。",
  DELETE_RECENT_FAILED: "删除最近连接失败。",
};

/* ---------------- 状态 ---------------- */

const S = {
  view: "home",
  code: null,
  expiresAt: null,
  countdownTimer: null,
  pollTimer: null,
  connectedInfo: null,
  deviceId: null,
  friends: [],        // 好友列表缓存（Agent 数据，经 ListFriends 拉取）
  recent: [],         // 最近连接缓存（M1-1.5；经 ListRecentConnections 拉取）
  pendingReq: null,   // {session_id, from_name, from_device_id}
  inviteResult: null, // {uri, token}
  toastTimer: null,
  controllerUrl: "",
  controllerCfg: {},   // 连接配置（mode / lan_ip / effective_url，供设置页展示）
  ctlErr: false,      // 网络服务不可达横幅可见性（事件驱动 + poll 兜底）
  // 综合修复 P0-5：全局连接状态机（STARTING / CONNECTING / CONNECTED / DISCONNECTED / ERROR）。
  connState: "STARTING",
  connMeta: { server: "", latency: "" }, // 首页顶部：服务器 + 延迟
  reconnectTimer: null,
};

/* ---------------- 工具 ---------------- */

const $ = (id) => document.getElementById(id);

function show(view) {
  S.view = view;
  for (const v of document.querySelectorAll(".view")) {
    v.classList.toggle("active", v.id === "view-" + view);
  }
  for (const b of document.querySelectorAll(".nav-btn")) {
    b.classList.toggle("active", b.dataset.view === view);
  }
}

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  }
  return Promise.resolve(fallbackCopy(text));
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } finally { ta.remove(); }
}

/* ---------------- 6 位连接码（全链路 STRING；用户规格一/二/五） ---------------- */

// 输入归一化：只保留数字、最多 6 位、保留前导零（固定宽度字符串，不做数字转换）。
function normalizeQuickCode(value) {
  return String(value ?? "").replace(/\D/g, "").slice(0, 6);
}

// schema 断言：code 必须是 string 且精确匹配 /^\d{6}$/。
function isValidQuickCode(code) {
  return typeof code === "string" && /^\d{6}$/.test(code);
}

// CreateQuickSession 响应校验（用户规格二）：不合法直接抛 QUICK_CODE_INVALID_RESPONSE。
function validateQuickCodeResponse(data) {
  const code = data && data.code;
  if (!isValidQuickCode(code)) {
    const e = new Error("连接码响应无效：Controller 未返回有效的 6 位码");
    e.code = "QUICK_CODE_INVALID_RESPONSE";
    throw e;
  }
  return code;
}

// 立即渲染连接码（用户规格三：不依赖后续 WaitingForPeer 事件）。
function showQuickCode(code, expiresAt) {
  S.code = code;
  S.expiresAt = expiresAt || null;
  $("create-code").textContent = code;
  startCountdown(expiresAt);
  // 综合修复 P1-2：创建视图显示连接服务器（不显示本机局域网地址）。
  const cs = $("create-server");
  if (cs) cs.textContent = S.controllerUrl || "--";
  if (S.view === "home" || S.view === "friends") show("create");
}

// 复制：clipboard 严格等于纯 6 位数字（用户规格五），复制前断言 /^\d{6}$/。
async function copyQuickCode() {
  const code = S.code || String($("create-code").textContent || "").trim();
  if (!isValidQuickCode(code)) {
    toast("连接码无效，无法复制", true);
    return;
  }
  try {
    await copyText(code);
    toast("连接码已复制：" + code);
  } catch {
    toast("复制失败，请手动复制连接码", true);
  }
}

function startCountdown(expiresAt) {
  stopCountdown();
  S.expiresAt = expiresAt;
  S.countdownTimer = setInterval(() => {
    if (!S.expiresAt) return;
    const remain = Math.max(0, Math.floor((new Date(S.expiresAt) - Date.now()) / 1000));
    const mm = String(Math.floor(remain / 60)).padStart(2, "0");
    const ss = String(remain % 60).padStart(2, "0");
    $("create-countdown").textContent = `${mm}:${ss}`;
  }, 500);
}

function stopCountdown() {
  if (S.countdownTimer) clearInterval(S.countdownTimer);
  S.countdownTimer = null;
}

function shortId(id) {
  if (!id) return "--";
  return id.length > 12 ? id.slice(0, 12) + "…" : id;
}

/**
 * 统一错误归一化（用户规格二：禁止再出现 undefined / 空白错误）。
 * Tauri invoke 拒绝可能返回：string / Error / 序列化 Rust 错误对象 / 其它。
 */
function formatError(err) {
  if (err === null || err === undefined) return "ERROR_UNKNOWN";
  if (typeof err === "string") return err || "ERROR_UNKNOWN";
  if (typeof err === "object") {
    if (typeof err.message === "string" && err.message) return err.message;
    if (typeof err.error === "string" && err.error) return err.error;
    if (typeof err.code === "string" && err.code) {
      return err.message ? `${err.code}: ${err.message}` : err.code;
    }
    try {
      const s = JSON.stringify(err);
      if (s && s !== "{}" && s !== "null") return s;
    } catch { /* 落到 String(err) */ }
    const s = String(err);
    return s && s !== "[object Object]" ? s : "ERROR_UNKNOWN";
  }
  const s = String(err);
  return s || "ERROR_UNKNOWN";
}

/** 提取可展示的错误码（用于 ERROR_TEXT 本地化）；无则 null。 */
function errorCode(err) {
  if (err && typeof err === "object" && typeof err.code === "string") return err.code;
  return null;
}

/** Toast（代替 window.alert；用户规格九）。 */
function toast(msg, isError) {
  let t = $("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    t.className = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg || "ERROR_UNKNOWN";
  t.classList.toggle("toast-error", !!isError);
  t.classList.add("show");
  clearTimeout(S.toastTimer);
  S.toastTimer = setTimeout(() => t.classList.remove("show"), 4200);
}

function toastError(prefix, e) {
  toast(`${prefix}：${formatError(e)}`, true);
}

function showError(bannerEl, code, msg) {
  if (!bannerEl) return;
  bannerEl.classList.remove("hidden");
  const text = ERROR_TEXT[code] || msg || "操作失败，请重试。";
  let textEl = bannerEl.querySelector(".error-text");
  if (!textEl) { textEl = document.createElement("div"); textEl.className = "error-text"; bannerEl.appendChild(textEl); }
  textEl.textContent = text;
  let codeEl = bannerEl.querySelector(".error-code");
  if (codeEl) codeEl.textContent = code || "";
  else if (code) { codeEl = document.createElement("div"); codeEl.className = "error-code"; codeEl.textContent = code; bannerEl.appendChild(codeEl); }
}

function hideError(bannerEl) { if (bannerEl) bannerEl.classList.add("hidden"); }

/* ---------------- 首页状态渲染 ---------------- */

function renderStatus(snap) {
  const pill = $("status-pill");
  const text = $("status-text");
  const state = snap && snap.state;
  // 综合修复 P0-5：全局连接状态机（STARTING/CONNECTING/CONNECTED/DISCONNECTED/ERROR）。
  // UI 不自行推断 Agent 内部状态；这里只映射 GetStatus.state。
  if (state === "READY" || state === "CONNECTED") {
    setConnState("CONNECTED");
    hideReconnect();
    hideControllerUnreachable();
    $("home-noconfig").classList.add("hidden");
  } else if (state === "FAILED" || state === "STOPPED") {
    setConnState("ERROR");
  } else if (state === "STARTING") {
    setConnState("STARTING");
  } else if (state === "NOT_CONFIGURED") {
    // 综合修复：正式版未配置时默认连公网 Controller，本分支仅防御（不会出现）。
    setConnState("DISCONNECTED");
  } else if (state) {
    setConnState("CONNECTING");
  }
  let cls = "dot-gray", label = "未知";
  if (state === "READY") { cls = "dot-green"; label = "已就绪"; }
  else if (state === "CONNECTED") { cls = "dot-green"; label = "已连接"; }
  else if (state === "NOT_CONFIGURED") {
    cls = "dot-gray";
    label = "等待创建连接";
    // 首页明确提示去设置选择创建/加入（首次启动无配置时不默认本机地址）。
    $("home-noconfig").classList.remove("hidden");
  }
  else if (state === "FAILED" || state === "STOPPED") { cls = "dot-red"; }
  else if (state && state !== "STARTING") { cls = "dot-blue"; }
  label = (snap && snap.user_facing) || label;
  // 网络服务未连接：明确提示（用户化：不显示技术术语）。
  // FAILED/STOPPED 且 agent 尚未注册成功（无 device_id）→ 不是会话失败，是网络服务未连上。
  if (state === "FAILED" || state === "STOPPED") {
    const ctlDown = S.ctlErr || !(snap && snap.device_id);
    if (ctlDown && label === "连接失败") label = "网络服务未启动";
  }
  pill.className = "dot " + cls;
  text.textContent = label;
  if (snap && snap.device_id) {
    S.deviceId = snap.device_id;
    $("home-device").textContent = snap.device_id;
    $("home-device-card").style.display = "flex";
  }
  // 用户规格四：GetStatus active_session 恢复 6 位码（UI 刷新 / 页面切换 / 窗口重绘）。
  if (snap.active_session && isValidQuickCode(snap.active_session.code)) {
    S.code = snap.active_session.code;
    const st = snap.active_session.status;
    if (st === "WAITING_FOR_PEER" || st === "SESSION_CREATING") {
      if (S.view === "home" || S.view === "friends") showQuickCode(S.code, snap.active_session.expires_at);
    } else if (S.view === "create" && isValidQuickCode(S.code)) {
      $("create-code").textContent = S.code;
      if (snap.active_session.expires_at) startCountdown(snap.active_session.expires_at);
    }
  }
  if (snap && snap.session && snap.session.peers && snap.session.peers[0]) {
    const ip = snap.session.peers[0].local_overlay_ip;
    $("home-overlay-ip").textContent = ip || "--";
  } else {
    $("home-overlay-ip").textContent = "--";
  }
  // M1-2：首页状态同步显示当前路径（DirectLink / N2N Relay；未连接 = --）。
  const hp = $("home-path");
  if (hp) {
    hp.textContent = snap && snap.current_path ? (snap.current_path === "n2n" ? "N2N Relay" : "DirectLink") : "--";
  }
  // 好友在线状态随 ListFriends 刷新（列表含在线位）。
  if (snap && snap.state === "READY") refreshFriends();
}

/* ---------------- 步骤渲染 ---------------- */

function setStep(n) {
  for (const li of document.querySelectorAll(".step")) {
    const i = Number(li.dataset.step);
    li.classList.toggle("done", i < n);
    li.classList.toggle("active", i === n);
  }
}

/* ---------------- IPC 请求 ---------------- */

async function ipcRequest(cmd, payload) {
  return invoke("ipc_request", { cmd, payload: payload || null });
}

async function sendRaw(cmd, payload) {
  let r;
  try {
    r = await ipcRequest(cmd, payload);
  } catch (e) {
    // invoke 拒绝（桥接/序列化失败）：归一化为 {code, message}，禁止 undefined 外泄。
    throw { code: errorCode(e) || "INVOKE_FAILED", message: formatError(e) };
  }
  if (!r || !r.ok) {
    const err = r && r.error ? r.error : { code: "UNKNOWN", message: "未知错误" };
    throw { code: err.code || "UNKNOWN", message: formatError(err) };
  }
  return r;
}

async function send(cmd, payload) {
  return (await sendRaw(cmd, payload)).data;
}

/* ---------------- 事件处理（Agent → UI） ---------------- */

function handleEvent(ev) {
  const kind = ev.event;
  const d = ev;
  switch (kind) {
    case "ControllerConnected":
      S.ctlErr = false;
      hideControllerUnreachable();
      hideReconnect();
      renderStatus({ state: "READY", user_facing: "已就绪", device_id: d.device_id });
      refreshFriends();
      // 设置页「当前 Controller 地址」实时刷新（即便不在设置页也保持最新值）。
      loadControllerStatus();
      break;

    case "WaitingForPeer":
      // 事件携带 code 时同样做 schema 断言（用户规格二）。
      if (isValidQuickCode(d.code)) {
        showQuickCode(d.code, d.expires_at);
      } else {
        toast("连接码响应无效：QUICK_CODE_INVALID_RESPONSE", true);
      }
      break;

    case "PeerFound":
      if (S.view !== "create") show("progress");
      setStep(STEP_DIRECT);
      break;

    case "GatheringCandidates":
      if (S.view === "home" || S.view === "join" || S.view === "friends") show("progress");
      setStep(STEP_DIRECT);
      break;

    case "Punching":
      if (S.view !== "progress") show("progress");
      setStep(STEP_DIRECT);
      break;

    case "NoiseHandshaking":
      if (S.view !== "progress") show("progress");
      setStep(STEP_SECURE);
      break;

    case "Connected":
      S.connectedInfo = {
        local: d.local_overlay_ip, peer: d.peer_overlay_ip, peerDevice: d.peer_device_id,
        path: d.path || "",
      };
      $("conn-peer-ip").textContent = d.peer_overlay_ip || "--";
      $("conn-local-ip").textContent = d.local_overlay_ip || "--";
      $("conn-peer-device").textContent = d.peer_device_id || "--";
      // M1-2：普通 UI 显示 DirectLink / N2N Relay（不暴露技术术语）。
      $("conn-path").textContent = d.path === "n2n" ? "N2N Relay" : "DirectLink";
      renderStatus({ state: "CONNECTED", user_facing: "已连接" });
      show("connected");
      // M1-1.5：连接成功即记录 recent（Agent 异步落库后推送 RecentConnectionsChanged）。
      refreshRecent();
      break;

    case "PathChanged":
      break;

    case "Disconnected":
      resetSessionUi();
      renderStatus({ state: "READY", user_facing: "已就绪" });
      if (S.view === "connected" || S.view === "progress" || S.view === "create") show("home");
      refreshFriends();
      break;

    case "IncomingConnectionRequest":
      S.pendingReq = { session_id: d.session_id, from_device_id: d.from_device_id, from_name: d.from_name };
      $("req-from").textContent = d.from_name || d.from_device_id || "--";
      $("modal-request").classList.remove("hidden");
      break;

    case "FriendPending":
    case "FriendAccepted":
    case "FriendRemoved":
    case "FriendOnline":
    case "FriendOffline":
    case "FriendsChanged":
      refreshFriends();
      break;

    case "RecentConnectionsChanged":
      refreshRecent();
      break;

    case "FriendConnected":
      // 好友直连成功（与 Connected 事件配合；无需额外 UI）。
      break;
    case "FriendDisconnected":
      refreshFriends();
      break;

    case "Error":
      handleErrorEvent(d);
      break;
  }
}

function handleErrorEvent(d) {
  const code = d.code || "UNKNOWN";
  // 后台服务断开：显示「连接断开 [重新连接]」+ 自动重连（P0-5/P2-2）。
  if (code === "AGENT_STOPPED") {
    S.ctlErr = false;
    setConnState("DISCONNECTED");
    showReconnect();
    renderStatus({ state: "FAILED", user_facing: "网络服务未启动" });
    return;
  }
  // 网络服务不可达：不要只卡着等待，显示专用横幅（当前地址 + 重连 + 改设置）。
  if (code === "CONTROLLER_UNREACHABLE") {
    S.ctlErr = true;
    setConnState("ERROR");
    showReconnect();
    showControllerUnreachable(S.controllerUrl || "");
    renderStatus({ state: "FAILED", user_facing: "网络服务未启动" });
    if (S.view === "progress") setStep(-1);
    return;
  }
  if (S.view === "join") {
    showError($("join-error"), code);
    $("btn-join-connect").disabled = false;
  } else if (S.view === "progress") {
    setStep(-1);
    showError($("progress-error"), code);
    renderStatus({ state: "FAILED", user_facing: "连接失败" });
    $("progress-title").textContent = "连接失败";
  } else {
    showError($("home-error"), code);
    renderStatus({ state: "FAILED", user_facing: "连接失败" });
  }
}

function resetSessionUi() {
  stopCountdown();
  S.code = null;
  S.expiresAt = null;
  S.connectedInfo = null;
  $("create-code").textContent = "------";
  $("create-countdown").textContent = "--:--";
  setStep(STEP_FIND);
  hideError($("progress-error"));
  hideError($("join-error"));
  hideError($("home-error"));
  $("progress-title").textContent = "正在连接";
  $("btn-join-connect").disabled = false;
}

/* ---------------- 网络服务不可达横幅 ---------------- */

function showControllerUnreachable(url) {
  $("ctl-err-url").textContent = url || S.controllerUrl || "--";
  $("ctl-err").classList.remove("hidden");
}

function hideControllerUnreachable() {
  $("ctl-err").classList.add("hidden");
}

async function retryController() {
  const url = (S.controllerUrl || "").trim();
  if (!url) { show("settings"); syncControllerModeUI(); return; }
  try {
    await send("SetControllerUrl", { url });
    renderStatus({ state: "STARTING", user_facing: "正在连接服务..." });
  } catch (e) {
    // 重连失败会由 Agent 再发 CONTROLLER_UNREACHABLE 事件，横幅保持。
  }
}

/* ---------------- 综合修复 P0-5：实时连接状态机 ---------------- */

function setConnState(state) {
  if (S.connState === state) return;
  S.connState = state;
  if (state === "CONNECTED") {
    hideReconnect();
  }
}

function showReconnect() {
  const b = $("btn-reconnect");
  if (b) b.classList.remove("hidden");
}

function hideReconnect() {
  const b = $("btn-reconnect");
  if (b) b.classList.add("hidden");
}

// 更新首页顶部服务器 + 延迟（经 GetControllerStatus；与设置页同一数据源）。
function updateConnMeta(status) {
  if (!status) return;
  S.connMeta.server = status.url ? hostOf(status.url) : "--";
  S.connMeta.latency = status.connected ? status.latency_ms + " ms" : "--";
  $("conn-server").textContent = S.connMeta.server;
  $("conn-latency").textContent = S.connMeta.latency;
  const meta = $("conn-meta");
  if (meta) meta.classList.toggle("hidden", !status.connected);
}

function hostOf(url) {
  try { return new URL(url).host; } catch { return url || "--"; }
}

// 断开后自动重连（Agent 管道恢复时）：先清理残留会话 UI，再调 agent_connect。
async function reconnectNow() {
  const b = $("btn-reconnect");
  if (b) b.disabled = true;
  renderStatus({ state: "STARTING", user_facing: "正在连接服务..." });
  try {
    const r = await invoke("agent_connect");
    if (r && r.ok && r.data) {
      renderStatus(r.data);
      loadControllerStatus();
      refreshFriends();
      refreshRecent();
      toast("已重新连接");
    } else {
      showReconnect();
    }
  } catch (e) {
    // 失败：保持可重试（下次 poll 或手动点击再试）。
    showReconnect();
    toast("重新连接失败：" + formatError(e), true);
  } finally {
    if (b) b.disabled = false;
  }
}

// 心跳：定期探测 Agent 状态（P0-5）。GetStatus 失败 / AGENT_STOPPED → 显示断开 +
// 自动重连。恢复（READY/CONNECTED）→ 清除断开态。同时刷新连接延迟。
async function heartbeat() {
  let r = null;
  try {
    r = await ipcRequest("GetStatus");
  } catch { /* Agent 断开：走 r 为 null 分支 */ }
  if (r && r.ok && r.data) {
    const snap = r.data;
    renderStatus(snap);
    if (S.view === "progress" && snap.state === "CONFIGURING_OVERLAY") {
      setStep(STEP_OVERLAY);
    }
    if (snap.state === "FAILED" && S.view === "progress") {
      setStep(-1);
      $("progress-title").textContent = "连接失败";
    }
    if (snap.state === "READY" || snap.state === "CONNECTED") {
      // 已恢复：拉一次连接延迟（服务器 + 延迟实时刷新）。
      loadControllerStatus();
    }
  } else {
    // GetStatus 失败 → Agent 管道断开 → 断开态 + 自动重连。
    setConnState("DISCONNECTED");
    showReconnect();
    renderStatus({ state: "FAILED", user_facing: "网络服务未启动" });
  }
}

/* ---------------- GetStatus 心跳轮询（综合修复 P0-5：3s） ---------------- */

function startStatusPoll() {
  if (S.pollTimer) clearInterval(S.pollTimer);
  S.pollTimer = setInterval(heartbeat, 3000);
}

/* ---------------- 6 位码视图动作 ---------------- */

async function startCreate() {
  hideError($("home-error"));
  try {
    // 用户规格二/三：响应本身必须携带合法 6 位码，立即显示，不依赖后续事件。
    const r = await sendRaw("CreateQuickSession");
    const code = validateQuickCodeResponse(r.data);
    showQuickCode(code, r.data.expires_at);
  } catch (e) {
    showError($("home-error"), errorCode(e), formatError(e));
  }
}

async function startJoin() {
  // 用户规格七：join 前严格校验，长度≠6 不发；normalize 保留前导零。
  const code = normalizeQuickCode($("join-code").value);
  hideError($("join-error"));
  if (!/^\d{6}$/.test(code)) {
    showError($("join-error"), "SESSION_CODE_INVALID");
    return;
  }
  $("btn-join-connect").disabled = true;
  try {
    await send("JoinQuickSession", { code });
    show("progress");
    setStep(STEP_FIND);
  } catch (e) {
    showError($("join-error"), errorCode(e), formatError(e));
    $("btn-join-connect").disabled = false;
  }
}

async function cancelSession() {
  try { await send("CancelSession"); } catch { /* 事件兜底 */ }
  resetSessionUi();
  show("home");
  refreshFriends();
}

async function disconnectPeer() {
  if (S.connectedInfo && S.connectedInfo.peerDevice) {
    try { await send("DisconnectPeer", { peer: S.connectedInfo.peerDevice }); } catch { /* 事件兜底 */ }
  }
  resetSessionUi();
  show("home");
}

/* ---------------- 好友（M1-1） ---------------- */

async function refreshFriends() {
  if (!S.deviceId) return;
  try {
    const data = await send("ListFriends");
    S.friends = (data.friendships || []).map((f) => ({
      friendship_id: f.friendship_id,
      status: f.status,
      device_id: f.peer_device_id,
      name: f.peer_name || f.peer_device_id || "--",
      online: !!f.peer_online,
    }));
    renderFriendList();
    renderHomeFriends();
    renderInviteList();
  } catch (e) {
    // Controller 未就绪时不打扰用户。
    if (S.view === "friends") {
      $("friends-list").innerHTML = `<div class="empty">好友列表加载失败：${formatError(e)}</div>`;
    }
  }
}

function renderFriendList() {
  const box = $("friends-list");
  if (!S.friends.length) {
    box.innerHTML = `<div class="empty">暂无好友。点「邀请好友」发送邀请，收到邀请后在此接受。</div>`;
    return;
  }
  box.innerHTML = S.friends
    .map((f) => {
      const online = f.online ? '<span class="dot-online"></span>在线' : '<span class="dot-offline"></span>离线';
      const statusBadge =
        f.status === "PENDING" ? '<span class="badge-pending">待接受</span>' :
        f.status === "REMOVED" ? '<span class="badge-removed">已删除</span>' : online;
      const actions = [];
      if (f.status === "ACCEPTED") {
        actions.push(`<button class="btn btn-primary" data-act="connect" data-id="${f.friendship_id}" data-dev="${f.device_id}" data-name="${escapeHtml(f.name)}">连接</button>`);
        actions.push(`<button class="btn btn-secondary" data-act="detail" data-id="${f.friendship_id}" data-dev="${f.device_id}" data-name="${escapeHtml(f.name)}" data-online="${f.online}">详情</button>`);
      } else if (f.status === "PENDING") {
        actions.push(`<button class="btn btn-primary" data-act="accept" data-id="${f.friendship_id}">接受</button>`);
        actions.push(`<button class="btn btn-danger" data-act="reject" data-id="${f.friendship_id}">拒绝</button>`);
      } else {
        actions.push(`<button class="btn btn-secondary" data-act="delete" data-id="${f.friendship_id}">删除</button>`);
      }
      return `<div class="friend-row">
        <div class="friend-row-top">
          <span class="friend-name">${escapeHtml(f.name)}</span>
          <span class="friend-row-status">${statusBadge}</span>
        </div>
        <div class="friend-sub">${shortId(f.device_id)}</div>
        <div class="row-actions">${actions.join("")}</div>
      </div>`;
    })
    .join("");
}

function renderHomeFriends() {
  const box = $("home-friends");
  const accepted = S.friends.filter((f) => f.status === "ACCEPTED");
  if (!accepted.length) {
    box.innerHTML = `<span class="muted">暂无好友，点「邀请好友」添加。</span>`;
    return;
  }
  box.innerHTML = accepted
    .map((f) => `<div class="friend-mini-row">
        <div><div class="friend-name">${f.online ? '<span class="dot-online"></span>' : '<span class="dot-offline"></span>'}${escapeHtml(f.name)}</div>
        <div class="friend-sub">${f.online ? "在线" : "离线"}</div></div>
        <button class="friend-connect" data-act="home-connect" data-dev="${f.device_id}" data-name="${escapeHtml(f.name)}" ${f.online ? "" : "disabled"}>${f.online ? "连接" : "离线"}</button>
      </div>`)
    .join("");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------- 最近连接（M1-1.5） ---------------- */

// 拉取最近连接（6 位码临时连接历史，与好友关系分离；对端指纹来自 Controller Registry）。
async function refreshRecent() {
  if (!S.deviceId) return;
  try {
    const data = await send("ListRecentConnections");
    S.recent = data.recent_connections || [];
    renderHomeRecent();
  } catch (e) {
    // Controller 未就绪时静默；首页给出可见错误。
    renderHomeRecent();
  }
}

// 相对时间（"X分钟前"）；解析失败回退原始时间。
function recentRelativeTime(iso) {
  if (!iso) return "--";
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return iso;
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60) return "刚刚";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}分钟前`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}小时前`;
  const d = Math.floor(h / 24);
  return `${d}天前`;
}

// 最近连接在好友列表中的关系（用于「好友」标记）：friend → ACCEPTED / PENDING / null。
function recentFriendStatus(deviceId) {
  const f = S.friends.find((x) => x.device_id === deviceId);
  if (!f) return null;
  if (f.status === "ACCEPTED") return "好友";
  if (f.status === "PENDING") return "待接受";
  return null;
}

function renderHomeRecent() {
  const box = $("home-recent");
  if (!S.recent.length) {
    box.innerHTML = `<span class="muted">暂无最近连接</span>`;
    return;
  }
  box.innerHTML = S.recent
    .map((r) => {
      const name = r.remote_name || shortId(r.remote_device_id);
      const fs = recentFriendStatus(r.remote_device_id);
      const badge = fs ? `<span class="badge-pending">${fs}</span>` : "";
      const path = r.last_path === "n2n" ? "N2N" : "DirectLink";
      const actions = [];
      actions.push(`<button class="friend-connect" data-act="recent-connect" data-dev="${r.remote_device_id}" data-name="${escapeHtml(name)}">连接</button>`);
      if (!fs) actions.push(`<button class="btn btn-secondary btn-xs" data-act="recent-add-friend" data-dev="${r.remote_device_id}" data-name="${escapeHtml(name)}">添加好友</button>`);
      actions.push(`<button class="btn btn-secondary btn-xs" data-act="recent-delete" data-dev="${r.remote_device_id}">删除</button>`);
      return `<div class="friend-mini-row">
        <div>
          <div class="friend-name">${escapeHtml(name)} ${badge}</div>
          <div class="friend-sub">上次连接：${recentRelativeTime(r.last_connected_at)} · 路径：${path} · ${r.connection_count}次</div>
        </div>
        <div class="recent-actions">${actions.join("")}</div>
      </div>`;
    })
    .join("");
}

// 最近连接 → 连接（规格十）：好友 → 一键 ConnectFriend；
// 非好友 → 重新创建临时 6 位 session（不自动永久授权），把码给对方确认。
async function recentConnect(deviceId, name) {
  const fs = recentFriendStatus(deviceId);
  if (fs === "好友") {
    friendConnect(deviceId, name);
    return;
  }
  hideError($("home-error"));
  try {
    const r = await sendRaw("CreateQuickSession");
    const code = validateQuickCodeResponse(r.data);
    showQuickCode(code, r.data.expires_at);
    toast("对方不是好友，已创建临时 6 位码：请把 " + code + " 发给对方确认连接（不建立长期授权）");
  } catch (e) {
    showError($("home-error"), errorCode(e), formatError(e));
  }
}

async function deleteRecent(deviceId) {
  try {
    await send("DeleteRecentConnection", { remote_device_id: deviceId });
    S.recent = S.recent.filter((r) => r.remote_device_id !== deviceId);
    renderHomeRecent();
    toast("已删除最近连接记录");
  } catch (e) {
    toastError("删除失败", e);
  }
}

function recentAddFriend() {
  // 从最近连接添加好友：走标准邀请流程（生成邀请 → 对方兑换 → 成为好友）。
  openInviteModal();
}

async function friendConnect(deviceId, name) {
  hideError($("home-error"));
  try {
    await send("ConnectFriend", { device_id: deviceId });
    $("progress-title").textContent = "正在连接" + (name ? " " + name : "");
    setStep(STEP_FIND);
    show("progress");
  } catch (e) {
    showError($("home-error"), errorCode(e), formatError(e));
    if (S.view === "friends") {
      const box = $("friends-list");
      const err = document.createElement("div");
      err.className = "empty";
      err.textContent = "连接失败：" + (ERROR_TEXT[errorCode(e)] || formatError(e));
      box.prepend(err);
    }
  }
}

async function friendAccept(friendshipId) {
  try {
    await send("AcceptFriendship", { friendship_id: friendshipId });
    refreshFriends();
  } catch (e) { toastError("接受失败", e); }
}

async function friendReject(friendshipId) {
  try {
    await send("RejectFriendship", { friendship_id: friendshipId });
    refreshFriends();
  } catch (e) { toastError("删除失败", e); }
}

function openFriendDetail(f) {
  $("fd-title").textContent = f.name;
  $("fd-body").innerHTML = `
    <div class="info-row"><span class="info-label">设备</span><span class="info-value mono">${escapeHtml(f.name)}</span></div>
    <div class="info-row"><span class="info-label">device_id</span><span class="info-value mono">${shortId(f.device_id)}</span></div>
    <div class="info-row"><span class="info-label">状态</span><span class="info-value">${f.online ? "在线" : "离线"}</span></div>
    <div class="info-row"><span class="info-label">授权</span><span class="info-value">已授权</span></div>`;
  $("modal-friend").dataset.dev = f.device_id;
  $("modal-friend").dataset.name = f.name;
  $("modal-friend").dataset.fid = f.friendship_id;
  $("modal-friend").classList.remove("hidden");
}

/* ---------------- 邀请（M1-1） ---------------- */

function openInviteModal() {
  $("invite-form").classList.remove("hidden");
  $("invite-result").classList.add("hidden");
  S.inviteResult = null;
  refreshInviteList();
  $("modal-invite").classList.remove("hidden");
}

async function generateInvite() {
  let ttlVal = document.querySelector('input[name="ttl"]:checked').value;
  let maxUses = Number(document.querySelector('input[name="uses"]:checked').value);
  if (ttlVal === "custom") {
    const h = Number($("invite-custom-h").value);
    if (!h || h < 1 || h > 720) {
      toast("自定义有效期需填 1-720 小时");
      return;
    }
    ttlVal = h + "h";
  }
  try {
    const data = await send("CreateFriendInvite", { ttl: ttlVal, max_uses: maxUses });
    const token = data.invite_token;
    const uri = "meshlink://invite/" + data.invite_id + "." + token;
    S.inviteResult = { uri, token };
    $("invite-uri").textContent = uri;
    $("invite-token").textContent = token;
    $("invite-form").classList.add("hidden");
    $("invite-result").classList.remove("hidden");
    refreshInviteList();
  } catch (e) {
    toastError("生成失败", e);
  }
}

async function refreshInviteList() {
  try {
    const data = await send("ListInvites");
    const list = data.invites || [];
    const box = $("invite-list");
    if (!list.length) {
      box.innerHTML = `<span class="muted">暂无邀请</span>`;
      return;
    }
    box.innerHTML = list
      .map((i) => {
        const uses = i.max_uses === 0 ? "不限次" : `${i.used_count}/${i.max_uses}`;
        const st = i.status === "ACTIVE" ? "未使用" : i.status === "EXHAUSTED" ? "已用尽" : i.status === "REVOKED" ? "已撤销" : i.status;
        const revoke = i.status === "ACTIVE" ? `<button class="btn btn-danger" data-act="revoke" data-id="${i.invite_id}">撤销</button>` : "";
        return `<div class="friend-mini-row"><div><div class="friend-name">邀请 ${shortId(i.invite_id)}</div>
          <div class="friend-sub">${st} · 使用 ${uses}</div></div>${revoke}</div>`;
      })
      .join("");
  } catch { /* 忽略 */ }
}

async function revokeInvite(inviteId) {
  try {
    await send("RevokeInvite", { invite_id: inviteId });
    refreshInviteList();
  } catch (e) { toastError("撤销失败", e); }
}

function extractInviteRef(input) {
  const s = input.trim();
  if (!s) return null;
  // meshlink://invite/<invite_id>.<token>
  const m = s.match(/meshlink:\/\/invite\/([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]+)/);
  if (m) return { invite_id: m[1], token: m[2] };
  // 直接粘贴 "invite_id.token" 组合
  const d = s.match(/^([A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]{10,})$/);
  if (d) return { invite_id: d[1], token: d[2] };
  return null;
}

async function redeemInvite(input) {
  const ref = extractInviteRef(input);
  if (!ref) {
    $("redeem-error").textContent = "邀请格式无效：请粘贴 meshlink://invite/ 链接或「邀请ID.邀请码」。";
    return;
  }
  $("redeem-error").textContent = "";
  try {
    const data = await send("RedeemFriendInvite", { invite_id: ref.invite_id, token: ref.token });
    $("modal-redeem").classList.add("hidden");
    $("redeem-input").value = "";
    // 兑换成功 → PENDING 好友关系；由对方接受后成为好友（好友关系与 Session 分离）。
    const creatorName = data.creator_name || data.creator_device_id || "";
    if (creatorName) {
      $("home-error").querySelector(".error-text").textContent = `已向 ${creatorName} 发出好友申请，等待对方接受。`;
      $("home-error").classList.remove("hidden");
    }
    refreshFriends();
    show("friends");
  } catch (e) {
    $("redeem-error").textContent = "兑换失败：" + (ERROR_TEXT[errorCode(e)] || formatError(e));
  }
}

/* ---------------- 设备（M1-1） ---------------- */

async function refreshDevices() {
  const box = $("devices-list");
  box.innerHTML = `<span class="muted">加载中...</span>`;
  try {
    const data = await send("ListDevices");
    const list = data.devices || [];
    if (!list.length) {
      box.innerHTML = `<div class="empty">暂无设备</div>`;
      return;
    }
    box.innerHTML = list
      .map((d) => `<div class="device-row">
          <div class="device-row-top">
            <span class="friend-name">${d.online ? '<span class="dot-online"></span>' : '<span class="dot-offline"></span>'}${escapeHtml(d.device_name || d.device_id)}</span>
            <span class="friend-row-status">${d.online ? "在线" : "离线"}</span>
          </div>
          <div class="friend-sub">device_id ${shortId(d.device_id)}</div>
          <div class="friend-sub">虚拟 IP：${d.overlay_ip || "--"} · 最后在线：${d.last_seen ? new Date(d.last_seen).toLocaleString() : "--"}</div>
        </div>`)
      .join("");
  } catch (e) {
    box.innerHTML = `<div class="empty">设备列表加载失败：${formatError(e)}</div>`;
  }
}

/* ---------------- 设置：连接模式（创建连接 / 加入连接，用户化） ---------------- */

// 综合修复 P0-2：默认公网 Controller（用户已实测可用）。JS 不再各自硬编码 127.0.0.1。
const DEFAULT_PUBLIC_CONTROLLER_URL = "https://controller.bpbpanel.cc.cd";

// 用户可见模式：创建连接 = 本机发起网络（内部 local，有局域网地址自动启用局域网访问）；
// 加入连接 = 连接别人的网络（内部 remote，不启动本机服务）。
function currentControllerMode() {
  return $("mode-local").checked ? "local" : "remote";
}

function applyControllerModeUI(mode, url) {
  const local = mode === "local" || mode === "lan";
  $("mode-local").checked = local;
  $("mode-remote").checked = !local;
  syncControllerModeUI();
  const u = (url || "").trim();
  $("controller-url").value = u;
  if (!local && !u) $("controller-url").value = "";
}

function syncControllerModeUI() {
  const local = currentControllerMode() === "local";
  $("ctl-url-row").style.display = "flex";
  if (local) {
    // 综合修复 P1-3：创建连接不再展示「我的电脑地址」——公网跨网无意义；
    // 连接服务始终使用当前服务器（默认公网 Controller）。
    $("ctl-mode-hint").textContent = "我的电脑作为连接发起方：生成连接码，让其他设备加入。";
  } else {
    $("ctl-mode-hint").textContent = "我的电脑加入别人创建的网络。需要填写对方提供的服务器地址。";
  }
}

function isProdHttpRejected(url) {
  let u;
  try { u = new URL(url); } catch { return true; } // 非法 URL 直接拒
  if (u.protocol === "http:") {
    // DEV 白名单：仅 localhost / 127.0.0.1 / RFC1918 私网（与 controller-client 对齐）。
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return false;
    if (isPrivateHost(u.hostname)) return false;
    return true; // 公网明文 HTTP 拒绝
  }
  return false;
}

// RFC1918 私网判定（10/8、172.16/12、192.168/16；与 Rust controller-client 对齐）。
function isPrivateHost(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const a = Number(m[1]);
  if (a === 10) return true;
  if (a === 172 && Number(m[2]) >= 16 && Number(m[2]) <= 31) return true;
  if (a === 192 && Number(m[2]) === 168) return true;
  return false;
}

async function testController() {
  const mode = currentControllerMode();
  let url = ($("controller-url").value || "").trim();
  const local = mode === "local";
  $("settings-error").textContent = "";
  if (!local && isProdHttpRejected(url)) {
    $("settings-error").textContent = "加入连接需要有效的服务器地址（https:// 或可信局域网 http://）。";
    return;
  }
  if (!local && !url) {
    $("settings-error").textContent = "请先填写对方提供的服务器地址（可展开「高级设置」）。";
    return;
  }
  try {
    // 通过 Agent GetControllerStatus 测试（Agent 校验 + 健康检查）。
    const data = await send("GetControllerStatus");
    const c = data.connected;
    $("ctl-state").textContent = c ? "已连接" : "未连接";
    $("ctl-effective-url").textContent = data.url || "--";
    $("ctl-latency").textContent = c ? data.latency_ms + " ms" : "--";
    $("ctl-server").textContent = data.url ? new URL(data.url).host : "--";
    $("ctl-device").textContent = data.device_id || "--";
    if (c) $("settings-error").textContent = "连接正常（" + data.url + "）。";
    else $("settings-error").textContent = "无法连接服务器，请检查地址与网络。";
  } catch (e) {
    $("settings-error").textContent = "测试失败：" + (ERROR_TEXT[errorCode(e)] || formatError(e));
  }
}

async function saveController() {
  const mode = currentControllerMode();
  let url = ($("controller-url").value || "").trim();
  $("settings-error").textContent = "";
  const local = mode === "local";
  if (!local) {
    if (!url) { $("settings-error").textContent = "请填写对方提供的服务器地址（可展开「高级设置」）。"; return; }
    if (isProdHttpRejected(url)) {
      $("settings-error").textContent = "加入连接需要有效的服务器地址（https:// 或可信局域网 http://）。";
      return;
    }
  }
  try {
    const cfg = await invoke("save_controller_config", { mode, url });
    $("settings-error").textContent = "已保存，正在应用...";
    // 持久化 UI 内存态 + 让 Agent 用新地址重连（若已在跑）。
    S.controllerUrl = (cfg && cfg.controller_url) || url;
    try { await send("SetControllerUrl", { url: S.controllerUrl }); } catch { /* Agent 未在跑，由重连处理 */ }
    invoke("agent_connect").then(() => loadControllerStatus()).catch(() => {});
    setTimeout(testController, 1500);
  } catch (e) {
    $("settings-error").textContent = "保存失败：" + (ERROR_TEXT[errorCode(e)] || formatError(e));
  }
}

/* ---------------- 连接请求（M1-1） ---------------- */

async function acceptConnectionRequest() {
  if (!S.pendingReq) return;
  $("modal-request").classList.add("hidden");
  try {
    await send("AcceptConnectionRequest", { session_id: S.pendingReq.session_id });
    $("progress-title").textContent = "正在连接" + (S.pendingReq.from_name || "");
    setStep(STEP_FIND);
    show("progress");
  } catch (e) {
    showError($("home-error"), errorCode(e), formatError(e));
  } finally {
    S.pendingReq = null;
  }
}

async function rejectConnectionRequest() {
  if (!S.pendingReq) return;
  const sid = S.pendingReq.session_id;
  S.pendingReq = null;
  $("modal-request").classList.add("hidden");
  try { await send("RejectConnectionRequest", { session_id: sid }); } catch { /* 尽力 */ }
}

/* ---------------- 诊断（高级） ---------------- */

async function openDiagnostics() {
  show("diag");
  $("diag-body").innerHTML = "加载中...";
  try {
    const data = await send("GetDiagnostics");
    renderDiagnostics(data);
  } catch (e) {
    $("diag-body").innerHTML = "诊断加载失败：" + formatError(e);
  }
}

/* ---------------- 诊断中心（综合修复 P2-1：健康/详情/日志三层） ---------------- */

async function openDiagCenter() {
  show("diagcenter");
  renderDiagCenter();
  loadDiagLogs("all");
}

// 第一、二层：健康状态 + 详细信息（GetControllerStatus + GetDiagnostics）。
async function renderDiagCenter() {
  // 连接服务（Agent 在跑） + 服务器连接（Controller）——同一数据源。
  try {
    const ctl = await send("GetControllerStatus");
    $("dc-h-agent").textContent = "正常";
    $("dc-h-agent").className = "dc-health-val ok";
    $("dc-h-ctl").textContent = ctl.connected ? "正常" : "断开";
    $("dc-h-ctl").className = "dc-health-val " + (ctl.connected ? "ok" : "bad");
    $("dc-server").textContent = ctl.url ? hostOf(ctl.url) : "--";
    $("dc-latency").textContent = ctl.connected ? ctl.latency_ms + " ms" : "--";
    $("dc-device").textContent = ctl.device_id || "--";
  } catch (e) {
    $("dc-h-agent").textContent = "异常";
    $("dc-h-agent").className = "dc-health-val bad";
    $("dc-h-ctl").textContent = "断开";
    $("dc-h-ctl").className = "dc-health-val bad";
    $("dc-latency").textContent = "--";
  }
  // 网络：无 Peer 是正常空闲态（"暂无连接数据"与"接口失败"分开）。
  try {
    const d = await send("GetDiagnostics");
    const hasPeer = d.session && d.session.peers && d.session.peers.length;
    $("dc-path").textContent = d.current_path === "n2n" ? "N2N Relay" : d.current_path === "directlink" ? "DirectLink" : "--";
    $("dc-h-net").textContent = hasPeer ? "正常" : "空闲";
    $("dc-h-net").className = "dc-health-val" + (hasPeer ? " ok" : "");
  } catch {
    $("dc-h-net").textContent = "未知";
    $("dc-h-net").className = "dc-health-val bad";
  }
  $("dc-uptime").textContent = "本次运行";
}

// 第三层：日志查看（分类读取 logs/ 目录）。
async function loadDiagLogs(cat) {
  const view = $("dc-log-view");
  view.textContent = "加载中...";
  try {
    const data = await invoke("read_log_files", { category: cat, limit: 300 });
    const lines = (data && data.lines) || [];
    view.textContent = lines.length ? lines.join("\n") : "（暂无日志）";
  } catch (e) {
    view.textContent = "日志加载失败：" + formatError(e);
  }
}

function renderDiagnostics(d) {
  const sel = d.selected_pair || {};
  const noise = d.noise || {};
  const punch = d.punch_evidence || {};
  const overlay = d.overlay || {};
  const session = d.session || {};
  const rttMs = Number.isFinite(punch.first_punch_tx_ms) && Number.isFinite(punch.first_peer_rx_ms)
    ? punch.first_peer_rx_ms - punch.first_punch_tx_ms : null;

  const row = (k, v) =>
    `<div class="diag-row"><span class="diag-key">${k}</span><span class="diag-val">${v ?? "--"}</span></div>`;

  // 无 Peer/无会话是正常状态（"暂无连接数据"），与"诊断接口失败"严格分开（用户规格七）。
  const hasSession = !!(d.session && d.session.peers && d.session.peers.length);
  const noDataNote = hasSession ? "" : `<p class="muted" style="margin-bottom:10px">暂无连接数据（当前未连接 Peer，仅显示基础状态）。</p>`;

  let html = noDataNote + `<div class="diag-section">路径</div>`;
  html += row("Path", sel.local ? `${sel.local} → ${sel.remote}` : "未建立");
  html += row("当前路径", d.current_path === "n2n" ? "N2N Relay" : d.current_path === "directlink" ? "DirectLink" : "--");
  html += row("对端类型", sel.remote_kind || "--");
  html += row("RTT", rttMs !== null ? rttMs + " ms" : "--");
  html += row("STUN", d.stun || "未使用（同机/直连）");
  html += `<div class="diag-section">Overlay</div>`;
  html += row("Overlay IP", overlay.local_ip || "--");
  html += row("路由", (overlay.peer_routes && overlay.peer_routes.join(" ")) || "--");
  html += row("网段", session.overlay_subnet || "--");
  html += row("后端", overlay.kind || "--");
  html += `<div class="diag-section">身份与会话</div>`;
  html += row("Peer device", (session.peers && session.peers[0] && session.peers[0].device_id) || "--");
  html += row("本机设备", d.device_id || "--");
  html += row("Controller", d.controller || "--");
  html += row("DirectLink Track", punch.role === "creator" ? "B (MinimalPunchAgent)" : punch.role || "--");
  html += row("Noise epoch", noise.epoch ?? "--");
  html += row("状态", d.state_user_facing || d.state || "--");
  html += `<pre class="diag-raw">${JSON.stringify(d, null, 2)}</pre>`;
  $("diag-body").innerHTML = html;
}

/* ---------------- 事件委托（列表按钮） ---------------- */

document.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-act]");
  if (!btn) return;
  const act = btn.dataset.act;
  switch (act) {
    case "home-connect":
      friendConnect(btn.dataset.dev, btn.dataset.name);
      break;
    case "connect":
      friendConnect(btn.dataset.dev, btn.dataset.name);
      break;
    case "detail": {
      const f = S.friends.find((x) => x.friendship_id === btn.dataset.id) ||
        { name: btn.dataset.name, device_id: btn.dataset.dev, online: btn.dataset.online === "true" };
      openFriendDetail(f);
      break;
    }
    case "accept":
      friendAccept(btn.dataset.id);
      break;
    case "reject":
      if (confirm("删除/拒绝该好友（撤销授权）？")) friendReject(btn.dataset.id);
      break;
    case "delete":
      if (confirm("删除该好友（撤销授权）？")) friendReject(btn.dataset.id);
      break;
    case "revoke":
      if (confirm("撤销该邀请？撤销后旧邀请码立即失效。")) revokeInvite(btn.dataset.id);
      break;
    case "recent-connect":
      recentConnect(btn.dataset.dev, btn.dataset.name);
      break;
    case "recent-add-friend":
      recentAddFriend();
      break;
    case "recent-delete":
      if (confirm("删除这条最近连接记录？（只删除本地历史，不影响好友关系）")) deleteRecent(btn.dataset.dev);
      break;
  }
});

/* ---------------- 启动 ---------------- */

async function boot() {
  try {
    const r = await invoke("agent_connect");
    if (r && r.ok && r.data) renderStatus(r.data);
    else if (r && !r.ok && r.error) {
      // 综合修复 P2-2：启动失败给出用户化提示 + 查看诊断。
      $("status-pill").className = "dot dot-red";
      $("status-text").textContent = "连接服务启动失败";
      showReconnect();
      toast("连接服务启动失败，请查看诊断中心获取详情", true);
    }
  } catch (e) {
    $("status-pill").className = "dot dot-red";
    $("status-text").textContent = "连接服务启动失败";
    showReconnect();
    showError($("home-error"), errorCode(e), "连接服务启动失败：" + formatError(e));
  }
  await listen("agent-event", (e) => handleEvent(e.payload));
  await listen("meshlink-invite", (e) => {
    // 启动参数 --invite 或 URI 触达：预填兑换框。
    const v = e.payload && e.payload.value;
    if (v) {
      $("redeem-input").value = v;
      $("modal-redeem").classList.remove("hidden");
    }
  });
  startStatusPoll();
  // 读取已保存的连接配置回填设置页（含模式与生效地址）；无保存值保持默认公网。
  try {
    const cfg = await invoke("get_controller_config");
    if (cfg) {
      S.controllerCfg = cfg;
      S.controllerUrl = cfg.effective_url || S.controllerUrl;
      if (cfg.mode) applyControllerModeUI(cfg.mode, cfg.controller_url || cfg.effective_url || "");
      else applyControllerModeUI("remote", cfg.controller_url || "");
    }
  } catch { /* 默认值由 spawn_agent_process 兜底 */ }
  // 首次启动即加载「当前地址 / 连接状态」（无需先点进设置页）。
  loadControllerStatus();
  refreshFriends();
  refreshRecent();
}

/* ---------------- 事件绑定 ---------------- */

document.querySelectorAll(".nav-btn").forEach((b) => {
  b.addEventListener("click", () => {
    const v = b.dataset.view;
    show(v);
    if (v === "friends") refreshFriends();
    if (v === "devices") refreshDevices();
    if (v === "settings") { syncControllerModeUI(); loadControllerStatus(); }
    if (v === "home") refreshRecent();
  });
});

async function loadControllerStatus() {
  try {
    const data = await send("GetControllerStatus");
    $("ctl-state").textContent = data.connected ? "已连接" : "未连接";
    $("ctl-effective-url").textContent = data.url || "--";
    $("ctl-latency").textContent = data.connected ? data.latency_ms + " ms" : "--";
    $("ctl-server").textContent = data.url ? hostOf(data.url) : "--";
    $("ctl-device").textContent = data.device_id || "--";
    // 首页顶部服务器 + 延迟（P0-5 实时连接状态）。
    S.controllerUrl = data.url || S.controllerUrl;
    updateConnMeta(data);
  } catch { /* 忽略 */ }
}

$("btn-create").addEventListener("click", startCreate);
$("btn-join").addEventListener("click", () => { hideError($("join-error")); $("join-code").value = ""; show("join"); });
$("btn-invite-2").addEventListener("click", openInviteModal);
$("btn-ctl-retry").addEventListener("click", retryController);
$("btn-ctl-change").addEventListener("click", () => { show("settings"); const el = $("controller-url"); el.focus(); el.select(); });
$("btn-noconfig-settings").addEventListener("click", () => { show("settings"); const el = $("controller-url"); el.focus(); el.select(); });
$("mode-local").addEventListener("change", syncControllerModeUI);
$("mode-remote").addEventListener("change", syncControllerModeUI);
$("btn-copy-code").addEventListener("click", copyQuickCode);
$("btn-join-connect").addEventListener("click", startJoin);
$("btn-join-back").addEventListener("click", () => { hideError($("join-error")); show("home"); });
$("btn-cancel-progress").addEventListener("click", cancelSession);
$("btn-disconnect").addEventListener("click", disconnectPeer);
$("btn-connected-home").addEventListener("click", () => show("home"));
$("btn-diag").addEventListener("click", openDiagnostics);
$("btn-diag-back").addEventListener("click", () => show("home"));
// 综合修复 P0-5：首页「重新连接」按钮。
$("btn-reconnect").addEventListener("click", reconnectNow);
// 综合修复 P2-1：诊断中心入口与返回。
$("btn-diagcenter").addEventListener("click", openDiagCenter);
$("btn-diagcenter-back").addEventListener("click", () => show("settings"));
document.querySelectorAll(".dc-tab").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".dc-tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    loadDiagLogs(b.dataset.logcat);
  });
});
$("join-code").addEventListener("input", (e) => {
  e.target.value = normalizeQuickCode(e.target.value);
});
$("join-code").addEventListener("paste", (e) => {
  // 用户规格六：paste 必须 preventDefault + clipboardData.getData("text") + normalize，
  // 禁止读取 keyCode/charCode/event.which。粘贴前导零 001234 必须完整保留。
  e.preventDefault();
  const text = e.clipboardData ? e.clipboardData.getData("text") : "";
  e.target.value = normalizeQuickCode(text);
  e.target.dispatchEvent(new Event("input", { bubbles: true }));
});
$("join-code").addEventListener("keydown", (e) => { if (e.key === "Enter") startJoin(); });

/* 邀请模态 */
$("invite-gen").addEventListener("click", generateInvite);
$("invite-cancel").addEventListener("click", () => $("modal-invite").classList.add("hidden"));
$("invite-done").addEventListener("click", () => $("modal-invite").classList.add("hidden"));
$("invite-copy-uri").addEventListener("click", () => { if (S.inviteResult) copyText(S.inviteResult.uri); });
$("invite-copy-token").addEventListener("click", () => { if (S.inviteResult) copyText(S.inviteResult.token); });
$("invite-custom-h").addEventListener("input", (e) => {
  document.querySelector('input[name="ttl"][value="custom"]').checked = true;
});

/* 兑换模态 */
$("redeem-go").addEventListener("click", () => redeemInvite($("redeem-input").value));
$("redeem-cancel").addEventListener("click", () => { $("modal-redeem").classList.add("hidden"); $("redeem-input").value = ""; $("redeem-error").textContent = ""; });
$("redeem-input").addEventListener("keydown", (e) => { if (e.key === "Enter") redeemInvite($("redeem-input").value); });

/* 连接请求模态 */
$("req-accept").addEventListener("click", acceptConnectionRequest);
$("req-reject").addEventListener("click", rejectConnectionRequest);

/* 好友详情模态 */
$("fd-connect").addEventListener("click", () => {
  const dev = $("modal-friend").dataset.dev;
  const name = $("modal-friend").dataset.name;
  $("modal-friend").classList.add("hidden");
  friendConnect(dev, name);
});
$("fd-delete").addEventListener("click", () => {
  const fid = $("modal-friend").dataset.fid;
  $("modal-friend").classList.add("hidden");
  if (fid && confirm("删除该好友（撤销授权）？")) friendReject(fid);
});
$("fd-close").addEventListener("click", () => $("modal-friend").classList.add("hidden"));

/* 设置页 */
$("btn-test-controller").addEventListener("click", testController);
$("btn-save-controller").addEventListener("click", saveController);
$("controller-url").addEventListener("keydown", (e) => { if (e.key === "Enter") saveController(); });

boot();

/* 测试钩子：仅当 window.__MESHLINK_TEST__ 存在时暴露内部状态（生产不启用）。
 * 用于 quick_code_ui_contract.test.js 读取 S（const 顶层绑定不会成为 VM global）。 */
if (typeof window !== "undefined" && window.__MESHLINK_TEST__) {
  window.__MESHLINK_TEST__.S = S;
  window.__MESHLINK_TEST__.ERROR_TEXT = ERROR_TEXT;
}
