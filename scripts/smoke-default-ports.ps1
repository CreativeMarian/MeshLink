# MeshLink release 二进制默认端口冒烟（用户 Bug 复现验证）
#
# 场景：controller.exe 无 -addr、mesh-agent.exe 无 MESHLINK_CONTROLLER_URL，
# 双方都走「默认值」——若默认值漂移（8080 vs 18080）本脚本 FAIL。
#
# 判定委托给确定性的 Rust 冒烟测试（crates/mesh-agent/tests/release_binary_smoke.rs，
# 用 Rust 原生 PipeClient 轮询 GetStatus，不依赖日志 flush / .NET 管道兼容性）：
#   1) 直接执行 dist\controller.exe（不传 -addr）→ 必须监听 127.0.0.1:18080；
#   2) 启动 dist\mesh-agent.exe（无 MESHLINK_CONTROLLER_URL）→ 默认连 18080；
#   3) 必须到达 READY 并收到 ControllerConnected，且无 CONTROLLER_UNREACHABLE。
#
# 用法（在项目根 E:\Demo\NtNTier 下）：
#   powershell -ExecutionPolicy Bypass -File scripts\smoke-default-ports.ps1
#
# 要求：dist\controller.exe / dist\mesh-agent.exe 已构建（release）。

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $root "dist"
if (-not (Test-Path (Join-Path $dist "controller.exe"))) {
    Write-Error "缺少 dist\controller.exe（先构建 dist）"; exit 2
}
if (-not (Test-Path (Join-Path $dist "mesh-agent.exe"))) {
    Write-Error "缺少 dist\mesh-agent.exe（先构建 dist）"; exit 2
}

# 预检查：18080 若已被占用，冒烟测试会连到已有服务——显式提示，避免误判。
$busy = Test-NetConnection -ComputerName 127.0.0.1 -Port 18080 -WarningAction SilentlyContinue -InformationLevel Quiet
if ($busy) {
    Write-Host "[WARN] 127.0.0.1:18080 已被占用；冒烟将连接现有服务（仍验证 Agent 默认地址）。" -ForegroundColor Yellow
}

Write-Host "== 运行 release 冒烟（controller 无 -addr → agent 无 URL → READY）==" -ForegroundColor Cyan
Push-Location $root
try {
    cargo test -p mesh-agent --test release_binary_smoke -- --ignored --nocapture
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($code -eq 0) {
    Write-Host "RESULT: PASS（Controller 默认 18080 ↔ Agent 默认 18080 天然匹配）" -ForegroundColor Green
    exit 0
} else {
    Write-Host "RESULT: FAIL" -ForegroundColor Red
    exit 1
}
