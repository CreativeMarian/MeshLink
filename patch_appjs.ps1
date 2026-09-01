$ErrorActionPreference = 'Stop'
$p = 'E:\Demo\NtNTier\apps\meshlink-ui\ui\app.js'
$t = [System.IO.File]::ReadAllText($p)
# 目标文件为 LF；here-string 统一归一化到 LF 再匹配。
$anchor0 = @'
    $("home-device-card").style.display = "flex";
  }
  if (snap && snap.session && snap.session.peers && snap.session.peers) {
'@
$anchor = $anchor0 -replace "`r`n", "`n"

$ins0 = @'
    $("home-device-card").style.display = "flex";
  }
  // 用户规格四：GetStatus active_session 恢复 6 位码（UI 刷新 / 页面切换 / 窗口重绘）。
  if (snap && snap.active_session && isValidQuickCode(snap.active_session.code)) {
    S.code = snap.active_session.code;
    const st = snap.active_session.status;
    if ((st === "WAITING_FOR_PEER" || st === "SESSION_CREATING") &&
        (S.view === "home" || S.view === "friends")) {
      showQuickCode(S.code, snap.active_session.expires_at);
    } else if (S.view === "create" && isValidQuickCode(S.code)) {
      $("create-code").textContent = S.code;
      if (snap.active_session.expires_at) startCountdown(snap.active_session.expires_at);
    }
  }
  if (snap && snap.session && snap.session.peers && snap.session.peers) {
'@
$ins = $ins0 -replace "`r`n", "`n"

if (-not $t.Contains($anchor)) {
  Write-Output 'ANCHOR NOT FOUND'
  exit 1
}
$t = $t.Replace($anchor, $ins)
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($p, $t, $utf8)
Write-Output 'WRITTEN OK'
