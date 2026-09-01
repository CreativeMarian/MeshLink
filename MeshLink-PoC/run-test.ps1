# ============================================================
#  M0-4R DirectLink 直连测试（朋友模式：双击 run-test.bat 启动）
#  §十  窗口只显示关键状态（[UI] 行翻译成人话），全部技术细节写 logs\client.log
#  §十一 测试结束一键打包 MeshLink-Test-<test_id>.zip（只含测试报告，不含其他文件）
#  §十二 运行前显示一次隐私说明（报告含公网 IP / 局域网 IP / 网络接口信息）
#  模式：
#    [1] 加入测试：对方已生成连接码，粘贴即测（Track B / Track A 均可）
#    [2] 发起测试：本机生成连接码发给对方（Track B 推荐；Track A 需二次回传 Answer Code）
#    [3] 矩阵测试：自动多轮（默认 20），需要双方都能访问同一个共享文件夹
#  保存格式要求：UTF-8 with BOM（否则 Windows PowerShell 5.1 按 ANSI 解析会乱码）。
# ============================================================
$ErrorActionPreference = 'Stop'
try {
    $Host.UI.RawUI.WindowTitle = 'MeshLink P2P 测试'
    # directlink-poc.exe 输出 UTF-8：设控制台解码避免中文乱码（与系统代码页无关）
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

    $exe    = Join-Path $PSScriptRoot 'directlink-poc.exe'
    $outDir = Join-Path $PSScriptRoot 'results'
    $logDir = Join-Path $PSScriptRoot 'logs'
    $testId = 'friend-' + (Get-Date -Format 'yyyyMMdd-HHmmss')

    Write-Host ''
    Write-Host '  ============================================'
    Write-Host '    MeshLink P2P 测试（无需任何技术知识）'
    Write-Host '  ============================================'
    Write-Host ''
    if (-not (Test-Path $exe)) {
        Write-Host "  未找到 directlink-poc.exe（应与本脚本在同一文件夹）：`n  $exe" -ForegroundColor Red
        Read-Host '  按回车退出'
        exit 1
    }
    Write-Host '  【隐私说明】测试报告会包含：公网 IP、局域网 IP、网络接口信息。'
    Write-Host '  这些信息仅用于诊断直连测试；请只把生成的结果 ZIP 发给发起测试的人。'
    Write-Host ''
    Write-Host '  如果 Windows 防火墙弹出"允许访问网络"提示，'
    Write-Host '  请点击"允许访问"（专用网络和公用网络都勾选）。'
    Write-Host ''
    Write-Host '  请选择测试模式：'
    Write-Host '   [1] 加入测试（对方已把连接码发给你）'
    Write-Host '   [2] 发起测试（本机生成连接码发给对方）'
    Write-Host '   [3] 矩阵测试（自动多轮，需要双方共享一个文件夹）'
    $mode = (Read-Host '  输入 1 / 2 / 3 后回车').Trim()
    Write-Host ''

    # 把长代码保存为文本文件并用记事本打开（控制台里复制长文本容易出错）
    function Save-CodeFile([string]$Content, [string]$Name, [string]$Hint) {
        $p = Join-Path $PSScriptRoot $Name
        [System.IO.File]::WriteAllText($p, $Content + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "  $Hint" -ForegroundColor Cyan
        Write-Host "  （已保存到 $Name 并打开记事本：全选 Ctrl+A → 复制 Ctrl+C → 粘贴发给对方）" -ForegroundColor Cyan
        Start-Process notepad.exe -ArgumentList "`"$p`""
    }

    # [UI] 状态行 → 朋友能看懂的话（§十：普通窗口只显示关键状态）
    function Show-Uiline([string]$Raw) {
        $t = $Raw.Substring(5).Trim()
        switch -Regex ($t) {
            '^STAGE: code_ok$'      { Write-Host '  连接码有效。' }
            '^STAGE: gathering$'    { Write-Host '  正在检测本机网络...' }
            '^STAGE: punching$'     { Write-Host '  正在建立直连（打洞，可能需要 10-30 秒）...' }
            '^STAGE: waiting_join$' { Write-Host '  连接码已生成。正在等待对方加入（窗口保持开启）...' }
            '^SESSION: connected$'  { Write-Host '  对方已接入！直连建立。' }
            '^STAGE: data_test$'    { Write-Host '  正在验证连通性（收发测试包）...' }
            '^STAGE: '              { }  # 其他阶段名原样隐藏
            '^SESSION_CODE:(.+)$'   { Save-CodeFile $Matches[1] 'MeshLink-Connect-Code.txt' '  请把连接码发给对方。' }
            '^ANSWER_CODE:(.+)$'    { Save-CodeFile $Matches[1] 'MeshLink-Answer-Code.txt' '  请把 Answer Code 发回给发起测试的人。' }
            '^RESULT: SUCCESS$'     { $script:lastSuccess = $true }  # 成功由主流程统一展示
            '^RESULT: FAIL:(.*)$'   { $script:lastFail = $Matches[1].Trim() }  # 失败由主流程按退出码统一展示
            default                 { Write-Host "  $t" }
        }
    }

    # 友好失败码 → 朋友能看懂的一句话（附给发起人的技术码）
    function Explain-Fail([string]$Code) {
        switch ($Code) {
            'SESSION_CODE_EXPIRED'           { return '连接码已过期（有效期 10 分钟），请对方重新生成一个。' }
            'SESSION_CODE_INVALID'           { return '连接码无效（可能复制不完整），请重新完整复制。' }
            'punch_timeout_or_check_failed'  { return '无法建立直连（PUNCH_TIMEOUT）。请检查双方都已联网，且防火墙已放行。' }
            'punch_timeout'                  { return '无法建立直连（PUNCH_TIMEOUT）。请检查双方都已联网，且防火墙已放行。' }
            'dial_failed'                    { return '无法建立直连（连接检查失败）。请确认对方仍在等待中。' }
            'no_local_candidates'            { return '本机没有可用网络连接。' }
            'smoke_all_lost'                 { return '连接建立了，但测试包全部丢失，直连质量不可用。' }
            'smoke_below_threshold'          { return '连接建立了，但测试包丢包过多，未达通过标准。' }
            default                          { return "测试失败（$Code）。" }
        }
    }

    # 运行 exe：全部输出进 logs\client.log，窗口只显示 [UI] 行；返回退出码
    function Run-Live([string[]]$ExeArgs) {
        $script:lastFail = ''
        $script:lastSuccess = $false
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $logFile = Join-Path $logDir 'client.log'
        & $exe @ExeArgs 2>&1 | ForEach-Object {
            $line = "$_"
            $line | Out-File -FilePath $logFile -Append -Encoding utf8
            if ($line.StartsWith('[UI] ')) { Show-Uiline $line }
        }
        return $LASTEXITCODE
    }

    $ok = $false
    $lastFailCode = ''

    if ($mode -eq '2') {
        # ---------- 发起测试（本机生成连接码） ----------
        $trackIn = (Read-Host '  轨型 [B=普通直连 / A=标准ICE]（回车默认 B）').Trim()
        $trackArgs = if ($trackIn -match '^[Aa]$') { @('--track', 'a') } else { @('--track', 'b') }
        if ($trackArgs[1] -eq 'a') {
            Write-Host '  流程：把连接码发给对方 → 对方加入后会把 Answer Code 发给你 → 直接粘贴到本窗口回车。'
        }
        Write-Host ''
        Write-Host '  正在生成连接码...'
        Write-Host ''
        $rc = Run-Live (@('create') + $trackArgs + @('--friend', '--report', '--test-id', $testId, '--out-dir', $outDir))
        $ok = ($rc -eq 0) -and ($script:lastSuccess -or -not $script:lastFail)
        if (-not $ok) { $lastFailCode = $script:lastFail }
    }
    elseif ($mode -eq '3') {
        # ---------- 矩阵测试（自动多轮；共享文件夹交换） ----------
        Write-Host '  前提：双方约定同一个共享文件夹（如 OneDrive/坚果云同步目录），本机都能直接访问。'
        Write-Host ''
        $trackIn = (Read-Host '  轨型 [B=普通直连 / A=标准ICE]（回车默认 B）').Trim()
        $trackVal = if ($trackIn -match '^[Aa]$') { 'a' } else { 'b' }
        $sideIn = (Read-Host '  本机角色 [b=加入方 / a=发起方]（回车默认 b）').Trim()
        $sideVal = if ($sideIn -match '^[Aa]$') { 'a' } else { 'b' }
        $roundsIn = (Read-Host '  轮数（回车默认 20）').Trim()
        $roundsVal = if ($roundsIn -match '^\d+$') { $roundsIn } else { '20' }
        $xdir = (Read-Host '  共享文件夹完整路径').Trim('"')
        if (-not $xdir) {
            Write-Host '  未输入共享文件夹路径，退出。' -ForegroundColor Yellow
            Read-Host '  按回车退出'
            exit 1
        }
        Write-Host ''
        Write-Host "  矩阵测试开始：track=$trackVal 本机=$sideVal 轮数=$roundsVal。全程保持窗口开启。"
        Write-Host ''
        $rc = Run-Live @('matrix', '--track', $trackVal, '--rounds', $roundsVal, '--side', $sideVal, '--exchange', $xdir, '--out-dir', $outDir, '--report', '--test-id', $testId)
        $ok = ($rc -eq 0)
        if (-not $ok) { $lastFailCode = $script:lastFail }
    }
    else {
        # ---------- 加入测试（粘贴连接码） ----------
        while ($true) {
            $code = (Read-Host '  请粘贴对方发给你的连接码，然后按回车').Trim()
            if (-not $code) {
                Write-Host '  未输入连接码，退出。' -ForegroundColor Yellow
                Read-Host '  按回车退出'
                exit 1
            }
            Write-Host ("  你粘贴的连接码长度 = {0} 字符（请与对方显示的长度对照；不一致=复制不完整）" -f $code.Length)
            Write-Host ''
            Write-Host '  正在测试...'
            Write-Host ''
            $rc = Run-Live @('join', $code, '--friend', '--report', '--test-id', $testId, '--out-dir', $outDir)
            $ok = ($rc -eq 0)
            if ($ok) {
                Write-Host ''
                Write-Host '  ============================================'
                Write-Host '    测试结果：成功'  -ForegroundColor Green
                Write-Host '  ============================================'
                break
            }
            $lastFailCode = $script:lastFail
            if ($lastFailCode) {
                Write-Host ''
                Write-Host ("  " + (Explain-Fail $lastFailCode)) -ForegroundColor Yellow
            } else {
                Write-Host ''
                Write-Host '  程序异常退出，请把 results 文件夹发给测试发起人。' -ForegroundColor Yellow
            }
            # 连接码问题允许重粘；网络类失败直接结束（重试也一样）
            if ($lastFailCode -eq 'SESSION_CODE_INVALID' -or $lastFailCode -eq 'SESSION_CODE_EXPIRED') {
                Write-Host '  可以重新粘贴连接码再试一次。'
                Write-Host ''
                continue
            }
            break
        }
    }

    # §十一：一键打包（只含测试报告与日志，不含用户其他文件）
    $zip = $null
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
    $verInfo = "MeshLink DirectLink PoC`r`ntest_id: $testId`r`ntime: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`nexe: $((Get-Item $exe).LastWriteTime.ToString('yyyy-MM-dd HH:mm'))"
    [System.IO.File]::WriteAllText((Join-Path $outDir 'version.txt'), $verInfo, (New-Object System.Text.UTF8Encoding($false)))
    $files = @()
    foreach ($f in 'result.json', 'network_snapshot.json', 'candidate_trace.json', 'version.txt') {
        $p = Join-Path $outDir $f
        if (Test-Path $p) { $files += $p }
    }
    # 矩阵模式产物：每轮 result-rNN.json + summary
    $files += @(Get-ChildItem -Path $outDir -Filter 'result-r*.json' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $files += @(Get-ChildItem -Path $outDir -Filter 'summary-*.json' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    if (Test-Path (Join-Path $logDir 'client.log')) { $files += Join-Path $logDir 'client.log' }
    if ($files.Count -gt 0) {
        $zip = Join-Path $PSScriptRoot ("MeshLink-Test-{0}.zip" -f $testId)
        Compress-Archive -Path $files -DestinationPath $zip -Force
    }

    if (-not $ok) {
        Write-Host ''
        Write-Host '  ============================================'
        Write-Host '    测试结果：失败' -ForegroundColor Red
        Write-Host '  ============================================'
    }
    Write-Host ''
    if (Test-Path $outDir) {
        Write-Host '  测试报告已生成。'
        if ($lastFailCode) { Write-Host "  测试失败：$lastFailCode" -ForegroundColor Yellow }
        if ($zip -and (Test-Path $zip)) {
            Write-Host "  请把这个文件发给测试发起人：$(Split-Path $zip -Leaf)"
            Start-Process explorer.exe -ArgumentList "/select,`"$zip`""
        } else {
            Write-Host '  请把 results 文件夹发给测试发起人。'
            Start-Process explorer.exe $outDir
        }
    } else {
        Write-Host '  请把本窗口截图发回给发起测试的人。'
    }
} catch {
    Write-Host "  发生错误：$_" -ForegroundColor Red
} finally {
    Read-Host '  按回车退出'
}
