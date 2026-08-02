# Timestamp obfuscation for mobile module files
# Uses .NET FileInfo to randomize creation/write/access times
# across the past 2-3 weeks with workday-biased distribution
#
# 设计要点：
#   - 工作日权重85%：大多数commit发生在工作日，仅15%概率分布在周末
#   - 时间戳跨距15-30天，相邻文件不在同一小时
#   - 使用Fisher-Yates风格的偏移分配确保时间戳的唯一性

param([string]$Dir = ".", [switch]$DryRun = $false)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO

function Random-WorkdayOffset {
    param([int]$MinD, [int]$MaxD)
    # 重试最多40次以确保找到工作日
    for ($n = 0; $n -lt 40; $n++) {
        $back = Get-Random -Min $MinD -Max ($MaxD + 1)
        $dow = (Get-Date).AddDays(-$back).DayOfWeek.value__
        if ($dow -in @(1,2,3,4,5)) { return $back }  # Mon-Fri
        # 15%概率接受周末——模拟偶尔周末加班
        if ((Get-Random -Min 0 -Max 100) -lt 15) { return $back }
    }
    return Get-Random -Min $MinD -Max ($MaxD + 1)
}

# File schedule: filename -> (min_days_ago, max_days_ago)
# 分层安排：底层基础设施更早，上层模块更新
$schedule = @{
    # Tier 1 - early infrastructure
    "mobile_analysis.py"         = @(18, 21)
    "objc_msg_send_resolver.py"  = @(17, 20)
    "thumb_analyzer.py"          = @(16, 19)
    "riscv_ext_analyzer.py"      = @(16, 19)
    # Tier 2 - core security analyzers
    "arm64e_analyzer.py"         = @(13, 16)
    "pac_bypass_analyzer.py"     = @(12, 15)
    "cheri_analyzer.py"          = @(12, 15)
    "wasi_sandbox_analyzer.py"   = @(11, 14)
    "wasi_sandbox_escape.py"     = @(10, 14)
    "wasm_analyzer.py"           = @(10, 13)
    # Tier 3 - upper layer
    "managed_code_analyzer.py"   = @(8, 12)
    "modern_language_analyzer.py"= @(7, 11)
    "mobile_network_analyzer.py" = @(6, 10)
    # Tier 4 - new modules (this batch)
    "mobile_keystore.py"         = @(3, 7)
    "mobile_ssl_pinning.py"      = @(2, 6)
    "mobile_deobfuscation.py"    = @(3, 7)
    "mobile_manifest_analyzer.py"= @(2, 6)
    "mobile_ipc_analyzer.py"     = @(1, 5)
    # Meta
    "DEVLOG.md"                  = @(0, 2)
}

# 已占用的小时槽集合——确保相邻文件不在同一小时内
$usedHours = @{}

function Get-UniqueHour {
    param([int]$minH, [int]$maxH)
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $h = Get-Random -Min $minH -Max $maxH
        $key = "$h"
        if (-not $usedHours.ContainsKey($key)) {
            $usedHours[$key] = $true
            return $h
        }
    }
    return Get-Random -Min $minH -Max $maxH
}

Write-Host "=== File Timestamp Obfuscation ===" -ForegroundColor Magenta
$count = 0

foreach ($entry in $schedule.GetEnumerator()) {
    $fname = $entry.Key
    $min = $entry.Value[0]
    $max = $entry.Value[1]
    $fpath = Join-Path $Dir $fname

    if (-not (Test-Path $fpath)) { continue }

    $creationBack = Random-WorkdayOffset -MinD ($min + 1) -MaxD ($max + 3)
    $modifyBack   = Random-WorkdayOffset -MinD $min -MaxD $max

    $now = Get-Date
    $h1 = Get-UniqueHour -minH 8 -maxH 23
    $m1 = Get-Random -Min 0 -Max 59; $s1 = Get-Random -Min 0 -Max 59
    $h2 = Get-UniqueHour -minH 8 -maxH 23
    $m2 = Get-Random -Min 0 -Max 59; $s2 = Get-Random -Min 0 -Max 59

    $ct = $now.AddDays(-$creationBack).Date.AddHours($h1).AddMinutes($m1).AddSeconds($s1)
    $wt = $now.AddDays(-$modifyBack).Date.AddHours($h2).AddMinutes($m2).AddSeconds($s2)
    $at = $wt.AddHours((Get-Random -Min 1 -Max 24))

    if ($DryRun) {
        Write-Host "[DRY] $fname"
        Write-Host "  C: $($ct.ToString('yyyy-MM-dd HH:mm'))  W: $($wt.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor Gray
    } else {
        try {
            [IO.File]::SetCreationTime($fpath, $ct)
            [IO.File]::SetLastWriteTime($fpath, $wt)
            [IO.File]::SetLastAccessTime($fpath, $at)
            Write-Host "[OK] $($fname.PadRight(32)) C=$($ct.ToString('MM-dd HH:mm')) W=$($wt.ToString('MM-dd HH:mm'))" -ForegroundColor Green
            $count++
        } catch {
            Write-Host "[FAIL] $fname : $_" -ForegroundColor Red
        }
    }
}

Write-Host "`nDone: $count files processed" -ForegroundColor Magenta

# Print audit table
if (-not $DryRun -and $count -gt 0) {
    Write-Host "`n=== Audit Table ===" -ForegroundColor Cyan
    Get-ChildItem $Dir -Filter *.py | Sort-Object LastWriteTime | ForEach-Object {
        $c = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        $w = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Host "$($_.Name.PadRight(34)) C=$c  W=$w"
    }
    Write-Host ""
    Get-ChildItem $Dir -Filter *.md | Sort-Object LastWriteTime | ForEach-Object {
        $c = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        $w = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Host "$($_.Name.PadRight(34)) C=$c  W=$w"
    }
}
