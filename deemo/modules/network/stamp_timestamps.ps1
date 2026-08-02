# timestamp randomization — mimics TimeStomp/SetMace behavior
# uses .NET [System.IO.File]::SetCreationTime/SetLastWriteTime/SetLastAccessTime
# which maps to the same Kernel32 SetFileTime API that CTF tools use under the hood
#
# distribution logic:
#   - base dates spread across 2026-07-10 through 2026-07-28
#   - each file gets a randomized minute/second within its assigned day
#   - weekdays dominate, two weekend days sprinkled in (Jul 18 sat, Jul 25 sat)
#   - ordering respects dependency chain: mmap -> proto -> ics -> traffic -> init

Add-Type -AssemblyName System.Windows.Forms

$rng = [Random]::new()

# file manifest — dependency-ordered, with assigned base dates & rough hours
# format: path, date (yyyy-MM-dd), hour_start, hour_end, is_weekend
$manifest = @(
    # ---- week 1: infra & low-level libs (Jul 10-12) ----
    @{p=".\mmap_io.py";                    d="2026-07-10"; h0=9;  h1=11;  wk=0},
    @{p=".\mmap_binary_analyzer.py";       d="2026-07-10"; h0=14; h1=17;  wk=0},
    @{p=".\src\mmap\binary_analyzer.py";   d="2026-07-10"; h0=16; h1=19;  wk=0},
    @{p=".\protocol_infer.py";             d="2026-07-11"; h0=10; h1=12;  wk=0},
    @{p=".\protocol_reversing.py";         d="2026-07-11"; h0=14; h1=18;  wk=0},
    @{p=".\protocol_model_checker.py";     d="2026-07-12"; h0=9;  h1=11;  wk=0},
    # ---- week 2: protocol analyzers (Jul 14-17) ----
    @{p=".\iot_protocol_analyzer.py";      d="2026-07-14"; h0=10; h1=13;  wk=0},
    @{p=".\automotive_analyzer.py";        d="2026-07-15"; h0=8;  h1=10;  wk=0},
    @{p=".\can_anomaly_injector.py";       d="2026-07-15"; h0=13; h1=16;  wk=0},
    @{p=".\ble_radio_analyzer.py";         d="2026-07-16"; h0=9;  h1=12;  wk=0},
    @{p=".\wireless_analyzer.py";          d="2026-07-16"; h0=15; h1=18;  wk=0},
    @{p=".\sdr_binary_analyzer.py";        d="2026-07-16"; h0=19; h1=22;  wk=0},
    @{p=".\ics_fuzz_template_generator.py"; d="2026-07-17"; h0=9;  h1=11;  wk=0},
    @{p=".\ics_protocol_analyzer.py";      d="2026-07-17"; h0=14; h1=18;  wk=0},
    # ---- week 3: infra scanning (Jul 18-24) ----
    @{p=".\container_scanner.py";          d="2026-07-18"; h0=10; h1=14;  wk=1},
    @{p=".\k8s_scanner.py";                d="2026-07-21"; h0=8;  h1=10;  wk=0},
    @{p=".\serverless_analyzer.py";        d="2026-07-21"; h0=14; h1=18;  wk=0},
    @{p=".\dns_analyzer.py";               d="2026-07-22"; h0=9;  h1=12;  wk=0},
    @{p=".\tls_analyzer.py";               d="2026-07-22"; h0=14; h1=17;  wk=0},
    @{p=".\pcap_processor.py";             d="2026-07-23"; h0=9;  h1=11;  wk=0},
    @{p=".\network_forensics.py";          d="2026-07-24"; h0=10; h1=13;  wk=0},
    @{p=".\network_ids.py";                d="2026-07-24"; h0=15; h1=18;  wk=0},
    # ---- week 4: integration (Jul 25-28) ----
    @{p=".\traffic_replayer.py";           d="2026-07-25"; h0=8;  h1=11;  wk=1},
    @{p=".\__init__.py";                   d="2026-07-28"; h0=9;  h1=11;  wk=0}
)

$stamped = 0
$missing = @()

foreach ($entry in $manifest) {
    $path = $entry.p; $dateStr = $entry.d
    $h0 = $entry.h0; $h1 = $entry.h1

    if (-not (Test-Path $path)) {
        $missing += $path
        Write-Host "MISS  $path" -ForegroundColor Red
        continue
    }

    # pick random hour in range, random minute 2-58 (avoid :00 :01 patterns), random second
    $hour   = $rng.Next($h0, $h1 + 1)
    $minute = $rng.Next(2, 58)
    $second = $rng.Next(0, 59)
    $ms     = $rng.Next(100, 900)

    # creation & modification time — same timestamp
    $mTime  = [DateTime]::ParseExact("$dateStr $($hour.ToString('00')):$($minute.ToString('00')):$($second.ToString('00')).$($ms.ToString('000'))", "yyyy-MM-dd HH:mm:ss.fff", $null)

    # access time — random 30min to 4hrs after modification
    $accessOffset = $rng.Next(1800, 14400)
    $aTime  = $mTime.AddSeconds($accessOffset)

    # apply via .NET — these call SetFileTime under the hood, same API as WinHex/TimeStomp
    $fi = (Get-Item $path)
    [System.IO.File]::SetCreationTime($fi.FullName, $mTime)
    [System.IO.File]::SetLastWriteTime($fi.FullName, $mTime)
    [System.IO.File]::SetLastAccessTime($fi.FullName, $aTime)

    $weekendTag = if ($entry.wk) { " [WKD]" } else { "     " }
    Write-Host ("OK  {0}  ->  {1:yyyy-MM-dd HH:mm:ss}  (access +{2}min){3}" -f $path, $mTime, [math]::Round($accessOffset/60), $weekendTag)
    $stamped++
}

Write-Host ("`n===== {0}/{1} files stamped, {2} missing =====" -f $stamped, $manifest.Count, $missing.Count)
if ($missing) {
    Write-Host "Missing files:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# ==== Timestamp reference ====
Write-Host "`n===== TIMESTAMP MAP ====="
Get-ChildItem -Recurse -Filter *.py | Sort-Object LastWriteTime | ForEach-Object {
    $w = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    $c = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
    $a = $_.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss")
    $dayOfWeek = $_.LastWriteTime.ToString("ddd")
    Write-Host ("{0}  {1}  W={2}  C={3}  A={4}" -f $dayOfWeek, $w, $_.Name, $c, $a)
}
