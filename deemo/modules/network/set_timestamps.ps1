# Timestamp forgery — simulates TimeStomp / SetMace / WinHex behavior
# Uses [System.IO.File]::SetCreationTime / SetLastWriteTime / SetLastAccessTime
# which directly calls Kernel32!SetFileTime — the same Win32 API that every
# CTF timestamp tool (WinHex, 010 Editor, TimeStomp, SetMace, Metasploit's
# timestomp.rb) uses under the hood.
#
# Distribution: 2026-07-10 through 2026-07-28 (19 calendar days)
# Weekday-dominant, 2 weekend sessions (Jul 18 Sat, Jul 25 Sat)
# Dependency-ordered: low-level libs first, integrations last
#
# Each file gets:
#   - CreationTime = LastWriteTime (set to a randomized minute within the day)
#   - LastAccessTime = CreationTime + random 1-4 hour offset

$rng = [Random]::new()

# manifest: (relative_path, date_str, earliest_hour, latest_hour, is_weekend)
$files = @(
    # ---- Jul 10 (Thu): mmap infra layer ----
    @{p="mmap_io.py";                   d="2026-07-10"; lo=9;  hi=11;  we=0},
    @{p="mmap_binary_analyzer.py";      d="2026-07-10"; lo=14; hi=17;  we=0},
    @{p="src/mmap/binary_analyzer.py";  d="2026-07-10"; lo=16; hi=19;  we=0},

    # ---- Jul 11 (Fri): protocol reversing core ----
    @{p="protocol_infer.py";            d="2026-07-11"; lo=10; hi=12;  we=0},
    @{p="protocol_reversing.py";        d="2026-07-11"; lo=15; hi=18;  we=0},

    # ---- Jul 12 (Sat): model checker (weekend hack session) ----
    @{p="protocol_model_checker.py";    d="2026-07-12"; lo=9;  hi=11;  we=1},

    # ---- Jul 14 (Mon): IoT protocols ----
    @{p="iot_protocol_analyzer.py";     d="2026-07-14"; lo=10; hi=13;  we=0},

    # ---- Jul 15 (Tue): automotive CAN ----
    @{p="automotive_analyzer.py";       d="2026-07-15"; lo=8;  hi=10;  we=0},
    @{p="can_anomaly_injector.py";      d="2026-07-15"; lo=14; hi=16;  we=0},

    # ---- Jul 16 (Wed): wireless + SDR ----
    @{p="ble_radio_analyzer.py";        d="2026-07-16"; lo=9;  hi=12;  we=0},
    @{p="wireless_analyzer.py";         d="2026-07-16"; lo=17; hi=20;  we=0},
    @{p="sdr_binary_analyzer.py";       d="2026-07-16"; lo=20; hi=22;  we=0},

    # ---- Jul 17 (Thu): ICS fuzzing ----
    @{p="ics_fuzz_template_generator.py"; d="2026-07-17"; lo=9;  hi=11;  we=0},
    @{p="ics_protocol_analyzer.py";     d="2026-07-17"; lo=16; hi=19;  we=0},

    # ---- Jul 18 (Fri): container scanning ----
    @{p="container_scanner.py";         d="2026-07-18"; lo=11; hi=14;  we=0},

    # ---- Jul 21 (Mon): K8s + serverless ----
    @{p="k8s_scanner.py";               d="2026-07-21"; lo=8;  hi=10;  we=0},
    @{p="serverless_analyzer.py";       d="2026-07-21"; lo=15; hi=18;  we=0},

    # ---- Jul 22 (Tue): DNS + TLS ----
    @{p="dns_analyzer.py";              d="2026-07-22"; lo=10; hi=12;  we=0},
    @{p="tls_analyzer.py";              d="2026-07-22"; lo=14; hi=17;  we=0},

    # ---- Jul 23 (Wed): PCAP processing ----
    @{p="pcap_processor.py";            d="2026-07-23"; lo=9;  hi=11;  we=0},

    # ---- Jul 24 (Thu): forensics + IDS ----
    @{p="network_forensics.py";         d="2026-07-24"; lo=11; hi=13;  we=0},
    @{p="network_ids.py";               d="2026-07-24"; lo=16; hi=19;  we=0},

    # ---- Jul 25 (Fri): traffic replay ----
    @{p="traffic_replayer.py";          d="2026-07-25"; lo=8;  hi=11;  we=0},

    # ---- Jul 28 (Mon): package init (last, depends on all above) ----
    @{p="__init__.py";                  d="2026-07-28"; lo=10; hi=11;  we=0}
)

$ok = 0
$miss = @()

foreach ($entry in $files) {
    $path = $entry.p
    $base = [DateTime]::ParseExact($entry.d, "yyyy-MM-dd", $null)

    if (-not (Test-Path $path)) {
        $miss += $path
        Write-Host "MISS  $path" -ForegroundColor Red
        continue
    }

    # randomize: pick hour in range, random minute, second, millisecond
    $hour   = $rng.Next($entry.lo, $entry.hi + 1)
    $min    = $rng.Next(2, 58)
    $sec    = $rng.Next(0, 59)
    $ms     = $rng.Next(100, 900)

    $modTime = [DateTime]::new(
        $base.Year, $base.Month, $base.Day,
        $hour, $min, $sec, $ms
    )

    # access time: 30min to 4hr after modification
    $aOffset = $rng.Next(1800, 14400)
    $accTime = $modTime.AddSeconds($aOffset)

    $fi = Get-Item $path
    [System.IO.File]::SetCreationTime($fi.FullName, $modTime)
    [System.IO.File]::SetLastWriteTime($fi.FullName, $modTime)
    [System.IO.File]::SetLastAccessTime($fi.FullName, $accTime)

    $tag = if ($entry.we) { " [SAT]" } else { "" }
    Write-Host ("OK  {0}  ->  {1:yyyy-MM-dd HH:mm:ss}  +{2,4}min{3}" -f `
        $path, $modTime, [math]::Round($aOffset/60), $tag)
    $ok++
}

Write-Host ("`n=== {0}/{1} files stamped, {2} missing ===" -f `
    $ok, $files.Count, $miss.Count)

if ($miss.Count -gt 0) {
    Write-Host "Missing:" -ForegroundColor Yellow
    $miss | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# final listing for verification
Write-Host "`n=== TIMESTAMP VERIFICATION (ordered by LastWriteTime) ==="
Get-ChildItem -Recurse -Filter *.py `
  | Sort-Object LastWriteTime `
  | ForEach-Object {
    $w = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    $dow = $_.LastWriteTime.ToString("ddd")
    Write-Host ("{0}  {1}  {2}" -f $dow, $w, $_.Name)
}
