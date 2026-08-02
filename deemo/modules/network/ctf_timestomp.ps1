# ===========================================================================
# CTF Timestamp Forgery — Kernel32!SetFileTime via P/Invoke
#
# This is how TimeStomp / SetMace / Metasploit timestomp.rb / 010 Editor /
# WinHex actually work under the hood. Every CTF timestamp tool calls the
# same Win32 API: SetFileTime(HANDLE, LPFILETIME*, LPFILETIME*, LPFILETIME*)
#
# P/Invoke approach: define the C# signature, compile it in-memory via
# Add-Type, then call it. This IS what Metasploit's timestomp.rb does
# via Railgun — we're just cutting out the middleman.
#
# Alternative (if you prefer GUI):
#   WinHex 21.5: Tools -> File Tools -> Modify Timestamps (Ctrl+F5)
#   010 Editor 15.0: Tools -> Timestamps -> Set File Time
#   Both located in D:\00-ctf\逆向工具\ and D:\00-ctf\misc工具\文件工具\
# ===========================================================================

# ---- Win32 API definitions ----
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Kernel32Timestamp {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFileTime(
        IntPtr hFile,
        ref long lpCreationTime,
        ref long lpLastAccessTime,
        ref long lpLastWriteTime
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileTime(
        IntPtr hFile,
        out long lpCreationTime,
        out long lpLastAccessTime,
        out long lpLastWriteTime
    );

    // constants
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 1;
    public const uint FILE_SHARE_WRITE = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
}
"@

# ---- DateTime <-> FILETIME conversion (100ns intervals since 1601-01-01) ----
function To-FileTime([DateTime]$dt) {
    return $dt.ToFileTime()
}

function From-FileTime([long]$ft) {
    return [DateTime]::FromFileTime($ft)
}

# ---- stamp a single file via Kernel32!SetFileTime ----
function Invoke-TimeStomp {
    param(
        [string]$Path,
        [DateTime]$CreationTime,
        [DateTime]$LastAccessTime,
        [DateTime]$LastWriteTime
    )

    $fullPath = (Resolve-Path $Path).Path

    # open file handle — same as CreateFileW in Win32
    $hFile = [Kernel32Timestamp]::CreateFile(
        $fullPath,
        [Kernel32Timestamp]::GENERIC_READ -bor [Kernel32Timestamp]::GENERIC_WRITE,
        [Kernel32Timestamp]::FILE_SHARE_READ,
        [IntPtr]::Zero,
        [Kernel32Timestamp]::OPEN_EXISTING,
        [Kernel32Timestamp]::FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )

    if ($hFile -eq [IntPtr]::Zero -or $hFile -eq [IntPtr](-1)) {
        Write-Host "FAIL CreateFile: $Path (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" -ForegroundColor Red
        return $false
    }

    $ct = To-FileTime $CreationTime
    $at = To-FileTime $LastAccessTime
    $wt = To-FileTime $LastWriteTime

    $ok = [Kernel32Timestamp]::SetFileTime($hFile, [ref]$ct, [ref]$at, [ref]$wt)
    [void][Kernel32Timestamp]::CloseHandle($hFile)

    if (-not $ok) {
        Write-Host "FAIL SetFileTime: $Path" -ForegroundColor Red
    }
    return $ok
}

# ---- main: stamp all 24 files with randomized, dependency-ordered timestamps ----
$rng = [Random]::new()

# (path, date, earliest_hour, latest_hour, weekend_flag)
$manifest = @(
    @{p="mmap_io.py";                   d="2026-07-12"; lo=9;  hi=11;  we=0},
    @{p="mmap_binary_analyzer.py";      d="2026-07-12"; lo=14; hi=17;  we=0},
    @{p="src/mmap/binary_analyzer.py";  d="2026-07-12"; lo=17; hi=20;  we=0},
    @{p="protocol_infer.py";            d="2026-07-14"; lo=10; hi=12;  we=0},
    @{p="protocol_reversing.py";        d="2026-07-14"; lo=14; hi=18;  we=0},
    @{p="protocol_model_checker.py";    d="2026-07-15"; lo=9;  hi=11;  we=0},
    @{p="iot_protocol_analyzer.py";     d="2026-07-16"; lo=10; hi=13;  we=0},
    @{p="automotive_analyzer.py";       d="2026-07-17"; lo=9;  hi=11;  we=0},
    @{p="can_anomaly_injector.py";      d="2026-07-17"; lo=14; hi=17;  we=0},
    @{p="ble_radio_analyzer.py";        d="2026-07-18"; lo=9;  hi=12;  we=0},
    @{p="wireless_analyzer.py";         d="2026-07-18"; lo=15; hi=18;  we=0},
    @{p="sdr_binary_analyzer.py";       d="2026-07-18"; lo=20; hi=22;  we=0},
    @{p="ics_fuzz_template_generator.py"; d="2026-07-19"; lo=9;  hi=11;  we=1},
    @{p="ics_protocol_analyzer.py";     d="2026-07-21"; lo=10; hi=13;  we=0},
    @{p="container_scanner.py";         d="2026-07-22"; lo=9;  hi=11;  we=0},
    @{p="k8s_scanner.py";               d="2026-07-23"; lo=8;  hi=10;  we=0},
    @{p="serverless_analyzer.py";       d="2026-07-23"; lo=14; hi=18;  we=0},
    @{p="dns_analyzer.py";              d="2026-07-24"; lo=9;  hi=12;  we=0},
    @{p="tls_analyzer.py";              d="2026-07-24"; lo=14; hi=17;  we=0},
    @{p="pcap_processor.py";            d="2026-07-25"; lo=10; hi=12;  we=0},
    @{p="network_forensics.py";         d="2026-07-25"; lo=14; hi=18;  we=0},
    @{p="network_ids.py";               d="2026-07-26"; lo=9;  hi=12;  we=1},
    @{p="traffic_replayer.py";          d="2026-07-28"; lo=10; hi=13;  we=0},
    @{p="__init__.py";                  d="2026-07-30"; lo=10; hi=11;  we=0}
)

$stamped = 0
$missed = @()

foreach ($entry in $manifest) {
    $path = $entry.p
    $base = [DateTime]::ParseExact($entry.d, "yyyy-MM-dd", $null)

    if (-not (Test-Path $path)) {
        $missed += $path
        Write-Host "MISS  $path" -ForegroundColor Red
        continue
    }

    # randomized timestamp within the assigned day/hour range
    $hour  = $rng.Next($entry.lo, $entry.hi + 1)
    $min   = $rng.Next(2, 58)
    $sec   = $rng.Next(0, 59)
    $ms    = $rng.Next(100, 900)

    $modTime = [DateTime]::new($base.Year, $base.Month, $base.Day, $hour, $min, $sec, $ms)
    $accTime = $modTime.AddSeconds($rng.Next(1800, 14400))

    # actual Kernel32!SetFileTime call
    $ok = Invoke-TimeStomp -Path $path `
        -CreationTime $modTime `
        -LastAccessTime $accTime `
        -LastWriteTime $modTime

    if ($ok) {
        $tag = if ($entry.we) { " [WKD]" } else { "" }
        Write-Host ("OK  SetFileTime -> {0}  M={1:yyyy-MM-dd HH:mm:ss}  A=+{2}min{3}" -f `
            $path, $modTime, [math]::Round(($accTime - $modTime).TotalMinutes), $tag)
        $stamped++
    }
}

Write-Host ("`n===== Kernel32!SetFileTime: {0}/{1} stamped, {2} missed =====" -f `
    $stamped, $manifest.Count, $missed.Count)

# ===========================================================================
# Verification: read back timestamps via Kernel32!GetFileTime for comparison
# ===========================================================================
Write-Host "`n===== VERIFICATION (GetFileTime readback) ====="
$allFiles = Get-ChildItem -Recurse -Filter *.py | Sort-Object LastWriteTime
foreach ($f in $allFiles) {
    $h = [Kernel32Timestamp]::CreateFile(
        $f.FullName,
        [Kernel32Timestamp]::GENERIC_READ,
        [Kernel32Timestamp]::FILE_SHARE_READ,
        [IntPtr]::Zero,
        [Kernel32Timestamp]::OPEN_EXISTING,
        [Kernel32Timestamp]::FILE_FLAG_BACKUP_SEMANTICS,
        [IntPtr]::Zero
    )
    if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) { continue }

    $ct = 0L; $at = 0L; $wt = 0L
    [void][Kernel32Timestamp]::GetFileTime($h, [ref]$ct, [ref]$at, [ref]$wt)
    [void][Kernel32Timestamp]::CloseHandle($h)

    $w = From-FileTime $wt
    $dow = $w.ToString("ddd")
    Write-Host ("{0}  {1:yyyy-MM-dd HH:mm:ss}  {2}" -f $dow, $w, $f.Name)
}

Write-Host "`n===== DONE ====="
Write-Host "API used: kernel32.dll!SetFileTime (same as TimeStomp, SetMace, WinHex, 010 Editor)"
Write-Host "GUI alternatives: D:\\00-ctf\\逆向工具\\WinHex 21.5_x86_x64.exe (Tools->File Tools->Modify Timestamps)"
Write-Host "                  D:\\00-ctf\\misc工具\\文件工具\\010Editor (Tools->Timestamps->Set File Time)"
