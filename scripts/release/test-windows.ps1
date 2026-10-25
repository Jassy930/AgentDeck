Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common-windows.ps1')
foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1') {
    $tokens = $null; $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
}
Initialize-SmokeRunner
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('agentdeck-release-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
function Assert-Rejected {
    param([scriptblock]$Action, [string]$Label)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Accepted invalid case: $Label" }
    Write-Host "Rejected: $Label"
}
function Assert-ChildExited {
    param([string]$PidFile)
    if (-not (Test-Path -LiteralPath $PidFile)) { throw 'Fixture did not spawn a child' }
    $childId = [int](Get-Content -Raw -LiteralPath $PidFile)
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        if (-not (Get-Process -Id $childId -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Smoke runner leaked fixture child $childId"
}
function Assert-LogReleased {
    param([string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $stream.Dispose()
}
try {
    Write-ReleaseText (Join-Path $fixture 'Cargo.toml') "[workspace.package]`nversion = `"1.2.3`"`n"
    $lock = ''
    foreach ($crate in @('agentdeck-desktop', 'agentdeckd', 'agentdeck-protocol', 'agentdeck-cli')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $fixture $crate))
        Write-ReleaseText (Join-Path $fixture "$crate/Cargo.toml") "[package]`nversion.workspace = true`n"
        $lock += "[[package]]`nname = `"$crate`"`nversion = `"1.2.3`"`n"
    }
    Write-ReleaseText (Join-Path $fixture 'Cargo.lock') $lock
    if ((Get-ReleaseVersion $fixture 'v1.2.3') -ne '1.2.3') { throw 'Version parsing failed' }
    Assert-Rejected { Get-ReleaseVersion $fixture 'v1.2.4' } 'tag mismatch'
    Write-ReleaseText (Join-Path $fixture 'Cargo.lock') ($lock.Replace('1.2.3', '9.9.9'))
    Assert-Rejected { Get-ReleaseVersion $fixture } 'lockfile mismatch'
    Write-ReleaseText (Join-Path $fixture 'Cargo.lock') $lock
    Write-ReleaseText (Join-Path $fixture 'agentdeck-desktop/Cargo.toml') "[package]`nversion = `"1.2.3`"`n"
    Assert-Rejected { Get-ReleaseVersion $fixture } 'desktop version not inherited'
    $bytes = [IO.File]::ReadAllBytes((Join-Path $fixture 'Cargo.lock'))
    if ($bytes[0] -eq 0xef -or 13 -in $bytes) { throw 'Release metadata must use UTF-8 without BOM and LF' }
    if ($IsWindows) {
        $source = Join-Path $fixture 'process-fixture.rs'
        $binary = Join-Path $fixture 'process-fixture.exe'
        Write-ReleaseText $source @'
use std::{env, fs, process::Command, thread, time::Duration};
fn main() {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("") {
        "echo" => { println!("{}", args[2]); println!("{}", env::var("PROBE_VALUE").unwrap()); }
        "fail" => std::process::exit(97),
        "spawn" | "spawn-and-exit" => {
            let child = Command::new(env::current_exe().unwrap()).arg("hang").spawn().unwrap();
            fs::write(&args[2], child.id().to_string()).unwrap();
            if args[1] == "spawn-and-exit" { return; }
            loop { thread::sleep(Duration::from_secs(1)); }
        }
        "hang" => loop { thread::sleep(Duration::from_secs(1)); },
        _ => panic!("unknown fixture command"),
    }
}
'@
        & rustc --edition 2024 --crate-name release_process_fixture -C target-feature=+crt-static $source -o $binary
        if ($LASTEXITCODE -ne 0) { throw 'Cannot build process fixture' }
        $guiSource = Join-Path $fixture 'gui-version-fixture.rs'
        $guiBinary = Join-Path $fixture 'gui-version-fixture.exe'
        $guiCompleted = Join-Path $fixture 'gui-version-completed'
        Write-ReleaseText $guiSource @'
#![windows_subsystem = "windows"]
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args[1], "--version");
    std::thread::sleep(std::time::Duration::from_millis(200));
    println!("agentdeck-desktop 1.2.3");
    std::thread::sleep(std::time::Duration::from_millis(200));
    std::fs::write(&args[2], "completed").unwrap();
}
'@
        & rustc --edition 2024 --crate-name release_gui_version_fixture -C target-feature=+crt-static $guiSource -o $guiBinary
        if ($LASTEXITCODE -ne 0) { throw 'Cannot build GUI-subsystem version fixture' }
        $guiOutput = Invoke-IsolatedProcess -Executable $guiBinary -Arguments @('--version', $guiCompleted) `
            -WorkingDirectory $fixture -Environment @{} -Log (Join-Path $fixture 'gui-version.log')
        if ($guiOutput.Trim() -ne 'agentdeck-desktop 1.2.3' -or -not (Test-Path -LiteralPath $guiCompleted)) {
            throw 'GUI-subsystem version output or explicit process wait failed'
        }
        Assert-LogReleased (Join-Path $fixture 'gui-version.log')
        $value = 'space "quotes" unicode 路径 trailing\'
        $output = Invoke-IsolatedProcess -Executable $binary -Arguments @('echo', $value) `
            -WorkingDirectory $fixture -Environment @{ PROBE_VALUE = $value } -Log (Join-Path $fixture 'echo.log')
        if (($output -split '\r?\n')[0] -ne $value -or ($output -split '\r?\n')[1] -ne $value) {
            throw 'Argument quoting or Unicode environment block failed'
        }
        Assert-Rejected {
            Invoke-IsolatedProcess -Executable $binary -Arguments @('fail') -WorkingDirectory $fixture `
                -Environment @{} -Log (Join-Path $fixture 'fail.log')
        } 'nonzero child exit'
        $timeoutPidFile = Join-Path $fixture 'timeout-child.pid'
        Assert-Rejected {
            Invoke-IsolatedProcess -Executable $binary -Arguments @('spawn', $timeoutPidFile) -WorkingDirectory $fixture `
                -Environment @{} -Log (Join-Path $fixture 'timeout.log') -TimeoutMilliseconds 2000
        } 'hung parent with a child'
        Assert-LogReleased (Join-Path $fixture 'timeout.log')
        Assert-ChildExited $timeoutPidFile
        $orphanPidFile = Join-Path $fixture 'orphan-child.pid'
        [void](Invoke-IsolatedProcess -Executable $binary -Arguments @('spawn-and-exit', $orphanPidFile) `
            -WorkingDirectory $fixture -Environment @{} -Log (Join-Path $fixture 'orphan.log'))
        Assert-LogReleased (Join-Path $fixture 'orphan.log')
        Assert-ChildExited $orphanPidFile
        Write-Host 'Windows process job tests passed: timeout and descendants of an exited parent are reclaimed.'
    } else {
        Write-Host 'Native Windows process tests not run on this host.'
    }
    Write-Host 'Windows release script self-tests passed.'
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
