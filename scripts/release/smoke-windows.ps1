param([string]$OutputDir = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common-windows.ps1')
if (-not $IsWindows) { throw 'Windows smoke tests require PowerShell 7 on Windows' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$target = 'x86_64-pc-windows-msvc'
$version = Get-ReleaseVersion $root $env:AGENTDECK_RELEASE_TAG
if (-not $OutputDir) { $OutputDir = Join-Path $root 'dist/release' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('agentdeck-release-smoke-' + [guid]::NewGuid().ToString('N'))
try {
    foreach ($directory in @('', 'home', 'bin', 'data', 'temp', 'home/AppData/Roaming', 'home/AppData/Local')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $scratch $directory))
    }
    $vendorSource = Join-Path $scratch 'vendor-guard.rs'
    Write-ReleaseText $vendorSource @'
fn main() {
    std::fs::write(std::env::var_os("AGENTDECK_OFFLINE_MARKER").expect("marker path"), "unexpected vendor invocation\n").unwrap();
    std::process::exit(97);
}
'@
    & rustc --edition 2024 --crate-name release_vendor_guard --target $target -C target-feature=+crt-static $vendorSource -o (Join-Path $scratch 'bin/codex.exe')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot build offline vendor tripwire' }
    Copy-Item -LiteralPath (Join-Path $scratch 'bin/codex.exe') -Destination (Join-Path $scratch 'bin/claude.exe')
    $marker = Join-Path $scratch 'vendor-invoked'
    $environment = @{
        USERPROFILE = (Join-Path $scratch 'home'); HOME = (Join-Path $scratch 'home')
        APPDATA = (Join-Path $scratch 'home/AppData/Roaming'); LOCALAPPDATA = (Join-Path $scratch 'home/AppData/Local')
        TEMP = (Join-Path $scratch 'temp'); TMP = (Join-Path $scratch 'temp')
        PATH = "$(Join-Path $scratch 'bin');$env:SystemRoot\System32;$env:SystemRoot"
        AGENTDECK_DATA_DIR = (Join-Path $scratch 'data'); AGENTDECK_OFFLINE_MARKER = $marker
        AGENTDECK_CODEX_BIN = (Join-Path $scratch 'bin/codex.exe')
    }
    $environment.HOMEDRIVE = [IO.Path]::GetPathRoot($environment.USERPROFILE).TrimEnd('\')
    $environment.HOMEPATH = $environment.USERPROFILE.Substring($environment.HOMEDRIVE.Length)
    Expand-Archive -LiteralPath (Join-Path $OutputDir "agentdeckd-$target.zip") -DestinationPath (Join-Path $scratch 'daemon')
    Expand-Archive -LiteralPath (Join-Path $OutputDir "AgentDeck-$target.zip") -DestinationPath (Join-Path $scratch 'desktop')
    $daemonDir = Join-Path $scratch 'daemon'
    $desktopDir = Join-Path $scratch 'desktop/AgentDeck'
    foreach ($directory in @($daemonDir, $desktopDir)) {
        if ((Get-Content -Raw -LiteralPath (Join-Path $directory 'RELEASE-VERSION')).Trim() -ne $version) {
            throw 'Archive version metadata mismatch'
        }
        $info = Get-Content -LiteralPath (Join-Path $directory 'RELEASE-INFO.txt')
        foreach ($line in @("version=$version", "target=$target", 'signing=unsigned', 'runtime=static-crt')) {
            if ($line -notin $info) { throw "Missing metadata: $line" }
        }
        if ((Get-FileHash -LiteralPath (Join-Path $directory 'LICENSE')).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $root 'LICENSE')).Hash) { throw 'License mismatch' }
    }
    $standalone = Join-Path $daemonDir 'agentdeckd.exe'
    $bundled = Join-Path $desktopDir 'agentdeckd.exe'
    $desktop = Join-Path $desktopDir 'AgentDeck.exe'
    if ((Get-FileHash -LiteralPath $standalone).Hash -ne (Get-FileHash -LiteralPath $bundled).Hash) {
        throw 'Standalone and bundled daemon differ'
    }
    foreach ($entry in @(
        @{ Path = $standalone; Name = 'agentdeckd'; Label = 'standalone' },
        @{ Path = $bundled; Name = 'agentdeckd'; Label = 'bundled' },
        @{ Path = $desktop; Name = 'agentdeck-desktop'; Label = 'desktop' }
    )) {
        Assert-WindowsBinary $entry.Path
        if ((Get-AuthenticodeSignature -LiteralPath $entry.Path).Status -ne 'NotSigned') {
            throw 'Package signing metadata does not match its executable'
        }
        $text = Invoke-IsolatedProcess -Executable $entry.Path -Arguments @('--version') `
            -WorkingDirectory $scratch -Environment $environment -Log (Join-Path $scratch "$($entry.Label)-version.log")
        if (($text -split '\r?\n')[0] -ne "$($entry.Name) $version") { throw 'Actual binary version mismatch' }
        $text = Invoke-IsolatedProcess -Executable $entry.Path -Arguments @('--selfcheck') `
            -WorkingDirectory $scratch -Environment $environment -Log (Join-Path $scratch "$($entry.Label)-selfcheck.log")
        $expected = if ($entry.Name -eq 'agentdeckd') { 'OK' } else { '{"status":"ok","surface":"desktop","ui":"gpui"}' }
        if ($expected -notin ($text -split '\r?\n')) { throw "Missing $($entry.Label) selfcheck success report" }
        if (Test-Path -LiteralPath $marker) { throw 'Selfcheck invoked a vendor' }
    }
    [void](Invoke-IsolatedProcess -Executable $standalone -Arguments @('--diagnostics-report') `
        -WorkingDirectory $scratch -Environment $environment -Log (Join-Path $scratch 'diagnostics.log'))
    if (Test-Path -LiteralPath $marker) { throw 'Smoke test invoked a vendor' }
    Write-Host "Smoke passed: Windows x64 $version; archive binaries, isolated data, no vendor session."
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
