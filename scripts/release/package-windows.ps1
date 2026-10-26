param([string]$OutputDir = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common-windows.ps1')
if (-not $IsWindows) { throw 'Windows packaging requires PowerShell 7 on Windows' }
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$target = 'x86_64-pc-windows-msvc'
$version = Get-ReleaseVersion $root $env:AGENTDECK_RELEASE_TAG
if (-not $OutputDir) { $OutputDir = Join-Path $root 'dist/release' }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
[void][IO.Directory]::CreateDirectory($OutputDir)
if ($env:RUSTFLAGS -or $env:CARGO_ENCODED_RUSTFLAGS) {
    throw 'Clear global RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS so the target-specific static CRT setting is effective'
}
$previousFlags = $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS
$previousFxc = $env:GPUI_FXC_PATH
$stage = Join-Path $OutputDir ('.package-' + [guid]::NewGuid().ToString('N'))
Push-Location $root
try {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
    if (-not $env:GPUI_FXC_PATH) {
        $fxc = Get-Command fxc.exe -ErrorAction SilentlyContinue
        if ($fxc) { $env:GPUI_FXC_PATH = $fxc.Source }
        else {
            $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
            $fxc = Get-ChildItem -Path "$sdk/*/x64/fxc.exe" -ErrorAction SilentlyContinue |
                Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
            if ($fxc) { $env:GPUI_FXC_PATH = $fxc.FullName }
        }
    }
    if (-not $env:GPUI_FXC_PATH -or -not (Test-Path -LiteralPath $env:GPUI_FXC_PATH)) {
        throw 'Windows SDK fxc.exe is required to compile and embed GPUI release shaders; set GPUI_FXC_PATH'
    }
    [void](Get-Command dumpbin.exe -ErrorAction Stop)
    & cargo build --release --locked --target $target --target-dir target/release-build `
        -p agentdeckd --bin agentdeckd -p agentdeck-desktop --bin agentdeck-desktop
    if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed' }
    $binDir = Join-Path $root "target/release-build/$target/release"
    $probeDir = Join-Path $stage 'version-probe'
    foreach ($directory in @('', 'home', 'data', 'temp', 'home/AppData/Roaming', 'home/AppData/Local')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $probeDir $directory))
    }
    $probeEnvironment = @{
        USERPROFILE = (Join-Path $probeDir 'home'); HOME = (Join-Path $probeDir 'home')
        APPDATA = (Join-Path $probeDir 'home/AppData/Roaming'); LOCALAPPDATA = (Join-Path $probeDir 'home/AppData/Local')
        TEMP = (Join-Path $probeDir 'temp'); TMP = (Join-Path $probeDir 'temp')
        PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        AGENTDECK_DATA_DIR = (Join-Path $probeDir 'data')
    }
    $probeEnvironment.HOMEDRIVE = [IO.Path]::GetPathRoot($probeEnvironment.USERPROFILE).TrimEnd('\')
    $probeEnvironment.HOMEPATH = $probeEnvironment.USERPROFILE.Substring($probeEnvironment.HOMEDRIVE.Length)
    foreach ($name in @('agentdeckd', 'agentdeck-desktop')) {
        $binary = Join-Path $binDir "$name.exe"
        Assert-WindowsBinary $binary
        # GUI-subsystem executables need an explicit process wait; never rely on PowerShell's pipeline lifetime.
        $actual = Invoke-IsolatedProcess -Executable $binary -Arguments @('--version') `
            -WorkingDirectory $probeDir -Environment $probeEnvironment -Log (Join-Path $probeDir "$name-version.log")
        if ([string]::IsNullOrEmpty($actual) -or ($actual -split '\r?\n')[0] -ne "$name $version") {
            throw "Binary version mismatch: $binary"
        }
        if ((Get-AuthenticodeSignature -LiteralPath $binary).Status -ne 'NotSigned') {
            throw "Expected unsigned output from this pipeline: $binary"
        }
    }
    $daemonDir = Join-Path $stage 'daemon'
    $desktopParent = Join-Path $stage 'desktop'
    $desktopDir = Join-Path $desktopParent 'AgentDeck'
    [void][IO.Directory]::CreateDirectory($daemonDir)
    [void][IO.Directory]::CreateDirectory($desktopDir)
    Copy-Item -LiteralPath (Join-Path $binDir 'agentdeckd.exe') -Destination $daemonDir
    Copy-Item -LiteralPath (Join-Path $daemonDir 'agentdeckd.exe') -Destination $desktopDir
    Copy-Item -LiteralPath (Join-Path $binDir 'agentdeck-desktop.exe') -Destination (Join-Path $desktopDir 'AgentDeck.exe')
    $commit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve source commit' }
    foreach ($directory in @($daemonDir, $desktopDir)) {
        Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $directory
        Write-ReleaseText (Join-Path $directory 'RELEASE-VERSION') "$version`n"
        Write-ReleaseText (Join-Path $directory 'RELEASE-INFO.txt') @"
version=$version
target=$target
commit=$commit
signing=unsigned
runtime=static-crt
Windows packages have no Authenticode signature; SmartScreen acceptance is not certified.
"@
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($entry in @(
        @{ Source = $daemonDir; Name = "agentdeckd-$target.zip" },
        @{ Source = $desktopParent; Name = "AgentDeck-$target.zip" }
    )) {
        $archive = Join-Path $stage $entry.Name
        [IO.Compression.ZipFile]::CreateFromDirectory($entry.Source, $archive,
            [IO.Compression.CompressionLevel]::Optimal, $false)
        Move-Item -LiteralPath $archive -Destination (Join-Path $OutputDir $entry.Name) -Force
    }
    Write-Host "Packaged Windows x64 $version; unsigned, static CRT, embedded release shaders."
} finally {
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = $previousFlags
    $env:GPUI_FXC_PATH = $previousFxc
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    Pop-Location
}
