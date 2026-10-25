# Windows release helpers; PowerShell 7+. No signing or machine configuration.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ReleaseVersion {
    param([string]$Root, [string]$Tag = '')
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $Root 'Cargo.toml')
    $match = [regex]::Match($manifest, '(?ms)^\[workspace\.package\]\s*\n(?:(?!^\[).)*?^version = "([^"]+)"')
    $version = $match.Groups[1].Value
    if ($version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
        throw "Invalid workspace version: $version"
    }
    $lock = Get-Content -Raw -LiteralPath (Join-Path $Root 'Cargo.lock')
    foreach ($crate in @('agentdeck-desktop', 'agentdeckd', 'agentdeck-protocol', 'agentdeck-cli')) {
        $crateManifest = Get-Content -Raw -LiteralPath (Join-Path $Root "$crate/Cargo.toml")
        if ($crateManifest -notmatch '(?m)^version\.workspace = true\r?$') {
            throw "$crate must inherit workspace version"
        }
        $locked = [regex]::Matches($lock, ('(?m)^name = "' + [regex]::Escape($crate) + '"\r?\nversion = "([^"]+)"'))
        if ($locked.Count -ne 1 -or $locked[0].Groups[1].Value -ne $version) {
            throw "$crate lock version differs from $version"
        }
    }
    if ($Tag -and $Tag -ne "v$version") { throw "Tag $Tag differs from workspace v$version" }
    return $version
}

function Write-ReleaseText {
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText($Path, ($Text -replace "`r`n", "`n"), [Text.UTF8Encoding]::new($false))
}

function Assert-WindowsBinary {
    param([string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not a PE executable: $Path" }
        $stream.Position = 0x3c
        $stream.Position = $reader.ReadInt32()
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw "Expected an x86_64 PE executable: $Path"
        }
    } finally { $reader.Dispose() }
    $imports = & dumpbin.exe /NOLOGO /DEPENDENTS $Path
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect DLL imports: $Path" }
    # Only Windows-provided libraries are allowed; static CRT avoids a hidden VC redistributable prerequisite.
    $systemDlls = @('advapi32', 'bcrypt', 'bcryptprimitives', 'cfgmgr32', 'combase', 'comctl32',
        'comdlg32', 'crypt32', 'cryptbase', 'd2d1', 'd3d11', 'd3d12', 'd3dcompiler_47', 'dbghelp',
        'dcomp', 'dnsapi', 'dwmapi', 'dwrite', 'dxgi', 'gdi32', 'hid', 'imm32', 'iphlpapi', 'kernel32',
        'kernelbase', 'msimg32', 'msvcrt', 'ncrypt', 'netapi32', 'normaliz', 'ntdll', 'ole32', 'oleaut32',
        'opengl32', 'powrprof', 'profapi', 'propsys', 'psapi', 'rpcrt4', 'runtimeobject', 'secur32',
        'setupapi', 'shell32', 'shlwapi', 'user32', 'userenv', 'usp10', 'uxtheme', 'version',
        'windowscodecs', 'winhttp', 'wininet', 'winmm', 'winspool', 'wintrust', 'ws2_32', 'wtsapi32')
    $dependencies = @($imports | ForEach-Object {
        if ($_ -match '^\s+([A-Za-z0-9_.-]+\.dll)\s*$') { $Matches[1].ToLowerInvariant() }
    })
    if ($dependencies.Count -eq 0) { throw "No import table found: $Path" }
    foreach ($dll in $dependencies) {
        if ($dll -match '^(api-ms-win-|ext-ms-win-)') { continue }
        if ([IO.Path]::GetFileNameWithoutExtension($dll) -notin $systemDlls) {
            throw "Unexpected non-system DLL dependency $dll in $Path; package its licensed runtime explicitly"
        }
        if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot "System32/$dll"))) {
            throw "Required Windows DLL is missing: $dll"
        }
    }
    Write-Host "$([IO.Path]::GetFileName($Path)): x64 PE; Windows DLLs: $($dependencies -join ', ')"
}

function Initialize-SmokeRunner {
    if (-not ('AgentDeck.ReleaseSmokeProcess' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'WindowsSmokeProcess.cs')
    }
}

function Invoke-IsolatedProcess {
    param([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory,
        [hashtable]$Environment, [string]$Log, [int]$TimeoutMilliseconds = 60000)
    Initialize-SmokeRunner
    $childEnvironment = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $childEnvironment[$entry.Key] = $entry.Value
    }
    [void]$childEnvironment.Remove('AGENTDECK_E2E')
    foreach ($entry in $Environment.GetEnumerator()) { $childEnvironment[$entry.Key] = $entry.Value }
    try {
        $exitCode = [AgentDeck.ReleaseSmokeProcess]::Run($Executable, $Arguments, $WorkingDirectory,
            $childEnvironment, $Log, $TimeoutMilliseconds)
        if ($exitCode -ne 0) { throw "$Executable exited $exitCode" }
    } finally {
        if (Test-Path -LiteralPath $Log) { Write-Host (Get-Content -Raw -LiteralPath $Log) }
    }
    return Get-Content -Raw -LiteralPath $Log
}
