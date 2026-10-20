param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ProgramArgs
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$jarPath = Join-Path $projectRoot 'build\netsentinel-dpi.jar'
$javaHome = $env:JAVA_HOME
if (-not $javaHome -or -not (Test-Path -LiteralPath (Join-Path $javaHome 'bin\java.exe'))) {
    $javaInstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Java'
    $installedJdks = @(Get-ChildItem -Path $javaInstallRoot -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue |
        Sort-Object { try { [version]($_.Name -replace '^jdk-', '') } catch { [version]'0.0' } } -Descending)
    if ($installedJdks.Count -gt 0) {
        $javaHome = $installedJdks[0].FullName
    }
}
$javaPath = if ($javaHome -and (Test-Path -LiteralPath (Join-Path $javaHome 'bin\java.exe'))) {
    Join-Path $javaHome 'bin\java.exe'
} else {
    (Get-Command java -ErrorAction Stop).Source
}
if (-not (Test-Path -LiteralPath $jarPath)) {
    & (Join-Path $projectRoot 'build.ps1')
}

& $javaPath -jar $jarPath @ProgramArgs
exit $LASTEXITCODE
