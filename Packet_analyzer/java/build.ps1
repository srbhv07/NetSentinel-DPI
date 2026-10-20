$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceRoot = Join-Path $projectRoot 'src\main\java'
$classesRoot = Join-Path $projectRoot 'build\classes'
$jarPath = Join-Path $projectRoot 'build\netsentinel-dpi.jar'

$javaHome = $env:JAVA_HOME
if (-not $javaHome -or -not (Test-Path -LiteralPath (Join-Path $javaHome 'bin\javac.exe'))) {
    $javaInstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Java'
    $installedJdks = @(Get-ChildItem -Path $javaInstallRoot -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue |
        Sort-Object { try { [version]($_.Name -replace '^jdk-', '') } catch { [version]'0.0' } } -Descending)
    if ($installedJdks.Count -gt 0) {
        $javaHome = $installedJdks[0].FullName
    }
}

$javacPath = if ($javaHome -and (Test-Path -LiteralPath (Join-Path $javaHome 'bin\javac.exe'))) {
    Join-Path $javaHome 'bin\javac.exe'
} else {
    (Get-Command javac -ErrorAction Stop).Source
}
$jarToolPath = if ($javaHome -and (Test-Path -LiteralPath (Join-Path $javaHome 'bin\jar.exe'))) {
    Join-Path $javaHome 'bin\jar.exe'
} else {
    (Get-Command jar -ErrorAction Stop).Source
}

New-Item -ItemType Directory -Force -Path $classesRoot | Out-Null
$sources = Get-ChildItem -Path $sourceRoot -Recurse -Filter '*.java' |
    ForEach-Object { $_.FullName }
if ($sources.Count -eq 0) {
    throw "No Java source files found under $sourceRoot"
}

& $javacPath --release 11 -encoding UTF-8 -d $classesRoot @sources
if ($LASTEXITCODE -ne 0) {
    throw "javac failed with exit code $LASTEXITCODE"
}

& $jarToolPath --create --file $jarPath --main-class com.packetanalyzer.PacketAnalyzer -C $classesRoot .
if ($LASTEXITCODE -ne 0) {
    throw "jar failed with exit code $LASTEXITCODE"
}

Write-Host "Built $jarPath"
