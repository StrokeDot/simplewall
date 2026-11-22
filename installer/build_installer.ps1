$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$vsDev = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$ver = (Select-String -Path "$root\src\app.h" -Pattern '#define APP_VERSION L"([^"]+)"').Matches[0].Groups[1].Value
$outExe = "$root\bin\64\simplewall_setup_$ver.exe"
$tmpDir = "$root\x64\Release\installer"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

$cmd = "`"$vsDev`" && rc /nologo /fo `"$tmpDir\setup.res`" `"$PSScriptRoot\setup.rc`" && cl /nologo /O2 /MT /EHsc /std:c++20 /DUNICODE /D_UNICODE `"$PSScriptRoot\setup.cpp`" `"$tmpDir\setup.res`" /Fe:`"$outExe`" /Fo:`"$tmpDir\setup.obj`" /link /SUBSYSTEM:WINDOWS"
cmd.exe /c $cmd
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "Built installer: $outExe ($((Get-Item $outExe).Length) bytes)"
