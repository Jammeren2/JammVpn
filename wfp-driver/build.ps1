# Build JammVpnSplit.sys from the command line (cl/link), WITHOUT the WDK VS extension.
# Requires: Windows SDK + WDK (km headers/libs) + MSVC from VS 2022.
# Adjust the paths/version below to match your install if needed.
#
# Run:    powershell -ExecutionPolicy Bypass -File build.ps1
# Output: build\JammVpnSplit.sys (unsigned; for signing/loading see README.md).
#
# ASCII-only on purpose: Windows PowerShell 5.1 mis-decodes UTF-8-without-BOM .ps1.

$ErrorActionPreference = "Stop"

$msvcRoot = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
$kit      = "C:\Program Files (x86)\Windows Kits\10"
$ver      = "10.0.26100.0"

# Newest installed MSVC toolset.
$msvc = (Get-ChildItem $msvcRoot | Sort-Object Name -Descending | Select-Object -First 1).FullName
$cl   = "$msvc\bin\Hostx64\x64\cl.exe"
$link = "$msvc\bin\Hostx64\x64\link.exe"
$env:PATH = "$msvc\bin\Hostx64\x64;$env:PATH"

$src = Join-Path $PSScriptRoot "src"
$out = Join-Path $PSScriptRoot "build"
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "== Compiling driver.c (cl /kernel) =="
& $cl /nologo /c /kernel /GS- /W3 /Od /Zi `
  /D_AMD64_ /DAMD64 /D_WIN64 /DNTDDI_VERSION=0x0A000010 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DPOOL_NX_OPTIN=1 /DNDIS_WDM=1 /DNDIS630=1 `
  /I"$kit\Include\$ver\km\crt" `
  /I"$kit\Include\$ver\km" `
  /I"$kit\Include\$ver\shared" `
  /I"$msvc\include" `
  /Fo"$out\driver.obj" /Fd"$out\driver.pdb" `
  "$src\driver.c"
if ($LASTEXITCODE -ne 0) { throw "cl failed ($LASTEXITCODE)" }

Write-Host "== Linking JammVpnSplit.sys (link /DRIVER) =="
& $link /NOLOGO /OUT:"$out\JammVpnSplit.sys" /DRIVER /ENTRY:DriverEntry "/SUBSYSTEM:NATIVE,10.00" `
  /NODEFAULTLIB /MACHINE:X64 "/OPT:REF,ICF" /RELEASE `
  "$out\driver.obj" `
  /LIBPATH:"$kit\Lib\$ver\km\x64" `
  ntoskrnl.lib fwpkclnt.lib BufferOverflowK.lib
if ($LASTEXITCODE -ne 0) { throw "link failed ($LASTEXITCODE)" }

$sys = Join-Path $out "JammVpnSplit.sys"
Write-Host ("== Done: {0} ({1} bytes) ==" -f $sys, (Get-Item $sys).Length)
Write-Host "Driver is UNSIGNED. To load: enable test-signing + sign it (see README.md)."
