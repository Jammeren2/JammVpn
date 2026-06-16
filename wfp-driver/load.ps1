# Load the JammVpnSplit kernel driver on THIS machine for local/dev use.
# Self-signs (test certificate), trusts it, signs the .sys, registers + starts
# the kernel service. NOT for distribution (test-signing only).
#
# Run ELEVATED (Administrator):
#   powershell -ExecutionPolicy Bypass -File load.ps1
#
# Prerequisite (one-time, needs reboot): enable test-signing, see step 0 below.
# ASCII-only on purpose (Windows PowerShell 5.1 mis-decodes UTF-8-without-BOM).

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$sys     = Join-Path $PSScriptRoot "build\JammVpnSplit.sys"
$svc     = "JammVpnSplit"
$subject = "CN=JammVPN Test Driver"

if (-not (Test-Path $sys)) {
    throw "Not found: $sys`nBuild it first:  powershell -ExecutionPolicy Bypass -File build.ps1"
}

# 0. Test-signing must be ON. (One-time; requires reboot. If Secure Boot is on,
#    disable it in BIOS first, otherwise testsigning will not take effect.)
$bcd = (bcdedit /enum CURRENT | Out-String)
if ($bcd -notmatch "testsigning\s+Yes") {
    Write-Warning "Test-signing appears OFF. If the driver fails to start, run (elevated):"
    Write-Warning "    bcdedit /set testsigning on"
    Write-Warning "  then REBOOT and re-run this script."
}

# 1. Get-or-create a self-signed code-signing certificate.
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5)
    Write-Host "Created test certificate: $($cert.Thumbprint)"
} else {
    Write-Host "Using existing test certificate: $($cert.Thumbprint)"
}

# 2. Trust it so the test-signed driver loads (LocalMachine Root + TrustedPublisher).
$cer = Join-Path $PSScriptRoot "JammVpnTest.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root          | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

# 3. Sign the .sys (SHA256).
$res = Set-AuthenticodeSignature -FilePath $sys -Certificate $cert -HashAlgorithm SHA256
if ($res.Status -ne "Valid") { throw "Signing failed: $($res.StatusMessage)" }
Write-Host "Signed: $sys"

# 4. (Re)create and start the kernel service.
& sc.exe stop   $svc 2>$null | Out-Null
& sc.exe delete $svc 2>$null | Out-Null
& sc.exe create $svc type= kernel start= demand binPath= "$sys" | Out-Null
& sc.exe start  $svc
if ($LASTEXITCODE -ne 0) {
    throw "sc start failed (code $LASTEXITCODE). Most likely test-signing is OFF (see step 0) or Secure Boot blocks it."
}
Write-Host ""
Write-Host "Driver '$svc' is running."
Write-Host "Now in JammVPN: start the local proxy, add a rule with a process + action 'proxy',"
Write-Host "then press 'Apply' in the split-tunneling section."
Write-Host "Unload later with:  powershell -ExecutionPolicy Bypass -File unload.ps1"
