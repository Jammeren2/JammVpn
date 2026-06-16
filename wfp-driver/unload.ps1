# Stop and remove the JammVpnSplit kernel driver service.
# Run ELEVATED (Administrator):
#   powershell -ExecutionPolicy Bypass -File unload.ps1

#Requires -RunAsAdministrator
& sc.exe stop   JammVpnSplit 2>$null
& sc.exe delete JammVpnSplit
Write-Host "Driver 'JammVpnSplit' stopped and removed."
