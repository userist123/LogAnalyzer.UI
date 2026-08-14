<#
.SYNOPSIS
    Generator de chei de licență pentru LogAnalyzer DFIR Enterprise.
.DESCRIPTION
    Calculează cheia SHA-256 pe baza Hardware ID-ului stației țintă și a datei de expirare.
.PARAMETER HardwareId
    (Opțional) Hardware ID-ul stației (16 caractere). Dacă nu este specificat, se extrage automat de pe stația curentă.
.PARAMETER ExpiryDate
    (Opțional) Data de expirare în formatul YYYY-MM-DD. Implicit: 1 an de la data curentă.
.EXAMPLE
    .\Generate-LicenseKey.ps1
.EXAMPLE
    .\Generate-LicenseKey.ps1 -HardwareId "A1B2C3D4E5F67890" -ExpiryDate "2030-12-31"
#>
param (
    [string]$HardwareId,
    [string]$ExpiryDate = (Get-Date).AddYears(1).ToString("yyyy-MM-dd")
)

$salt = "INFOSEC_ROMANIA_SOC_2026_SECURE_KEY"

if (-not $HardwareId) {
    # Extrage Hardware ID-ul mașinii locale via CIM/WMI
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).ProcessorId
    $board = (Get-CimInstance Win32_BaseBoard | Select-Object -First 1).SerialNumber
    $rawHw = "$cpu$board"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($rawHw)
    $hashBytes = $sha256.ComputeHash($bytes)
    $hex = [BitConverter]::ToString($hashBytes).Replace("-", "").ToUpper()
    $HardwareId = $hex.Substring(0, 16)
}

$datePart = ([DateTime]::Parse($ExpiryDate)).ToString("yyyyMMdd")
$payload = "$($HardwareId.Trim().ToUpper())$datePart$salt"

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$hashBytes = $sha256.ComputeHash($bytes)
$hex = [BitConverter]::ToString($hashBytes).Replace("-", "").ToUpper()
$key = $hex.Substring(0, 20)

$fullLicenseString = "$key|$ExpiryDate"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " 🛡️ LOGANALYZER DFIR - GENERATOR CHEIE LICENȚĂ" -ForegroundColor Yellow
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " Hardware ID:      $HardwareId" -ForegroundColor White
Write-Host " Data Expirare:    $ExpiryDate" -ForegroundColor White
Write-Host " Cheie Generată:   $key" -ForegroundColor Green
Write-Host " Format Licență:   $fullLicenseString" -ForegroundColor Magenta
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Formatul de introdus în aplicație sau fișierul license.lic este:"
Write-Host "$fullLicenseString" -ForegroundColor Yellow
Write-Host "===================================================" -ForegroundColor Cyan

return $fullLicenseString
