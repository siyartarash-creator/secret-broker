# Stores a secret encrypted with Windows DPAPI (readable only by this Windows user on this PC).
# The value is typed hidden and never appears on the command line or in a file.
# Usage: powershell -ExecutionPolicy Bypass -File set-secret.ps1 -Name openrouter

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{1,63}$')]
    [string]$Name
)

$root = if ($env:SECRETS_ROOT) { $env:SECRETS_ROOT } else { Join-Path $env:USERPROFILE '.ecc\secrets\vault' }
New-Item -ItemType Directory -Path $root -Force | Out-Null

$secure = Read-Host -AsSecureString "Value for '$Name' (hidden)"
$blob = ConvertFrom-SecureString $secure
Set-Content -Path (Join-Path $root "$Name.dpapi") -Value $blob -Encoding ascii -NoNewline
Write-Output "Saved '$Name' to $root (encrypted for this Windows user)."
