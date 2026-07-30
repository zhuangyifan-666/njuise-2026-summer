param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = "Stop"
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
$name = Split-Path -Leaf $Path
Set-Content -LiteralPath $Output -Value "$hash  $name" -Encoding ascii -NoNewline
