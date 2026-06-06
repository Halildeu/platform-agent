param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$Subject = "CN=platform-agent local ag029 test",
    [int]$Days = 7
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Path not found: $Path"
}

$cert = New-SelfSignedCertificate `
    -Subject $Subject `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -NotAfter (Get-Date).AddDays($Days)

$signature = Set-AuthenticodeSignature `
    -LiteralPath $Path `
    -Certificate $cert `
    -HashAlgorithm SHA256

$fileHash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
$version = (Get-Item -LiteralPath $Path).VersionInfo

$signerSha256 = $null
if ($null -ne $signature.SignerCertificate) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $signerSha256 = (($sha256.ComputeHash($signature.SignerCertificate.RawData) | ForEach-Object { $_.ToString("X2") }) -join "")
    }
    finally {
        $sha256.Dispose()
    }
}

[pscustomobject]@{
    path = (Resolve-Path -LiteralPath $Path).Path
    status = [string]$signature.Status
    statusMessage = [string]$signature.StatusMessage
    signerThumbprintSha1 = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
    signerThumbprintSha256 = $signerSha256
    sha256 = $fileHash.Hash
    productVersion = $version.ProductVersion
    fileVersion = $version.FileVersion
    subject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    notAfter = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.NotAfter.ToString("o") } else { $null }
} | ConvertTo-Json -Compress
