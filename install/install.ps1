# ezcrypt installer for Windows.
#   irm https://github.com/bitcrshr/ezcrypt/releases/latest/download/install.ps1 | iex
# Set $env:EZCRYPT_BASE_URL to install from somewhere other than the latest release.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$baseUrl = $env:EZCRYPT_BASE_URL
if (-not $baseUrl) { $baseUrl = 'https://github.com/bitcrshr/ezcrypt/releases/latest/download' }

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'x86_64' }
    'ARM64' { $arch = 'aarch64' }
    default { throw "ezcrypt install: unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$target = "$arch-pc-windows-msvc"
$archive = "ezcrypt-$target.zip"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ezcrypt-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $archive"
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archive" -OutFile (Join-Path $tmp $archive)
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') |
        Where-Object { ($_ -split '\s+', 2)[1] -eq $archive } |
        Select-Object -First 1
    if (-not $line) { throw "ezcrypt install: $archive is not listed in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLower()
    if ($actual -ne $expected) { throw "ezcrypt install: checksum mismatch for $archive" }

    $dest = Join-Path $env:LOCALAPPDATA 'Programs\ezcrypt'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $dest -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if (($userPath -split ';') -notcontains $dest) {
        $newPath = if ($userPath) { "$userPath;$dest" } else { $dest }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "Added $dest to your user PATH. Open a new terminal to use it."
    }

    Write-Host "Installed to $dest\ezcrypt.exe"
    & (Join-Path $dest 'ezcrypt.exe') --version
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
