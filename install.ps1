# Installs pbx, the Passbox command-line client, on Windows from the GitHub releases.
#
#   irm https://raw.githubusercontent.com/passboxnet/cli/main/install.ps1 | iex
#
# Environment:
#   PBX_VERSION       version to install, e.g. 0.1.0 (default: the latest release)
#   PBX_INSTALL_DIR   where to put pbx.exe (default: %LOCALAPPDATA%\Programs\pbx)
#
# The archive is checked against the release's SHA256SUMS before anything is
# installed. Nothing needs administrator rights.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

& {
  $repo = 'passboxnet/cli'
  # x64 build; Windows on Arm runs it through emulation.
  $target = 'x86_64-pc-windows-msvc'

  $version = "$env:PBX_VERSION".TrimStart('v')
  if (-not $version) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
    $version = "$($release.tag_name)".TrimStart('v')
    if (-not $version) { throw "could not find the latest release of $repo" }
  }
  $installDir = if ($env:PBX_INSTALL_DIR) { $env:PBX_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\pbx' }

  $name = "pbx-$version-$target"
  $base = "https://github.com/$repo/releases/download/v$version"
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pbx-" + [System.Guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "Downloading pbx $version for $target"
    $zip = Join-Path $tmp "$name.zip"
    Invoke-WebRequest -Uri "$base/$name.zip" -OutFile $zip -UseBasicParsing
    $sums = (Invoke-WebRequest -Uri "$base/SHA256SUMS" -UseBasicParsing).Content
    if ($sums -is [byte[]]) { $sums = [System.Text.Encoding]::UTF8.GetString($sums) }

    $expected = $null
    foreach ($line in $sums -split "`n") {
      $parts = $line.Trim() -split '\s+'
      if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq "$name.zip") { $expected = $parts[0].ToLower() }
    }
    if (-not $expected) { throw "$name.zip is not listed in SHA256SUMS" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
    if ($actual -ne $expected) {
      throw "checksum mismatch for $name.zip (expected $expected, got $actual); nothing was installed"
    }
    Write-Host 'Checksum verified'

    Expand-Archive -Path $zip -DestinationPath $tmp
    $exe = Join-Path $tmp "$name\pbx.exe"
    if (-not (Test-Path $exe)) { throw 'the archive does not contain pbx.exe' }

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -Path $exe -Destination (Join-Path $installDir 'pbx.exe') -Force
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }

  $installed = & (Join-Path $installDir 'pbx.exe') --version
  Write-Host "Installed $installed to $installDir\pbx.exe"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  $onPath = ($env:Path -split ';') + ($userPath -split ';') | Where-Object { $_.TrimEnd('\') -eq $installDir.TrimEnd('\') }
  if (-not $onPath) {
    Write-Host ''
    Write-Host "$installDir is not on your PATH. Add it for your user with:"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$installDir;`" + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
    Write-Host 'Then open a new terminal.'
  }
}
