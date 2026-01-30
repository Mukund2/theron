#Requires -Version 5.1
<#
.SYNOPSIS
    Theron Installer for Windows
.DESCRIPTION
    Downloads and installs Theron security proxy for AI agents.
    Usage: irm https://get.theron.dev/install.ps1 | iex
.NOTES
    This script:
    1. Checks for Python 3.11+, installs if missing
    2. Installs Theron via pip
    3. Runs theron setup to configure automatic protection
#>

$ErrorActionPreference = "Stop"

# Minimum Python version
$MinPythonMajor = 3
$MinPythonMinor = 11

function Write-Banner {
    Write-Host ""
    Write-Host "  _____ _                            " -ForegroundColor Blue
    Write-Host " |_   _| |__   ___ _ __ ___  _ __    " -ForegroundColor Blue
    Write-Host "   | | | '_ \ / _ \ '__/ _ \| '_ \   " -ForegroundColor Blue
    Write-Host "   | | | | | |  __/ | | (_) | | | |  " -ForegroundColor Blue
    Write-Host "   |_| |_| |_|\___|_|  \___/|_| |_|  " -ForegroundColor Blue
    Write-Host ""
    Write-Host "  Security proxy for agentic AI systems" -ForegroundColor White
    Write-Host ""
}

function Write-Info {
    param([string]$Message)
    Write-Host "==> " -ForegroundColor Blue -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Success {
    param([string]$Message)
    Write-Host "==> " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Warning {
    param([string]$Message)
    Write-Host "==> " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Error {
    param([string]$Message)
    Write-Host "==> " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Get-PythonVersion {
    param([string]$PythonCmd)

    try {
        $version = & $PythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $version
        }
    } catch {
        # Ignore errors
    }
    return $null
}

function Find-Python {
    $minVersion = [version]"$MinPythonMajor.$MinPythonMinor"

    # Check common Python commands
    $pythonCommands = @("python3.13", "python3.12", "python3.11", "python3", "python", "py -3.12", "py -3.11", "py -3")

    foreach ($cmd in $pythonCommands) {
        $parts = $cmd -split " "
        $pythonExe = $parts[0]
        $args = if ($parts.Length -gt 1) { $parts[1..($parts.Length-1)] } else { @() }

        try {
            if ($args.Length -gt 0) {
                $versionStr = & $pythonExe $args -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            } else {
                $versionStr = & $pythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            }

            if ($LASTEXITCODE -eq 0 -and $versionStr) {
                $version = [version]$versionStr.Trim()
                if ($version -ge $minVersion) {
                    return @{
                        Command = $cmd
                        Version = $versionStr.Trim()
                    }
                }
            }
        } catch {
            # Continue to next command
        }
    }

    return $null
}

function Install-Python {
    Write-Info "Installing Python $MinPythonMajor.$MinPythonMinor..."

    # Check if winget is available
    $wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue

    if ($wingetAvailable) {
        Write-Info "Using winget to install Python..."
        try {
            winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements

            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

            $python = Find-Python
            if ($python) {
                Write-Success "Python installed successfully via winget"
                return $python
            }
        } catch {
            Write-Warning "winget installation failed, trying manual download..."
        }
    }

    # Fall back to manual download
    Write-Info "Downloading Python installer..."
    $installerUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
    $installerPath = Join-Path $env:TEMP "python-installer.exe"

    try {
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

        Write-Info "Running Python installer (this may take a moment)..."
        # Silent install with PATH modification
        Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_pip=1" -Wait -NoNewWindow

        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        $python = Find-Python
        if ($python) {
            Write-Success "Python installed successfully"
            return $python
        }
    } catch {
        Write-Error "Failed to download/install Python: $_"
    }

    return $null
}

function Install-Theron {
    param([string]$PythonCmd)

    Write-Info "Installing Theron..."

    $parts = $PythonCmd -split " "
    $pythonExe = $parts[0]
    $args = if ($parts.Length -gt 1) { $parts[1..($parts.Length-1)] } else { @() }

    try {
        # Upgrade pip
        if ($args.Length -gt 0) {
            & $pythonExe $args -m pip install --upgrade pip 2>&1 | Out-Null
            & $pythonExe $args -m pip install theron 2>&1
        } else {
            & $pythonExe -m pip install --upgrade pip 2>&1 | Out-Null
            & $pythonExe -m pip install theron 2>&1
        }

        if ($LASTEXITCODE -ne 0) {
            throw "pip install failed"
        }

        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        # Check if theron is available
        $theronPath = Get-Command theron -ErrorAction SilentlyContinue
        if ($theronPath) {
            Write-Success "Theron installed successfully"
            return $true
        }

        # Check common locations
        $userScripts = Join-Path $env:APPDATA "Python\Python312\Scripts"
        if (Test-Path (Join-Path $userScripts "theron.exe")) {
            $env:Path = "$userScripts;$env:Path"
            Write-Success "Theron installed successfully"
            return $true
        }

        Write-Error "Theron installation completed but 'theron' command not found in PATH"
        return $false
    } catch {
        Write-Error "Failed to install Theron: $_"
        return $false
    }
}

function Invoke-TheronSetup {
    Write-Info "Configuring Theron..."

    try {
        & theron setup
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Theron configured successfully"
            return $true
        }
    } catch {
        Write-Error "Setup failed: $_"
    }

    return $false
}

function Write-FinalInstructions {
    Write-Host ""
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "                  Installation Complete!                    " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  NEXT STEP:" -ForegroundColor White
    Write-Host ""
    Write-Host "  Close this terminal and open a new one." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  That's it! After you restart your terminal:" -ForegroundColor White
    Write-Host ""
    Write-Host "    - Theron starts automatically in the background" -ForegroundColor Gray
    Write-Host "    - All your AI agents are now protected" -ForegroundColor Gray
    Write-Host "    - You don't need to do anything else" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Just use your AI agents normally:" -ForegroundColor White
    Write-Host ""
    Write-Host "    > claude           # Protected automatically" -ForegroundColor Gray
    Write-Host "    > your-ai-agent    # Protected automatically" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Optional:" -ForegroundColor White
    Write-Host ""
    Write-Host "    View dashboard:   " -NoNewline -ForegroundColor Gray
    Write-Host "http://localhost:8080" -ForegroundColor Blue
    Write-Host "    Check status:     theron setup --status" -ForegroundColor Gray
    Write-Host "    Uninstall:        theron setup --uninstall" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
}

# Main installation flow
function Main {
    Write-Banner

    # Check for Python
    Write-Info "Checking for Python $MinPythonMajor.$MinPythonMinor+..."
    $python = Find-Python

    if ($python) {
        Write-Success "Found Python $($python.Version) ($($python.Command))"
    } else {
        Write-Warning "Python $MinPythonMajor.$MinPythonMinor+ not found"
        $python = Install-Python

        if (-not $python) {
            Write-Error "Failed to install Python. Please install Python $MinPythonMajor.$MinPythonMinor+ manually from https://python.org"
            exit 1
        }
    }

    # Install Theron
    if (-not (Install-Theron -PythonCmd $python.Command)) {
        exit 1
    }

    # Run setup
    if (-not (Invoke-TheronSetup)) {
        exit 1
    }

    # Success!
    Write-FinalInstructions
}

# Run main
Main
