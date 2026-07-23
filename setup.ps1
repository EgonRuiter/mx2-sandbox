# MX2 Windows Local Development Setup Script
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Setting up MX2 Local Sandbox Environment " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Verify Python is installed
try {
    $pythonVersion = & python --version 2>&1
    Write-Host "[+] Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Error "[-] Python not found on PATH. Please install Python 3.9+."
    Exit 1
}

# 2. Create Virtual Environment
if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating Python virtual environment in '.venv'..." -ForegroundColor Yellow
    & python -m venv .venv
    Write-Host "[+] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Virtual environment '.venv' already exists." -ForegroundColor Green
}

# 3. Determine Activation Script
$activateScript = ".venv\Scripts\Activate.ps1"
Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
& $activateScript

# 4. Install Developer Dependencies
Write-Host "[*] Upgrading pip and installing dev dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip
pip install -e .[dev]
Write-Host "[+] Dependencies successfully installed." -ForegroundColor Green

# 5. Install Pre-Commit Hooks
if (Get-Command pre-commit -ErrorAction SilentlyContinue) {
    Write-Host "[*] Registering git pre-commit hooks..." -ForegroundColor Yellow
    pre-commit install
    Write-Host "[+] Pre-commit hooks installed." -ForegroundColor Green
}

# 6. Run Verification Test Suite
Write-Host "[*] Running verification tests..." -ForegroundColor Yellow
python -m unittest discover -s tests -p "test_*.py"

Write-Host "=============================================" -ForegroundColor Green
Write-Host " Setup Completed Successfully! " -ForegroundColor Green
Write-Host " You are now ready to write code for MX2! " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
