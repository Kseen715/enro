# Build script for ENRO on Windows

Write-Host "🔨 Building ENRO - File Encryption & Randomness Observer" -ForegroundColor Cyan
Write-Host ""

# Check if we have MSVC linker
$hasMSVC = $false
try {
    $null = Get-Command link.exe -ErrorAction Stop
    $hasMSVC = $true
    Write-Host "✓ Found MSVC linker" -ForegroundColor Green
} catch {
    Write-Host "✗ MSVC linker not found" -ForegroundColor Yellow
}

if (-not $hasMSVC) {
    Write-Host ""
    Write-Host "Attempting to build with GNU toolchain..." -ForegroundColor Yellow
    
    # Check if GNU target is installed
    $targets = rustup target list --installed
    if ($targets -notcontains "x86_64-pc-windows-gnu") {
        Write-Host "Installing GNU target..." -ForegroundColor Cyan
        rustup target add x86_64-pc-windows-gnu
    }
    
    # Check if MinGW is available
    $hasMinGW = $false
    try {
        $null = Get-Command gcc.exe -ErrorAction Stop
        $hasMinGW = $true
        Write-Host "✓ Found MinGW GCC" -ForegroundColor Green
    } catch {
        Write-Host "✗ MinGW not found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install one of the following:" -ForegroundColor Yellow
        Write-Host "  1. Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/" -ForegroundColor White
        Write-Host "  2. MinGW-w64 via Chocolatey: choco install mingw" -ForegroundColor White
        Write-Host "  3. MinGW-w64 via MSYS2: https://www.msys2.org/" -ForegroundColor White
        exit 1
    }
    
    Write-Host ""
    Write-Host "Building with GNU toolchain..." -ForegroundColor Cyan
    cargo build --release --target x86_64-pc-windows-gnu
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Build successful!" -ForegroundColor Green
        Write-Host "Binary location: target\x86_64-pc-windows-gnu\release\enro.exe" -ForegroundColor Cyan
        
        # Copy to root target directory for convenience
        Copy-Item "target\x86_64-pc-windows-gnu\release\enro.exe" "target\release\enro.exe" -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host ""
        Write-Host "✗ Build failed!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "Building with MSVC toolchain..." -ForegroundColor Cyan
    cargo build --release
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Build successful!" -ForegroundColor Green
        Write-Host "Binary location: target\release\enro.exe" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "✗ Build failed!" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Run with: .\target\release\enro.exe --help" -ForegroundColor White
