@echo off
:: ============================================================
:: build.bat - PE Visualizer Build Script
:: Requires: Visual Studio 2026 Developer Command Prompt v18.5.0
::           Copyright (c) 2026 Microsoft Corporation
::           x64 Native Tools Command Prompt
:: ============================================================
setlocal EnableDelayedExpansion

echo ============================================================
echo   PE Visualizer - Build Script
echo   Visual Studio 2026 Developer Command Prompt v18.5.0
echo ============================================================
echo.

:: ---- Parse arguments ----------------------------------------
set BUILD_TYPE=Release
set BUILD_SERVER=1
set BUILD_FRONTEND=1
set CLEAN_BUILD=0
set INSTALL_DEPS=1

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--debug"         ( set BUILD_TYPE=Debug    & shift & goto :parse_args )
if /i "%~1"=="--release"       ( set BUILD_TYPE=Release  & shift & goto :parse_args )
if /i "%~1"=="--server-only"   ( set BUILD_FRONTEND=0    & shift & goto :parse_args )
if /i "%~1"=="--frontend-only" ( set BUILD_SERVER=0      & shift & goto :parse_args )
if /i "%~1"=="--clean"         ( set CLEAN_BUILD=1       & shift & goto :parse_args )
if /i "%~1"=="--no-deps"       ( set INSTALL_DEPS=0      & shift & goto :parse_args )
if /i "%~1"=="--help"          goto :show_help
echo [WARN] Unknown argument: %~1
shift
goto :parse_args

:show_help
echo Usage: build.bat [OPTIONS]
echo.
echo   --debug           Build server in Debug mode (default: Release)
echo   --release         Build server in Release mode
echo   --server-only     Build C++ server only
echo   --frontend-only   Build Next.js frontend only
echo   --clean           Clean build directories before building
echo   --no-deps         Skip vcpkg and npm dependency installation
echo   --help            Show this help message
exit /b 0

:args_done

:: ---- Script root directory ----------------------------------
set SCRIPT_DIR=%~dp0
:: %~dp0 always ends with \, strip it
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

set SERVER_DIR=%SCRIPT_DIR%\server
set FRONTEND_DIR=%SCRIPT_DIR%\frontend
set BUILD_DIR=%SCRIPT_DIR%\build\server
set DIST_DIR=%SCRIPT_DIR%\dist

:: ---- Check prerequisites ------------------------------------
echo [INFO] Checking prerequisites...

if "%BUILD_SERVER%"=="1" (
    where cmake >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] cmake not found. Please install CMake 3.20+
        exit /b 1
    )
    echo [OK] CMake found

    where cl >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] cl.exe not found. Open a Visual Studio Developer Command Prompt with the Desktop development with C++ workload.
        exit /b 1
    )
    echo [OK] MSVC compiler found

    if not defined VCPKG_ROOT (
        echo [WARN] VCPKG_ROOT is not set. Trying PATH...
        where vcpkg >nul 2>&1
        if errorlevel 1 (
            echo [ERROR] vcpkg not found. Run: set VCPKG_ROOT=C:\vcpkg
            exit /b 1
        )
        for /f "delims=" %%p in ('where vcpkg') do (
            if not defined VCPKG_ROOT set VCPKG_ROOT=%%~dpp
        )
    )
    if "!VCPKG_ROOT:~-1!"=="\" set VCPKG_ROOT=!VCPKG_ROOT:~0,-1!
    echo [OK] vcpkg: %VCPKG_ROOT%

    if not defined VCPKG_INSTALLED_DIR set VCPKG_INSTALLED_DIR=%SERVER_DIR%\vcpkg_installed
    if not defined VCPKG_BUILDTREES_ROOT set VCPKG_BUILDTREES_ROOT=%VCPKG_ROOT%\buildtrees
    if not defined VCPKG_DOWNLOADS_ROOT set VCPKG_DOWNLOADS_ROOT=%VCPKG_ROOT%\downloads
    if not defined VCPKG_PACKAGES_ROOT set VCPKG_PACKAGES_ROOT=%VCPKG_ROOT%\packages
    echo.
)

if "%BUILD_FRONTEND%"=="1" (
    where node >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] node.js not found. Please install Node.js 18+
        exit /b 1
    )
    for /f %%v in ('node --version') do echo [OK] Node.js %%v

    where npm >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] npm not found.
        exit /b 1
    )
    for /f %%v in ('npm --version') do echo [OK] npm %%v
)

:: ---- Clean --------------------------------------------------
if "%CLEAN_BUILD%"=="1" (
    echo [INFO] Cleaning build directories...
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
    if exist "%FRONTEND_DIR%\.next" rmdir /s /q "%FRONTEND_DIR%\.next"
    echo [OK] Clean done.
    echo.
)

:: ============================================================
:: BUILD SERVER
:: ============================================================
if "%BUILD_SERVER%"=="1" (
    echo ------------------------------------------------------------
    echo   [1/2] Building C++ Server ^(%BUILD_TYPE%^)
    echo ------------------------------------------------------------

    if not exist "%SERVER_DIR%" (
        echo [ERROR] Server directory not found: %SERVER_DIR%
        exit /b 1
    )

    if "%INSTALL_DEPS%"=="1" (
        echo [INFO] Installing vcpkg dependencies...
        "%VCPKG_ROOT%\vcpkg.exe" install ^
            --triplet x64-windows ^
            --vcpkg-root "%VCPKG_ROOT%" ^
            --x-manifest-root "%SERVER_DIR%" ^
            --x-install-root "%VCPKG_INSTALLED_DIR%" ^
            --x-buildtrees-root "%VCPKG_BUILDTREES_ROOT%" ^
            --x-packages-root "%VCPKG_PACKAGES_ROOT%" ^
            --downloads-root "%VCPKG_DOWNLOADS_ROOT%"
        if errorlevel 1 (
            echo [ERROR] vcpkg install failed.
            exit /b 1
        )
        echo [OK] vcpkg done.
    )

    echo [INFO] Configuring CMake...
    if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

    cmake -S "%SERVER_DIR%" ^
          -B "%BUILD_DIR%" ^
          -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
          -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" ^
          -DVCPKG_TARGET_TRIPLET=x64-windows ^
          -DVCPKG_INSTALLED_DIR="%VCPKG_INSTALLED_DIR%" ^
          "-DVCPKG_INSTALL_OPTIONS=--x-buildtrees-root=%VCPKG_BUILDTREES_ROOT%;--x-packages-root=%VCPKG_PACKAGES_ROOT%;--downloads-root=%VCPKG_DOWNLOADS_ROOT%" ^
          -DCMAKE_INSTALL_PREFIX="%DIST_DIR%"

    if errorlevel 1 (
        echo [ERROR] CMake configure failed.
        exit /b 1
    )
    echo [OK] CMake configured.

    echo [INFO] Building...
    cmake --build "%BUILD_DIR%" --config %BUILD_TYPE% --parallel
    if errorlevel 1 (
        echo [ERROR] Build failed.
        exit /b 1
    )
    echo [OK] Server built.

    cmake --install "%BUILD_DIR%" --config %BUILD_TYPE%
    if errorlevel 1 (
        echo [ERROR] Install failed.
        exit /b 1
    )
    if exist "%SERVER_DIR%\vcpkg_installed\x64-windows\bin\*.dll" (
        copy /Y "%SERVER_DIR%\vcpkg_installed\x64-windows\bin\*.dll" "%DIST_DIR%\bin\" >nul
        if errorlevel 1 (
            echo [ERROR] Failed to copy backend runtime dependencies.
            exit /b 1
        )
    )
    echo [OK] Installed to: %DIST_DIR%
    echo.
)

:: ============================================================
:: BUILD FRONTEND
:: ============================================================
if "%BUILD_FRONTEND%"=="1" (
    echo ------------------------------------------------------------
    echo   [2/2] Building Next.js Frontend
    echo ------------------------------------------------------------

    if not exist "%FRONTEND_DIR%" (
        echo [ERROR] Frontend directory not found: %FRONTEND_DIR%
        exit /b 1
    )

    pushd "%FRONTEND_DIR%"

    if "%INSTALL_DEPS%"=="1" (
        echo [INFO] npm install...
        npm install
        if errorlevel 1 ( popd & exit /b 1 )
        echo [OK] npm install done.
    )

    echo [INFO] npm run build...
    npm run build
    if errorlevel 1 ( popd & exit /b 1 )
    echo [OK] Frontend built.

    popd
    echo.
)

:: ============================================================
:: DONE
:: ============================================================
echo ============================================================
echo   BUILD COMPLETE
echo ============================================================
if "%BUILD_SERVER%"=="1"   echo   Server  : %DIST_DIR%\bin\pe_server.exe
if "%BUILD_FRONTEND%"=="1" echo   Frontend: %FRONTEND_DIR%\.next
echo.
echo To run server  : %DIST_DIR%\bin\pe_server.exe
echo To run frontend: cd frontend ^&^& npm run start
echo.

endlocal
exit /b 0
