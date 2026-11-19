@echo off
rem Copyright 2026 YurilLAB
rem SPDX-License-Identifier: Apache-2.0
setlocal DisableDelayedExpansion
for %%i in ("%~dp0..") do set "BINARYRAT_BUNDLE_DIR=%%~fi"
if "%~1"=="--version" if "%~2"=="" (
    type "%BINARYRAT_BUNDLE_DIR%\VERSION.txt"
    exit /b
)
set "JAVA_HOME=%BINARYRAT_BUNDLE_DIR%\jdk"
if not exist "%JAVA_HOME%\bin\java.exe" (
    echo The bundled JDK is missing. Extract the complete BinaryRat archive. 1>&2
    exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "BINARYRAT_ENGINE="
if defined XDG_CONFIG_HOME (
    set "XDG_CONFIG_HOME=%XDG_CONFIG_HOME%\BinaryRat"
) else (
    set "XDG_CONFIG_HOME=%LOCALAPPDATA%\BinaryRat\config"
)
if defined XDG_CACHE_HOME (
    set "XDG_CACHE_HOME=%XDG_CACHE_HOME%\BinaryRat"
) else (
    set "XDG_CACHE_HOME=%LOCALAPPDATA%\BinaryRat\cache"
)
if not exist "%XDG_CONFIG_HOME%\." mkdir "%XDG_CONFIG_HOME%"
if not exist "%XDG_CONFIG_HOME%\." exit /b 1
if not exist "%XDG_CACHE_HOME%\." mkdir "%XDG_CACHE_HOME%"
if not exist "%XDG_CACHE_HOME%\." exit /b 1
if "%BINARYRAT_LAUNCH_MODE%"=="headless" goto headless
call "%BINARYRAT_BUNDLE_DIR%\ghidra\ghidraRun.bat" %*
exit /b %ERRORLEVEL%
:headless
call "%BINARYRAT_BUNDLE_DIR%\ghidra\support\analyzeHeadless.bat" %*
exit /b %ERRORLEVEL%
