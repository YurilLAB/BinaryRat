@echo off
rem Copyright 2026 YurilLAB
rem SPDX-License-Identifier: Apache-2.0
setlocal DisableDelayedExpansion
set "BINARYRAT_LAUNCH_MODE=headless"
call "%~dp0launchers\launch.bat" %*
exit /b %ERRORLEVEL%
