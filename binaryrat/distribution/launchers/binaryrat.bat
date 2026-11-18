@echo off
rem SPDX-License-Identifier: Apache-2.0
setlocal DisableDelayedExpansion
set "BINARYRAT_LAUNCH_MODE=desktop"
call "%~dp0launchers\launch.bat" %*
exit /b %ERRORLEVEL%
