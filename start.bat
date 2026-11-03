@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto run
call "安装依赖.bat"
if errorlevel 1 exit /b 1
:run
".venv\Scripts\python.exe" RayNeo_Log_Tool.py
if errorlevel 1 pause
