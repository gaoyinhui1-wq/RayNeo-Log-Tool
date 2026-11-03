@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0\.."
if not exist ".venv\Scripts\python.exe" (
    echo Run the dependency installer in the project root first.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install "pyinstaller>=6.10,<7"
if errorlevel 1 goto failed
rem Shared build driver also starts and verifies the packaged EXE.
".venv\Scripts\python.exe" tools\build_windows.py
if errorlevel 1 goto failed
echo Output: dist\RayNeo_Log_Tool\RayNeo_Log_Tool.exe
pause
exit /b 0
:failed
echo Build failed. See the error above.
pause
exit /b 1
