@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>nul
if errorlevel 1 (
    python -m venv .venv
) else (
    py -3 -m venv .venv
)
if errorlevel 1 goto failed
:install
".venv\Scripts\python.exe" -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'"
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Installation complete. Run start.bat.
pause
exit /b 0
:failed
echo Installation failed. Install Python 3.10+ and check the error above.
pause
exit /b 1
