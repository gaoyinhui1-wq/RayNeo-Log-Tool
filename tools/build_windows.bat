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
rem onedir avoids decompressing the entire Qt runtime on every launch.
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onedir --windowed --name RayNeo_Log_Tool --collect-submodules rayneo --hidden-import ahocorasick --collect-submodules lz4 --collect-submodules cryptography --add-data "异常判定规则.json;." RayNeo_Log_Tool.py
if errorlevel 1 goto failed
echo Output: dist\RayNeo_Log_Tool\RayNeo_Log_Tool.exe
pause
exit /b 0
:failed
echo Build failed. See the error above.
pause
exit /b 1
