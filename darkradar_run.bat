@echo off
REM === DarkRadar Automation Script ===
REM Pastikan path sesuai venv Anda

SET PYTHON="D:\Dark Radar TNI\.venv\Scripts\python.exe"
SET SCRIPT="D:\Dark Radar TNI\darkradar.py"
SET CONFIG="D:\Dark Radar TNI\darkradar_config.yaml"

echo [1] Generate config (jika belum ada)
%PYTHON% %SCRIPT% generate-config --output %CONFIG%

echo.
echo [2] Fetch data...
%PYTHON% %SCRIPT% fetch --config %CONFIG% --domain tni.mil.id --output feed.json

echo.
echo [3] Scan feed.json...
%PYTHON% %SCRIPT% scan --config %CONFIG% -i feed.json -o hasil.json

echo.
echo [4] Analyze hasil.json...
%PYTHON% %SCRIPT% analyze -i hasil.json

echo.
echo [5] Kirim alert (stdout)...
%PYTHON% %SCRIPT% alert -i hasil.json -t stdout

echo.
echo === Workflow selesai ===
pause
