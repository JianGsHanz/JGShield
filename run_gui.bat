@echo off
chcp 65001 >nul
cd /d E:\jiagu
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
set PATH=D:\Android\AndoridSDK\platform-tools;%PATH%
"E:\WorkBuddy\.workbuddy\binaries\python\envs\default\Scripts\python.exe" "E:\jiagu\jiagu_gui.py"
if errorlevel 1 (
  echo.
  echo [JGShield] 程序异常退出，退出码 %errorlevel%
  pause
)
