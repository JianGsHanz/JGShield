@echo off
setlocal
cd /d "%~dp0"

REM JGShield GUI one-click build. Double-click to run in repo root E:/jiagu.
REM Whole output is saved to build\build_exe.log then shown and paused at end.

call :run > build\build_exe.log 2>&1
echo.
echo ================= build\build_exe.log =================
type build\build_exe.log
echo ======================================================
echo Build finished (log: build\build_exe.log). Press any key to close.
pause >nul
goto :eof

:run
set "VENV=.\_build_venv"
set "PYTHON38=E:\soft\workSoft\Python\python.exe"

echo environment check
javac -version >nul 2>nul
if errorlevel 1 goto ERR_JAVAC
if not exist "%PYTHON38%" goto ERR_PY
if not exist tools\d8.jar goto ERR_D8
if not exist tools\android.jar goto ERR_ANDROID

if not exist "%VENV%\Scripts\python.exe" (
    echo [1/4] creating virtualenv
    "%PYTHON38%" -m venv "%VENV%"
) else (
    echo [1/4] virtualenv exists
)
echo [2/4] installing deps
"%VENV%\Scripts\pip.exe" install pyinstaller pycryptodome
if errorlevel 1 goto ERR_PIP

echo [3/4] compiling stub.dex
if not exist build\classes mkdir build\classes
javac --release 8 -encoding UTF-8 -cp tools\android.jar -d build\classes src\java\com\jiagu\shield\ShieldApplication.java
if errorlevel 1 goto ERR_JAVAC2
if exist build\classes.jar del /f /q build\classes.jar
jar cf build\classes.jar -C build\classes .
if errorlevel 1 goto ERR_JAR
if exist build\dex_out rmdir /s /q build\dex_out
mkdir build\dex_out
java -cp tools\d8.jar com.android.tools.r8.D8 --output build\dex_out --lib tools\android.jar --min-api 21 build\classes.jar
if errorlevel 1 goto ERR_D8B
copy /y build\dex_out\classes.dex build\dex\stub.dex
if errorlevel 1 goto ERR_COPY

echo [4/4] packaging
taskkill /f /im jiagu_gui.exe >nul 2>nul
if exist "%~dp0_noop_sc" (set "PYTHONPATH=%~dp0_noop_sc")
rem rename old exe away first; if it is locked by another process, rename still
rem succeeds (unlike delete) so pyinstaller will not hit os.remove PermissionError
if exist dist\jiagu_gui.exe move /y dist\jiagu_gui.exe dist\jiagu_gui.bak.exe >nul 2>nul
"%VENV%\Scripts\pyinstaller.exe" jiagu_gui.spec
if errorlevel 1 goto ERR_PYI

echo build done: dist\jiagu_gui.exe
exit /b 0

:ERR_JAVAC
echo [ERR] javac not found, install JDK and add to PATH
exit /b 1
:ERR_PY
echo [ERR] Python 3.8.10 not found: %PYTHON38%
echo       edit PYTHON38 in this script to your actual path
exit /b 1
:ERR_D8
echo [ERR] missing tools\d8.jar
exit /b 1
:ERR_ANDROID
echo [ERR] missing tools\android.jar
exit /b 1
:ERR_PIP
echo [ERR] pip install failed (no network or bad index)
exit /b 1
:ERR_JAVAC2
echo [ERR] javac failed
exit /b 1
:ERR_JAR
echo [ERR] jar packaging failed
exit /b 1
:ERR_D8B
echo [ERR] d8 failed
exit /b 1
:ERR_COPY
echo [ERR] copy stub.dex failed
exit /b 1
:ERR_PYI
echo [ERR] pyinstaller failed
exit /b 1
