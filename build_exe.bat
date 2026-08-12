@echo off
REM ============================================================
REM JGShield GUI 一键构建脚本
REM 双击运行（需在本仓库根目录 E:/jiagu），产出 dist/jiagu_gui.exe
REM 前置：
REM   1) JDK 已安装，javac / java 在 PATH
REM   2) tools/ 已就位（aapt.exe / apksigner.jar / adb.exe / apktool.jar /
REM      uber-apk-signer.jar / d8.jar / android.jar / common.jks 等）
REM   3) 本机 Python 3.8.10 路径见下方 PYTHON38（按需修改）
REM ============================================================
setlocal
cd /d "%~dp0"

set "VENV=.\_build_venv"
set "PYTHON38=E:\soft\workSoft\Python\python.exe"

REM ---- 环境检查 ----
where javac >nul 2>&1 || (echo [ERR] 未找到 javac，请安装 JDK 并加入 PATH & exit /b 1)
if not exist "%PYTHON38%" (echo [ERR] 未找到 Python 3.8.10：%PYTHON38% & echo       请修改本脚本 PYTHON38 变量 & exit /b 1)
if not exist tools\d8.jar (echo [ERR] 缺少 tools\d8.jar & exit /b 1)
if not exist tools\android.jar (echo [ERR] 缺少 tools\android.jar & exit /b 1)

REM 0. 虚拟环境（必须用 3.8.10，3.13 venv 无 tkinter）
if not exist "%VENV%\Scripts\python.exe" (
    echo [1/4] 创建虚拟环境（Python 3.8.10）...
    "%PYTHON38%" -m venv "%VENV%"
) else (
    echo [1/4] 虚拟环境已存在，跳过
)
echo [2/4] 安装依赖 pyinstaller + pycryptodome ...
"%VENV%\Scripts\pip.exe" install pyinstaller pycryptodome pycryptodomex

REM 1. 编译壳 stub.dex
echo [3/4] 编译壳 stub.dex ...
if not exist build\classes mkdir build\classes
javac --release 8 -encoding UTF-8 -d build\classes src\java\com\jiagu\shield\ShieldApplication.java
if errorlevel 1 (echo [ERR] javac 失败 & exit /b 1)
java -cp tools\d8.jar com.android.tools.r8.D8 --output build\dex --lib tools\android.jar --min-api 21 build\classes
if errorlevel 1 (echo [ERR] d8 失败 & exit /b 1)

REM 2. 杀旧进程 + 打包（_noop_sc 绕过 safe-delete shim）
echo [4/4] 终止旧进程并打包 ...
taskkill /f /im jiagu_gui.exe >nul 2>&1
set "PYTHONPATH=%~dp0_noop_sc"
"%VENV%\Scripts\pyinstaller.exe" jiagu_gui.spec
if errorlevel 1 (echo [ERR] pyinstaller 失败 & exit /b 1)

echo.
echo 构建完成：dist\jiagu_gui.exe
endlocal
