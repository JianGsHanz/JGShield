@echo off
REM ============================================================
REM JGShield 依赖工具一键准备脚本
REM 用途：clone 仓库后运行，补齐 tools/ 下 harden.py 所需的外部工具
REM 前置：本机已安装 Android SDK（设 ANDROID_HOME 或 ANDROID_SDK_ROOT）
REM       脚本会复制 SDK 内工具，并下载 apktool / uber-apk-signer
REM ============================================================
setlocal
cd /d "%~dp0"

REM ---- 定位 Android SDK ----
set "SDK="
if defined ANDROID_HOME set "SDK=%ANDROID_HOME%"
if defined ANDROID_SDK_ROOT set "SDK=%ANDROID_SDK_ROOT%"
if "%SDK%"=="" (
    echo [ERR] 未设置 ANDROID_HOME / ANDROID_SDK_ROOT
    echo       请先设置，例如： set ANDROID_HOME=C:\Users\You\AppData\Local\Android\Sdk
    exit /b 1
)
if not exist "%SDK%" (echo [ERR] SDK 路径不存在：%SDK% & exit /b 1)

REM ---- 找最新 build-tools（含 aapt.exe）----
set "BT="
for /f "delims=" %%d in ('dir /b /ad /o-n "%SDK%\build-tools" 2^>nul') do (
    if not defined BT if exist "%SDK%\build-tools\%%d\aapt.exe" set "BT=%SDK%\build-tools\%%d"
)
if "%BT%"=="" (echo [ERR] 未找到 build-tools（需含 aapt.exe）& exit /b 1)
echo 使用 build-tools: %BT%

REM ---- 找最大 API level 的 android.jar ----
set "ANDJAR="
for /f "delims=" %%d in ('dir /b /ad /o-n "%SDK%\platforms" 2^>nul') do (
    if exist "%SDK%\platforms\%%d\android.jar" set "ANDJAR=%SDK%\platforms\%%d\android.jar"
)
if "%ANDJAR%"=="" (echo [ERR] 未找到 platforms/android-*/android.jar & exit /b 1)

if not exist tools mkdir tools

echo [1/3] 复制 SDK 工具到 tools/ ...
copy /y "%BT%\aapt.exe"                 tools\aapt.exe
copy /y "%BT%\libwinpthread-1.dll"      tools\libwinpthread-1.dll
copy /y "%BT%\apksigner.jar"            tools\apksigner.jar
copy /y "%BT%\d8.jar"                   tools\d8.jar
copy /y "%SDK%\platform-tools\adb.exe"          tools\adb.exe
copy /y "%SDK%\platform-tools\AdbWinApi.dll"    tools\AdbWinApi.dll
copy /y "%SDK%\platform-tools\AdbWinUsbApi.dll" tools\AdbWinUsbApi.dll
copy /y "%ANDJAR%"                      tools\android.jar

echo [2/3] 下载非 SDK 工具（apktool / uber-apk-signer）...
powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar' -OutFile 'tools\apktool.jar'" 2>nul
if not exist tools\apktool.jar (echo [WARN] apktool.jar 下载失败，请手动下载放到 tools\apktool.jar)

powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar' -OutFile 'tools\uber-apk-signer.jar'" 2>nul
if not exist tools\uber-apk-signer.jar (echo [WARN] uber-apk-signer.jar 下载失败，请手动下载放到 tools\uber-apk-signer.jar)

echo [3/3] 生成测试签名密钥 common.jks（如不存在）...
if not exist tools\common.jks (
    keytool -genkey -v -keystore tools\common.jks -alias jgshield -keyalg RSA -keysize 2048 -validity 3650 -storepass jgshield -keypass jgshield -dname "CN=JGShield, OU=Dev, O=JG, L=Local, S=Local, C=CN" 2>nul
    keytool -exportcert -keystore tools\common.jks -alias jgshield -storepass jgshield -file tools\common.cer 2>nul
    echo   已生成 tools\common.jks（测试密钥，密码 jgshield）。生产请用自己的密钥（--ks）。
) else (
    echo common.jks 已存在，跳过
)

echo.
echo 依赖校验：
for %%f in (aapt.exe libwinpthread-1.dll apksigner.jar d8.jar adb.exe AdbWinApi.dll AdbWinUsbApi.dll android.jar apktool.jar uber-apk-signer.jar common.jks common.cer) do (
    if exist tools\%%f (echo   [OK]   %%f) else (echo   [MISS] %%f)
)
echo.
echo 完成。之后直接双击 build_exe.bat 即可构建 exe；或 python harden.py 加固 APK。
endlocal
