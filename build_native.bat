@echo off
REM ============================================================================
REM 用 NDK 编译 native 反篡改库 src/native/jg_guard.c
REM   -> tools/libjgguard/<abi>/libjgguard.so  (arm64-v8a / armeabi-v7a / x86_64 / x86)
REM 链接 liblog。产物由 harden.py 注入加固后 APK 的 lib/<abi>/。
REM
REM NDK 路径查找顺序：环境变量 JG_NDK -> ANDROID_NDK -> 默认 D:\Android\AndoridSDK\ndk\25.1.8937393
REM （你的 NDK 在 D:\Android\AndoridSDK\ndk\25.1.8937393，已验证可用）
REM ============================================================================
setlocal

set "SRC=src\native\jg_guard.c"

if defined JG_NDK (
  set "NDK=%JG_NDK%"
) else if defined ANDROID_NDK (
  set "NDK=%ANDROID_NDK%"
) else (
  set "NDK=D:\Android\AndoridSDK\ndk\25.1.8937393"
)

if not exist "%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin" (
  echo [ERR] 找不到 NDK 工具链: %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin
  echo 请设置环境变量 JG_NDK 指向你的 NDK 根目录（其下应有 toolchains\llvm\prebuilt\windows-x86_64\bin）
  exit /b 1
)
set "PRE=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin"

echo [build_native] NDK = %NDK%
call :build arm64-v8a aarch64-linux-android21-clang.cmd
if errorlevel 1 exit /b 1
call :build armeabi-v7a armv7a-linux-androideabi21-clang.cmd
if errorlevel 1 exit /b 1
call :build x86_64 x86_64-linux-android21-clang.cmd
if errorlevel 1 exit /b 1
call :build x86 i686-linux-android21-clang.cmd
if errorlevel 1 exit /b 1
echo [build_native] 全部 ABI 编译完成
endlocal
goto :eof

:build
set "ABI=%1"
set "CLANG=%2"
if not exist "tools\libjgguard\%ABI%" mkdir "tools\libjgguard\%ABI%"
echo [build_native] %ABI%  (%PRE%\%CLANG%)
"%PRE%\%CLANG%" --shared -fPIC -O2 -o "tools\libjgguard\%ABI%\libjgguard.so" "%SRC%" -llog
if errorlevel 1 (
  echo [ERR] %ABI% 编译失败
  exit /b 1
)
echo [OK] tools\libjgguard\%ABI%\libjgguard.so
goto :eof
