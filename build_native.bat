@echo off
REM ============================================================================
REM Compile native anti-tamper lib src/native/jg_guard.c with NDK
REM   -> tools/libjgguard/<abi>/libjgguard.so  (arm64-v8a / armeabi-v7a / x86_64 / x86)
REM Links liblog. harden.py injects the .so into hardened APK lib/<abi>/.
REM
REM NDK lookup order: env JG_NDK -> ANDROID_NDK -> default D:\Android\AndoridSDK\ndk\25.1.8937393
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
  echo [ERR] NDK toolchain not found: %NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin
  echo Set env JG_NDK to your NDK root, it should contain toolchains\llvm\prebuilt\windows-x86_64\bin
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
echo [build_native] all ABIs built
endlocal
goto :eof

:build
set "ABI=%1"
set "CLANG=%2"
if not exist "tools\libjgguard\%ABI%" mkdir "tools\libjgguard\%ABI%"
echo [build_native] %ABI%  %PRE%\%CLANG%
call "%PRE%\%CLANG%" --shared -fPIC -O2 -o "tools\libjgguard\%ABI%\libjgguard.so" "%SRC%" -llog
if errorlevel 1 (
  echo [ERR] %ABI% build failed
  exit /b 1
)
echo [OK] tools\libjgguard\%ABI%\libjgguard.so
goto :eof
