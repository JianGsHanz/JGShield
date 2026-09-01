#!/usr/bin/env bash
# ============================================================================
# 在 Ubuntu 上把 OLLVM 14.x 交叉编译成 Windows 原生 clang（host = Windows）
# 产出 clang.exe / clang++.exe，可直接覆盖进 Windows 的 Android NDK bin 目录，
# 让 Windows 版 JGShield 的 --ollvm-ndk 直接用到带 -fla/-bcf 的 clang14。
#
# 前置：
#   1) LLVM_SRC 指向【含 OLLVM pass】的 llvm-project（yangFenTuoZi/ollvm release/14.x
#      或 sr-tream/obfuscator release/14.x，已 git submodule update --init llvm-project
#      且已 git apply obfuscator.patch）。纯官方 LLVM 14 没有 pass，必须先换 OLLVM 源码树。
#   2) 本机装 mingw-w64（用来编出 Windows PE）。
#
# 用法：
#   LLVM_SRC=$HOME/ollvm-14.x INSTALL=$HOME/ollvm14-win JOBS=$(nproc) bash build_ollvm14_win_cross.sh
# ============================================================================
set -euo pipefail

LLVM_SRC=${LLVM_SRC:-$HOME/ollvm-14.x}      # 含 OLLVM passes 的 llvm-project 根
INSTALL=${INSTALL:-$HOME/ollvm14-win}       # 产出目录（里面是 Windows 二进制）
JOBS=${JOBS:-$(nproc)}

echo ">>> [1/4] 安装 MinGW-w64 交叉工具链"
sudo apt-get update
sudo apt-get install -y --no-install-recommends mingw-w64 cmake ninja-build gcc g++

echo ">>> [2/4] 配置：host=Windows，用 MinGW gcc/g++ 作构建编译器"
echo "    LLVM_SRC = $LLVM_SRC"
echo "    INSTALL  = $INSTALL"
[ -d "$LLVM_SRC/llvm" ] || { echo "ERROR: $LLVM_SRC/llvm 不存在，检查 LLVM_SRC"; exit 1; }

rm -rf "$LLVM_SRC/build-win"
cmake -G Ninja -S "$LLVM_SRC/llvm" -B "$LLVM_SRC/build-win" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
  -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
  -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
  -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++" \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_ENABLE_LLD=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DLLVM_STATIC_LINK_CXX_STDLIB=ON \
  -DLLVM_USE_STATIC_WINDOWS_RUNTIME=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL"

echo ">>> [3/4] 编译 + 安装（VM 上最慢一步，几小时；链接易 OOM，-j 调小可加 -DLLVM_PARALLEL_LINK_JOBS=1）"
cmake --build "$LLVM_SRC/build-win" --parallel "$JOBS"
cmake --install "$LLVM_SRC/build-win"

echo ">>> [4/4] 校验产物"
ls -la "$INSTALL/bin" 2>/dev/null | grep -E 'clang|lld' || true
echo "--- 期望看到 clang.exe / clang++.exe / clang-14.exe ---"
echo "--- 下一步：把 $INSTALL/bin 和 $INSTALL/lib 覆盖进 Windows NDK r25c 的"
echo "    toolchains/llvm/prebuilt/windows-x86_64/ 对应目录（保留 NDK 自带的 *-clang.cmd 包装器）---"
