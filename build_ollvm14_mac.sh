#!/usr/bin/env bash
# macOS 原生构建 OLLVM 14 —— JGShield Mac 端完整混淆链（-fla/-bcf 四件套）
#
# 与 Linux 版(build_ollvm14_v4.sh)的差异：
#   1. NDK prebuilt 目录是 darwin-x86_64（NDK r25 的 mac 包只有 x86_64 宿主，
#      Apple Silicon 上靠 Rosetta 2 跑——本就如此，NDK r25 在 M 系列必须 Rosetta）
#   2. JOBS 用 sysctl -n hw.ncpu（macOS 无 nproc）
#   3. LLVM_ENABLE_LLD 强制 OFF（macOS 系统链接器是 ld64，宿主一般没有 ld.lld）
#   4. stat 是 BSD 语法（stat -f%z）
#   5. patch 优先 gpatch（brew install gpatch；系统 patch 对 --ignore-whitespace 支持不一）
#
# 一次性前置（先跑一遍，缺什么装什么）：
#   xcode-select --install          # Apple clang 工具链（宿主编译器）
#   brew install cmake ninja gpatch
#   softwareupdate --install-rosetta   # 仅 Apple Silicon 需要（NDK 宿主工具是 x86_64）
#
# 源码：可直接把 Windows 侧已打好 patch 的 llvm-project-llvmorg-14.0.6 整目录拷到 Mac，
#       （E:\jiagu\llvm-project-llvmorg-14.0.6，patch 已在源码树里，本脚本会自动识别跳过）
#       或用原始 tarball + 本仓库 obfuscator.patch（脚本自动打）。
#
# NDK：Mac 版 25.1.8937393（字母命名，别用版本号命名的 URL 会 404）：
#   https://dl.google.com/android/repository/android-ndk-r25b-darwin.zip
#
# 用法：
#   LLVM_SRC=$HOME/llvm-project-llvmorg-14.0.6 bash build_ollvm14_mac.sh
#   （编译 1~2 小时，ninja 断点续编：失败后直接重跑）
set -euo pipefail

# ---------- 默认值（都可用环境变量覆盖） ----------
JOBS=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}
BUILD=${BUILD_DIR:-$HOME/build-llvm14-mac}
INSTALL=${INSTALL:-$HOME/ollvm14-mac}
NDK=${NDK:-$HOME/android-ndk-r25b}
PATCH=${PATCH_FILE:-$HOME/obfuscator.patch}

echo ">>> [0/5] 前置检查"
for t in cmake ninja; do
  command -v "$t" >/dev/null 2>&1 || { echo "ERROR: 缺 $t —— brew install cmake ninja"; exit 1; }
done
xcode-select -p >/dev/null 2>&1 || { echo "ERROR: 未装 Xcode CLT —— xcode-select --install"; exit 1; }

# ---------- 源码定位 ----------
if [ -z "${LLVM_SRC:-}" ]; then
  for cand in "$HOME/llvm-project-llvmorg-14.0.6" "$HOME/Downloads/llvm-project-llvmorg-14.0.6" \
              "$HOME/Desktop/llvm-project-llvmorg-14.0.6"; do
    [ -d "$cand/llvm" ] && { LLVM_SRC="$cand"; break; }
  done
fi
[ -n "${LLVM_SRC:-}" ] && [ -d "$LLVM_SRC/llvm" ] || {
  echo "ERROR: 找不到 LLVM 源码树。用 LLVM_SRC=/path/to/llvm-project-llvmorg-14.0.6 指定"; exit 1; }
echo "    LLVM_SRC = $LLVM_SRC"

# ---------- [1/5] OLLVM patch 检查（没它就没有任何混淆 pass） ----------
if [ ! -d "$LLVM_SRC/llvm/lib/Transforms/Obfuscation" ]; then
  PATCH_CMD=$(command -v gpatch || command -v patch)
  [ -f "$PATCH" ] || { echo "ERROR: 找不到 obfuscator.patch（$PATCH）——从仓库拷一份或用 PATCH_FILE= 指定"; exit 1; }
  echo "    Obfuscation 目录不存在 -> $PATCH_CMD 自动打 patch"
  ( cd "$LLVM_SRC" && "$PATCH_CMD" -p1 --ignore-whitespace < "$PATCH" ) \
    || ( cd "$LLVM_SRC" && "$PATCH_CMD" -p1 -l < "$PATCH" )
fi
ls "$LLVM_SRC/llvm/lib/Transforms/Obfuscation" | grep -qE 'Flattening|Substitution|BogusControlFlow' \
  && echo "    >>> OK: OLLVM pass 已在源码树中" \
  || { echo "ERROR: 仍找不到 OLLVM pass，patch 未成功"; exit 1; }

# ---------- [2/5] 配置（macOS 原生；LLD 强制 OFF，用系统 ld64） ----------
echo ">>> [2/5] 配置：macOS 原生构建（JOBS=$JOBS，磁盘剩余：$(df -h "$HOME" | tail -1 | awk '{print $4}')）"
if [ "${CLEAN:-0}" = "1" ]; then rm -rf "$BUILD"; fi
mkdir -p "$BUILD"

cmake -G Ninja -S "$LLVM_SRC/llvm" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_LLD=OFF \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DLLVM_PARALLEL_LINK_JOBS=2 \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_ENABLE_BINDINGS=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL"

# ---------- [3/5] 编译 + 安装（ninja 断点续编） ----------
echo ">>> [3/5] 编译 + 安装（Apple Silicon 约 1~2 小时；失败直接重跑本脚本续编）"
cmake --build "$BUILD" --parallel "$JOBS"
cmake --install "$BUILD"

# ---------- [4/5] 验证四件套 ----------
echo ">>> [4/5] 验证 OLLVM pass"
"$INSTALL/bin/clang" --version | head -2
cat > /tmp/tl.c <<'EOF'
#include <stdio.h>
int sum_to(int n){ int s=0; for(int i=0;i<n;i++){ if(i&1) s+=i; else s-=i; } return s; }
EOF
"$INSTALL/bin/clang" -O2 -mllvm -fla -c /tmp/tl.c -o /tmp/tl_fla.o && echo "    FLA_OK"
"$INSTALL/bin/clang" -O2 -mllvm -sub -mllvm -sobf -mllvm -bcf -c /tmp/tl.c -o /tmp/tl_rest.o \
  && echo "    SUB_SOBF_BCF_OK"

# ---------- [5/5] 注入 Mac NDK（darwin-x86_64！） ----------
echo ">>> [5/5] 把 OLLVM clang 注入 Mac NDK"
HOST_DIR=darwin-x86_64
if [ ! -d "$NDK/toolchains/llvm/prebuilt/$HOST_DIR" ]; then
  for cand in "$HOME"/android-ndk-r25b "$HOME"/android-ndk-25.1.8937393 \
              "$HOME"/Downloads/android-ndk-r25b "$HOME"/Downloads/android-ndk-25.1.8937393; do
    if [ -d "$cand/toolchains/llvm/prebuilt/$HOST_DIR" ]; then
      NDK="$cand"; echo "    >>> 自动探测到 NDK: $NDK"; break
    fi
  done
fi
if [ ! -d "$NDK/toolchains/llvm/prebuilt/$HOST_DIR" ]; then
  cat <<EOF
ERROR: 未找到 Mac 宿主 NDK：\$NDK/toolchains/llvm/prebuilt/$HOST_DIR
  下载（macOS 版 25.1.8937393，注意是 darwin 包）：
    https://dl.google.com/android/repository/android-ndk-r25b-darwin.zip
  解压到 ~/android-ndk-r25b 再重跑本脚本（编译已完成，直接进注入步骤）。
  Windows/Mac 的 NDK 宿主二进制不通用：Windows 装的 NDK 里是 windows-x86_64，Mac 用不了。
EOF
  exit 1
fi

TC="$NDK/toolchains/llvm/prebuilt/$HOST_DIR"
BIN="$TC/bin"
SYSROOT="$TC/sysroot"

# NDK 自带 clang 资源目录：r25 是 lib64/clang/<ver>，r27 起是 lib/clang/<ver>
NDK_RES=$(ls -d "$TC"/lib*/clang/*/ 2>/dev/null | head -1 || true)
NDK_VER=$(basename "${NDK_RES:-unknown}")
OUR_VER=$(ls "$INSTALL/lib/clang" | head -1)
echo "    NDK 自带 clang = $NDK_VER ；我们编的 OLLVM = $OUR_VER"
[ "$NDK_VER" = "$OUR_VER" ] && echo "    >>> 版本完全一致（最佳）" \
  || echo "    >>> 注意：版本不同，将把 NDK 的 Android builtins 并入 $OUR_VER 资源目录（14.0.x 内兼容）"

# 1) 我们的 OLLVM clang 覆盖进 NDK bin（NDK 的 ld.lld/llvm-ar 等宿主工具保留不动）
cp -f "$INSTALL/bin/clang"   "$BIN/clang"
cp -f "$INSTALL/bin/clang++" "$BIN/clang++"

# 2) 反向补：NDK 宿主工具拷进我们的 install/bin（[B] 裸 clang 直链时用）
for t in ld.lld llvm-ar llvm-ranlib llvm-strip llvm-objcopy; do
  [ -f "$BIN/$t" ] && cp -f "$BIN/$t" "$INSTALL/bin/$t" || true
done

# 3) resource dir：我们的 clang 按自身版本找 lib/clang/<OUR_VER>
mkdir -p "$TC/lib/clang/$OUR_VER"
cp -a "$INSTALL/lib/clang/$OUR_VER/." "$TC/lib/clang/$OUR_VER/"

# 4) Android builtins 只在 NDK 自己资源目录里（stock LLVM 不带 Android runtime）
if [ -n "$NDK_RES" ] && [ "$NDK_RES" != "$TC/lib/clang/$OUR_VER/" ]; then
  mkdir -p "$TC/lib/clang/$OUR_VER/lib/linux"
  cp -f "$NDK_RES"lib/linux/libclang_rt.builtins-*android*.a \
        "$TC/lib/clang/$OUR_VER/lib/linux/" 2>/dev/null || true
fi
echo "    builtins: $(ls "$TC/lib/clang/$OUR_VER/lib/linux" 2>/dev/null | wc -l) 个文件"

# ---------- 验收：四件套全开 + 真实链接 .so ----------
echo ">>> 验收：四件套全开 + 真实链接 Android .so"
cat > /tmp/tl2.c <<'EOF'
#include <android/log.h>
int sum_to(int n){ int s=0; for(int i=0;i<n;i++){ if(i&1) s+=i; else s-=i; } return s; }
int add(int a,int b){ __android_log_print(3,"t","x"); return a+b; }
EOF
PASS="-mllvm -sub -mllvm -sobf -mllvm -fla -mllvm -bcf"
SZ() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1"; }

echo "    [A] 经 NDK 包装器（--sysroot/-unwindlib=none 必须显式给：我们自编的 stock clang"
echo "        没有 NDK 的自动定位补丁，且 upstream 对 Android 无条件加 -l:libunwind.a，"
echo "        而 NDK r23+ sysroot 已无 libunwind → 必须关掉）"
if "$BIN/aarch64-linux-android21-clang" --sysroot="$SYSROOT" -unwindlib=none --shared -fPIC -O2 $PASS \
     -o /tmp/tl2.so /tmp/tl2.c -llog -lz; then
  echo "    ANDROID_4PASS_LINK_OK ($(SZ /tmp/tl2.so) bytes)"
else
  echo "    LINK_FAIL ← 把这段报错发我"
fi

echo "    [B] 绕过包装器，直接用 \$INSTALL/bin/clang + --target + --sysroot"
if "$INSTALL/bin/clang" --target=aarch64-linux-android21 --sysroot="$SYSROOT" -fuse-ld=lld -unwindlib=none \
     --shared -fPIC -O2 $PASS -o /tmp/tl3.so /tmp/tl2.c -llog -lz; then
  echo "    DIRECT_LINK_OK ($(SZ /tmp/tl3.so) bytes)"
else
  echo "    DIRECT_LINK_FAIL（若 A 成功，可忽略）"
fi

echo
echo "============================================================"
echo " Mac 端 JGShield 用法（本地通路，无需 SSH）："
echo "   export JGSHIELD_OLLVM_NDK_BIN=$BIN"
echo "   export ANDROID_NDK_HOME=$NDK     # 若未设"
echo "   export JGSHIELD_OLLVM_REMOTE_HOST=   # 留空=走本地 OLLVM，不进远端分支"
echo "   python3 harden.py 输入.apk -o 输出.apk --dex-obf ..."
echo "============================================================"
