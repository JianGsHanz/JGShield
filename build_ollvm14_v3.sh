#!/usr/bin/env bash
# 原生 Linux 构建 OLLVM 14（Route B：JGShield 通过 SSH 中继调用）
# 在 Ubuntu VM 里跑。产物是 Linux 原生 clang，不是 Windows 交叉编译。
#
# 用法：
#   LLVM_SRC=/mnt/hgfs/jiagu/llvm-project-llvmorg-14.0.6 \
#   NDK=$HOME/android-ndk-25.1.8937393 \
#   INSTALL=$HOME/ollvm14-linux JOBS=$(nproc) \
#   bash ~/build_ollvm14_native_linux.sh
#
# 为什么 NDK 用 25.1.8937393：它自带 clang 14.0.6（资源目录 lib64/clang/14.0.6），
# 与我们编的 OLLVM 14.0.6 完全同版。NDK 25.2.9519653(r25c) 是 clang 14.0.7，会错版。
# 注意：必须是 NDK 的 **Linux 宿主版**（Windows 装的 NDK 只含 windows-x86_64 二进制）。
#
# 可选：
#   COPY_SRC=1   把源码从共享文件夹拷到 VM 本地 ext4 再编（hgfs 慢/出怪错时用）
#   CLEAN=1      重新清空构建目录（默认沿用已有构建目录，ninja 断点续编）
set -euo pipefail

SRC=${LLVM_SRC:-/mnt/hgfs/jiagu/llvm-project-llvmorg-14.0.6}
INSTALL=${INSTALL:-$HOME/ollvm14-linux}
NDK=${NDK:-$HOME/android-ndk-r25b}
JOBS=${JOBS:-$(nproc)}
BUILD=${BUILD_DIR:-$HOME/build-llvm14}
PATCH=${PATCH_FILE:-/mnt/hgfs/jiagu/ollvm-14/obfuscator.patch}

echo ">>> [0/5] 检查 OLLVM patch 是否已打上（最关键：没它就完全没有混淆 pass）"
if [ ! -d "$SRC/llvm/lib/Transforms/Obfuscation" ]; then
  echo "    Obfuscation 目录不存在 -> 自动打 patch"
  [ -f "$PATCH" ] || { echo "ERROR: 找不到 patch 文件 $PATCH"; exit 1; }
  ( cd "$SRC" && patch -p1 --ignore-whitespace < "$PATCH" )
fi
ls "$SRC/llvm/lib/Transforms/Obfuscation" | grep -qE 'Flattening|Substitution|BogusControlFlow' \
  && echo "    >>> OK: OLLVM pass 已在源码树中" \
  || { echo "ERROR: 仍找不到 OLLVM pass，patch 未成功"; exit 1; }

echo ">>> [1/5] 源码位置处理"
echo "    磁盘剩余："; df -h "$HOME" | tail -1
if [ "${COPY_SRC:-0}" = "1" ]; then
  LOCAL_SRC=${LOCAL_SRC:-$HOME/llvm-src}
  if [ ! -d "$LOCAL_SRC/llvm/lib/Transforms/Obfuscation" ]; then
    echo "    拷贝源码到 VM 本地 $LOCAL_SRC（patch 已打在文件里，会一起跟过来）"
    rm -rf "$LOCAL_SRC"
    cp -a "$SRC" "$LOCAL_SRC"
  fi
  SRC="$LOCAL_SRC"
fi
[ -d "$SRC/llvm" ] || { echo "ERROR: $SRC/llvm 不存在"; exit 1; }
echo "    LLVM_SRC = $SRC"

echo ">>> [2/5] 配置：原生 Linux 构建"
echo "    构建目录 = $BUILD （必须 VM 本地 ext4；vmhgfs 不支持 symlink，LLVM 构建必挂）"
case "$BUILD" in /mnt/hgfs/*) echo "ERROR: 构建目录不能放在共享文件夹里"; exit 1;; esac
if [ "${CLEAN:-0}" = "1" ]; then rm -rf "$BUILD"; fi
mkdir -p "$BUILD"

# 坑：LLVM14 的 LLVM_ENABLE_LLD 默认 ON（llvm/CMakeLists.txt:463），宿主没装 lld 时
# 会在 HandleLLVMOptions.cmake:308 直接 FATAL_ERROR "does not support '-fuse-ld=lld'"。
# 这里按宿主是否真有 lld 自动决定，不依赖默认值。
if command -v ld.lld >/dev/null 2>&1 || command -v lld >/dev/null 2>&1; then
  LLD_OPT=ON
  echo "    宿主有 lld -> LLVM_ENABLE_LLD=ON（链接更快、更省内存）"
else
  LLD_OPT=OFF
  echo "    宿主无 lld -> LLVM_ENABLE_LLD=OFF（退回系统 GNU ld，能编但链接较慢）"
  echo "    想更快：sudo apt-get install -y lld   装完重跑本脚本（会自动切回 ON）"
fi

cmake -G Ninja -S "$SRC/llvm" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_LLD="$LLD_OPT" \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DLLVM_PARALLEL_LINK_JOBS=2 \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_ENABLE_BINDINGS=OFF \
  -DLLVM_ENABLE_OCAMLDOC=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL"

echo ">>> [3/5] 编译 + 安装（VM 上 1~3 小时；ninja 断点续编，失败后直接重跑本脚本）"
cmake --build "$BUILD" --parallel "$JOBS"
cmake --install "$BUILD"

echo ">>> [4/5] 验证 OLLVM pass（原生 Linux）"
"$INSTALL/bin/clang" --version | head -2
cat > /tmp/tl.c <<'EOF'
#include <stdio.h>
int sum_to(int n){ int s=0; for(int i=0;i<n;i++){ if(i&1) s+=i; else s-=i; } return s; }
EOF
"$INSTALL/bin/clang" -O2 -mllvm -fla -c /tmp/tl.c -o /tmp/tl_fla.o && echo "    FLA_OK"
"$INSTALL/bin/clang" -O2 -mllvm -sub -mllvm -sobf -mllvm -bcf -c /tmp/tl.c -o /tmp/tl_rest.o \
  && echo "    SUB_SOBF_BCF_OK"

echo ">>> [5/5] 把 OLLVM clang 注入 NDK（让 aarch64-linux-android21-clang 变 OLLVM14）"
# 自动探测 NDK 目录，避免解压出来的目录名（android-ndk-r25b / 25.1.8937393 / ...）
# 和默认值对不上导致白跑一趟
if [ ! -d "$NDK/toolchains/llvm/prebuilt/linux-x86_64" ]; then
  for cand in "$HOME"/android-ndk-r25b "$HOME"/android-ndk-25.1.8937393 \
              "$HOME"/android-ndk-r25c "$HOME"/android-ndk-25.2.9519653 \
              "$HOME"/android-ndk-r*; do
    if [ -d "$cand/toolchains/llvm/prebuilt/linux-x86_64" ]; then
      NDK="$cand"
      echo "    >>> 自动探测到 NDK: $NDK"
      break
    fi
  done
fi

if [ ! -d "$NDK/toolchains/llvm/prebuilt/linux-x86_64" ]; then
  cat <<EOF
WARN: 未找到 Linux 宿主 NDK：$NDK/toolchains/llvm/prebuilt/linux-x86_64
  Windows 装的 NDK 只含 windows-x86_64 宿主二进制，VM 里必须另备一份 **Linux 版**。
  在 Windows（带宽快）下载同版本 25.1.8937393 的 Linux 包（NDK 用字母后缀命名，
  版本号命名的 android-ndk-25.1.8937393-linux.zip 会 404，别用）：
    https://dl.google.com/android/repository/android-ndk-r25b-linux.zip
  （全部历史版本索引：https://github.com/android/ndk/wiki/Unsupported-Downloads）
  解压后把 toolchains/llvm/prebuilt/linux-x86_64 整个目录拷到 VM 的：
    $NDK/
  再重跑本脚本（编译已完成，会直接进注入步骤，不重编）。
EOF
  exit 0
fi

TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
BIN="$TC/bin"
SYSROOT="$TC/sysroot"

# NDK 自带 clang 的资源目录：r25 是 lib64/clang/<ver>，r27 起是 lib/clang/<ver>
NDK_RES=$(ls -d "$TC"/lib*/clang/*/ 2>/dev/null | head -1 || true)
NDK_VER=$(basename "${NDK_RES:-unknown}")
OUR_VER=$(ls "$INSTALL/lib/clang" | head -1)
echo "    NDK 自带 clang = $NDK_VER ；我们编的 OLLVM = $OUR_VER"
[ "$NDK_VER" = "$OUR_VER" ] && echo "    >>> 版本完全一致（最佳）" \
  || echo "    >>> 注意：版本不同，将把 NDK 的 Android builtins 并入 $OUR_VER 资源目录"

# 1) 我们的 OLLVM clang 覆盖进 NDK bin（NDK 的 ld.lld / llvm-ar 等宿主工具保留不动）
cp -f "$INSTALL/bin/clang"   "$BIN/clang"
cp -f "$INSTALL/bin/clang++" "$BIN/clang++"

# 2) 反向补：把 NDK 宿主工具拷进我们的 install/bin，
#    这样即使绕过 NDK 包装器、直接用 $INSTALL/bin/clang + --sysroot 也能链接
for t in ld.lld llvm-ar llvm-ranlib llvm-strip llvm-objcopy; do
  [ -f "$BIN/$t" ] && cp -f "$BIN/$t" "$INSTALL/bin/$t" || true
done

# 3) resource dir：我们的 clang 按自身版本找 lib/clang/<OUR_VER>
mkdir -p "$TC/lib/clang/$OUR_VER"
cp -a "$INSTALL/lib/clang/$OUR_VER/." "$TC/lib/clang/$OUR_VER/"

# 4) 关键：Android builtins 只在 NDK 自己资源目录里（stock LLVM 不带 Android runtime）。
#    只拷 builtins：asan/tsan 等 sanitizer 运行时合计 ~195MB，JGShield 用不上，省磁盘。
#    NDK 版本不同（如 r25c=14.0.7 vs 我们 14.0.6）也没关系，builtins 是目标端归档，
#    14.0.x 内互相兼容。
if [ -n "$NDK_RES" ] && [ "$NDK_RES" != "$TC/lib/clang/$OUR_VER/" ]; then
  mkdir -p "$TC/lib/clang/$OUR_VER/lib/linux"
  cp -f "$NDK_RES"lib/linux/libclang_rt.builtins-*android*.a \
        "$TC/lib/clang/$OUR_VER/lib/linux/" 2>/dev/null || true
fi
echo "    builtins: $(ls "$TC/lib/clang/$OUR_VER/lib/linux" 2>/dev/null | wc -l) 个文件"

echo ">>> 验收：四件套全开 + 真实链接 .so（JGShield 真正要跑的动作）"
cat > /tmp/tl2.c <<'EOF'
#include <android/log.h>
int sum_to(int n){ int s=0; for(int i=0;i<n;i++){ if(i&1) s+=i; else s-=i; } return s; }
int add(int a,int b){ __android_log_print(3,"t","x"); return a+b; }
EOF
PASS="-mllvm -sub -mllvm -sobf -mllvm -fla -mllvm -bcf"

echo "    [A] 经 NDK 包装器（--sysroot 必须显式给：我们自编的 clang 没有 NDK 的自动定位补丁）"
echo "        -unwindlib=none 必须显式给：upstream clang 对 Android 目标无条件追加"
echo "        -l:libunwind.a（clang/lib/Driver/ToolChains/CommonArgs.cpp 的 AddUnwindLibrary），"
echo "        而 NDK r23+ 的 sysroot 已移除 libunwind → 不关掉就链接失败。"
echo "        NDK 自带的 clang 有私有补丁规避，我们自编的 stock LLVM 没有。"
if "$BIN/aarch64-linux-android21-clang" --sysroot="$SYSROOT" -unwindlib=none --shared -fPIC -O2 $PASS \
     -o /tmp/tl2.so /tmp/tl2.c -llog -lz; then
  echo "    ANDROID_4PASS_LINK_OK ($(stat -c%s /tmp/tl2.so) bytes)"
else
  echo "    LINK_FAIL ← 把这段报错发我"
fi

echo "    [B] 绕过包装器，直接用 \$INSTALL/bin/clang + --target + --sysroot"
echo "        -fuse-ld=lld 必须显式给：绕过 NDK 包装器后默认 ld 退化为宿主 GNU ld（x86），"
echo "        认不出 aarch64linux 仿真 → 用我们拷进去的 ld.lld；-unwindlib=none 同理 [A]。"
if "$INSTALL/bin/clang" --target=aarch64-linux-android21 --sysroot="$SYSROOT" -fuse-ld=lld -unwindlib=none \
     --shared -fPIC -O2 $PASS -o /tmp/tl3.so /tmp/tl2.c -llog -lz; then
  echo "    DIRECT_LINK_OK ($(stat -c%s /tmp/tl3.so) bytes)"
else
  echo "    DIRECT_LINK_FAIL（若 A 成功，可忽略）"
fi

echo
echo "============================================================"
echo " 远端 NDK bin（填进 JGShield GUI『通过 SSH 调用 Ubuntu OLLVM』→ 远端 NDK bin）："
echo "   $BIN"
echo " sysroot（JGShield 会自动推导为 <bin>/../sysroot，一般不用手填）："
echo "   $SYSROOT"
echo "============================================================"
