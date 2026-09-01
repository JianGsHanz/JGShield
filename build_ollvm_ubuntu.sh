#!/usr/bin/env bash
# ============================================================
# 在 Ubuntu(VM) 上构建 LLVM 14 + OLLVM，并安装进 Android NDK，供 JGShield 使用
#
# 注意：本脚本未在沙箱内实测（沙箱是 Windows、无外网、无 Ubuntu）。
#       它是省你敲命令的模板，跑之前请逐个确认下面的变量与每一步的输出。
#
# 用法：
#   LLVM_SRC=$HOME/llvm-project ANDROID_NDK=$HOME/android-ndk-r25c bash build_ollvm_ubuntu.sh
# ============================================================
set -euo pipefail

# ---------- 按你的环境改这几行（也可通过环境变量传入） ----------
LLVM_SRC="${LLVM_SRC:-$HOME/llvm-project}"          # 你已有的 LLVM 14.0.6 源码树（含 llvm/ 子目录）
LLVM_BUILD="${LLVM_BUILD:-$LLVM_SRC/build}"         # 已有 build 目录就填它，可增量重编
OLLVM_FORK="${OLLVM_FORK:-https://github.com/sr-tream/obfuscator}"
OLLVM_BRANCH="${OLLVM_BRANCH:-release/14.x}"        # 14.0.6 对应 release/14.x
OLLVM_DIR="${OLLVM_DIR:-$HOME/obfuscator}"
ANDROID_NDK="${ANDROID_NDK:-$HOME/android-ndk-r25c}" # NDK r25c 自带 clang 14.0.7，与 14.x 同一代
JOBS="${JOBS:-$(nproc)}"

NDK_PREBUILT="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
NDK_BIN="$NDK_PREBUILT/bin"
NDK_LIB="$NDK_PREBUILT/lib/clang"

die()  { echo; echo "!! $*"; exit 1; }
step() { echo; echo "==== $* ===="; }

[ -d "$ANDROID_NDK" ] || die "找不到 Android NDK: $ANDROID_NDK
  先下载 linux 版 NDK r25c 解压：https://developer.android.com/ndk/downloads"

# ------------------------------------------------------------
step "1/7 取 OLLVM 14.x 源码（含 Obfuscation passes）"
if [ ! -d "$OLLVM_DIR" ]; then
  git clone -b "$OLLVM_BRANCH" "$OLLVM_FORK" "$OLLVM_DIR"
  ( cd "$OLLVM_DIR" && git submodule update --init --depth 1 llvm-project )
fi
[ -d "$OLLVM_DIR" ] || die "OLLVM 源码拉取失败：$OLLVM_DIR"

# ------------------------------------------------------------
step "2/7 准备 LLVM 源码树"
if [ ! -d "$LLVM_SRC/llvm" ]; then
  echo "  未发现已有 LLVM 树 -> 复用 OLLVM fork 自带的 llvm-project"
  LLVM_SRC="$OLLVM_DIR/llvm-project"
  [ -f "$OLLVM_DIR/obfuscator.patch" ] && ( cd "$LLVM_SRC" && git apply ../obfuscator.patch )
  LLVM_BUILD="$LLVM_SRC/build"
fi
echo "  LLVM_SRC=$LLVM_SRC"
echo "  LLVM_BUILD=$LLVM_BUILD"

# Obfuscation 必须真的进了源码树，否则编出来的 clang 不认 -fla
[ -f "$LLVM_SRC/llvm/lib/Transforms/Obfuscation/Flattening.cpp" ] \
  || die "$LLVM_SRC 里没有 lib/Transforms/Obfuscation/Flattening.cpp
  补丁没打上。请确认 fork 分支是 release/14.x，或手工把 Obfuscation 目录拷进对应位置。"

# PassBuilder 里要注册 cl::opt（-fla/-sub/-bcf/-sobf），否则 -mllvm -fla 会报
# 'Unknown command line argument'（这正是现有 clang18 OLLVM 不支持 -seed 的同类问题）
if ! grep -q "Obfuscation" "$LLVM_SRC/llvm/lib/Passes/PassBuilder.cpp"; then
  die "PassBuilder.cpp 未注册 Obfuscation passes。
  需手工加入（模式参考 CompileSnoop/ollvm17 的 README）：
    #include \"Obfuscation/Flattening.h\"
    #include \"Obfuscation/BogusControlFlow.h\"
    #include \"Obfuscation/Substitution.h\"
    #include \"Obfuscation/StringEncryption.h\"
    static cl::opt<bool> s_obf_fla(\"fla\",  cl::init(false), cl::desc(\"Flattening\"));
    static cl::opt<bool> s_obf_sub(\"sub\",  cl::init(false), cl::desc(\"Substitution\"));
    static cl::opt<bool> s_obf_bcf(\"bcf\",  cl::init(false), cl::desc(\"BogusControlFlow\"));
    static cl::opt<bool> s_obf_sobf(\"sobf\",cl::init(false), cl::desc(\"StringObfuscation\"));
  并在合适的优化管线位置调用对应 pass。"
fi

grep -q "Obfuscation" "$LLVM_SRC/llvm/lib/Transforms/CMakeLists.txt" \
  || echo "add_subdirectory(Obfuscation)" >> "$LLVM_SRC/llvm/lib/Transforms/CMakeLists.txt"

# ------------------------------------------------------------
step "3/7 cmake 配置（VM 优化：只编 3 个 target、断言关、lld 链接、限并行链接数）"
mkdir -p "$LLVM_BUILD"
cmake -G Ninja -S "$LLVM_SRC/llvm" -B "$LLVM_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
  -DLLVM_ENABLE_LLD=ON \
  -DLLVM_USE_LINKER=lld \
  -DLLVM_PARALLEL_LINK_JOBS=2
# VM 内存小的话，链接 clang 是最容易 OOM 的一步；LLVM_PARALLEL_LINK_JOBS=2 就是为此。
# 若仍 OOM，把它降到 1，或加 -DBUILD_SHARED_LIBS=ON（重链更快、占盘更省，但 clang 略慢）。

# ------------------------------------------------------------
step "4/7 编译（VM 上最久的一步，全新编约 1~3 小时；已有 build 目录则增量，快很多）"
cmake --build "$LLVM_BUILD" --parallel "$JOBS" --target clang --target lld

# ------------------------------------------------------------
step "5/7 安装进 Android NDK"
cmake --install "$LLVM_BUILD" --prefix "$NDK_PREBUILT"

# ------------------------------------------------------------
step "6/7 复制 NDK 自带的 Android 运行时库（compiler-rt / builtins）到 OLLVM 版本目录"
# 漏掉这步，链接 .so 时会找不到 libclang_rt.builtins-aarch64-android.a
OLLVM_VER="$("$NDK_BIN/clang" --version | sed -nE 's/.*clang version ([0-9.]+).*/\1/p' | head -1)"
[ -n "$OLLVM_VER" ] || die "读不到 clang 版本号"
SRC_VER="$(ls "$NDK_LIB" 2>/dev/null | grep -v "^${OLLVM_VER}$" | head -1)"
[ -n "$SRC_VER" ] || die "在 $NDK_LIB 下找不到 NDK 原版 clang 的 lib 目录"
echo "  NDK 原版 clang: $SRC_VER  ->  OLLVM: $OLLVM_VER"
mkdir -p "$NDK_LIB/$OLLVM_VER"
cp -rn "$NDK_LIB/$SRC_VER/lib" "$NDK_LIB/$OLLVM_VER/lib"

# ------------------------------------------------------------
step "7/7 验证：用 -fla 编一个带循环的函数（arm64）"
cat > /tmp/_fla_test.c <<'EOF'
int jg_probe(int x){int a=0;for(int i=0;i<x;i++){if(i%2==0)a+=i;else a-=i;}return a;}
EOF
rm -f /tmp/_fla_test.so
"$NDK_BIN/aarch64-linux-android21-clang" --shared -fPIC -O2 -mllvm -fla \
  -o /tmp/_fla_test.so /tmp/_fla_test.c -llog -lz
[ -f /tmp/_fla_test.so ] || die "-fla 编译失败（未产出 .so）"
echo "  OK：-fla 编译通过"
ls -la /tmp/_fla_test.so

# JGShield 要求的 4 个 NDK 包装器必须存在（名字一字不差）
for w in aarch64-linux-android21-clang armv7a-linux-androideabi21-clang \
         x86_64-linux-android21-clang i686-linux-android21-clang; do
  [ -x "$NDK_BIN/$w" ] || die "缺少 JGShield 需要的包装器：$NDK_BIN/$w"
done
echo "  OK：4 个 NDK 包装器齐备"

cat <<EOF

================ 完成 ================
在 JGShield 里这样用（先只开 fla，确认能跑再加 bcf）：

  python harden.py in.apk -o out.apk \\
    --ollvm-ndk "$NDK_BIN" \\
    --ollvm-passes "sub,sobf,fla"

GUI：加固页勾「启用 OLLVM」，NDK 目录填上面这行 --ollvm-ndk 的值。
EOF
