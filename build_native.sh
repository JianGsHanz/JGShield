#!/usr/bin/env bash
# ============================================================================
# 用 NDK 编译 native 反篡改库 src/native/jg_guard.c
#   -> tools/libjgguard/<abi>/libjgguard.so (arm64-v8a / armeabi-v7a / x86_64 / x86)
# 链接 liblog。产物由 harden.py 注入加固后 APK 的 lib/<abi>/。
#
# NDK 路径查找顺序：环境变量 JG_NDK -> ANDROID_NDK ->
#   默认 $HOME/Library/Android/sdk/ndk/<ver> 或 $ANDROID_HOME/ndk/<ver>
# （macOS/Linux 支持未经真机实测，仅静态校验，成功率约 60-70%）
# ============================================================================
set -e

SRC="src/native/jg_guard.c src/native/jg_method_restore.c src/native/jg_integrity.c src/native/jg_inline_hook.c src/native/jg_method_restore_hook.c"

if [ -n "$JG_NDK" ]; then
  NDK="$JG_NDK"
elif [ -n "$ANDROID_NDK" ]; then
  NDK="$ANDROID_NDK"
else
  # 常见默认位置（取首个存在的 ndk 目录）
  for cand in "$HOME/Library/Android/sdk/ndk" "$ANDROID_HOME/ndk" "$HOME/Android/Sdk/ndk"; do
    if [ -d "$cand" ]; then
      NDK=$(ls -d "$cand"/* 2>/dev/null | head -1)
      [ -n "$NDK" ] && break
    fi
  done
fi

PRE="$NDK/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
if [ ! -d "$PRE" ]; then
  echo "[ERR] 找不到 NDK 工具链: $PRE"
  echo "请设置环境变量 JG_NDK 指向你的 NDK 根目录"
  exit 1
fi

declare -A MAP=(
  [arm64-v8a]=aarch64-linux-android21-clang
  [armeabi-v7a]=armv7a-linux-androideabi21-clang
  [x86_64]=x86_64-linux-android21-clang
  [x86]=i686-linux-android21-clang
)

echo "[build_native] NDK = $NDK"
for ABI in arm64-v8a armeabi-v7a x86_64 x86; do
  CLANG="${MAP[$ABI]}"
  mkdir -p "tools/libjgguard/$ABI"
  echo "[build_native] $ABI ($PRE/$CLANG)"
  "$PRE/$CLANG" --shared -fPIC -O2 -o "tools/libjgguard/$ABI/libjgguard.so" $SRC -llog -lz
  echo "[OK] tools/libjgguard/$ABI/libjgguard.so"
done
echo "[build_native] 全部 ABI 编译完成"
