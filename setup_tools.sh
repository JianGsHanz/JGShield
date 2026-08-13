#!/usr/bin/env bash
# ============================================================
# JGShield 依赖工具一键准备脚本 (macOS / Linux)
# 用途：clone 仓库后运行，补齐 tools/ 下 harden.py 所需的外部工具
# 前置：本机已安装 Android SDK（设 ANDROID_HOME 或 ANDROID_SDK_ROOT）
#       脚本会复制 SDK 内工具，并下载 apktool / uber-apk-signer
# ⚠️ 未经 Mac/Linux 真实环境实测；本脚本仅做静态逻辑校验，请按 README 说明准备环境后运行
# ============================================================
set -e
cd "$(dirname "$0")"

# ---- 定位 Android SDK ----
SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
if [ -z "$SDK" ]; then
  for d in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk" "/opt/android-sdk" "/usr/lib/android-sdk"; do
    if [ -d "$d" ]; then SDK="$d"; break; fi
  done
fi
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
  echo "[ERR] 未设置 ANDROID_HOME / ANDROID_SDK_ROOT，且未找到常见 SDK 路径"
  echo "      请先安装 Android SDK 并设置环境变量，例如："
  echo "      export ANDROID_HOME=\$HOME/Library/Android/sdk"
  exit 1
fi
echo "使用 Android SDK: $SDK"

# ---- 找 build-tools（含 aapt / apksigner.jar / d8.jar）----
BT=""
for d in "$SDK"/build-tools/*/; do
  if [ -f "${d}aapt" ] || [ -f "${d}aapt.exe" ]; then BT="$d"; break; fi
done
if [ -z "$BT" ]; then
  for d in "$SDK"/build-tools/*/; do
    if [ -f "${d}apksigner.jar" ]; then BT="$d"; break; fi
  done
fi
if [ -z "$BT" ]; then
  echo "[ERR] 未找到 build-tools（需含 aapt 或 apksigner.jar）"
  exit 1
fi
echo "使用 build-tools: $BT"

# ---- 找最大 API level 的 android.jar ----
ANDJAR=""
for d in "$SDK"/platforms/android-*/; do
  if [ -f "${d}android.jar" ]; then ANDJAR="${d}android.jar"; fi
done
if [ -z "$ANDJAR" ]; then
  echo "[ERR] 未找到 platforms/android-*/android.jar"
  exit 1
fi

mkdir -p tools

echo "[1/3] 复制 SDK 工具到 tools/ ..."
# aapt（原生二进制，无扩展名）
if [ -f "${BT}aapt" ]; then
  cp -f "${BT}aapt" tools/aapt
  chmod +x tools/aapt
  echo "  [OK] aapt"
elif [ -f "${BT}aapt2" ]; then
  echo "  [WARN] 该 SDK 只有 aapt2，未找到 darwin 版 aapt。aapt 仅用于真机验证/静态回测"
  echo "         提取包名，加固核心路径不依赖它。如需完整功能，请手动将 darwin 版 aapt"
  echo "         放到 tools/aapt（可从旧版 build-tools 或 brew install android-sdk 获取）。"
else
  echo "  [WARN] 未找到 aapt，请手动放置 tools/aapt（darwin 版）"
fi
[ -f "${BT}apksigner.jar" ] && cp -f "${BT}apksigner.jar" tools/apksigner.jar && echo "  [OK] apksigner.jar"
[ -f "${BT}d8.jar" ]        && cp -f "${BT}d8.jar"        tools/d8.jar        && echo "  [OK] d8.jar"
if [ -f "${SDK}/platform-tools/adb" ]; then
  cp -f "${SDK}/platform-tools/adb" tools/adb
  chmod +x tools/adb
  echo "  [OK] adb"
else
  echo "  [WARN] 未找到 platform-tools/adb"
fi
cp -f "$ANDJAR" tools/android.jar && echo "  [OK] android.jar"

echo "[2/3] 下载非 SDK 工具（apktool / uber-apk-signer）..."
curl -fsSL -o tools/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar" \
  || echo "  [WARN] apktool.jar 下载失败，请手动下载放到 tools/apktool.jar"
curl -fsSL -o tools/uber-apk-signer.jar "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar" \
  || echo "  [WARN] uber-apk-signer.jar 下载失败，请手动下载放到 tools/uber-apk-signer.jar"

echo "[3/3] 生成测试签名密钥 common.jks（如不存在）..."
if [ ! -f tools/common.jks ]; then
  keytool -genkey -v -keystore tools/common.jks -alias jgshield -keyalg RSA -keysize 2048 -validity 3650 \
    -storepass jgshield -keypass jgshield \
    -dname "CN=JGShield, OU=Dev, O=JG, L=Local, S=Local, C=CN"
  keytool -exportcert -keystore tools/common.jks -alias jgshield -storepass jgshield -file tools/common.cer
  echo "  已生成 tools/common.jks（测试密钥，密码 jgshield）。生产请用自己的密钥（--ks）。"
else
  echo "  common.jks 已存在，跳过"
fi

echo
echo "依赖校验："
for f in aapt apksigner.jar d8.jar adb android.jar apktool.jar uber-apk-signer.jar common.jks common.cer; do
  if [ -f "tools/$f" ]; then echo "  [OK]   $f"; else echo "  [MISS] $f"; fi
done
echo
echo "完成。之后运行 ./build_exe.sh 构建 .app；或直接 python3 jiagu_gui.py 启动 GUI。"
