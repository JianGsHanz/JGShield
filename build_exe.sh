#!/usr/bin/env bash
# ============================================================
# JGShield GUI 构建脚本 (macOS / Linux)
# 产出：dist/jiagu_gui.app (macOS) 或 dist/jiagu_gui (Linux)
# 前置：python3（建议 brew install python，自带 tkinter）、JDK、已完成 ./setup_tools.sh
# ⚠️ 未经 Mac/Linux 真实环境实测；构建成功率约 60-70%，失败多在 PyInstaller+tkinter 打包，详见 README「macOS / Linux 支持」章节
# ============================================================
set -e
cd "$(dirname "$0")"

# 0) 校验 java/javac 在 PATH（不在则尝试常见 JDK 位置）
if ! command -v javac >/dev/null 2>&1; then
  for d in /Library/Java/JavaVirtualMachines/*/Contents/Home/bin \
           /opt/homebrew/opt/openjdk/bin /usr/local/opt/openjdk/bin \
           /usr/lib/jvm/default-java/bin /usr/lib/jvm/java-11-openjdk/bin; do
    if [ -x "$d/javac" ]; then export PATH="$d:$PATH"; break; fi
  done
fi
if ! command -v javac >/dev/null 2>&1; then
  echo "[ERR] 未找到 javac，请先安装 JDK 11+ 并设置 PATH / JAVA_HOME"
  exit 1
fi

# 1) 选择 python3（需带 tkinter）
PYTHON="$(command -v python3 || true)"
if [ -z "$PYTHON" ]; then
  echo "[ERR] 未找到 python3，请先安装（macOS: brew install python）"
  exit 1
fi
if ! "$PYTHON" -c "import tkinter" 2>/dev/null; then
  echo "[ERR] $PYTHON 缺少 tkinter 模块。macOS 请用 brew install python（系统自带 python 无 tkinter）"
  exit 1
fi

# 2) venv
VENV="./_build_venv"
if [ ! -x "$VENV/bin/python" ]; then
  echo "[1/4] 创建虚拟环境"
  "$PYTHON" -m venv "$VENV"
else
  echo "[1/4] 虚拟环境已存在"
fi
VPY="$VENV/bin/python"
"$VPY" -m pip install --upgrade pip >/dev/null 2>&1 || true
echo "[2/4] 安装依赖"
"$VPY" -m pip install pyinstaller pycryptodome

# 3) 编译壳 stub.dex
echo "[3/4] 编译壳 stub.dex"
rm -rf build/classes build/dex_out
mkdir -p build/classes build/dex_out
javac --release 8 -encoding UTF-8 -cp tools/android.jar -d build/classes \
  src/java/com/gx/runtime/*.java
jar cf build/classes.jar -C build/classes .
java -cp tools/d8.jar com.android.tools.r8.D8 --output build/dex_out --lib tools/android.jar --min-api 21 build/classes.jar
mkdir -p build/dex
cp -f build/dex_out/classes.dex build/dex/stub.dex

# 3.5) 编译 native 反篡改库 (.so)
echo "[3.5/4] 编译 native 反篡改库"
if bash build_native.sh; then
  echo "[OK] native 反篡改库编译完成"
else
  echo "[WARN] native 库编译失败，exe/app 仍会构建，但加固时 harden.py 跳过 native 注入"
fi

# 4) 打包
echo "[4/4] 打包"
if [ -d dist/jiagu_gui.app ]; then
  rm -rf dist/jiagu_gui.app
elif [ -f dist/jiagu_gui ]; then
  rm -f dist/jiagu_gui
fi
"$VPY" -m PyInstaller jiagu_gui.spec

if [ -d dist/jiagu_gui.app ]; then
  echo "构建完成：dist/jiagu_gui.app"
elif [ -f dist/jiagu_gui ]; then
  echo "构建完成：dist/jiagu_gui"
else
  echo "[WARN] 未找到构建产物，请检查上方 pyinstaller 输出"
fi
