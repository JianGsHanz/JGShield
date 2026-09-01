# JGShield OLLVM 混淆使用说明（Windows + macOS 双平台）

> 目的：给壳 `libjgguard.so` 加控制流混淆 `-fla`（CFF 扁平化）/ `-bcf`（虚假控制流），
> 配合原有的 `-sub`（指令替换）/ `-sobf`（字符串加密），四件套 `sub,sobf,fla,bcf`。
>
> **验证铁律**：加固验证一律用 `dist/device_ylyk*.apk`（未受 SecShell 保护的 ylyk 包），
> 禁用 JG 自带双壳玩具样本（样本不能代表真实 app 行为）。

---

## 0. 为什么这么绕

- **Windows 本机 NDK = clang18（LLVM18）**：`-fla`/`-bcf` 在 clang18 上是**编译期 ICE**（崩在 `Canonicalize natural loops`），本地走不通。
- **Windows 编不出 OLLVM clang 二进制**：交叉编译 Windows 版 LLVM 撞 `CMAKE_SYSTEM_NAME=Windows` 的 NATIVE 墙（宿主 tblgen 被编成 Windows exe，Linux 跑不动），已放弃。
- **结论**：OLLVM 后端只能跑在 **Linux / macOS 原生 clang14**（源码 `llvm-project-llvmorg-14.0.6` + `obfuscator.patch`）。
  - **Windows**：通过 SSH 把编译任务中转给 **Ubuntu VM**（已落地，代码平台无关）。
  - **macOS**：本机原生编 OLLVM14 注入 Mac NDK，纯本地零网络依赖。

---

## 1. Ubuntu VM 侧（两平台共用后端）

在 VM 里一次性构建并注入 OLLVM 到 NDK r25b（clang 14.0.6 同版最佳）：

```bash
# 把修好的脚本从共享文件夹拷进来（新名避开 hgfs 同名缓存）
cp /mnt/hgfs/jiagu/build_ollvm14_v4.sh ~/build_ollvm14_v4.sh
grep -c unwindlib ~/build_ollvm14_v4.sh   # 应 > 0，确认拿到修过的版本

# 重跑（编译早完，会直接跳到注入+链接验收，不重编，几十秒）
bash ~/build_ollvm14_v4.sh 2>&1 | tee ~/ollvm_build.log

# 预期看到：
#   FLA_OK  SUB_SOBF_BCF_OK
#   NDK 自带 clang = 14.0.6 ；我们编的 OLLVM = 14.0.6   （版本一致）
#   ANDROID_4PASS_LINK_OK (xxxx bytes)
# DIRECT_LINK_FAIL 可忽略（绕过 NDK 包装器的备用路径，JGShield 不走）
```

**关键修复（已固化在脚本里）**：upstream stock clang 对 Android 目标无条件追加 `-l:libunwind.a`
（`CommonArgs.cpp` 的 `AddUnwindLibrary`），而 NDK r23+ 的 sysroot 已移除 libunwind。
编译命令统一加 `-unwindlib=none`（NDK 自带 clang 有私有补丁规避，自编的没有）。
另：绕过包装器时 GNU ld 认不出 aarch64 仿真，需 `-fuse-ld=lld`。

---

## 2. Windows 上使用（SSH 调 Ubuntu VM）

### 2.1 一次性：VM 起 sshd + 免密

```bash
# VM 里：
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
systemctl status ssh | head -3        # 看到 active (running)

# Windows 的 Git Bash 里（输一次 VM 密码）：
ssh-copy-id abs@172.16.139.128        # 换成你 VM 的真实用户/IP
ssh abs@172.16.139.128 "echo SSH_OK"  # 验证免密
```

> 已知：VM 在 VMware NAT 网段，Windows 主机可直接通（已实测 ping 通）。
> 若换了 VM IP，GUI/CLI 同步改 host 即可。

### 2.2 加固（每次）

**方式 A — GUI（推荐）**：双击 `dist/jiagu_gui.exe` → 加固页勾「通过 SSH 调用 Ubuntu OLLVM」
→ `SSH host=abs@172.16.139.128`、`port=22`
→ `远端 NDK bin=/home/abs/android-ndk-r25b/toolchains/llvm/prebuilt/linux-x86_64/bin`
→ `passes` 留默认 `sub,sobf,fla,bcf`（远端专属字段，不要复用本地的 `sub,sobf`）
→ 选 ylyk 包 → 开始加固。

**方式 B — CLI（等价）**：
```bat
cd /e/jiagu
_build_venv\Scripts\python.exe harden.py dist\device_ylyk_nosecshell.apk -o output\ylyk_ollvm.apk ^
  --ollvm-remote-host abs@172.16.139.128 ^
  --ollvm-remote-ndk /home/abs/android-ndk-r25b/toolchains/llvm/prebuilt/linux-x86_64/bin ^
  --ollvm-remote-passes sub,sobf,fla,bcf
```
> `--ollvm-remote-sysroot` 不用给，自动按 `bin/../sysroot` 推导。
> `build_stub.py` 远端命令已带 `MSYS_NO_PATHCONV=1`，防 Windows `ssh/scp` 路径被 MSYS 转换错。

---

## 3. macOS 上使用（原生，零网络依赖）

### 3.1 一次性：本机编 OLLVM14 注入 Mac NDK

```bash
xcode-select --install
brew install cmake ninja gpatch
softwareupdate --install-rosetta            # 仅 Apple Silicon（NDK 宿主工具靠 Rosetta）

# 把 Windows 侧已打好 patch 的源码树整体拷到 Mac：
#   E:\jiagu\llvm-project-llvmorg-14.0.6  →  ~/llvm-project-llvmorg-14.0.6
# 下载 Mac 版 NDK r25b 解压到 ~/android-ndk-r25b
#   https://dl.google.com/android/repository/android-ndk-r25b-darwin.zip

cd ~/jiagu        # 项目源码树（含 build_ollvm14_mac.sh）
bash build_ollvm14_mac.sh 2>&1 | tee ~/ollvm_build.log
# 预期同 VM：FLA_OK / SUB_SOBF_BCF_OK / ANDROID_4PASS_LINK_OK
```
> Mac 脚本差异点：NDK prebuilt = `darwin-x86_64`；`nproc`→`sysctl`；BSD `stat`；
> `gpatch` 兜底；`LLVM_ENABLE_LLD` 强制 OFF（macOS 宿主链接器是 ld64）。

### 3.2 加固（每次）

```bash
export JGSHIELD_OLLVM_NDK_BIN=$HOME/android-ndk-r25b/toolchains/llvm/prebuilt/darwin-x86_64/bin
python3 harden.py 输入.apk -o 输出.apk
# 或 GUI：python3 jiagu_gui.py ，勾 OLLVM 但不填 SSH host 即走本地通路
```
> 本地通路同样带 `-unwindlib=none`（Mac 自编 stock clang14 必踩 libunwind 缺失，
> Windows clang18 是发行版配置侥幸绕过）。源码级查证：LLVM14 上游
> `Linux::computeSysRoot()` 自带 `<clang目录>/../sysroot` 自动定位，无需显式 `--sysroot`。
> NDK bin 里的 `ld` 实为 lld，经包装器链接 OK。

---

## 4. 已知坑（排错速查）

| 现象 | 根因 | 处理 |
|---|---|---|
| `Unknown command line argument '-fla'` | 用的是纯 LLVM，没打 obfuscator.patch | 必须用源码树重编（见 §1/§3） |
| `unable to find library -l:libunwind.a` | stock clang 对 Android 无条件加 libunwind，NDK r23+ 已移除 | 编译命令加 `-unwindlib=none`（已固化） |
| `无法辨认的仿真模式: aarch64linux` | 绕过包装器后默认 ld 退化成 x86 GNU ld | 加 `-fuse-ld=lld`（备用路径，主链不走） |
| VM 跑新脚本没生效 | hgfs 同名目录缓存 | 另存新名（如 v4.sh）再拷 |
| Windows `ssh` 路径被改坏 | MSYS 路径转换 | 已设 `MSYS_NO_PATHCONV=1`，勿删 |
| Mac 上开 L3 派生 javac 失败 | 旧版硬编码 `javac.exe` | 已修（按 java 实际命名派生 + isfile 兜底） |
| 链接验收慢/失败 | 没装/起 sshd | `sudo apt install -y openssh-server && sudo systemctl enable --now ssh` |

---

## 5. 文件清单

| 文件 | 作用 |
|---|---|
| `build_ollvm14_v4.sh` | Ubuntu VM 构建+注入+验收脚本（修过 libunwind） |
| `build_ollvm14_mac.sh` | macOS 原生构建+注入+验收脚本 |
| `obfuscator.patch` | sr-tream/obfuscator 14.0.6 控制流混淆补丁 |
| `llvm-project-llvmorg-14.0.6/` | 已打 patch 的 LLVM14 源码树（大件，已 .gitignore） |
| `build_stub.py` | `_build_native_remote()`（SSH 中转）/ 本地 OLLVM 分支（带 `-unwindlib=none`） |
| `jiagu_gui.py` | 「SSH 调用 Ubuntu OLLVM」开关联动 + 远端专属 passes |
| `harden.py` | `--ollvm-remote-host/port/ndk/passes/sysroot` CLI |
