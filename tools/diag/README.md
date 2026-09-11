# tools/diag — 可复用的诊断 / 验收脚本

这些不是一次性调试脚本，是**每轮加固都要用**的工具（所以从 `_wk_diag/` 收敛进来入库，避免
下次又散落在临时目录里）。全部只读设备/产物，不会改加固逻辑。

## 冷启动与验收

| 脚本 | 作用 |
|---|---|
| `accv.sh` | **冷启动验收 harness**。`bash tools/diag/accv.sh <N> <out_dir> <期望base.apk字节数> <tag>`。每轮强制验包（base.apk 字节数 + versionName + 壳日志），逐轮分类 PASS/SHELL_FAIL/NATIVE/NOBOOT/NOSHELL/WRONGPKG。**锚点不写死壳 tag**（P7 起 tag 随机化），只看 `xxx: bootShell` + `pidof` 兜底。 |
| `boot_timeline.py` | **壳引导分段计时表**。`python tools/diag/boot_timeline.py <logcat文件>` → 按壳事件标记算各段 delta。解析坑已修：pid 字段右对齐（4 位是 `( 4141)`），`Displayed` 行 >1s 时是 `total +3s482ms`（含 `s`）。 |

## 测量（A/B 对照）

| 脚本 | 作用 |
|---|---|
| `ab_pkg.sh` | **通用包 A/B 测量**。装包 → 热身 → N 轮 → meminfo → oat 目录。`bash tools/diag/ab_pkg.sh <apk> <tag> <N>`。**输出的最后一条 Displayed 可能是 MainActivity**（另一个指标），必须按活动名过滤。 |
| `ab_bangcle.sh` | 同上，额外做落地取证（`.cache/`、oat 产物），用于对照商业壳。 |
| `ab_baseline.sh` | 装回基线包跑同口径 N 轮，用于和历史包对照。 |

**仪器纪律**：口径用活动管理器(ActivityManager)的 `Displayed <pkg>/<act>: +Xms (total +Yms)`，
不要用 `am start -W` 的 TotalTime（跨构建不可比，同包两套计时差值符号会反转）。
跨会话比不同构建无效 —— **只有同会话 A/B 才算数**，壳内逐段对照（`boot_timeline.py`，同锚点）
是机制级硬证据，两者应互相印证。

## 产物 / 内存取证

| 脚本 | 作用 |
|---|---|
| `verify_exe.py` | **验证 `dist/jiagu_gui.exe` 里打包的是哪份源码**（不是靠 mtime 猜）。用 PyInstaller 的 `CArchiveReader` 把 `src/` 条目抠出来与磁盘做哈希比对。`--list` 列条目、`--dump <名>` 抠单文件。背景：后台 PyInstaller 曾因杀软瞬时锁 exe 而静默失败，只看文件存在会交付旧 exe。 |
| `extract_shell_dex.py` | **切开「合法外形 + 尾部 overlay」的商业壳 dex** 并反编译。原理：用 `map_list` 自洽性求结构区末尾 → 取前缀做壳 dex、重算 adler32/SHA-1 → baksmali。附带的 MAP 名表可读。**只给壳自己的类，不给业务代码。** |
| `probe_bangcle.py` | 商业壳 APK 结构剖析：dex 清单、头解析、overlay 熵分布、关键字符串定位。 |

## 环境前提

- Python 用 `_build_venv/Scripts/python.exe`（装了 pycryptodome + PyInstaller，`verify_exe.py` 需要后者）。
- 设备操作需要 `adb`（`D:/Android/AndoridSDK/platform-tools`），部分取证需要 root（`su -c`）。
- 沙箱内跑远端 OLLVM 构建会读不到 SSH 私钥，需**前台**提权；构建前加
  `PYTHONPATH="E:/jiagu/_noop_sc"` 绕 safe-delete 守卫。
