# 梆梆(SecShell) vs JGShield 冷启动 A/B 证据

日期：2026-09-11　设备：小米 MIX2 / arm64-v8a / Android 9 (A9)
被测包：同一 app、同一版本 ylyk 5.9.5、**同一签名**（证书 SHA256 `33:71:03:CF…:98:91`）
仪器：`ActivityManager: Displayed <act>: +Xms`（系统侧），冷启动 = `am force-stop` 后 `am start`
脚本：`_wk_diag/ab_pkg.sh`（通用）、`_wk_diag/ab_bangcle.sh`（含落地/oat 取证）

## 1. 冷启动耗时（SplashActivity）

| 包 | 冷启动 Displayed | 相对未加固 |
|---|---|---|
| 未加固 `app-Ptest-5.9.5` | 2058 / **546 / 546 / 520 / 495 / 506** ms | — |
| 梆梆 `app-huawei-5.9.5_protected_sign` | **1145 / 1172 / 1183 / 1219** ms | **+≈660 ms** |
| JGShield `hardened_coldfix2` | 2931 / 3175 ms（早前 15 轮中位 3482） | **+≈2500–2970 ms** |

## 2. 结构对照（决定性）

### 梆梆包的 classes.dex（32,670,068 B）
- magic `dex\n035`，**adler32 覆盖全文件自洽**，`map_list` 18 项完整覆盖到 1,372,500
- 但 `data_size=1,161,352` / `map_list` 结束于 1.37MB，而 `file_size=32,670,068`
  → **尾部 31.3MB 不被 dex 结构引用**，起始处有标记串 `dexdata0`
- 壳可见 683 个类（`class_defs_size=683`），即 `com.SecShell.SecShell.*`；真实 app 类不在这 683 里
- 重算过：`zlib.adler32(data[12:]) == 头内 checksum` → **ART 认它是合法 dex**

### 安装/运行后 ART 产物（`/data/app/<pkg>/oat/arm64/`）

| | base.art | base.odex | **base.vdex** |
|---|---|---|---|
| 未加固（安装后） | 385,024 | 809,368 | **33,874,336** |
| 未加固（运行后） | 2,457,600 | 6,772,368 | 30,471,612 |
| **梆梆（安装后）** | 28,672 | 38,224 | **32,752,136** |
| 梆梆（运行后） | 126,976 | 249,472 | 1,363,688 |
| **JGShield（安装后=运行后）** | 8,192 | 21,720 | **442** |

→ 梆梆与未加固包一样，**安装期 ART 就处理了整份 30MB+ dex**（vdex ≈ dex 全量副本）；
→ JGShield 的 classes.dex 只有 7KB GxBootstrap，**ART 全程不认识真实 dex，vdex 恒为 442 B**。

### 内存（`dumpsys meminfo`）

| | `.dex mmap` | Native Heap | Unknown |
|---|---|---|---|
| 未加固 | 12,708 KB | 81,880 KB | 27,657 KB |
| 梆梆 | 2,306 KB | 109,984 KB | 118,264 KB |
| JGShield | 1,650 KB | 61,297 KB | 43,722 KB |

### 梆梆运行期落地物（`/data/data/<pkg>/`）
- `.cache/classes.dex` = **4 B**（内容 `dex\n`）、`.cache/classes.dve` = 24 B、`.cache/oat/arm64/` = **空目录**
- `.payload/` = **空目录**
（即：不是"落盘 dex 后让 ART 编译"）

## 3. 梆梆的装载路径（反编译实证）

壳 dex 已切出（1,372,500 B，修好 file_size/checksum/SHA-1 后合法），`baksmali` 得 683 个 smali。

`com/SecShell/SecShell/H.smali`（native 桥）：
```
.method public static native attach(Landroid/app/Application;Landroid/content/Context;)V
.method public static native e(Ljava/lang/Object;Ljava/util/List;Ljava/lang/String;)[Ljava/lang/Object;   ← ★
```
`com/SecShell/SecShell/a.smali:300-320`：
```
const-string "pathList"  → 反射取 ClassLoader.pathList
new ArrayList()
invoke-static {pathList, list, dexName}, Lcom/SecShell/SecShell/H;->e(...)[Ljava/lang/Object;   ← native 构造 dexElements
const-string "dexElements" → 反射写回 pathList.dexElements
```
全壳 683 个 smali 中 dex 装载 API 统计：`ClassLoader->loadClass ×3`、`DexFile->loadDex ×1`、
`PathClassLoader->findClass ×1` ——**没有任何 `InMemoryDexClassLoader`**。

日志旁证：`E/libdex: ERROR: unsupported dex version (30 33 39 00)` + `Byte swap + verify failed`
（ART 侧对某个 dex 的校验失败被软处理，未影响启动）

## 4. 结论（含边界）

**已证实**
1. 梆梆额外开销 ≈ 0.66s；我们 ≈ 2.5–3.0s（同设备同 app 同仪器）。
2. 梆梆让 ART 在**安装期**处理了整份 30MB 级 dex（vdex 规模为证）；我们 ART 全程不参与，
   30.4MB 全部压在**每次冷启动路径**上。
3. 梆梆的 dex 装载是 **native 侧直接构造 dexElements** + Java 反射换 `pathList.dexElements`；
   不使用公开的 `InMemoryDexClassLoader`。
4. 我们独有 777ms 的 maps 逐页扫描（1,017,938 次页探测，`jg_method_restore_hook.c:1029-1066`），
   梆梆无此项。

**推断（待实验证实）**
- 公开 API `InMemoryDexClassLoader` 会对 30.4MB 做完整校验（≈835ms）；native 侧
  `DexFile::OpenFromMemory(..., verify=false)` 可绕过 → 这是梆梆 660ms 能装下 30MB 的主因。

**代价对比（诚实）**
梆梆的 `classes.dex` 对 ART 是**明文合法 dex**（尾部 blob 才是密文），静态可见性显著高于
我们的全加密载荷。它是在「静态暴露」与「启动速度」之间做了交换；我们的密文载荷是安全优势，
但**性能差距并非 fileless 的先天代价**——其中 777ms 纯属自伤，另 ~835ms 来自选了公开 API。
