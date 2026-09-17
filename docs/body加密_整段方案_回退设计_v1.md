# body 加密存储格式：逐方法 → 整段（回退设计 v1）

> 2026-09-14 · 状态：**待评审，未动代码**
> 目标：把 `--method-extract` 的包体代价从 **+12.24 MiB** 降到 **+0.68 MiB**，启动从 **~6s** 降到 **<1s**，
> 且**抗 dump 强度不下降**。

---

## 0. 背景：这不是新设计，是「回退」

整段方案**不是本次新发明的格式**，而是把格式退回 `84d8ac8` 之前的那套 —— 已实现、真机验证过、
且被连续 40 个提交沿用的成熟方案。逐方法才是后来被改出来的。

### 0.1 演化链（逐提交查实，非推测）

| 提交 | 阶段 | 格式 | 关键数据 |
|---|---|---|---|
| `26411c5` | P3.1 首版 | **逐方法** | 每方法各自 zlib + 各自 GCM |
| `13f5c05` | P5 | **改整段** | 整 dex 拼流，密钥改 per-dex；+19.4% → +1.0% |
| `5138d03` | P6 | **整段 + 元数据表 zlib** | 12B 三元组压缩；APK 79.42 MB (+1.8%)；真机 A9 19dex mismatches=0 |
| ↑ | P7 / P8 / P0-A~D | **沿用整段** | `df5a53d..b8e6326` 共 **40 个提交**均为 2 参 `derive_method_key(seed, dex_idx)` |
| `84d8ac8` | VMP 集成 | **改回逐方法** | 3 参签名首次出现；同提交加入 `# 3.0 T4-lite VMP` |
| `cd794d8` | 配套 | 逐方法 hook 路径 | `jg_method_restore_hook.c` +571 行（按需还原 / 空闲擦除） |
| `89b4ae3` | VMP 下线 | **逐方法遗留** | 删 2450 行（`vmp_protect.py` / `jg_vmp.c` / `experiments/`），**未动 `jg_method_restore.c`** |
| `13c351d` | 现在 HEAD | **逐方法** | 净增 +12.24 MiB；启动 ~6s；收益未启用 |

### 0.2 重要澄清：VMP 并没有「要求」逐方法

`84d8ac8` 里 VMP 用的是**它自己的独立密钥派生** —— `derive_key(seed, i, b"vmp")`，
**没有**碰 `derive_method_key`。逐方法在同一提交里落地的**自述动机**是：

> 使运行时 hook 可在「方法首次执行 / 空闲擦除后再调用」时 O(1) 单方法解密写回
> （无需为单个热方法解密整 dex 拼流）

⇒ 两者是**被捆进同一个提交**，而**不是**「VMP 需要逐方法」。本节措辞不应写成前者。

### 0.3 后果：为 VMP 付的代价留下了，VMP 删了

- 逐方法引入了 `P3.4 按需还原 / 即用即擦` 路径 ⇒ 该路径**两次真机实测崩**
  （`ERASE` 崩 Mterp 解释执行方法；`ONCALL_HOOK` 有竞态）⇒ 两个开关**均为 `false`**
- ⇒ 实际运行时 = **加载期一次性全量还原、之后永久明文** = 与整段方案**行为完全等价**
- ⇒ 付了 **+12.24 MiB 体积 + ~6s 启动**，换来的是整段方案本来就有的效果
- ⇒ 且 6s 阻塞逼近 `CONTENT_PROVIDER_PUBLISH_TIMEOUT`(10s)：实测那批 **0/12** 正是被
  `am_kill ... depends on provider` 杀掉的（**不是崩溃**，`logcat -b crash` 为空）

### 0.4 安全等价性声明（必须明示）

| 层 | 整段 | 逐方法 | 判定 |
|---|---|---|---|
| **静态（APK 内）** | 4 段大密文，取用须整段解 ⇒ 无法选择性提取单方法 | 18.6 万段独立密文，可选择性解密 | **略有差别**（整段略强）；但两者都需 seed（证书绑定 + 构建盐），对拿不到 key 的攻击者无差别 |
| **运行时内存** | 加载期全量还原 → 之后永久明文 | 加载期全量还原 → 之后永久明文 | **完全等价** |
| **演进潜力** | 放弃按需 / 即用即擦 | 保留基础（未启用且实测崩） | **唯一真实差别** |

另有「可用性外溢」：逐方法的 6s 阻塞引发 provider 超时被系统杀 = **交付风险**，
比「抗 dump 弱」更严重。

> ⇒ **在当前配置下，回退整段不降低任何实际安全强度**，却拿回 8.72 MiB 体积 + ~5s 启动，
> 并消除 provider 超时风险。唯一的取舍是放弃「将来做真按需还原」的现成基础（见 §7 块化演进位）。

---

## 0.5 为什么做这次改造

| 包 | 体积 | 相对原包 |
|---|---|---|
| 原始未加固 `app-Ptest-5.9.5-2026-09-07.apk` | 71,358,897 B | — |
| 默认加固（无抽取） | 71,502,342 B | **+143 KB** |
| 开 `--method-extract` | 84,335,108 B | **+12.24 MiB** |

12.24 MiB 的构成（实测）：

| 项 | 体积 |
|---|---|
| 方法段（新增） | +14.44 MiB |
| dex 段（NOP 化后压缩率飙升） | −5.04 MiB |
| 净增 | **+12.24 MiB** |

方法段 14.44 MiB 再拆：
- **IV 12B + tag 16B × 185788 = 4.96 MiB**（纯固定开销，占 34%）
- 密文 9.48 MiB（明文 10.16 MiB ⇒ **压缩率仅 93.3%，几乎没压**）

**根因**：逐方法把数据切成 185788 份、每份单独 zlib ⇒ 跨方法压缩上下文全丢。

| 压缩方式 | 密文 | 压缩率 |
|---|---|---|
| 逐方法独立（现状） | 9.48 MiB | **93.3%** |
| 每 dex 一整段 | 5.11 MiB | **50.3%** |

**且当前 per-method 的收益并未启用**（`GxApp.java` 实测值）：

```
METHOD_RESTORE_ENABLED    = true
METHOD_RESTORE_ERASE      = false   ← 空闲擦除：关
METHOD_RESTORE_ONCALL_HOOK= false   ← 按需还原：关
```

⇒ 运行时实际是**加载期一次性全量还原、之后永久明文**（`nativeRestoreInit`），
与整段方案的行为**完全等价**。⇒ 当前为逐方法付了全部代价，只拿到整段的效果。

---

## 1. 目标格式（逐字节）

```
MAGIC(4)
dex_count(4)
  ×dex_count :  blob_len(4) + dex_blob                 # encrypt_dex(seed, i, NOP化后的dex)
asset_count(4)
  ×asset_count: name_len(4) + name + blob_len(4) + blob
method_dex_count(4)
  ×method_dex_count :
      dex_idx(4)
      entry_count(4)
      stream_blob_len(4) + stream_blob                 # iv(12) + AES-256-GCM(zlib(concat_insns)) + tag(16)
      meta_blob_len(4)   + meta_blob                   # zlib( (method_idx,code_off,insns_size) × n )  ← 12B/条
salt(32)
```

**密钥（per-dex，非 per-method）**：

```
key_dex = HMAC-SHA256( seed, KEY_PREFIX + "m" + str(dex_idx) )     # 无 "." + method_idx
```

> 该格式由两处**独立记录**互相印证，非新设计：
> 1. `src/native/jg_method_restore.c` 头注释（第 4–13 行）—— 含 meta_blob 压缩版
> 2. `test_p3_native_contract.py` 第 12–28 行 —— 含逐字节解析步骤（entry 为明文 20B 版）
>
> 本方案取**两者中更优者**：entry 用 12B 三元组 + zlib（省 3 MiB），
> `offset_in_stream` / `len_in_stream` **不存**，由 `insns_size` 在还原端按序累加推得。

**还原流程（native `jg_restore_methods`）**：

1. 解析帧，定位到 method 段，跳过非 `want_dex` 的段
2. 取 `stream_blob` 与 `meta_blob`
3. `key = HMAC(seed, KEY_PREFIX+"m"+dex_idx)`
4. `plain = AES-256-GCM-dec(key, iv, ct, tag)`（GCM 强制校验 tag）
5. 先解压 `meta_blob` → 得到 `(method_idx, code_off, insns_size)[]`
6. `total = Σ(insns_size × 2)` ← **dstcap 必须用这个值**
7. `concat = zlib-inflate(plain, dstcap=total)`
8. 按 meta 顺序写回：`memcpy(dex + code_off + 16, concat + off, insns_size*2)`，`off` 逐条累加

---

## 2. 与现有格式的差异

| 维度 | 现状（P3.4 逐方法） | 目标（整段） |
|---|---|---|
| 密文单元 | 每方法一个 blob | 每 dex 一条 stream |
| IV / tag 数量 | 185788 份 | 4 份 |
| 压缩上下文 | 每方法独立 | 整个 dex 共享 |
| 元数据 | 每方法 16B 明文头（含 blob_len） | 12B × n，zlib 压缩 |
| 密钥 | `…"m"+dex+"."+method` | `…"m"+dex` |
| 单方法解密 | 支持（**但未启用**） | 不支持（需解整段） |

---

## 3. 改动清单

### 3.1 `harden.py`

| 位置 | 改动 |
|---|---|
| L311 `derive_method_key(seed, dex_idx, method_idx)` | → 去掉 `method_idx`；label 改为 `KEY_PREFIX + b"m" + str(dex_idx)`。函数名建议改 `derive_stream_key` |
| L329 `extract_methods(seed, dex_idx, dex_bytes)` | 收集 `(method_idx, code_off, insns_size)` + 拼接全部 insns；<br>生成 `stream_blob = iv + GCM(zlib(concat)) + tag`、<br>`meta_blob = zlib(pack('<III', …) × n)`；<br>返回 `(nop_dex, stream_blob, meta_blob, entries)`。<br>**NOP 回填逻辑与 class_defs→class_data 遍历顺序保持不变** |
| L244 `build_payload` 方法段（L270–280） | 按 §1 布局改写每 dex 的写入 |
| L743 构建期打印 | 文案同步（去掉方法数量级带来的误导） |

### 3.2 `src/native/jg_method_restore.c`

| 位置 | 改动 |
|---|---|
| L85 `jg_restore_methods()` | 按 §1 的 §1-还原流程重写解析与写回 |
| L194 `jg_verify_methods()` | 同步改造（比对逻辑改为"整段解压后逐条 memcmp"） |
| L62 `jg_inflate_zlib()` | **不改**。本轮已实测证明其契约正确（`avail_out` 只需 ≥ **解压后**长度），仅**调用点传入的 dstcap 要改为 `total`** |

### 3.3 `src/native/jg_method_restore_hook.c`

| 位置 | 改动 |
|---|---|
| L427 `foreach_method_entry()` | 改为「先解压 meta_blob → 遍历三元组」。回调签名建议把 `blob_off/blob_len` 改为 `stream_off/stream_len` |
| L464 `collect_cb()` | 随签名同步 |
| L560–630 按需还原路径 | 整段下语义失效（无法单方法解密）。当前 `ONCALL_HOOK=false` **不触发**。<br>**建议本轮不动**，加注释标注「仅逐方法格式下有效，整段格式需改为『解密整段 + 缓存』」 |
| L1418 `nativeReencryptSweep()` | 同上：整段下无法单方法擦除。当前 `ERASE=false` **不触发**，加注释标注 |
| L776 `restored=1` 标记 | 逻辑不变 |

### 3.4 `src/java/com/gx/runtime/GxApp.java`

**不改。** `nativeRestoreInit` / `nativeRestoreMethods` / `nativeReencryptSweep` 签名全部保持（已核对 L596–606）。

### 3.5 测试脚本（当前已损坏，顺带修好）

| 文件 | 问题 |
|---|---|
| `test_p3_native_contract.py` L113 | 调 `derive_method_key(seed, dex_idx)` 传 2 参，但实现已是 3 参 → **现必 TypeError** |
| `verify_lt26.py` L46 | 同上 |
| `gen_method_restore_vectors.py` L48/67/78 | 同上 |
| `verify_payload.py` L107 `derive_method_key` | 改回 per-dex（2 参） |

> 这几处调用本来就是 **P6 整段方案**的写法，改造后**自动恢复一致**。

---

## 4. 关键风险（逐条必须验证）

1. **【最高】密钥标签变更**：`"m"+dex+"."+method` → `"m"+dex`。
   `harden.py` 与 native **必须同一批构建内改完**。任一侧漏改 ⇒ 全部解密失败 ⇒ App 起不来。
2. **dstcap 语义变更**：从「单方法 `2*insns_size`」变为「该 dex 全部 `2*Σinsns_size`」。
   沿用旧值 ⇒ inflate 必失败。**本轮已证明 inflate 契约本身正确，风险只在调用点传参。**
3. **meta 表必须校验**：解压 meta 后要断言 `Σ(insns_size*2) == inflate 实际输出长度`。
   不校验则错位写回 = **静默内存破坏**（比崩溃更危险，且难定位）。
4. **偏移推算的一致性**：`offset_in_stream` 由 `insns_size` 累加推得，要求
   **写端与读端遍历顺序完全一致**（均为 class_defs → class_data → direct+virtual 方法序）。
   任一侧顺序变动即整体错位。
5. **格式不向后兼容**：新旧载荷互不识别。必须避免"新 `harden.py` + 旧 `.so`"混用
   （本项目已被 `build/native_tmp/`、`dist/build/` 的 stamp 覆盖坑过两次）。
6. **按需/擦除路径成为"假实现"**：`ONCALL_HOOK` / `ERASE` 当前均 `false`，
   整段格式下这两条路径失效。需**显式注释标注**，避免将来打开时踩坑。

---

## 5. 验证计划

| # | 项 | 方法 | 判据 |
|---|---|---|---|
| 1 | 字节级契约 | `test_p3_native_contract.py`（修好后） | 写回后 DEX **==** 原始 DEX |
| 2 | 载荷自检 | `harden.py` 的 `self_verify` / `verify_payload` | 全绿 |
| 3 | 体积 | `ls -l` 三包对比 | 净增 ≈ **+0.68 MiB** |
| 4 | 真机冷启动 | MIX2 A9，`--method-extract` 包 | N 轮全绿 + logcat 四行 `batch-restore rc=0` |
| 5 | 启动耗时 | logcat 锚点 `dex0 → dex3` 时间差 | 预期 <1s（对比现状 ~6.0s） |
| 6 | 验收铁律 | 每轮 `dumpsys package codePath` + `ls -l base.apk` 比字节数 | 每轮验包 |
| 7 | 回归 | 默认（无抽取）包 | 保持 +143KB / 58-58 全绿 |

---

## 6. 预期收益

| 项 | 现状 | 目标 |
|---|---|---|
| 方法段 | 14.44 MiB | **5.72 MiB** |
| 包体净增 | +12.24 MiB | **+0.68 MiB** |
| 启动 batch-restore | ~6.0s | 待实测（估 <1s） |
| GCM 调用次数 | 185788 | **4** |
| 抗 dump 强度 | 加载期全量还原 | **不变**（等价） |

---

## 7. 取舍声明（必须明示）

本方案**放弃**「按需还原 + 即用即擦」的能力 —— 整段 GCM 的 tag 校验需要完整密文，
**无法只解密单个方法**。

若将来确实要做「真按需」，演进路径是**块化**：

> 每 dex 切 K 块（如每 256 个方法一块），每块独立 `iv + GCM(zlib(...)) + tag`。
> 体积 ≈ 整段 + `K × 28B`（K=200 时仅 ~5.6 KB，仍接近整段），
> 但支持**块级按需**解密/擦除。

本方案的结构**为块化预留了位置**（stream → blocks），届时只改分块粒度，不改帧布局。
