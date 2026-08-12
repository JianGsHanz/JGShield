# -*- coding: utf-8 -*-
"""
jiagu_gui.py —— JGShield APK 一键加固工具 桌面图形界面。

单页：一键加固（单个 APK 或整个目录批量加固），可选自定义签名密钥库。
底部实时日志控制台 + 进度条；任务在后台线程中以子进程运行，不阻塞界面。

冻结为 exe 后，GUI 通过 `sys.executable --cli <module> <args>` 派发 CLI 子进程，
保留 stdout 管道与 terminate 杀进程能力，无需独立 Python 解释器。
"""
import os
import sys
import queue
import threading
import subprocess
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import config

# --------------------------------------------------------------------------- #
# 路径常量
# --------------------------------------------------------------------------- #
def _is_frozen():
    return getattr(sys, "frozen", False)


ROOT = config.EXEC_DIR

# 子进程运行器：frozen 时用 exe 自身 --cli；非 frozen 时用 python jiagu_gui.py --cli
if _is_frozen():
    RUNNER = [sys.executable, "--cli"]
else:
    RUNNER = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "jiagu_gui.py"), "--cli"]

# adb 所在目录
ADB_DIR = os.path.dirname(config.ADB) if os.path.isfile(config.ADB) else ""

# 配色（light 主题）
C_BG       = "#f4f5f7"
C_CARD     = "#ffffff"
C_BORDER   = "#e2e5ea"
C_TEXT     = "#1f2430"
C_MUTED    = "#6b7280"
C_PRIMARY  = "#0d9488"   # teal —— 护盾感
C_PRIMARY_D= "#0b7a72"
C_OK       = "#15803d"
C_ERR      = "#dc2626"
C_STEP     = "#1d4ed8"
C_LOG_BG   = "#fbfbfd"


def child_env():
    """子进程环境：确保 adb 可见、输出为 UTF-8、关闭 Python 输出缓冲（实时日志）。"""
    env = os.environ.copy()
    if ADB_DIR:
        env["PATH"] = ADB_DIR + os.pathsep + env.get("PATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONUNBUFFERED"] = "1"   # 关键：子进程 stdout 不块缓冲，日志实时回显
    return env


# --------------------------------------------------------------------------- #
# CLI 派发（供 frozen exe 的 --cli 子进程模式使用）
# --------------------------------------------------------------------------- #
def cli_dispatch():
    """--cli <module> <args...>  以 CLI 模式运行某模块（供 GUI 子进程调用）。"""
    _ensure_stdio()
    if len(sys.argv) < 3:
        print("usage: --cli <module> <args...>")
        sys.exit(2)
    module = sys.argv[2]
    sys.argv = [module + ".py"] + sys.argv[3:]
    if module == "harden":
        import harden
        harden.main()
    elif module == "batch_harden":
        import batch_harden
        batch_harden.main()
    elif module == "verify":
        import verify
        verify.main()
    elif module == "device_check":
        import device_check
        device_check.main()
    else:
        print("unknown module:", module)
        sys.exit(2)


def _ensure_stdio():
    """在 windowed frozen 模式下，sys.stdout/stderr 可能为 None 或指向 nul。
    从 OS 文件描述符重建，使 CLI 子进程的 print() 能写入 GUI 的管道。"""
    import io
    for fd, attr in ((1, "stdout"), (2, "stderr")):
        cur = getattr(sys, attr, None)
        need_fix = cur is None
        if not need_fix and hasattr(cur, "name"):
            need_fix = cur.name in ("nul", os.devnull)
        if need_fix:
            try:
                stream = io.TextIOWrapper(
                    io.BufferedWriter(io.FileIO(fd, mode="w")),
                    encoding="utf-8", errors="replace", line_buffering=True)
                setattr(sys, attr, stream)
            except Exception:
                setattr(sys, attr, open(os.devnull, "w"))


# --------------------------------------------------------------------------- #
# 主窗口
# --------------------------------------------------------------------------- #
class JGShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("JGShield — APK 一键加固工具")
        self.geometry("980x680")
        self.minsize(880, 600)
        self.configure(bg=C_BG)

        self.log_queue = queue.Queue()
        self.proc = None
        self.worker_thread = None
        self._running = False

        self._setup_style()
        self._build_ui()
        self._load_settings()
        self.after(120, self._poll_queue)

    # ----------------------------- 样式 -------------------------------------
    def _setup_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background=C_BG)
        s.configure("Card.TFrame", background=C_CARD)
        s.configure("TLabel", background=C_BG, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("Card.TLabel", background=C_CARD, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("Muted.TLabel", background=C_BG, foreground=C_MUTED, font=("Microsoft YaHei UI", 9))
        s.configure("CardMuted.TLabel", background=C_CARD, foreground=C_MUTED, font=("Microsoft YaHei UI", 9))
        s.configure("Title.TLabel", background=C_BG, foreground=C_TEXT, font=("Microsoft YaHei UI", 16, "bold"))
        s.configure("Sub.TLabel", background=C_BG, foreground=C_MUTED, font=("Microsoft YaHei UI", 10))
        s.configure("TCheckbutton", background=C_BG, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("Card.TCheckbutton", background=C_CARD, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("TRadiobutton", background=C_BG, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("Card.TRadiobutton", background=C_CARD, foreground=C_TEXT, font=("Microsoft YaHei UI", 10))
        s.configure("TEntry", fieldbackground=C_CARD, foreground=C_TEXT, bordercolor=C_BORDER)
        s.configure("TCombobox", fieldbackground=C_CARD, foreground=C_TEXT)
        s.configure("TNotebook", background=C_BG, borderwidth=0)
        s.configure("TNotebook.Tab",
                    background=C_BG, foreground=C_MUTED,
                    padding=(22, 9), font=("Microsoft YaHei UI", 10, "bold"))
        s.map("TNotebook.Tab",
              background=[("selected", C_CARD)],
              foreground=[("selected", C_PRIMARY)])
        s.configure("Accent.TButton", font=("Microsoft YaHei UI", 10, "bold"))
        s.configure("Horizontal.TProgressbar",
                    troughcolor=C_BORDER, background=C_PRIMARY,
                    borderwidth=0, thickness=8)

    # ----------------------------- 布局 -------------------------------------
    def _build_ui(self):
        # 顶部标题栏
        top = ttk.Frame(self)
        top.pack(fill="x", padx=18, pady=(14, 6))
        ttk.Label(top, text="🛡  JGShield", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  APK 差异化一键加固（AES-256-GCM · 自定义载荷 · 签名绑定）",
                  style="Sub.TLabel").pack(side="left", padx=(2, 0), pady=(6, 0))

        # 加固卡片（单页）
        self._build_harden_tab(self)

        # 底部：进度 + 日志
        self._build_console()

    def _card(self, parent):
        """返回一个带边框的白色卡片 Frame。"""
        f = ttk.Frame(parent, style="Card.TFrame", padding=18)
        return f

    # ---- 加固页 ----
    def _build_harden_tab(self, tab):
        card = self._card(tab)
        card.pack(fill="both", expand=True, padx=18, pady=(4, 6))

        # 模式
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="加固模式", style="Card.TLabel", width=10).pack(side="left")
        self.harden_mode = tk.StringVar(value="single")
        ttk.Radiobutton(row, text="单个 APK", variable=self.harden_mode,
                        value="single", style="Card.TRadiobutton",
                        command=self._toggle_harden_mode).pack(side="left", padx=(0, 18))
        ttk.Radiobutton(row, text="整个目录（批量）", variable=self.harden_mode,
                        value="batch", style="Card.TRadiobutton",
                        command=self._toggle_harden_mode).pack(side="left")

        self._entry_row(card, "输入路径", "harden_input",
                        browse=lambda: self._browse_apk_or_dir("harden_input",
                                                                self.harden_mode.get()))
        self._entry_row(card, "输出目录", "harden_out", default=os.path.join(ROOT, "output"),
                        browse=lambda: self._browse_dir("harden_out"))

        # 选项
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 4))
        self.harden_keep = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="保留中间文件（便于排查，位于 work/）",
                        variable=self.harden_keep, style="Card.TCheckbutton").pack(side="left")

        # 签名证书（可选，留空则用内置）
        ttk.Label(card, text="签名证书（可选，留空则使用内置默认证书）",
                  style="Card.TLabel").pack(anchor="w", pady=(12, 2))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="密钥库", style="Card.TLabel", width=10).pack(side="left")
        self.ks_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ks_var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="浏览…", width=8,
                   command=lambda: self.ks_var.set(filedialog.askopenfilename(
                       title="选择密钥库", parent=self,
                       filetypes=[("密钥库", "*.jks *.keystore *.p12 *.pfx"),
                                  ("所有文件", "*.*")]))).pack(side="left")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text="别名", style="Card.TLabel", width=10).pack(side="left")
        self.ks_alias_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ks_alias_var, width=20).pack(side="left", padx=(0, 16))
        ttk.Label(row, text="密钥库密码", style="Card.TLabel").pack(side="left")
        self.ks_pass_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ks_pass_var, show="*", width=18).pack(side="left", padx=(0, 16))
        ttk.Label(row, text="密钥密码", style="Card.TLabel").pack(side="left")
        self.ks_keypass_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.ks_keypass_var, show="*", width=18).pack(side="left")

        # 记住签名信息（本地保存）
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        self.remember_sign = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="记住签名信息（保存到 exe 同目录 jiagu_settings.json，含密码明文）",
                        variable=self.remember_sign, style="Card.TCheckbutton").pack(side="left")

        # 按钮
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(10, 0))
        self.btn_harden = tk.Button(row, text="🚀  开始加固", bg=C_PRIMARY, fg="white",
                                    activebackground=C_PRIMARY_D, activeforeground="white",
                                    relief="flat", cursor="hand2", height=2, width=18,
                                    font=("Microsoft YaHei UI", 11, "bold"),
                                    command=self.start_harden)
        self.btn_harden.pack(side="left")

        # 说明
        ttk.Label(card,
                  text="单个模式：输出 hardened_<原名>.apk 到输出目录。  批量模式：加固目录下全部 APK 并逐个静态自检。",
                  style="CardMuted.TLabel").pack(side="left", padx=(12, 0), pady=(14, 0))

        self._toggle_harden_mode()

    def _toggle_harden_mode(self):
        pass

    # ---- 底部控制台 ----
    def _build_console(self):
        bot = ttk.Frame(self)
        bot.pack(fill="both", expand=False, padx=18, pady=(6, 12))

        bar = ttk.Frame(bot)
        bar.pack(fill="x")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", maximum=20)
        self.progress.pack(side="left", fill="x", expand=True)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(bar, textvariable=self.status_var, style="Muted.TLabel",
                  width=14).pack(side="left", padx=(10, 0))
        self.btn_stop = tk.Button(bar, text="停止", bg=C_ERR, fg="white",
                                  relief="flat", cursor="hand2", width=6, height=1,
                                  state="disabled", command=self.stop_task)
        self.btn_stop.pack(side="right", padx=(8, 0))
        ttk.Button(bar, text="清空日志", width=8,
                   command=self.clear_log).pack(side="right")

        # 日志文本框
        lf = ttk.Frame(bot)
        lf.pack(fill="both", expand=True, pady=(8, 0))
        self.log = tk.Text(lf, bg=C_LOG_BG, fg=C_TEXT, relief="solid", borderwidth=1,
                           highlightthickness=0, wrap="word", font=("Consolas", 10),
                           padx=10, pady=8, height=12)
        sb = ttk.Scrollbar(lf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)
        self.log.configure(state="disabled")
        # 颜色标签
        self.log.tag_configure("ok", foreground=C_OK)
        self.log.tag_configure("err", foreground=C_ERR)
        self.log.tag_configure("step", foreground=C_STEP)
        self.log.tag_configure("muted", foreground=C_MUTED)
        self.log.tag_configure("head", foreground=C_PRIMARY, font=("Consolas", 10, "bold"))

    # ----------------------------- 通用控件 ---------------------------------
    def _entry_row(self, parent, label, attr, default="", browse=None):
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, style="Card.TLabel", width=10).pack(side="left")
        var = tk.StringVar(value=default)
        e = ttk.Entry(row, textvariable=var)
        e.pack(side="left", fill="x", expand=True, padx=(0, 8))
        if browse:
            ttk.Button(row, text="浏览…", width=8, command=browse).pack(side="left")
        setattr(self, attr + "_var", var)

    # ----------------------------- 浏览/设备 ---------------------------------
    def _browse_apk(self, attr):
        p = filedialog.askopenfilename(
            title="选择 APK", parent=self,
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")])
        if p:
            getattr(self, attr + "_var").set(p)

    def _browse_dir(self, attr):
        p = filedialog.askdirectory(title="选择目录", parent=self, initialdir=ROOT)
        if p:
            getattr(self, attr + "_var").set(p)

    def _browse_apk_or_dir(self, attr, mode):
        if mode == "batch":
            self._browse_dir(attr)
        else:
            self._browse_apk(attr)

    # ----------------------------- 日志 -------------------------------------
    def _log(self, text, tag=None):
        self.log.configure(state="normal")
        self.log.insert("end", text if text.endswith("\n") else text + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ----------------------------- 设置持久化 -------------------------------
    def _settings_path(self):
        return os.path.join(ROOT, "jiagu_settings.json")

    def _load_settings(self):
        """启动时回填上次保存的输入/输出路径与签名信息（若勾选了记住）。"""
        import json
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as f:
                d = json.load(f) or {}
        except Exception:
            d = {}
        # 非敏感字段始终回填
        if d.get("input"):
            try: self.harden_input_var.set(d["input"])
            except Exception: pass
        if d.get("output"):
            try: self.harden_out_var.set(d["output"])
            except Exception: pass
        if d.get("keep") is not None:
            try: self.harden_keep.set(bool(d["keep"]))
            except Exception: pass
        # 签名信息仅当上次勾选了“记住”才回填
        if d.get("remember_sign"):
            try:
                self.remember_sign.set(True)
                if d.get("ks"):      self.ks_var.set(d["ks"])
                if d.get("ks_alias") is not None: self.ks_alias_var.set(d["ks_alias"])
                if d.get("ks_pass") is not None:  self.ks_pass_var.set(d["ks_pass"])
                if d.get("ks_keypass") is not None: self.ks_keypass_var.set(d["ks_keypass"])
            except Exception:
                pass

    def _save_settings(self):
        """保存当前配置。勾选“记住”则连同密码一起存；否则只存路径类字段并清掉密码。"""
        import json
        remember = bool(self.remember_sign.get())
        d = {
            "input": self.harden_input_var.get().strip(),
            "output": self.harden_out_var.get().strip(),
            "keep": bool(self.harden_keep.get()),
            "remember_sign": remember,
        }
        if remember:
            d["ks"] = self.ks_var.get().strip()
            d["ks_alias"] = self.ks_alias_var.get().strip()
            d["ks_pass"] = self.ks_pass_var.get()
            d["ks_keypass"] = self.ks_keypass_var.get()
        try:
            with open(self._settings_path(), "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _classify(self, line):
        l = line
        if any(k in l for k in ("ALL PASS", "PASS", "成功", "完成", "就绪", "BOOT COMPLETED")):
            if "FAIL" not in l:
                return "ok"
        if any(k in l for k in ("FAIL", "Error", "FATAL", "错误", "失败", "异常", "Traceback")):
            return "err"
        if re.match(r"\s*\[\d+\]", l) or l.startswith("====="):
            return "step"
        return None

    # ----------------------------- 任务执行 ---------------------------------
    def _set_running(self, running, status="就绪"):
        self._running = running
        self.btn_harden.configure(state="normal" if not running else "disabled")
        self.btn_stop.configure(state="normal" if running else "disabled")
        if running:
            self.progress.start(20)
        else:
            self.progress.stop()
        self.status_var.set(status)

    def stop_task(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self._log("已请求停止当前任务。", "err")

    def _run_cmd(self, cmd, label):
        if self._running:
            messagebox.showwarning("提示", "已有任务在运行，请先停止。", parent=self)
            return
        self._set_running(True, label + "…")
        self._log("════════════════════════════════════════════════════", "head")
        self._log("▶ %s" % label, "head")
        self._log("$ " + self._format_cmd(cmd), "muted")
        self.worker_thread = threading.Thread(target=self._worker,
                                              args=(cmd,), daemon=True)
        self.worker_thread.start()

    @staticmethod
    def _format_cmd(cmd):
        """把命令列表格式化为可读字符串，密码值显示为 ***。"""
        out = []
        i = 0
        while i < len(cmd):
            c = cmd[i]
            if c in ("--ksPass", "--ksKeyPass") and i + 1 < len(cmd):
                out.append(c)
                out.append("***")
                i += 2
                continue
            out.append('"%s"' % c if " " in c else c)
            i += 1
        return " ".join(out)

    def _worker(self, cmd):
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=ROOT, env=child_env(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="utf-8", errors="replace", bufsize=1)
            for line in self.proc.stdout:
                self.log_queue.put(("line", line.rstrip("\r\n")))
            rc = self.proc.wait()
            self.log_queue.put(("done", rc))
        except Exception as e:
            self.log_queue.put(("err", str(e)))

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.log_queue.get_nowait()
                if kind == "line":
                    self._log(data, self._classify(data))
                elif kind == "done":
                    rc = data
                    if rc == 0:
                        self._log("✔ 任务完成（退出码 0）", "ok")
                        self._set_running(False, "完成")
                    else:
                        self._log("✘ 任务结束，退出码 %s" % rc, "err")
                        self._set_running(False, "失败")
                elif kind == "err":
                    self._log("✘ 执行异常：%s" % data, "err")
                    self._set_running(False, "失败")
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    # ----------------------------- 各动作 -----------------------------------
    def start_harden(self):
        mode = self.harden_mode.get()
        inp = self.harden_input_var.get().strip()
        out = self.harden_out_var.get().strip() or os.path.join(ROOT, "output")
        keep = ["--keep"] if self.harden_keep.get() else []
        # 签名证书（可选）
        ks = self.ks_var.get().strip()
        ks_alias = self.ks_alias_var.get().strip()
        ks_pass = self.ks_pass_var.get()
        ks_keypass = self.ks_keypass_var.get()
        sign_args = []
        if ks:
            sign_args += ["--ks", ks]
            if ks_alias:
                sign_args += ["--ksAlias", ks_alias]
            if ks_pass:
                sign_args += ["--ksPass", ks_pass]
            if ks_keypass:
                sign_args += ["--ksKeyPass", ks_keypass]
        # 保存当前配置（含签名信息，若勾选了“记住”）
        self._save_settings()
        if not inp:
            messagebox.showinfo("提示", "请选择输入路径。", parent=self)
            return
        if mode == "single":
            if not os.path.isfile(inp):
                messagebox.showerror("错误", "输入 APK 不存在。", parent=self)
                return
            base = os.path.basename(inp)
            out_apk = os.path.join(out, "hardened_" + base)
            cmd = RUNNER + ["harden", inp, "-o", out_apk] + keep + sign_args
            label = "加固 %s" % base
        else:
            if not os.path.isdir(inp):
                messagebox.showerror("错误", "输入目录不存在。", parent=self)
                return
            cmd = RUNNER + ["batch_harden", "--input-dir", inp,
                            "--output-dir", out] + keep + sign_args
            label = "批量加固 %s" % os.path.basename(inp.rstrip("/\\"))
        self._run_cmd(cmd, label)


def main():
    # CLI 子进程模式：--cli <module> <args...>
    if len(sys.argv) >= 2 and sys.argv[1] == "--cli":
        cli_dispatch()
        return
    # GUI 模式
    app = JGShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
