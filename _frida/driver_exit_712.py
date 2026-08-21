import frida, sys, time

PKG = "com.zhuomogroup.ylyk"
dev = frida.get_usb_device()
print("[*] spawn", PKG)
pid = dev.spawn([PKG])
print("[*] spawned pid", pid)
sess = dev.attach(pid)
print("[*] attached -> frida-agent injected into process maps")

def on_detached(reason):
    print("[*] session detached, reason:", reason)
sess.on("detached", on_detached)

dev.resume(pid)
print("[*] resumed; holding 8s so AntiTamper/native guard periodic poll catches frida -> expect block")
time.sleep(8)
try:
    sess.detach()
    print("[*] detached")
except Exception as e:
    print("[!] detach err (app likely already dead):", e)
print("[*] done")
