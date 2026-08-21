import frida, time, sys

PKG = "com.zhuomogroup.ylyk"

d = frida.get_usb_device()
print(f"[*] attach to running process by name: {PKG}")
sess = d.attach(PKG)
print("[*] attached -> frida-agent now mapped into process; holding 8s for AntiTamper/native poll")
time.sleep(8)
try:
    sess.detach()
except Exception:
    pass
print("[*] detached; done (log mode: expect maps hit logged, app keeps running)")
