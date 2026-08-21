import frida, time, sys

SERIAL = "127.0.0.1:5555"
PKG = "com.zhuomogroup.ylyk"

dev = frida.get_device(SERIAL, timeout=30)
print("[driver] device:", dev.name, dev.id, flush=True)

try:
    dev.kill(PKG)
    print("[driver] killed old instance", flush=True)
except Exception as e:
    print("[driver] kill skip:", e, flush=True)

pid = dev.spawn([PKG])
print("[driver] spawned pid =", pid, flush=True)

sess = dev.attach(pid)
print("[driver] attached -> frida agent injected (gum thread + frida-agent.so)", flush=True)

dev.resume(pid)
time.sleep(15)

try:
    sess.detach()
except Exception:
    pass
print("[driver] detached, done", flush=True)
