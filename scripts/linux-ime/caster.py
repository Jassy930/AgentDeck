# 经 Mutter ScreenCast 录制无头 gnome-shell 的虚拟显示器，每秒存一帧 PNG，供 wayland.sh 使用。
# 用法：caster.py <输出目录>；收到 SIGTERM 时结束 gst 子进程后退出。
import signal
import subprocess
import sys

from gi.repository import Gio, GLib

out = sys.argv[1]
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)


def call(name, path, iface, method, args=None):
    return bus.call_sync(name, path, iface, method, args, None, Gio.DBusCallFlags.NONE, 10000, None).unpack()


state = call("org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig",
             "org.gnome.Mutter.DisplayConfig", "GetCurrentState")
connector = state[1][0][0][0]
SC = "org.gnome.Mutter.ScreenCast"
session = call(SC, "/org/gnome/Mutter/ScreenCast", SC, "CreateSession", GLib.Variant("(a{sv})", ({},)))[0]
stream = call(SC, session, SC + ".Session", "RecordMonitor", GLib.Variant("(sa{sv})", (connector, {})))[0]
procs = []
loop = GLib.MainLoop()


def on_stream_added(_conn, _sender, _path, _iface, _signal, params, _data):
    node = params.unpack()[0]
    procs.append(subprocess.Popen([
        "gst-launch-1.0", "-q", "pipewiresrc", f"path={node}", "always-copy=true",
        "!", "videorate", "!", "video/x-raw,framerate=1/1", "!", "videoconvert",
        "!", "pngenc", "!", "multifilesink", f"location={out}/f%04d.png",
    ]))


def on_term():
    for proc in procs:
        proc.terminate()
    loop.quit()
    return GLib.SOURCE_REMOVE


bus.signal_subscribe(None, SC + ".Stream", "PipeWireStreamAdded", stream, None,
                     Gio.DBusSignalFlags.NONE, on_stream_added, None)
GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, on_term)
call(SC, session, SC + ".Session", "Start")
print("casting", connector, flush=True)
loop.run()
