# 经 Mutter RemoteDesktop D-Bus 向无头 gnome-shell 注入按键，供 wayland.sh 使用。
# 用法：rd_keys.py 步骤...（type:<文本> / key:<键名>，键名可带 ctrl+ 前缀）
# 全部步骤在同一个 RemoteDesktop 会话里发送；每次调用新建会话时按键会丢失。
import sys
import time

from gi.repository import Gio, GLib

bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
NAME = "org.gnome.Mutter.RemoteDesktop"
KEYS = {
    "space": 0x20,
    "BackSpace": 0xFF08,
    "Return": 0xFF0D,
    "Escape": 0xFF1B,
    "Left": 0xFF51,
    "ctrl": 0xFFE3,
}


def call(path, iface, method, args=None, rtype=None):
    return bus.call_sync(NAME, path, iface, method, args, rtype, Gio.DBusCallFlags.NONE, 10000, None)


session = call("/org/gnome/Mutter/RemoteDesktop", NAME, "CreateSession", None, GLib.VariantType("(o)")).unpack()[0]


def session_call(method, args=None):
    call(session, NAME + ".Session", method, args)


def keysym(sym, pressed):
    session_call("NotifyKeyboardKeysym", GLib.Variant("(ub)", (sym, pressed)))


def tap(sym, mods=()):
    for mod in mods:
        keysym(KEYS[mod], True)
    keysym(sym, True)
    time.sleep(0.04)
    keysym(sym, False)
    for mod in mods:
        keysym(KEYS[mod], False)
    time.sleep(0.12)


session_call("Start")
time.sleep(2)
for n, step in enumerate(sys.argv[1:], 1):
    print("step", n, step, time.time(), flush=True)
    time.sleep(1)
    kind, _, value = step.partition(":")
    if kind == "type":
        for ch in value:
            tap(ord(ch))
    elif kind == "key":
        *mods, key = value.split("+")
        tap(KEYS.get(key, ord(key[0])), mods)
session_call("Stop")
