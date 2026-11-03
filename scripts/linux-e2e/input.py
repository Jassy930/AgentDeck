# 常驻的 Mutter RemoteDesktop 输入驱动，供 session.sh wayland 使用。
# 用法：input.py <FIFO> <屏宽> <屏高>；逐行读命令，全程复用同一个 RemoteDesktop 会话：
#   click X Y | move X Y | type <文本> | key [ctrl+]<键名>
# 没有关联 ScreenCast 流时只能发相对位移：先顶到右下角再移回目标。不能顶左上角，那里是
# GNOME 热角，会打开概览。
import sys
import time

from gi.repository import Gio, GLib

fifo, width, height = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
NAME = "org.gnome.Mutter.RemoteDesktop"
BTN_LEFT = 0x110
KEYS = {
    "space": 0x20,
    "Tab": 0xFF09,
    "BackSpace": 0xFF08,
    "Return": 0xFF0D,
    "Escape": 0xFF1B,
    "Left": 0xFF51,
    "Up": 0xFF52,
    "Right": 0xFF53,
    "Down": 0xFF54,
    "ctrl": 0xFFE3,
    "shift": 0xFFE1,
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
    time.sleep(0.1)


def pointer_to(x, y):
    session_call("NotifyPointerMotionRelative", GLib.Variant("(dd)", (10000.0, 10000.0)))
    time.sleep(0.1)
    session_call("NotifyPointerMotionRelative", GLib.Variant("(dd)", (x - width + 1, y - height + 1)))
    time.sleep(0.3)


session_call("Start")
time.sleep(2)
print("ready", flush=True)
while True:
    with open(fifo) as commands:
        for line in commands:
            kind, _, value = line.rstrip("\n").partition(" ")
            if kind in ("click", "move"):
                x, y = map(float, value.split())
                pointer_to(x, y)
                if kind == "click":
                    session_call("NotifyPointerButton", GLib.Variant("(ib)", (BTN_LEFT, True)))
                    time.sleep(0.05)
                    session_call("NotifyPointerButton", GLib.Variant("(ib)", (BTN_LEFT, False)))
            elif kind == "type":
                for ch in value:
                    tap(ord(ch))
            elif kind == "key":
                *mods, key = value.split("+")
                tap(KEYS.get(key, ord(key[0])), mods)
            print("done", line.strip(), flush=True)
