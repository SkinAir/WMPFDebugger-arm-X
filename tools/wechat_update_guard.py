#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wechat_update_guard.py — control WeChat for Mac auto-update.

Two independent layers (use either or both):

  LAYER 1 — Sparkle preference (reversible, recommended first):
      SUEnableAutomaticChecks = false  in com.tencent.xinWeChat.plist
      Stops Sparkle from automatically downloading updates. Manual
      "Check for Updates…" from the WeChat menu still works, so you can
      update on YOUR schedule (after you re-signed & re-derived offsets).

  LAYER 2 — file lock on the Sparkle download dir (hard stop):
      chflags uchg on ~/Library/Caches/com.tencent.xinWeChat/org.sparkle-project.Sparkle
      Update downloads fail even if something re-enables checks. Unlock to update.

Usage:
  python3 wechat_update_guard.py status          # show current state
  python3 wechat_update_guard.py off             # disable auto-update (L1+L2)
  python3 wechat_update_guard.py on              # re-enable (undo both)
  python3 wechat_update_guard.py --soft-off      # L1 only (no file lock)

Note: L1 writes to ~/Library/Preferences/com.tencent.xinWeChat.plist as the
current user — no sudo needed. L2 also runs as the user. Restart WeChat to apply.
"""
import os
import subprocess
import sys

PLIST = os.path.expanduser("~/Library/Preferences/com.tencent.xinWeChat.plist")
SPARKLE_CACHE = os.path.expanduser(
    "~/Library/Caches/com.tencent.xinWeChat/org.sparkle-project.Sparkle")

def defaults_read(key):
    r = subprocess.run(["defaults", "read", PLIST, key], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None

def defaults_write(key, value):
    subprocess.run(["defaults", "write", PLIST, key, "-bool", value], check=True)

def locked(path):
    r = subprocess.run(["ls", "-lO", os.path.dirname(path)], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if os.path.basename(path) in line:
            return "uchg" in line
    return False

def lock(path, on):
    flag = "uchg" if on else "nouchg"
    if os.path.exists(path):
        subprocess.run(["chflags", flag, path], check=True)
        return True
    return False

def status():
    print(f"SUFeedURL           : (not in Info.plist; Sparkle built-in feed)")
    print(f"SUEnableAutomaticChecks: {defaults_read('SUEnableAutomaticChecks')}")
    print(f"SUAutomaticallyUpdate  : {defaults_read('SUAutomaticallyUpdate')}")
    print(f"SUSkippedVersion       : {defaults_read('SUSkippedVersion')}")
    print(f"SUScheduledCheckInterval: {defaults_read('SUScheduledCheckInterval')}s")
    print(f"sparkle cache locked   : {locked(SPARKLE_CACHE)}")
    v = subprocess.run(["/usr/libexec/PlistBuddy", "-c", "Print CFBundleVersion",
                        "/Applications/WeChat.app/Contents/Info.plist"],
                       capture_output=True, text=True).stdout.strip()
    print(f"installed WeChat build : {v}")

def off(soft=False):
    defaults_write("SUEnableAutomaticChecks", "false")
    defaults_write("SUAutomaticallyUpdate", "false")
    print("[guard] Sparkle automatic checks disabled")
    if not soft:
        os.makedirs(SPARKLE_CACHE, exist_ok=True)
        if lock(SPARKLE_CACHE, True):
            print(f"[guard] locked {SPARKLE_CACHE}")
    print("[guard] restart WeChat to apply")

def on():
    defaults_write("SUEnableAutomaticChecks", "true")
    print("[guard] Sparkle automatic checks re-enabled")
    if os.path.exists(SPARKLE_CACHE):
        lock(SPARKLE_CACHE, False)
        print(f"[guard] unlocked {SPARKLE_CACHE}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        status()
    elif cmd == "off":
        off()
    elif cmd == "--soft-off":
        off(soft=True)
    elif cmd == "on":
        on()
    else:
        sys.exit(__doc__)
