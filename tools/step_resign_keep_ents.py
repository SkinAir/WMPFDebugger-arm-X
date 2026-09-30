#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
step_resign_keep_ents.py — Ad-hoc re-sign WeChat.app inside-out, restoring each
bundle's ORIGINAL entitlements (archived to ~/wechat_ents from a fresh install
BEFORE any resign).

Why: 4.1.15 exit(255)s on LaunchServices launch when `--deep --sign -` strips
its entitlements (app-sandbox etc). Hardened Runtime stays OFF (no
--options runtime), so Frida can still attach.

Usage (WeChat fully quit):
  sudo python3 step_resign_keep_ents.py                # keep original entitlements
  sudo python3 step_resign_keep_ents.py --drop-appid   # if AMFI kills it (signal 9)
  python3 step_resign_keep_ents.py --archive           # one-time: archive entitlements
                                                       # from a FRESH (untouched) install
"""
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile

APP = "/Applications/WeChat.app"
AEX = f"{APP}/Contents/MacOS/WeChatAppEx.app"
FW = f"{AEX}/Contents/Frameworks/WeChatAppEx Framework.framework"

def ents_dir() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    home = os.path.expanduser(f"~{sudo_user}") if sudo_user else os.path.expanduser("~")
    return os.path.join(home, "wechat_ents")

def bundle_name(bundle_path: str) -> str:
    return bundle_path.replace("/Applications/", "", 1).replace("/", "_")

def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)

def dump_entitlements(bundle: str, out_plist: str) -> bool:
    """codesign -d --entitlements :- --xml <bundle> > out_plist (False if none)."""
    r = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", "--xml", bundle],
        capture_output=True,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return False
    with open(out_plist, "wb") as f:
        f.write(r.stdout)
    return True

def archive() -> None:
    """Archive entitlements of every signable bundle (run on a fresh install)."""
    ents = ents_dir()
    os.makedirs(ents, exist_ok=True)
    targets = [APP, AEX, f"{APP}/Contents/MacOS/WeChatHelper.app", f"{APP}/Contents/MacOS/XPlayer.app"]
    helpers_dir = f"{FW}/Versions/C/Helpers"
    if os.path.isdir(helpers_dir):
        for name in sorted(os.listdir(helpers_dir)):
            if name.endswith(".app"):
                targets.append(os.path.join(helpers_dir, name))
    for bundle in targets:
        if not os.path.exists(bundle):
            continue
        out = os.path.join(ents, bundle_name(bundle) + ".plist")
        if dump_entitlements(bundle, out):
            print(f"[archive] {bundle} -> {out}")
        else:
            print(f"[archive] {bundle} (no entitlements, skipped)")
    print(f"\n[done] archived into {ents} — keep this directory safe across WeChat updates")

def sign_bundle(bundle: str) -> None:
    ent = os.path.join(ents_dir(), bundle_name(bundle) + ".plist")
    if os.path.isfile(ent) and os.path.getsize(ent) > 0:
        print(f"[sign+ents] {bundle}")
        run(["codesign", "--force", "--sign", "-", "--entitlements", ent, bundle])
    else:
        print(f"[sign]      {bundle}")
        run(["codesign", "--force", "--sign", "-", bundle])

def resign(drop_appid: bool) -> None:
    ents = ents_dir()
    main_ent_src = os.path.join(ents, "WeChat.app.plist")
    if os.geteuid() != 0:
        sys.exit("[error] run with sudo")
    if not (os.path.isfile(main_ent_src) and os.path.getsize(main_ent_src) > 0):
        sys.exit(f"[error] missing {main_ent_src} — run  python3 {sys.argv[0]} --archive  "
                 "on a fresh WeChat install first")
    if subprocess.run(["pgrep", "-f", "WeChat.app/Contents/MacOS"],
                      capture_output=True).returncode == 0:
        sys.exit("[error] WeChat is still running, quit it (Cmd+Q) first")

    # 1) Helpers inside the AppEx framework
    helpers_dir = f"{FW}/Versions/C/Helpers"
    if os.path.isdir(helpers_dir):
        for name in sorted(os.listdir(helpers_dir)):
            if name.endswith(".app"):
                sign_bundle(os.path.join(helpers_dir, name))
    # 2) Framework (reseal over the re-signed helpers)
    print(f"[sign]      {FW}")
    run(["codesign", "--force", "--sign", "-", FW])
    # 3) Nested apps under Contents/MacOS
    sign_bundle(AEX)
    for nested in ("WeChatHelper.app", "XPlayer.app"):
        p = f"{APP}/Contents/MacOS/{nested}"
        if os.path.exists(p):
            sign_bundle(p)
    # 4) Outer WeChat.app
    tmp = tempfile.NamedTemporaryFile(prefix="wechat_main_", suffix=".plist", delete=False)
    tmp.close()
    shutil.copy(main_ent_src, tmp.name)
    if drop_appid:
        subprocess.run(["plutil", "-remove", "com.apple.application-identifier", tmp.name],
                       capture_output=True)
        print("[info] dropped com.apple.application-identifier")
    print(f"[sign+ents] {APP}")
    run(["codesign", "--force", "--sign", "-", "--entitlements", tmp.name, APP])
    os.unlink(tmp.name)

    print("\n[verify]")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", "--verbose=1", APP])
    subprocess.run("codesign -dvv \"$APP\" 2>&1 | grep -E '^flags|CodeDirectory'",
                   shell=True, env={**os.environ, "APP": APP})
    print("\n[done] Launch WeChat from the Dock.")

if __name__ == "__main__":
    if "--archive" in sys.argv:
        archive()
    else:
        resign("--drop-appid" in sys.argv)
