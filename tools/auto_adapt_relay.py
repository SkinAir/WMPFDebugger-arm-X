#!/usr/bin/env python3
"""Auto-adapt WMPFDebugger relay-hijack script for a new WeChatAppEx Framework build.

Extracts all required offsets from the arm64 binary and generates a ready-to-use
frida/<build>.js.  Run:  python3 tools/auto_adapt_relay.py <path-to-arm64-binary>
"""
import re
import struct
import sys
from pathlib import Path

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def main(binary_path: str):
    data = open(binary_path, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    # __TEXT vmsize
    ncmds = struct.unpack("<I", data[16:20])[0]
    off = 32
    text_size = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[off:off+8])
        if cmd == 0x19 and data[off+8:off+24].rstrip(b"\0") == b"__TEXT":
            text_size = struct.unpack("<Q", data[off+32:off+40])[0]
            break
        off += cmdsize
    if not text_size:
        sys.exit("__TEXT not found")

    words = np.frombuffer(data[:text_size // 4 * 4], dtype="<u4")
    n = len(words)

    # ---------- xref scanner ----------
    is_adrp = (words & 0x9F000000) == 0x90000000
    idx = np.nonzero(is_adrp)[0]
    idx = idx[idx + 1 < n]
    w = words[idx].astype(np.int64); pc = idx.astype(np.int64) * 4
    imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 0x3)
    imm = np.where(imm & (1 << 20), imm - (1 << 21), imm)
    page = (pc & ~0xFFF) + (imm << 12)
    rd = (words[idx] & 0x1F).astype(np.uint32)
    nxt = words[idx + 1]
    is_add = (nxt & 0xFF800000) == 0x91000000
    add_imm = ((nxt >> 10) & 0xFFF).astype(np.int64)
    add_rn = ((nxt >> 5) & 0x1F).astype(np.uint32)

    def xrefs(target):
        m = (page == (target & ~0xFFF)) & is_add & (add_imm == (target & 0xFFF)) & (add_rn == rd)
        return [int(h * 4) for h in idx[m]]

    def find_str(s):
        b = s.encode() + b"\x00"
        hits = []
        i = 0
        while True:
            i = data.find(b, i)
            if i < 0:
                break
            hits.append(i)
            i += 1
        return hits

    def func_start(addr, lookback=0x400):
        code = data[max(0, addr - lookback):addr + 16]
        ins = list(md.disasm(code, max(0, addr - lookback)))
        for i in range(len(ins) - 1, -1, -1):
            if ins[i].mnemonic == "sub" and "sp, sp" in ins[i].op_str:
                return ins[i].address
        return None

    def disasm_range(start, size):
        return list(md.disasm(data[start:start + size], start))

    def bl_target(ins):
        """BL target from capstone without detail: parse op_str ('#0x1234')."""
        if ins.mnemonic != "bl":
            return None
        s = ins.op_str.lstrip('#')
        try:
            return int(s, 16)
        except ValueError:
            return None

    # ---------- strings ----------
    S = {}
    S["create_device"] = find_str("https://xweb.weixin.qq.com/api/rd/create_device")[0]
    S["device_ws"]     = find_str("wss://xweb.weixin.qq.com/rd/device/%s?role=user")[0]
    S["target_ws"]     = find_str("wss://xweb.weixin.qq.com/rd/target/%s?role=user&token=%s")[0]
    S["rtti_onload"]   = find_str("virtual void applet::AppletIndexContainer::OnLoadStart(bool, const std::string &)")[0]
    S["sendfilter"]    = find_str("SendToClientFilter")[0]
    S["wapc"]          = find_str("WAPCAdapterAppIndex.js")[0]
    S["host_status"]   = find_str("XWebRemoteDebugHost::status")[0]
    S["host_start"]    = find_str("XWebRemoteDebugHost::start")[0]
    S["start_rd"]      = find_str("StartRemoteDebug, linkToken: ")[0]
    S["stop_rd"]       = find_str("StopRemoteDebug, state_:")[0]

    # ---------- code xrefs -> function starts ----------
    O = {}
    O["OnLoadStart2"] = func_start(xrefs(S["rtti_onload"])[0])
    O["host_status"]  = func_start(xrefs(S["host_status"])[0])
    O["host_start"]   = func_start(xrefs(S["host_start"])[0])
    O["StartRemoteDebug"] = func_start(xrefs(S["start_rd"])[0])
    O["StopRemoteDebug"]  = func_start(xrefs(S["stop_rd"])[0])

    # SendToClientFilter: two candidates with cmp #6; pick the one with `ldr [x0+8]; cmp #6` shape
    cdp_candidates = [func_start(x) for x in xrefs(S["sendfilter"])]
    O["CDPFilter"] = None
    for c in cdp_candidates:
        ins = disasm_range(c, 0x80)
        for i in range(len(ins) - 1):
            if ins[i].mnemonic == "ldr" and "#8" in ins[i].op_str and ins[i+1].mnemonic == "cmp" and "#6" in ins[i+1].op_str:
                O["CDPFilter"] = c
                break
        if O["CDPFilter"]:
            break
    if not O["CDPFilter"]:
        O["CDPFilter"] = cdp_candidates[0]

    # WAPCAdapter
    O["WAPCAdapter"] = func_start(xrefs(S["wapc"])[0])

    # OnLoadStart1: find BL target from OnLoadStart2 tail
    bls = [t for t in (bl_target(i) for i in disasm_range(O["OnLoadStart2"], 0x2000))
           if t is not None and t > O["OnLoadStart2"] + 0x100]
    O["OnLoadStart1"] = None
    for t in bls:
        ins = disasm_range(t, 0x100)
        txt = " ".join(f"{i.mnemonic} {i.op_str}" for i in ins)
        if "0x610" in txt and "0x1e0" in txt and "0x44d" in txt:
            O["OnLoadStart1"] = t
            break
    if not O["OnLoadStart1"]:
        sys.exit("OnLoadStart1 not found from OnLoadStart2 tail")

    # GetHandler: the BL immediately BEFORE the 'ldr w8, [x0, #0x68]' read
    # in host::status. We scan backwards from that instruction.
    ins = disasm_range(O["host_status"], 0x120)
    get_handler = None
    state_read_idx = None
    for i, insn in enumerate(ins):
        if insn.mnemonic == "ldr" and "#0x68" in insn.op_str:
            state_read_idx = i
            break
    if state_read_idx is not None:
        for j in range(state_read_idx - 1, -1, -1):
            t = bl_target(ins[j])
            if t is not None:
                get_handler = t
                break
    O["GetHandler"] = get_handler

    # scene struct offsets from OnLoadStart1
    ins = disasm_range(O["OnLoadStart1"], 0x100)
    struct_off = scene_off = debug_flag = None
    for i in ins:
        if i.mnemonic == "ldr" and "0x610" in i.op_str:
            m = re.search(r"#0x([0-9a-f]+)", i.op_str)
            if m: struct_off = int(m.group(1), 16)
        if i.mnemonic == "ldr" and "0x1e0" in i.op_str:
            m = re.search(r"#0x([0-9a-f]+)", i.op_str)
            if m: scene_off = int(m.group(1), 16)
        if i.mnemonic == "ldr" and "0x2ec" in i.op_str:
            m = re.search(r"#0x([0-9a-f]+)", i.op_str)
            if m: debug_flag = int(m.group(1), 16)
    O["StructOffset"] = struct_off or 1552
    O["SceneOffset"] = scene_off or 480
    O["DebugFlagOffset"] = debug_flag or 0x2ec

    # URL patch page
    O["URL_PAGE"] = S["create_device"] & ~0xFFF

    # ---------- emit ----------
    # build = last numeric component in filename (e.g. ..._270353_arm64 -> 270353)
    m = re.search(r"_(\d+)_arm64", Path(binary_path).name)
    build = m.group(1) if m else Path(binary_path).stem
    out = Path(__file__).parent.parent / "frida" / f"{build}.js"

    tpl = f"""/**
 * WMPFDebugger Frida Hook Script — WeChat (build {build})
 * Auto-generated by tools/auto_adapt_relay.py
 */
const getMainModule = () => Process.findModuleByName("WeChatAppEx Framework");
const moduleBase = getMainModule().base;
const LOG = (msg) => send({{ tag: "relay", msg: String(msg) }});

send({{ tag: "hook", msg: "WeChatAppEx Framework base: " + moduleBase }});
send({{ tag: "hook", msg: "Auto-adapted build {build}" }});

// relay URLs
const URL_PATCHES = [
    {{ off: 0x{S['create_device']:x}, str: "http://127.0.0.1:9421/api/rd/create_device", origLen: 47 }},
    {{ off: 0x{S['device_ws']:x},     str: "ws://127.0.0.1:9421/rd/device/%s?role=user", origLen: 47 }},
    {{ off: 0x{S['target_ws']:x},     str: "ws://127.0.0.1:9421/rd/target/%s?role=user&token=%s", origLen: 56 }},
];
(function patchRelayUrls() {{
    const pageStart = moduleBase.add(0x{O['URL_PAGE']:x});
    try {{
        Memory.protect(pageStart, 0x1000, "rw-");
        for (const p of URL_PATCHES) {{
            const bytes = Array.from(p.str, (c) => c.charCodeAt(0));
            while (bytes.length < p.origLen + 1) bytes.push(0);
            moduleBase.add(p.off).writeByteArray(bytes);
            LOG("patched URL @ " + p.off.toString(16) + " -> " + p.str);
        }}
        Memory.protect(pageStart, 0x1000, "r--");
    }} catch (e) {{ LOG("URL patch FAILED: " + e); }}
}})();

// legacy hooks (kept off by default; enable if needed)
const ENABLE_LEGACY_HOOKS = false;
const ENABLE_CDP_FILTER = false;
const ENABLE_SCENE_HOOKS = false;
const ENABLE_WAPC = false;
const allowedValues = [1005,1007,1008,1012,1027,1035,1053,1074,1145,1168,1178,1256,1260,1302,1308];

if (ENABLE_CDP_FILTER) Interceptor.attach(moduleBase.add(0x{O['CDPFilter']:x}), {{
    onLeave(retval) {{ if (retval && !retval.isNull()) {{ try {{ if (retval.add(8).readU32()==6) retval.add(8).writeU32(0); }} catch(e){{}} }} }}
}});
if (ENABLE_SCENE_HOOKS) Interceptor.attach(moduleBase.add(0x{O['OnLoadStart1']:x}), {{
    onEnter(args) {{ try {{ const a1=args[0]; const v4=a1.add(8).readPointer(); if(v4&&!v4.isNull()){{ const q1=v4.add({O['StructOffset']}).readPointer(); if(q1&&!q1.isNull()){{ const b=q1.add(16).readPointer(); if(b&&!b.isNull()){{ const s=b.add({O['SceneOffset']}); const c=s.readInt(); if(allowedValues.includes(c)){{ s.writeInt(1101); b.add({O['DebugFlagOffset']}).writeInt(1); }} }} }} }} }} catch(e){{}} }}
}});
if (ENABLE_SCENE_HOOKS) Interceptor.attach(moduleBase.add(0x{O['OnLoadStart2']:x}), {{
    onEnter(args) {{ this.context.x1=ptr(1); try {{ const x8=args[0].add(0x38).readPointer(); if(x8&&!x8.isNull()){{ const q1=x8.add({O['StructOffset']}).readPointer(); if(q1&&!q1.isNull()){{ const b=q1.add(16).readPointer(); if(b&&!b.isNull()){{ const s=b.add({O['SceneOffset']}); const c=s.readInt(); if(allowedValues.includes(c)){{ s.writeInt(1101); b.add({O['DebugFlagOffset']}).writeInt(1); }} }} }} }} }} catch(e){{}} }}
}});
if (ENABLE_WAPC) Interceptor.attach(moduleBase.add(0x{O['WAPCAdapter']:x}), {{ onLeave(retval) {{ retval.replace(0x0); }} }});

// relay trigger
const FN_GET_HANDLER = moduleBase.add(0x{O['GetHandler']:x});
const FN_START_RD   = moduleBase.add(0x{O['StartRemoteDebug']:x});
const FN_STOP_RD    = moduleBase.add(0x{O['StopRemoteDebug']:x});
const ADDR_HOST_STATUS = moduleBase.add(0x{O['host_status']:x});

const getHandler = new NativeFunction(FN_GET_HANDLER, "pointer", []);
const startRemoteDebug = new NativeFunction(FN_START_RD, "void", ["pointer","pointer","pointer"]);
const stopRemoteDebug = new NativeFunction(FN_STOP_RD, "void", ["pointer"]);

const makeShortStdString = (text) => {{ const buf=Memory.alloc(24); buf.writeByteArray(Array.from(text,(c)=>c.charCodeAt(0)).concat([0])); buf.add(0x17).writeU8(text.length); return buf; }};
const LINK_TOKEN = "wmpf";
let lastTriggerMs = 0;

const triggerRemoteDebug = () => {{
    try {{
        const handler = getHandler();
        if (handler.isNull()) {{ LOG("GetHandler returned NULL"); return; }}
        const state = handler.add(0x68).readU32();
        LOG("XWebDevToolsHandler=" + handler + " state=" + state);
        const tokenStr = makeShortStdString(LINK_TOKEN);
        LOG("calling StartRemoteDebug(handler, \"" + LINK_TOKEN + "\", NULL) ...");
        startRemoteDebug(handler, tokenStr, NULL);
        LOG("StartRemoteDebug returned");
    }} catch (e) {{ LOG("triggerRemoteDebug FAILED: " + e); }}
}};

Interceptor.attach(ADDR_HOST_STATUS, {{
    onEnter(args) {{
        try {{
            const handler = getHandler();
            if (handler.isNull()) return;
            const state = handler.add(0x68).readU32();
            const now = Date.now();
            if (state !== 2 && now - lastTriggerMs > 15000) {{ lastTriggerMs = now; triggerRemoteDebug(); }}
        }} catch (e) {{}}
    }}
}});

send({{ tag: "hook", msg: "all hooks installed (relay hijack ready)" }});
"""
    out.write_text(tpl)
    print(f"✅ wrote {out}")
    print(f"offsets: {O}")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
