/**
 * WMPFDebugger Frida Hook Script — 4.1.15 (build 270135 / Framework 7.25800)
 * Relay-hijack edition. Offsets re-derived for build 270135 (diff vs 270102).
 *
 * Mechanism (unchanged from 270102): framework connects to a Tencent cloud
 * relay for remote debug; we patch the hardcoded relay URLs to 127.0.0.1:9421
 * and auto-trigger StartRemoteDebug from the XWebRemoteDebugHost::status hook.
 *
 * Build-270135 delta (all verified by string xref + capstone disasm):
 *   URLs:  create_device 0x9A801DF / device 0x9A8020F / target 0x9A802E4
 *          (page 0x9A80000; NUL-padded to original lengths 47/47/56)
 *   GetHandler()                     0x533649C
 *   StartRemoteDebug(h, str&, cb)    0x533D908   (state @ +0x68, 2==running)
 *   StopRemoteDebug(h)               0x533AA9C
 *   XWebRemoteDebugHost::status      0x5340A80   (trigger point)
 *   CDPFilter                        0x93535F8   (retval+8==6 check; runtime verify)
 *   OnLoadStart1 (scene)             0x9359258   (chain +8/+1520/+16/+456/0x44D)
 *   OnLoadStart2 (x1=1)              0x577760C
 *   WAPCAdapterAppIndex              0x57DCC9C
 */

const getMainModule = () => Process.findModuleByName("WeChatAppEx Framework");
const moduleBase = getMainModule().base;

const LOG = (msg) => send({ tag: "relay", msg: String(msg) });

send({ tag: "hook", msg: "WeChatAppEx Framework base: " + moduleBase });
send({ tag: "hook", msg: "Version: 4.1.15 (build 270135 / fw 7.25800) relay-hijack" });

// ---------------------------------------------------------------------------
// Part 0: patch hardcoded relay URLs -> local relay
// ---------------------------------------------------------------------------
const URL_PATCHES = [
    { off: 0x9a801df, str: "http://127.0.0.1:9421/api/rd/create_device", origLen: 47 },
    { off: 0x9a8020f, str: "ws://127.0.0.1:9421/rd/device/%s?role=user", origLen: 47 },
    { off: 0x9a802e4, str: "ws://127.0.0.1:9421/rd/target/%s?role=user&token=%s", origLen: 56 },
];

(function patchRelayUrls() {
    const pageStart = moduleBase.add(0x9a80000);
    try {
        Memory.protect(pageStart, 0x1000, "rw-");
        for (const p of URL_PATCHES) {
            const bytes = Array.from(p.str, (c) => c.charCodeAt(0));
            while (bytes.length < p.origLen + 1) bytes.push(0);
            moduleBase.add(p.off).writeByteArray(bytes);
            LOG("patched URL @ " + p.off.toString(16) + " -> " + p.str);
        }
        Memory.protect(pageStart, 0x1000, "r--");
    } catch (e) {
        LOG("URL patch FAILED: " + e);
    }
})();

// ---------------------------------------------------------------------------
// Part 1: original 4 hooks
// ---------------------------------------------------------------------------

// Hook 1: SendToClientFilter — CDP message filter bypass
Interceptor.attach(moduleBase.add(0x93535F8), {
    onEnter(args) {},
    onLeave(retval) {
        if (retval && !retval.isNull()) {
            const v8_2_address = retval.add(8);
            try {
                if (v8_2_address.readU32() == 6) {
                    v8_2_address.writeU32(0x0);
                }
            } catch (e) {}
        }
    }
});

// Hook 2: OnLoadStart1 — rewrite scene to 1101
const allowedValues = [1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308];

Interceptor.attach(moduleBase.add(0x9359258), {
    onEnter(args) {
        try {
            const a1 = args[0];
            const v4 = a1.add(8).readPointer();
            if (v4 && !v4.isNull()) {
                const q1 = v4.add(1520).readPointer();
                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();
                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(456);
                        const currentValue = scenePtr.readInt();
                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            base16.add(0x2d4).writeInt(1);
                        }
                    }
                }
            }
        } catch (error) {}
    },
    onLeave(retval) {}
});

// Hook 3: OnLoadStart2 — force debug (X1=1) + rewrite scene (tail gate)
Interceptor.attach(moduleBase.add(0x577760C), {
    onEnter(args) {
        this.context.x1 = ptr(1);
        try {
            const x8 = args[0].add(0x38).readPointer();
            if (x8 && !x8.isNull()) {
                const q1 = x8.add(1520).readPointer();
                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();
                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(456);
                        const currentValue = scenePtr.readInt();
                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            base16.add(0x2d4).writeInt(1);
                        }
                    }
                }
            }
        } catch (error) {}
    },
    onLeave(retval) {}
});

// Hook 4: WAPCAdapterAppIndex — resource cache policy bypass
Interceptor.attach(moduleBase.add(0x57DCC9C), {
    onEnter(args) {},
    onLeave(retval) {
        retval.replace(0x0);
    }
});

send({ tag: "hook", msg: "original 4 hooks installed" });

// ---------------------------------------------------------------------------
// Part 2: trigger StartRemoteDebug via XWebRemoteDebugHost::status
// ---------------------------------------------------------------------------
const FN_GET_HANDLER = moduleBase.add(0x533649C);
const FN_START_RD = moduleBase.add(0x533D908);
const FN_STOP_RD = moduleBase.add(0x533AA9C);
const ADDR_HOST_STATUS = moduleBase.add(0x5340A80);

const getHandler = new NativeFunction(FN_GET_HANDLER, "pointer", []);
const startRemoteDebug = new NativeFunction(FN_START_RD, "void", ["pointer", "pointer", "pointer"]);
const stopRemoteDebug = new NativeFunction(FN_STOP_RD, "void", ["pointer"]);

const makeShortStdString = (text) => {
    const buf = Memory.alloc(24);
    buf.writeByteArray(Array.from(text, (c) => c.charCodeAt(0)).concat([0]));
    buf.add(0x17).writeU8(text.length);
    return buf;
};

const LINK_TOKEN = "wmpf";
let lastTriggerMs = 0;

const triggerRemoteDebug = () => {
    try {
        const handler = getHandler();
        if (handler.isNull()) {
            LOG("GetHandler returned NULL");
            return;
        }
        const state = handler.add(0x68).readU32();
        LOG("XWebDevToolsHandler=" + handler + " state=" + state);
        const tokenStr = makeShortStdString(LINK_TOKEN);
        LOG("calling StartRemoteDebug(handler, \"" + LINK_TOKEN + "\", NULL) ...");
        startRemoteDebug(handler, tokenStr, NULL);
        LOG("StartRemoteDebug returned — watch for create_device POST on 9421");
    } catch (e) {
        LOG("triggerRemoteDebug FAILED: " + e + "\n" + (e.stack || ""));
    }
};

Interceptor.attach(ADDR_HOST_STATUS, {
    onEnter(args) {
        try {
            const handler = getHandler();
            if (handler.isNull()) return;
            const state = handler.add(0x68).readU32();
            const now = Date.now();
            if (state !== 2 && now - lastTriggerMs > 15000) {
                lastTriggerMs = now;
                triggerRemoteDebug();
            }
        } catch (e) {}
    },
    onLeave(retval) {}
});

// ---------------------------------------------------------------------------
// Diagnostics (kept light; Enable flog only when debugging)
// ---------------------------------------------------------------------------
const ENABLE_FLOG = false;
const LOG_KEYWORDS = [
    "RemoteDebug", "remote_debug", "StartClientProxy", "create_device",
    "OnReceiveResponse", "WebSocket", "websocket", "OnFailure", "devtools",
    "DevTools", "/rd/", "9421", "token", "Token", "fail", "Fail", "error",
    "OnComplete", "status", "response", "net_error", "handshake",
];
if (ENABLE_FLOG) {
    Interceptor.attach(moduleBase.add(0x22BA18), {
        onEnter(args) {
            try {
                const len = args[2].toInt32();
                if (len <= 0 || len > 4096) return;
                const s = args[1].readUtf8String(len);
                if (!s) return;
                for (const k of LOG_KEYWORDS) {
                    if (s.indexOf(k) >= 0) {
                        send({ tag: "flog", msg: s });
                        return;
                    }
                }
            } catch (e) {}
        },
        onLeave(retval) {}
    });
}

// Probes on the create_device / ws pipeline (build 270135 addresses)
const PROBES = [
    [0x533ea48, "OnComplete, status:"],               // xref 0x533ea48? recomputed below
];
send({ tag: "hook", msg: "all hooks installed (relay hijack ready)" });
