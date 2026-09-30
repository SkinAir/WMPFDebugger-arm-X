/**
 * WMPFDebugger Frida Hook Script — 4.1.15 (build 270102) RELAY HIJACK EDITION
 * Architecture: arm64, imagebase offsets.
 *
 * 4.1.15 replaced the hardcoded `ws://localhost:9421` dial-out with a
 * cloud-relay remote-debug flow:
 *
 *   JS window.xweb_remote_debug.RemoteDebugStart(url, token, cb)   [renderer]
 *     -> mojo flue.mojom.RemoteDebug                                [renderer]
 *     -> XWebRemoteDebugHost::start            (0x5340840)          [browser]
 *     -> XWebDevToolsHandler::StartRemoteDebug (0x533D854)          [browser]
 *        POST https://xweb.weixin.qq.com/api/rd/create_device
 *          {"linkToken":..,"ua":..,"pid":..,"pname":..}
 *        <- {"code":1, "data":{"token": <device_token>}}
 *     -> StartClientProxy: dials
 *          wss://xweb.weixin.qq.com/rd/device/<device_token>?role=user
 *        and proxies standard CDP (XWebTargetHandler/WebSocketAdapter).
 *
 * This script:
 *   1. Keeps the original 4 hooks (scene forge / CDPFilter / ResourceCache).
 *   2. Patches the 3 hardcoded relay URLs in __cstring to point at
 *      127.0.0.1:9421 (local WMPFDebugger relay impersonating Tencent's).
 *   3. Hooks XWebRemoteDebugHost::status (0x53409CC) — auto-invoked via the
 *      injected JS blob on every applet frame load — and uses it to trigger
 *      StartRemoteDebug(handler, "wmpf", NULL) from the browser's mojo thread.
 *
 * Result: the framework dials ws://127.0.0.1:9421/rd/device/wmpfdevtoken?role=user
 * speaking plain CDP; no Tencent round-trip, no linkToken needed.
 */

const getMainModule = () => Process.findModuleByName("WeChatAppEx Framework");
const moduleBase = getMainModule().base;

const LOG = (msg) => send({ tag: "relay", msg: String(msg) });

send({ tag: "hook", msg: "WeChatAppEx Framework base: " + moduleBase });
send({ tag: "hook", msg: "Version: 4.1.15 (build 270102) relay-hijack" });

// ---------------------------------------------------------------------------
// Part 0: patch the hardcoded Tencent relay URLs -> local relay
// ---------------------------------------------------------------------------
const URL_PATCHES = [
    // create_device API: "https://xweb.weixin.qq.com/api/rd/create_device" (47)
    { off: 0x9a7d19f, str: "http://127.0.0.1:9421/api/rd/create_device", origLen: 47 },
    // device ws: "wss://xweb.weixin.qq.com/rd/device/%s?role=user" (47)
    { off: 0x9a7d1cf, str: "ws://127.0.0.1:9421/rd/device/%s?role=user", origLen: 47 },
    // target ws: "wss://xweb.weixin.qq.com/rd/target/%s?role=user&token=%s" (56)
    { off: 0x9a7d2a4, str: "ws://127.0.0.1:9421/rd/target/%s?role=user&token=%s", origLen: 56 },
];

(function patchRelayUrls() {
    const pageStart = moduleBase.add(0x9a7d000);
    try {
        Memory.protect(pageStart, 0x1000, "rw-");
        for (const p of URL_PATCHES) {
            // pad with NUL to the FULL original length — the framework's
            // formatter copies origLen bytes regardless of embedded NULs
            // (observed: "?role=user%00user"), so any leftover of the original
            // string would leak into the URL. A leftover '%' at the end makes
            // the GURL invalid -> target connect silently aborts (status -1).
            const bytes = Array.from(p.str, (c) => c.charCodeAt(0));
            while (bytes.length < p.origLen + 1) bytes.push(0);
            const addr = moduleBase.add(p.off);
            addr.writeByteArray(bytes);
            LOG("patched URL @ " + p.off.toString(16) + " -> " + p.str);
        }
        Memory.protect(pageStart, 0x1000, "r--");
    } catch (e) {
        LOG("URL patch FAILED: " + e);
    }
})();

// ---------------------------------------------------------------------------
// Part 1: original 4 hooks (unchanged from frida/270102.js)
// ---------------------------------------------------------------------------

// Hook 1: SendToClientFilter — CDP message filter bypass
Interceptor.attach(moduleBase.add(0x93534C4), {
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

// Hook 2: OnLoadStart1 — Modify scene value to 1101
const allowedValues = [1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308];

Interceptor.attach(moduleBase.add(0x9356CC8), {
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

// Hook 3: OnLoadStart2 — Force enable debugging (X1=1) + rewrite scene
Interceptor.attach(moduleBase.add(0x5775170), {
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

// Hook 4: WAPCAdapterAppIndex — Resource cache policy bypass
Interceptor.attach(moduleBase.add(0x5787A54), {
    onEnter(args) {},
    onLeave(retval) {
        retval.replace(0x0);
    }
});

send({ tag: "hook", msg: "original 4 hooks installed" });

// ---------------------------------------------------------------------------
// Part 2: trigger StartRemoteDebug via XWebRemoteDebugHost::status
// ---------------------------------------------------------------------------
// XWebDevToolsHandler* GetHandler(void)            @ 0x53363E8 (no args)
// void StartRemoteDebug(handler, std::string&, cb) @ 0x533D854
// void StopRemoteDebug(handler)                    @ 0x533A9E8
// XWebRemoteDebugHost::status(host, cb)            @ 0x53409CC
const FN_GET_HANDLER = moduleBase.add(0x53363E8);
const FN_START_RD = moduleBase.add(0x533D854);
const FN_STOP_RD = moduleBase.add(0x533A9E8);
const ADDR_HOST_STATUS = moduleBase.add(0x53409CC);

const getHandler = new NativeFunction(FN_GET_HANDLER, "pointer", []);
const startRemoteDebug = new NativeFunction(FN_START_RD, "void", ["pointer", "pointer", "pointer"]);
const stopRemoteDebug = new NativeFunction(FN_STOP_RD, "void", ["pointer"]);

// libc++ (Apple ABI) short std::string: data at +0, size byte at +0x17
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
        // auto-fired by the injected JS blob (checkRemoteDebugStatus) on every
        // applet frame load — perfect, legitimately-scheduled trigger point.
        // Re-trigger whenever the handler is not in state 2 (running), with a
        // cooldown, so the channel self-heals after relay restarts.
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
// Part 2b: relay the Framework's own logs (log append helper @ 0x22BA18)
// signature: LogAppend(x0=logobj, x1=char* ptr, x2=len)
// WARNING: this function is EXTREMELY hot — enable only for diagnosis,
// it can stall script load on busy processes.
// ---------------------------------------------------------------------------
const ENABLE_FLOG = false;
const LOG_KEYWORDS = [
    "RemoteDebug", "remote_debug", "StartClientProxy", "create_device",
    "OnReceiveResponse", "WebSocket", "websocket", "OnFailure", "devtools",
    "DevTools", "/rd/", "9421", "token", "Token", "fail", "Fail", "error",
    "OnComplete", "status", "response", "net_error", "cancel", "Abort",
    "abort", "handshake", "Handshake", "xweb_devtools_handler",
    "xweb_remote_debug", "xweb_target_handler", "xweb_websocket_adapter",
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

// ---------------------------------------------------------------------------
// Part 2c: probes on OnReceiveResponse fail/success paths (xweb_devtools_handler.cc)
// ---------------------------------------------------------------------------
const PROBES = [
    [0x533e7c8, "FAIL: response data invalid (no 'data' key)"],
    [0x533e808, "FAIL: response code (bad 'code' value)"],
    [0x533e854, "FAIL: can not parse response (not JSON object?)"],
    [0x533e960, "FAIL: create device (net error)"],
    [0x533ea40, "SUCCESS: device_token accepted"],
    [0x533eb34, "StartClientProxy (device) building url"],
    [0x53418d4, "StartClientProxy (target) building url"],
    [0x533ee64, "createWebSocket called (device)"],
    [0x5341c00, "createWebSocket called (target)"],
    [0x533e578, "loader OnComplete"],
    [0x533e634, "loader OnReceiveResponse (headers)"],
    [0x5342fe8, "WS OnFailure"],
    [0x534311c, "WS OnConnectionEstablished"],
    [0x5342ee4, "WS OnOpeningHandshakeStarted"],
    [0x5338fa0, "OnTunnelData: CREATE target handler"],
    [0x5338f18, "OnTunnelData: stop running client proxy"],
    [0x53372c0, "OnTunnelReady: OK"],
    [0x53374f8, "OnTunnelReady: FAILED"],
];
for (const [off, label] of PROBES) {
    try {
        Interceptor.attach(moduleBase.add(off), {
            onEnter(args) { send({ tag: "probe", msg: label }); },
            onLeave(retval) {}
        });
    } catch (e) {
        LOG("probe @ " + off.toString(16) + " failed: " + e);
    }
}

// read the raw 'code' value encoding at the cmp site (0x533E780: cmp x8, x0, lsl #31)
try {
    Interceptor.attach(moduleBase.add(0x533e780), {
        onEnter(args) {
            send({ tag: "probe", msg: "code cmp: x0=" + this.context.x0 + " x8=" + this.context.x8 });
        },
        onLeave(retval) {}
    });
} catch (e) { LOG("code cmp probe failed: " + e); }

send({ tag: "hook", msg: "all hooks installed (relay hijack ready)" });

// NOTE: do NOT call triggerRemoteDebug() directly from frida's thread —
// Chromium thread-checks (brk) kill the call. The host::status hook above
// fires on the browser's mojo IPC thread whenever an applet frame loads,
// which is the legitimate context.
