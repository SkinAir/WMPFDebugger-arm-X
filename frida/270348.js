/**
 * WMPFDebugger Frida Hook Script — WeChat 4.2.0 (build 270348 / Framework 8.26062)
 * Relay-hijack edition. Offsets derived for 4.2.0 (diff vs 4.1.15-270135).
 *
 * NOTE 4.2.0: Framework moved to
 *   WeChatAppEx.app/Contents/Resources/WeChatAppEx Framework.framework/...
 * Frida resolves "WeChatAppEx Framework" by module name regardless of path.
 *
 * Mechanism (unchanged): framework connects to a Tencent cloud relay; we patch
 * the hardcoded relay URLs to 127.0.0.1:9421 and auto-trigger StartRemoteDebug
 * from the XWebRemoteDebugHost::status hook.
 *
 * Build-270348 delta (verified by string xref + capstone disasm):
 *   URLs:  create_device 0x9AD7AB7 / device 0x9AD7AE7 / target 0x9AD7BBC
 *          (page 0x9AD7A00; NUL-padded to original lengths 47/47/56)
 *   GetHandler()                     0x5324C38
 *   StartRemoteDebug(h, str&, cb)    0x532C0C0   (state @ +0x68, 2==running)
 *   StopRemoteDebug(h)               0x5329238
 *   XWebRemoteDebugHost::status      0x532F21C   (trigger point)
 *   CDPFilter                        0x93A61BC   (retval+8==6; runtime verify)
 *   OnLoadStart1 (scene)             0x93ABE1C   (chain +8/+1552/+16/+480==1101,
 *                                                debug flag +0x2EC)
 *   OnLoadStart2 (x1=1)              0x57C69B8   (tail gate this+0x38 → +1552/+16/+480)
 *   WAPCAdapterAppIndex              0x582BFB0
 */

/**
 * 4.2.0 NOTE: scene 结构体偏移这版改了（StructOffset 1552 / SceneOffset 480 /
 * debug flag +0x2EC），而且 SendToClientFilter 有两个同形候选。如果挂上后微信卡死/崩，
 * 先把 ENABLE_LEGACY_HOOKS 关掉（relay 调试功能照样能用，只是 CDP 消息过滤/scene 伪造没了），
 * 再逐项打开定位是哪个 hook 炸的。
 */
const ENABLE_LEGACY_HOOKS = false;   // 默认先关，确认稳定再开
const ENABLE_CDP_FILTER = true;      // 4 个老 hook 里相对最独立的一个
const ENABLE_SCENE_HOOKS = false;    // scene 伪造（OnLoadStart1/2）
const ENABLE_WAPC = false;           // 资源缓存 bypass

const getMainModule = () => Process.findModuleByName("WeChatAppEx Framework");
const moduleBase = getMainModule().base;

const LOG = (msg) => send({ tag: "relay", msg: String(msg) });

send({ tag: "hook", msg: "WeChatAppEx Framework base: " + moduleBase });
send({ tag: "hook", msg: "Version: 4.2.0 (build 270348 / fw 8.26062) relay-hijack" });

// ---------------------------------------------------------------------------
// Part 0: patch hardcoded relay URLs -> local relay
// ---------------------------------------------------------------------------
const URL_PATCHES = [
    { off: 0x9ad7ab7, str: "http://127.0.0.1:9421/api/rd/create_device", origLen: 47 },
    { off: 0x9ad7ae7, str: "ws://127.0.0.1:9421/rd/device/%s?role=user", origLen: 47 },
    { off: 0x9ad7bbc, str: "ws://127.0.0.1:9421/rd/target/%s?role=user&token=%s", origLen: 56 },
];

(function patchRelayUrls() {
    const pageStart = moduleBase.add(0x9ad7000);
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
if (ENABLE_LEGACY_HOOKS || ENABLE_CDP_FILTER) Interceptor.attach(moduleBase.add(0x93A61BC), {
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

// Hook 2: OnLoadStart1 — rewrite scene to 1101 (4.2.0: StructOffset=1552, SceneOffset=480)
const allowedValues = [1005, 1007, 1008, 1012, 1027, 1035, 1053, 1074, 1145, 1168, 1178, 1256, 1260, 1302, 1308];

if (ENABLE_LEGACY_HOOKS || ENABLE_SCENE_HOOKS) Interceptor.attach(moduleBase.add(0x93ABE1C), {
    onEnter(args) {
        try {
            const a1 = args[0];
            const v4 = a1.add(8).readPointer();
            if (v4 && !v4.isNull()) {
                const q1 = v4.add(1552).readPointer();          // StructOffset 1552 (0x610)
                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();
                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(480);       // SceneOffset 480 (0x1e0)
                        const currentValue = scenePtr.readInt();
                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            base16.add(0x2ec).writeInt(1);      // debug flag @ +0x2ec
                        }
                    }
                }
            }
        } catch (error) {}
    },
    onLeave(retval) {}
});

// Hook 3: OnLoadStart2 — force debug (X1=1) + rewrite scene (tail gate, base this+0x38)
if (ENABLE_LEGACY_HOOKS || ENABLE_SCENE_HOOKS) Interceptor.attach(moduleBase.add(0x57C69B8), {
    onEnter(args) {
        this.context.x1 = ptr(1);
        try {
            const x8 = args[0].add(0x38).readPointer();
            if (x8 && !x8.isNull()) {
                const q1 = x8.add(1552).readPointer();
                if (q1 && !q1.isNull()) {
                    const base16 = q1.add(16).readPointer();
                    if (base16 && !base16.isNull()) {
                        const scenePtr = base16.add(480);
                        const currentValue = scenePtr.readInt();
                        if (allowedValues.includes(currentValue)) {
                            scenePtr.writeInt(1101);
                            base16.add(0x2ec).writeInt(1);
                        }
                    }
                }
            }
        } catch (error) {}
    },
    onLeave(retval) {}
});

// Hook 4: WAPCAdapterAppIndex — resource cache policy bypass
if (ENABLE_LEGACY_HOOKS || ENABLE_WAPC) Interceptor.attach(moduleBase.add(0x582BFB0), {
    onEnter(args) {},
    onLeave(retval) {
        retval.replace(0x0);
    }
});

send({ tag: "hook", msg: "original 4 hooks installed" });

// ---------------------------------------------------------------------------
// Part 2: trigger StartRemoteDebug via XWebRemoteDebugHost::status
// ---------------------------------------------------------------------------
const FN_GET_HANDLER = moduleBase.add(0x5324C38);
const FN_START_RD = moduleBase.add(0x532C0A4);   // 真正的函数入口（stp 系列从这里开始）
const FN_STOP_RD = moduleBase.add(0x5329238);
const ADDR_HOST_STATUS = moduleBase.add(0x532F21C);

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
// Diagnostics
// ---------------------------------------------------------------------------
const ENABLE_FLOG = false;
const LOG_KEYWORDS = [
    "RemoteDebug", "remote_debug", "StartClientProxy", "create_device",
    "OnReceiveResponse", "WebSocket", "websocket", "OnFailure", "devtools",
    "DevTools", "/rd/", "9421", "token", "Token", "fail", "Fail", "error",
    "OnComplete", "status", "response", "net_error", "handshake",
];
if (ENABLE_FLOG) {
    Interceptor.attach(moduleBase.add(0x22B048), {   // log append helper (4.2.0)
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

send({ tag: "hook", msg: "all hooks installed (relay hijack ready)" });
