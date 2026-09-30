/**
 * WMPFDebugger 4.1.15 relay-mode server (src/relay.ts)
 *
 * 4.1.15 replaced the hardcoded ws://localhost:9421 dial-out with a cloud
 * relay (wss://xweb.weixin.qq.com/rd/...) speaking STANDARD CDP — the old
 * WARemoteDebug protobuf layer is gone. frida/270102_relay.js patches the
 * relay URLs inside the Framework to point at this server, so the Framework
 * connects HERE exactly as it would to Tencent's relay.
 *
 * Protocol (reverse engineered from WeChatAppEx Framework 7.25755):
 *
 *   1. Framework -> POST /api/rd/create_device {"linkToken":..,"ua":..,...}
 *      <- must be HTTP 201 with {"code":0,"data":{"token":<deviceToken>}}
 *      (status 201: cmp w8,#0xc9 @ 0x533E66C; code must be 0: getter returns
 *       v32|1<<32 and (x0<<31)==2^63 is required @ 0x533E780)
 *   2. Framework -> WS /rd/device/<deviceToken>?role=user   [control channel]
 *      - pushes {"event":"XWeb.targets","data":[{id,title,url,type,...}...]}
 *      - accepts {"event":"XWeb.inspect","data":{"targetId":..,"deviceToken":..}}
 *        (dispatcher: inline cmp "XWeb.inspect" @ 0x5338DC8; keys targetId /
 *         deviceToken looked up @ 0x5338DEC/0x5338E04)
 *   3. On XWeb.inspect the Framework opens
 *        WS /rd/target/<targetId>?role=user&token=<deviceToken>  [CDP channel]
 *      raw CDP is proxied between this socket and the DevTools frontend.
 *
 * This server also exposes ws://127.0.0.1:62000 for the DevTools frontend:
 *   devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
 *
 * Frida injection lives in src/inject.ts (run it once per WeChat session).
 *
 * Usage:  npx ts-node src/relay.ts [--target <targetId>]
 *         (default: auto-pick the real mini program page-frame target)
 */

import { promises } from "node:fs";
import * as http from "node:http";
import path from "node:path";
import WebSocket, { WebSocketServer } from "ws";
import { argv } from "node:process";

// Relay (fake Tencent rd server) port — must match frida/270102_relay.js URL patches
const RELAY_PORT = 9421;
// CDP port for the DevTools frontend
const CDP_PORT = 62000;
// device_token we hand out; we are the relay, no validation
const DEVICE_TOKEN = "wmpfdevtoken";

const DEFAULT_PROCESS_WAIT_MS = 120_000;
const PROCESS_POLL_INTERVAL_MS = 5_000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const getArgValue = (name: string): string | null => {
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === name && i + 1 < argv.length) {
            return argv[i + 1];
        }
    }
    return null;
};

const preview = (data: WebSocket.RawData, max = 1200): string => {
    let b: Buffer;
    if (Buffer.isBuffer(data)) b = data;
    else if (Array.isArray(data)) b = Buffer.concat(data);
    else b = Buffer.from(data as ArrayBuffer);
    const s = b.toString("utf-8");
    return `[${b.length}B] ` + (s.length > max ? s.slice(0, max) + "..." : s);
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
interface RdTarget {
    id: string;
    title?: string;
    url?: string;
    type?: string;
}

let deviceSocket: WebSocket | null = null;   // Framework control channel
let targetSocket: WebSocket | null = null;   // Framework CDP channel
let targetList: RdTarget[] = [];
let attachedTargetId: string | null = null;
const cdpClients = new Set<WebSocket>();

let lastInspectId: string | null = null;
let lastInspectMs = 0;

const sendInspect = (targetId: string) => {
    if (!deviceSocket || deviceSocket.readyState !== WebSocket.OPEN) {
        console.log("[relay] cannot inspect: no device connection");
        return;
    }
    const now = Date.now();
    // cooldown: re-sending inspect makes the framework stop+recreate the
    // target handler every time (CPU spin); only resend after 15s.
    if (lastInspectId === targetId && now - lastInspectMs < 15000) return;
    lastInspectId = targetId;
    lastInspectMs = now;
    // dispatcher reads "method" + "params" (0x53379A8/0x53379C8), NOT event/data
    const msg = JSON.stringify({
        method: "XWeb.inspect",
        params: { targetId, deviceToken: DEVICE_TOKEN },
    });
    console.log(`[relay] -> XWeb.inspect ${msg}`);
    deviceSocket.send(msg);
    attachedTargetId = targetId;
};

const pickTarget = (): RdTarget | null => {
    const manual = getArgValue("--target");
    if (manual) {
        const t = targetList.find((t) => t.id === manual);
        if (t) return t;
        console.log(`[relay] --target ${manual} not in list`);
    }
    // ranking: real applet page-frame (servicewechat.com/wx<appid>/...) first,
    // then xworker, then any other non-preload page, then anything.
    const score = (t: RdTarget): number => {
        const u = t.url || "";
        if (/servicewechat\.com\/wx[0-9a-f]{16}\//.test(u)) return 100;
        if (u.indexOf("xworker") >= 0) return 50;
        if (u.indexOf("/preload-") >= 0) return -100;
        return 0;
    };
    const pool = [...targetList].sort((a, b) => score(a) - score(b));
    return pool.length > 0 ? pool[pool.length - 1] : null;
};

const maybeAutoAttach = () => {
    const wanted = pickTarget();
    if (!wanted) return;
    if (attachedTargetId === wanted.id && targetSocket && targetSocket.readyState === WebSocket.OPEN) {
        return; // already attached
    }
    console.log(`[relay] auto-attaching target ${wanted.id} url=${wanted.url}`);
    sendInspect(wanted.id);
};

// ---------------------------------------------------------------------------
// Relay server: HTTP create_device + WS endpoints for the Framework
// ---------------------------------------------------------------------------
const relay_server = (): http.Server => {
    const server = http.createServer((req, res) => {
        if (req.method === "POST" && (req.url || "").startsWith("/api/rd/create_device")) {
            let body = "";
            req.on("data", (c) => (body += c));
            req.on("end", () => {
                console.log(`[relay] create_device request body: ${body}`);
                // Framework requires HTTP 201 (cmp w8,#0xc9 @ 0x533E66C).
                // 'code' getter (0x8F474C) returns (v32 | 1<<32) and the check
                // @ 0x533E780 requires (x0<<31)==2^63  =>  code must be 0.
                const resp = JSON.stringify({ code: 0, data: { token: DEVICE_TOKEN } });
                console.log(`[relay] create_device response: ${resp}`);
                res.writeHead(201, { "Content-Type": "application/json;charset=UTF-8" });
                res.end(resp);
            });
            return;
        }
        console.log(`[relay] HTTP ${req.method} ${req.url} -> 404`);
        res.writeHead(404);
        res.end();
    });

    const wss = new WebSocketServer({ noServer: true });

    server.on("upgrade", (req, socket, head) => {
        console.log(`[relay] WS upgrade: ${req.url}`);
        wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    });

    wss.on("connection", (ws: WebSocket, req: http.IncomingMessage) => {
        const url = req.url || "";
        if (url.startsWith("/rd/device")) {
            handleDeviceConnection(ws, url);
        } else if (url.startsWith("/rd/target")) {
            handleTargetConnection(ws, url);
        } else {
            console.log(`[relay] unknown WS path ${url}, treating as target channel`);
            handleTargetConnection(ws, url);
        }
    });

    server.listen(RELAY_PORT, "127.0.0.1", () => {
        console.log(`[relay] fake rd relay listening on http://127.0.0.1:${RELAY_PORT}`);
    });

    return server;
};

const handleDeviceConnection = (ws: WebSocket, url: string) => {
    console.log(`[relay] Framework DEVICE connected: ${url}`);
    if (deviceSocket && deviceSocket.readyState === WebSocket.OPEN) {
        console.log("[relay] replacing previous device connection");
        try { deviceSocket.terminate(); } catch (_) {}
    }
    deviceSocket = ws;
    attachedTargetId = null;

    ws.on("message", (data: WebSocket.RawData) => {
        const text = (Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer)).toString("utf-8");
        console.log(`[device->relay] ${preview(data)}`);
        try {
            const msg = JSON.parse(text);
            const list = msg?.data;
            if (Array.isArray(list) && list.length > 0 && list[0]?.id) {
                targetList = list.map((t: any) => ({ id: t.id, title: t.title, url: t.url, type: t.type }));
                console.log(`[relay] target list (${targetList.length}):`);
                for (const t of targetList) {
                    console.log(`        ${t.id}  ${t.type}  ${t.url}`);
                }
                maybeAutoAttach();
            }
        } catch (_) {
            // not JSON, ignore
        }
    });

    ws.on("close", (code, reason) => {
        console.log(`[relay] device disconnected - code: ${code}, reason: ${reason.toString()}`);
        if (deviceSocket === ws) deviceSocket = null;
        attachedTargetId = null;
    });

    ws.on("error", (err) => console.error("[relay] device ws error:", err));
};

const handleTargetConnection = (ws: WebSocket, url: string) => {
    console.log(`[relay] Framework TARGET connected: ${url}`);
    if (targetSocket && targetSocket.readyState === WebSocket.OPEN) {
        console.log("[relay] replacing previous target connection");
        try { targetSocket.terminate(); } catch (_) {}
    }
    targetSocket = ws;

    ws.on("message", (data: WebSocket.RawData, isBinary: boolean) => {
        console.log(`[applet->devtools]${isBinary ? " [binary]" : ""} ${preview(data)}`);
        const payload = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
        for (const client of cdpClients) {
            if (client.readyState === WebSocket.OPEN) {
                client.send(payload, { binary: isBinary });
            }
        }
    });

    ws.on("close", (code, reason) => {
        console.log(`[relay] target disconnected - code: ${code}, reason: ${reason.toString()}`);
        if (targetSocket === ws) targetSocket = null;
        attachedTargetId = null;
        // try to re-attach on next target list push
    });

    ws.on("error", (err) => console.error("[relay] target ws error:", err));
};

// ---------------------------------------------------------------------------
// CDP proxy server for the DevTools frontend
// ---------------------------------------------------------------------------
const cdp_server = (): WebSocketServer => {
    const wss = new WebSocketServer({ port: CDP_PORT, host: "127.0.0.1" });

    wss.on("connection", (ws: WebSocket) => {
        console.log("[cdp] DevTools frontend connected");
        cdpClients.add(ws);
        // make sure we are attached to something
        maybeAutoAttach();

        ws.on("message", (data: WebSocket.RawData, isBinary: boolean) => {
            console.log(`[devtools->applet]${isBinary ? " [binary]" : ""} ${preview(data)}`);
            if (targetSocket && targetSocket.readyState === WebSocket.OPEN) {
                const payload = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
                targetSocket.send(payload, { binary: isBinary });
            } else {
                console.log("[cdp] no target connection, dropping message");
                maybeAutoAttach();
            }
        });

        ws.on("close", () => {
            console.log("[cdp] DevTools frontend disconnected");
            cdpClients.delete(ws);
        });

        ws.on("error", (err) => {
            console.error("[cdp] error:", err);
            cdpClients.delete(ws);
        });
    });

    console.log(`[cdp] CDP proxy running on ws://127.0.0.1:${CDP_PORT}`);
    return wss;
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
const main = async () => {
    relay_server();
    cdp_server();

    process.on("SIGINT", () => process.exit(0));
    process.on("SIGTERM", () => process.exit(0));

    console.log(
        "[main] relay mode started.\n" +
        `Relay endpoint (Framework -> us): http://127.0.0.1:${RELAY_PORT}\n` +
        `CDP endpoint (DevTools -> us):    ws://127.0.0.1:${CDP_PORT}\n` +
        `Open: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${CDP_PORT}\n` +
        `(frida injection: run  npx ts-node src/inject.ts  in another terminal)`
    );
};

(async () => {
    try {
        await main();
    } catch (error) {
        console.error("[main] Error:", error);
        process.exit(1);
    }
})();
