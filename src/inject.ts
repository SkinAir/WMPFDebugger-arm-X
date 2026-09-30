/**
 * WMPFDebugger 4.1.15 frida injector (src/inject.ts)
 *
 * Standalone frida attach process — separated from src/relay.ts so the relay
 * server can restart freely without re-attaching (repeated attach/detach on
 * the same long-lived WeChatAppEx process wedges the frida agent).
 *
 * Run ONCE per WeChat session:
 *   npx ts-node src/inject.ts [--script frida/270102_relay.js] [--pid N]
 */

import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";
import { execSync } from "child_process";
import { argv } from "node:process";

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

const getPidsFromPgrep = (): number[] => {
    const commands = [
        "pgrep -f '/WeChatAppEx.app/Contents/MacOS/WeChatAppEx'",
        "pgrep -x 'WeChatAppEx'",
    ];
    for (const command of commands) {
        try {
            const output = execSync(command, { encoding: "utf-8" }).trim();
            const pids = output
                .split("\n")
                .map((pid) => parseInt(pid.trim(), 10))
                .filter((pid) => !isNaN(pid));
            if (pids.length > 0) {
                console.log(`[frida] Found WeChatAppEx PIDs via ${command}: ${pids.join(", ")}`);
                return pids;
            }
        } catch (_) {}
    }
    return [];
};

const waitForWeChatAppExPIDs = async (): Promise<number[]> => {
    const manualPid = getArgValue("--pid");
    if (manualPid) {
        const pid = parseInt(manualPid, 10);
        if (!isNaN(pid)) return [pid];
        throw new Error(`[frida] Invalid --pid value: ${manualPid}`);
    }
    const waitArg = getArgValue("--wait-process-ms");
    const maxWaitMs = waitArg ? parseInt(waitArg, 10) : DEFAULT_PROCESS_WAIT_MS;
    const startedAt = Date.now();
    while (true) {
        const pids = getPidsFromPgrep();
        if (pids.length > 0) return pids;
        const elapsed = Date.now() - startedAt;
        if (elapsed >= maxWaitMs) {
            throw new Error("[frida] No WeChatAppEx process found. Open a mini program first.");
        }
        console.log(`[frida] Waiting for WeChatAppEx... (${Math.ceil((maxWaitMs - elapsed) / 1000)}s left)`);
        await sleep(PROCESS_POLL_INTERVAL_MS);
    }
};

const main = async () => {
    const localDevice = await frida.getLocalDevice();
    const pids = await waitForWeChatAppExPIDs();

    const projectRoot = path.join(__dirname, "..");
    const scriptPath = getArgValue("--script") || "frida/270102_relay.js";
    const absoluteScriptPath = path.isAbsolute(scriptPath) ? scriptPath : path.join(projectRoot, scriptPath);
    const scriptContent = (await promises.readFile(absoluteScriptPath)).toString();
    console.log(`[frida] Loaded script from: ${absoluteScriptPath}`);

    const sessions: Array<{ session: frida.Session; script: frida.Script; pid: number }> = [];
    for (const pid of pids) {
        try {
            console.log(`[frida] Attaching to WeChatAppEx PID: ${pid}`);
            const session = await localDevice.attach(pid);
            session.detached.connect((reason, crash) => {
                console.error(`[frida] PID ${pid} detached: ${reason}${crash ? " (crash: " + crash.summary + ")" : ""}`);
            });
            const script = await session.createScript(scriptContent);
            script.message.connect((message) => {
                if (message.type === "send" && message.payload && (message.payload as any).tag) {
                    console.log(`[frida:${pid}] [${(message.payload as any).tag}] ${(message.payload as any).msg}`);
                } else if (message.type === "error") {
                    console.error(`[frida:${pid}] script error:`, message.description || message);
                } else {
                    console.log(`[frida:${pid}]`, message);
                }
            });
            await script.load();
            console.log(`[frida] Script loaded in PID ${pid}`);
            sessions.push({ session, script, pid });
        } catch (error) {
            console.error(`[frida] Error attaching to PID ${pid}: ${error}`);
        }
    }
    if (sessions.length === 0) {
        throw new Error("[frida] Failed to attach to any WeChatAppEx process");
    }

    const shutdown = async () => {
        console.log("\n[shutdown] detaching...");
        for (const { session, script, pid } of sessions) {
            try {
                await script.unload();
                await session.detach();
            } catch (e) {
                console.error(`[shutdown] PID ${pid}: ${e}`);
            }
        }
        process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

    console.log("[inject] frida hooks resident. Keep this process running.");
};

(async () => {
    try {
        await main();
    } catch (error) {
        console.error("[inject] Error:", error);
        process.exit(1);
    }
})();
