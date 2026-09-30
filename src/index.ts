// 注意：如果你的环境不支持 TypeScript 类型，可以将文件扩展名改为 .js 并移除类型注解
import { promises } from "node:fs";
import { EventEmitter } from "node:events";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";
import { execSync } from "child_process";
import { argv } from "node:process";
import * as fs from "fs";

// 重定向所有输出到文件
const logFile = '/Users/air/Security/Wechat Debug/WMPFDebugger-arm/1.txt';
const logStream = fs.createWriteStream(logFile, { flags: 'w' });

// 保存原始的 console 方法
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleDir = console.dir;

// 重写 console 方法
console.log = (...args: any[]) => {
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)).join(' ');
    logStream.write(message + '\n');
    originalConsoleLog(...args); // 同时输出到控制台
};

console.error = (...args: any[]) => {
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)).join(' ');
    logStream.write('[ERROR] ' + message + '\n');
    originalConsoleError(...args);
};

console.dir = (obj: any, options?: any) => {
    const message = JSON.stringify(obj, null, 2);
    logStream.write(message + '\n');
    originalConsoleDir(obj, options);
};

// 假设这些是 CommonJS 模块
const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

class DebugMessageEmitter extends EventEmitter {}

// 默认调试端口，请勿更改
const DEBUG_PORT = 9421;
// CDP 端口，可按需更改
// 通过导航到 devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${CDP_PORT} 使用此端口
const CDP_PORT = 62000;
// 调试开关
const DEBUG = false;
const DEFAULT_PROCESS_WAIT_MS = 120_000;
const PROCESS_POLL_INTERVAL_MS = 5_000;

const debugMessageEmitter = new DebugMessageEmitter();

const bufferToHexString = (buffer: ArrayBuffer) => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

// --- 全局变量用于存储服务器和 Frida 会话实例 ---
let debugWSS: WebSocketServer | null = null;
let proxyWSS: WebSocketServer | null = null;
let fridaSessions: Array<{session: frida.Session, script: frida.Script, pid: number}> = [];

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const getArgValue = (name: string): string | null => {
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === name && i + 1 < argv.length) {
            return argv[i + 1];
        }
    }
    return null;
};

const debug_server = () => {
    const wss = new WebSocketServer({ port: DEBUG_PORT });
    console.log(`[server] debug server running on ws://localhost:${DEBUG_PORT}`);

    let messageCounter = 0;

    const onMessage = (message: ArrayBuffer) => {
        DEBUG &&
            console.log(
                `[client] received raw message (hex): ${bufferToHexString(message)}`
            );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);

            // 只过滤日志输出，不影响消息处理
            let shouldLog = true;
            if (unwrappedData?.data?.payload) {
                try {
                    const payload = JSON.parse(unwrappedData.data.payload);

                    // 过滤空响应（检查是否只有 id，没有其他有用信息）
                    if (Object.keys(payload).length === 0 ||
                        (payload.result === undefined && payload.method === undefined && payload.error === undefined)) {
                        shouldLog = false;
                    }

                    // 需要过滤日志的 CDP 方法列表（包括请求和响应）
                    const noisyMethods = [
                        'Page.screencastFrame',
                        'Page.screencastFrameAck',
                        'Network.dataReceived',
                        'Network.responseReceivedExtraInfo',
                        'Network.loadingFinished',
                        'Network.requestWillBeSentExtraInfo',
                        'Network.responseReceived',
                        'Network.loadNetworkResource',
                        'Network.getSecurityIsolationStatus',
                        'Network.setCacheDisabled',
                        'Network.setBlockedURLs',
                        'Network.emulateNetworkConditionsByRule',
                        'Network.overrideNetworkState',
                        'Network.clearAcceptedEncodingsOverride'
                    ];

                    // 过滤方法名匹配的请求
                    if (payload.method && noisyMethods.includes(payload.method)) {
                        shouldLog = false;
                    }

                    // 过滤空响应（只有 id 和空 result）
                    if (payload.id && payload.result !== undefined &&
                        Object.keys(payload.result).length === 0) {
                        shouldLog = false;
                    }
                } catch (e) {
                    // payload 可能不是 JSON，继续处理
                }
            }

            // 也过滤掉 customMessage 和 domEvent 类别的日志
            if (unwrappedData?.category === 'customMessage' ||
                unwrappedData?.category === 'domEvent') {
                shouldLog = false;
            }

            if (DEBUG && shouldLog) {
                console.log(`[client] [DEBUG] decoded data:`);
                console.dir(unwrappedData);
            }
        } catch (e) {
            console.error(`[client] err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "setupContext") {
            // SetupContext is an initialization message from the miniapp
            // Just acknowledge it by not crashing - no response needed
            console.log("[client] received setupContext - miniapp initialized");
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            // 需要代理到 CDP 客户端
            debugMessageEmitter.emit("cdpmessage", unwrappedData.data.payload);
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        console.log("[conn] miniapp client connected");
        console.log("[conn] readyState:", ws.readyState, "protocol:", ws.protocol);

        ws.on("message", (data: any) => {
            const len = Buffer.isBuffer(data) ? data.length : (data as ArrayBuffer).byteLength;
            // console.log("[conn] received message, length:", len);
            onMessage(data);
        });

        ws.on("error", (err) => {
            console.error("[client] err:", err);
        });

        ws.on("close", (code, reason) => {
            console.log(`[client] client disconnected - code: ${code}, reason: ${reason.toString()}`);
        });

        // Send a test message to confirm connection
        setTimeout(() => {
            if (ws.readyState === WebSocket.OPEN) {
                console.log("[conn] connection still open after 100ms");
            } else {
                console.log("[conn] connection closed within 100ms, state:", ws.readyState);
            }
        }, 100);
    });

    debugMessageEmitter.on("proxymessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // 编码 CDP 并发送到小程序
                    const rawPayload = {
                        jscontext_id: "",
                        op_id: Math.round(100 * Math.random()),
                        payload: message.toString(),
                    };
                    DEBUG && console.log(rawPayload);
                    const wrappedData = codex.wrapDebugMessageData(
                        rawPayload,
                        "chromeDevtools",
                        0
                    );
                    const outData = {
                        seq: ++messageCounter,
                        category: "chromeDevtools",
                        data: wrappedData.buffer,
                        compressAlgo: 0,
                        originalSize: wrappedData.originalSize,
                    };
                    const encodedData =
                        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(
                            outData
                        ).finish();
                    client.send(encodedData, { binary: true });
                }
            });
    });

    return wss; // 返回实例以便后续管理
};

const proxy_server = () => {
    const wss = new WebSocketServer({ port: CDP_PORT });
    console.log(`[server] proxy server running on ws://localhost:${CDP_PORT}`);

    const onMessage = (message: string) => {
        debugMessageEmitter.emit("proxymessage", message);
    };

    wss.on("connection", (ws: WebSocket) => {
        console.log("[conn] CDP client connected");
        ws.on("message", onMessage);
        ws.on("error", (err) => {
            console.error("[client] CDP err:", err);
        });
        ws.on("close", () => {
            console.log("[client] CDP client disconnected");
        });
    });

    debugMessageEmitter.on("cdpmessage", (message: string) => {
        wss &&
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    // 发送 CDP 消息到 devtools
                    client.send(message);
                }
            });
    });

    return wss; // 返回实例以便后续管理
};

const getProcessPath = (process: frida.Process): string => {
    const parameters = process.parameters as Record<string, unknown>;
    const pathValue = parameters.path || parameters["Path"];
    return typeof pathValue === "string" ? pathValue : "";
};

const isWeChatAppExProcess = (process: frida.Process): boolean => {
    const name = process.name || "";
    const processPath = getProcessPath(process);
    return (
        name === "WeChatAppEx" ||
        name.includes("WeChatAppEx") ||
        processPath.includes("WeChatAppEx.app") ||
        processPath.includes("WeChatAppEx Framework")
    );
};

const getProcessPriority = (process: frida.Process): number => {
    const processPath = getProcessPath(process);
    if (processPath.endsWith("/WeChatAppEx.app/Contents/MacOS/WeChatAppEx")) {
        return 0;
    }
    if (process.name === "WeChatAppEx") {
        return 1;
    }
    if (process.name === "微信" && processPath.includes("/WeChatAppEx.app/Contents/MacOS/WeChatAppEx")) {
        return 2;
    }
    if (process.name.includes("Renderer")) {
        return 20;
    }
    if (process.name.includes("GPU")) {
        return 30;
    }
    return 10;
};

const getPidsFromPgrep = (): number[] => {
    const commands = [
        "pgrep -f '/WeChatAppEx.app/Contents/MacOS/WeChatAppEx'",
        "pgrep -f '/MacOS/WeChatAppEx.app/Contents/MacOS/WeChatAppEx'",
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
        } catch (_) {
            // Try the next pattern.
        }
    }

    return [];
};

// 动态获取 WeChatAppEx 进程 PID 的函数
const findWeChatAppExPIDs = async (localDevice: frida.Device): Promise<number[]> => {
    const manualPid = getArgValue("--pid");
    if (manualPid) {
        const pid = parseInt(manualPid, 10);
        if (!isNaN(pid)) {
            console.log(`[frida] Using PID from --pid: ${pid}`);
            return [pid];
        }
        throw new Error(`[frida] Invalid --pid value: ${manualPid}`);
    }

    try {
        const processes = await localDevice.enumerateProcesses({ scope: frida.Scope.Full });
        let matches = processes
            .filter(isWeChatAppExProcess)
            .sort((a, b) => getProcessPriority(a) - getProcessPriority(b));

        const includeHelpers = argv.includes("--include-helpers");
        if (!includeHelpers) {
            const mainMatches = matches.filter((process) => getProcessPriority(process) <= 2);
            if (mainMatches.length > 0) {
                matches = mainMatches;
            }
        }

        const pids = matches.map((process) => process.pid);

        if (pids.length > 0) {
            const labels = matches.map((process) => {
                const processPath = getProcessPath(process);
                return processPath ? `${process.pid}:${process.name} (${processPath})` : `${process.pid}:${process.name}`;
            });
            console.log(`[frida] Found WeChatAppEx processes: ${labels.join(", ")}`);
            return pids;
        }
    } catch (error) {
        console.warn(`[frida] Frida process enumeration failed: ${error}`);
    }

    return getPidsFromPgrep();
};

const waitForWeChatAppExPIDs = async (localDevice: frida.Device): Promise<number[]> => {
    const waitArg = getArgValue("--wait-process-ms");
    const maxWaitMs = waitArg ? parseInt(waitArg, 10) : DEFAULT_PROCESS_WAIT_MS;
    const startedAt = Date.now();

    while (true) {
        const pids = await findWeChatAppExPIDs(localDevice);
        if (pids.length > 0) {
            return pids;
        }

        const elapsed = Date.now() - startedAt;
        if (elapsed >= maxWaitMs) {
            throw new Error(
                "[frida] No WeChatAppEx process found. Open WeChat and launch a mini program, " +
                "then rerun this command. You can also pass --pid <PID> if you already know it."
            );
        }

        const remaining = Math.ceil((maxWaitMs - elapsed) / 1000);
        console.log(`[frida] Waiting for WeChatAppEx process... open a mini program in WeChat (${remaining}s left)`);
        await sleep(PROCESS_POLL_INTERVAL_MS);
    }
};

const frida_server = async () => {
    const localDevice = await frida.getLocalDevice();

    // 获取所有 WeChatAppEx 进程的 PID
    const pids = await waitForWeChatAppExPIDs(localDevice);

    // 查找 hook 脚本
    // 使用 __dirname 获取当前脚本所在目录更可靠
    const projectRoot = path.join(__dirname, "..");
    
    // 解析命令行参数，查找 --script 参数
    let scriptPath = "frida/hook.js"; // 默认脚本
    const customScriptPath = getArgValue("--script");
    if (customScriptPath) {
        scriptPath = customScriptPath;
        console.log(`[frida] Using custom script: ${scriptPath}`);
    }
    
    let scriptContent: string | null = null;
    try {
        // 使用绝对路径或相对于项目根目录的路径
        const absoluteScriptPath = path.isAbsolute(scriptPath) ? scriptPath : path.join(projectRoot, scriptPath);
        scriptContent = (
            await promises.readFile(absoluteScriptPath)
        ).toString();
        console.log(`[frida] Loaded script from: ${absoluteScriptPath}`);
    } catch (e) {
        console.error(`[frida] Error loading script: ${e}`);
        throw new Error("[frida] hook script not found");
    }

    // 附加到所有找到的进程并加载脚本
    const sessionsAndScripts: Array<{session: frida.Session, script: frida.Script, pid: number}> = [];
    const attachErrors: string[] = [];
    
    for (const pid of pids) {
        try {
            console.log(`[frida] Attaching to WeChatAppEx process PID: ${pid}`);
            // 附加到进程
            const session = await localDevice.attach(pid);
            
            // 加载脚本
            const script = await session.createScript(scriptContent);
            script.message.connect((message) => {
                console.log(`[frida client] PID ${pid}:`, message);
            });
            
            await script.load();
            console.log(`[frida] Successfully attached to PID ${pid}`);
            
            sessionsAndScripts.push({ session, script, pid });
        } catch (error) {
            const message = `${error}`;
            attachErrors.push(message);
            console.error(`[frida] Error attaching to PID ${pid}: ${message}`);
            // 继续尝试其他进程
        }
    }
    
    if (sessionsAndScripts.length === 0) {
        if (attachErrors.some((message) => message.includes("Unable to access process"))) {
            console.error(
                "[frida] macOS denied process attach. Try granting Developer Tools permission " +
                "to your terminal app, or run the command with sudo."
            );
        }
        throw new Error("[frida] Failed to attach to any WeChatAppEx process");
    }
    
    console.log(`[frida] Successfully attached to ${sessionsAndScripts.length} WeChatAppEx processes`);
    return sessionsAndScripts;
};

// --- 关闭服务器和清理资源的函数 ---
const shutdown = async () => {
    console.log("\n[shutdown] Shutting down servers and cleaning up...");

    const closePromises: Promise<void>[] = [];

    // 关闭所有 Frida 会话和脚本
    if (fridaSessions.length > 0) {
        console.log(`[shutdown] Detaching ${fridaSessions.length} Frida sessions...`);
        
        for (const { session, script, pid } of fridaSessions) {
            try {
                // 先卸载脚本
                if (script) {
                    console.log(`[shutdown] Unloading script from PID ${pid}...`);
                    await script.unload();
                }
                
                // 然后分离会话
                if (session) {
                    console.log(`[shutdown] Detaching from PID ${pid}...`);
                    await session.detach();
                }
            } catch (error) {
                console.error(`[shutdown] Error cleaning up PID ${pid}: ${error}`);
            }
        }
        
        // 清空会话数组
        fridaSessions = [];
        console.log("[shutdown] All Frida sessions detached.");
    }

    // 关闭 Debug WebSocket Server
    if (debugWSS) {
        console.log("[shutdown] Closing debug WebSocket connections...");
        // 关闭所有活动客户端连接
        debugWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate(); // 强制关闭客户端连接
            }
        });
        console.log("[shutdown] Closing debug WebSocket server...");
        closePromises.push(
            new Promise<void>((resolve, reject) => {
                debugWSS!.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing debug WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Debug WebSocket server closed."
                        );
                    }
                    resolve(); // 总是 resolve 以继续关闭流程
                });
            })
        );
        debugWSS = null; // 清除引用
    }

    // 关闭 Proxy WebSocket Server
    if (proxyWSS) {
        console.log("[shutdown] Closing proxy WebSocket connections...");
        proxyWSS.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CLOSING) {
                client.terminate();
            }
        });
        console.log("[shutdown] Closing proxy WebSocket server...");
        closePromises.push(
            new Promise<void>((resolve, reject) => {
                proxyWSS!.close((err) => {
                    if (err) {
                        console.error(
                            "[shutdown] Error closing proxy WSS:",
                            err
                        );
                    } else {
                        console.log(
                            "[shutdown] Proxy WebSocket server closed."
                        );
                    }
                    resolve();
                });
            })
        );
        proxyWSS = null; // 清除引用
    }

    // 等待所有 WebSocket 服务器关闭
    if (closePromises.length > 0) {
        try {
            await Promise.all(closePromises);
        } catch (err) {
            console.error(
                "[shutdown] Error waiting for WebSocket servers to close:",
                err
            );
        }
    }

    console.log("[shutdown] Shutdown complete. Exiting.");
    process.exit(0); // 强制退出，确保清理完毕
};
// --- 主函数 ---

const main = async () => {
    try {
        // 启动服务器并保存实例引用
        debugWSS = debug_server();
        proxyWSS = proxy_server();
        const fridaObjects = await frida_server();
        fridaSessions = fridaObjects; // 保存所有会话和脚本引用

        // 添加 SIGINT (Ctrl+C) 和 SIGTERM 监听器
        process.on("SIGINT", () => {
            console.log("\n[signal] Received SIGINT (Ctrl+C)");
            shutdown(); // 开始关闭流程
        });

        process.on("SIGTERM", () => {
            console.log("\n[signal] Received SIGTERM");
            shutdown();
        });

        // 可选：监听未捕获的异常，防止程序意外崩溃而不清理
        process.on('uncaughtException', (err) => {
            console.error('[main] Uncaught Exception:', err);
            shutdown(); // 出现严重错误也尝试清理
        });

        console.log(
            "[main] Servers started. Press Ctrl+C to stop.\n" +
            `Debug endpoint: ws://localhost:${DEBUG_PORT}\n` +
            `CDP endpoint:   ws://localhost:${CDP_PORT}`
        );
    } catch (error) {
        console.error("[main] Error starting services:", error);
        process.exit(1); // 启动失败则退出
    }
};

// --- 程序入口 ---
(async () => {
    await main();
})();
